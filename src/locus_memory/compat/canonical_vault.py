"""Legacy-shaped operations over the authoritative memory engine.

Hosts supply paths, key custody, the security partition and caller identity.
Compatibility policy, authorization, candidate handling, metadata revisions,
import/export and lifecycle operations belong to the package. Nothing in this
module imports a host application or discovers its profile.
"""
from __future__ import annotations

import contextlib
import dataclasses
import functools
import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

from locus_memory import MemoryEngine, policy, safety
from locus_memory.compat.legacy_vault import (
    LEGACY_MEMORY_VERSION,
    LegacyVaultError,
    legacy_target,
)
from locus_memory.crypto import KeyProvider
from locus_memory.errors import MemoryEngineError, NotFound, SuppressedError, ValidationError
from locus_memory.host import HostCapabilities
from locus_memory.migrations.state import OwnershipControl
from locus_memory.models import (
    AccessContext,
    Actor,
    CandidateProposal,
    Confidence,
    Correction,
    ForgetTarget,
    Lifecycle,
    MemoryKind,
    MemoryRecord,
    Operation,
    PartitionRef,
    Query,
    RememberRequest,
    Retention,
    Scope,
    ScopeGrants,
    SourceKind,
    SourceRef,
    StatementBasis,
    Validity,
)
from locus_memory.validation import check_id, check_mapping, check_text, check_timestamp

_SCOPES = ("personal", "workspace", "agent")
_LIVE = (Lifecycle.APPROVED, Lifecycle.CANDIDATE, Lifecycle.STALE, Lifecycle.SUPERSEDED)


def _api(method):
    @functools.wraps(method)
    def wrapped(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except MemoryEngineError as exc:
            raise LegacyVaultError(str(exc)) from exc
        except (TypeError, ValueError) as exc:
            raise LegacyVaultError("memory input is invalid") from exc
    return wrapped


class CanonicalMemoryVault:
    def __init__(self, root: Path | str, key_provider: KeyProvider, *,
                 partition: PartitionRef, workspace: str = "", agent_id: str = "primary",
                 actor: Actor = Actor.USER, scopes: tuple[str, ...] | list[str] | None = None,
                 principal: str = "local-user", host_name: str = "memory-host") -> None:
        self.path = Path(root)
        self.partition = partition
        self.workspace, self.agent_id = workspace, agent_id
        self.principal, self.host_name = principal, host_name
        self.actor = Actor(actor)
        if self.actor not in (Actor.USER, Actor.AGENT):
            raise LegacyVaultError("unsupported host memory actor")
        self.scopes = tuple(_SCOPES if scopes is None else scopes)
        self.control = OwnershipControl(self.path)
        self.engine = MemoryEngine(self.path, key_provider,
                                   host=HostCapabilities(ownership=self.control),
                                   create_partitions=False)

    def close(self) -> None:
        for name in ("engine", "control"):
            value = getattr(self, name, None)
            if value is not None:
                value.close()
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        with contextlib.suppress(Exception):
            self.close()

    def _access(self, workspace=None, agent_id=None, scopes=None) -> tuple[AccessContext, tuple[str, ...]]:
        if self.actor == Actor.AGENT and (
            (workspace is not None and workspace != self.workspace)
            or (agent_id is not None and agent_id != self.agent_id)
        ):
            raise ValidationError("agent memory identity cannot be widened")
        workspace = self.workspace if workspace is None else workspace
        agent_id = self.agent_id if agent_id is None else agent_id
        selected = tuple(s for s in (self.scopes if scopes is None else scopes)
                         if s in self.scopes and s in _SCOPES)
        projects, agents, targets = set(), set(), set()
        if "workspace" in selected and workspace:
            target = legacy_target("workspace", workspace=workspace)
            targets.add(target)
            projects.add("ws-" + target.split(":", 1)[1][:32])
        if "agent" in selected and agent_id:
            targets.add(legacy_target("agent", agent_id=agent_id))
            agents.add(agent_id)
        operations = ({Operation.READ, Operation.PROPOSE} if self.actor == Actor.AGENT else
                      {Operation.READ, Operation.WRITE, Operation.PROPOSE, Operation.APPROVE,
                       Operation.FORGET})
        return AccessContext(
            principal=self.principal, partition=self.partition, actor=self.actor,
            grants=ScopeGrants(projects=frozenset(projects), agents=frozenset(agents),
                               legacy_targets=frozenset(targets)),
            operations=frozenset(operations), purpose=f"{self.host_name}-memory-api", issuer=self.host_name,
        ), selected

    @staticmethod
    def _scope_name(record: MemoryRecord) -> str:
        if record.scope.is_global:
            return "personal"
        target = record.scope.get("legacy_target")
        if target and target.split(":", 1)[0] in {"workspace", "agent"}:
            return target.split(":", 1)[0]
        return "agent" if record.scope.get("agent") else "workspace"

    def _get(self, access, selected, memory_id):
        record = self.engine.get(access, memory_id)
        if self._scope_name(record) not in selected:
            raise NotFound("memory not found")
        return record

    def _shape(self, record: MemoryRecord) -> dict[str, Any]:
        extra = record.extra
        sources = {s.locator.get("legacy_field"): s.ref for s in record.sources}
        return {
            "id": record.id, "revision": record.revision,
            "status": "candidate" if record.lifecycle == Lifecycle.CANDIDATE else "approved",
            "scope": self._scope_name(record), "kind": record.kind.value,
            "title": record.title, "content": record.content, "tags": list(record.tags),
            "reason": record.reason, "confidence": record.confidence.value,
            "valid_from": record.validity.valid_from, "valid_until": record.validity.valid_until,
            "pinned": record.pinned, "stale": record.lifecycle in (Lifecycle.STALE, Lifecycle.SUPERSEDED),
            "supersedes": list(record.links.supersedes), "superseded_by": record.links.superseded_by,
            "created_at": record.created_at, "updated_at": record.updated_at,
            "expires_at": record.retention.expires_at,
            "last_confirmed_at": extra.get("last_confirmed_at"),
            "source_session_id": sources.get("source_session_id"),
            "source_run_id": sources.get("source_run_id"),
            "provenance": extra.get("legacy_provenance", {}),
            "feedback": extra.get("legacy_feedback", {}),
            "embedding_model": "", "last_used_at": extra.get("legacy_last_used_at"),
            "use_count": extra.get("legacy_use_count", 0),
        }

    @_api
    def list(self, *, workspace=None, agent_id=None, status="", scopes=None):
        access, selected = self._access(workspace, agent_id, scopes)
        if not selected:
            return []
        lifecycles = ((Lifecycle.CANDIDATE,) if status == "candidate" else
                      (Lifecycle.APPROVED, Lifecycle.STALE, Lifecycle.SUPERSEDED)
                      if status == "approved" else _LIVE)
        records, offset = [], 0
        while True:
            page = self.engine.list(access, lifecycles=lifecycles, limit=1000, offset=offset)
            records.extend(r for r in page if self._scope_name(r) in selected)
            if len(page) < 1000:
                break
            offset += len(page)
        return [self._shape(r) for r in sorted(records, key=lambda r: (r.pinned, r.updated_at), reverse=True)]

    @_api
    def search(self, query: str, *, workspace=None, agent_id=None, scopes=None, limit=8,
               embedding_model="", ollama_host="http://127.0.0.1:11434", **_):
        access, selected = self._access(workspace, agent_id, scopes)
        if not selected:
            return []
        # ScopeGrants permits global records; explicit host policy still excludes
        # personal records. Fetch a bounded larger window before that final filter.
        result = self.engine.search(access, Query(text=query, limit=200))
        return [{**self._shape(hit.record), "score": hit.score,
                 "retrieval_reason": ", ".join(hit.reasons) or "matched the request"}
                for hit in result.hits if self._scope_name(hit.record) in selected][:max(1, min(limit, 20))]

    def _target(self, name, workspace, agent_id):
        if name == "personal":
            return Scope.global_()
        workspace = self.workspace if workspace is None else workspace
        agent_id = self.agent_id if agent_id is None else agent_id
        return Scope.of(legacy_target=legacy_target(name, workspace=workspace, agent_id=agent_id))

    def _propose(self, access, request, value, memory_id):
        """Persist the host-observed proposal without falsely attesting user evidence.

        A tool invocation is itself provenance, not verification of its assertion.
        Package content gates, suppression and actor permissions still apply; this
        host-only seam never grants the agent WRITE or APPROVE.
        """
        ctx = self.engine.partition_context(self.partition)
        core = ctx.services.core
        basis, scan = core._check_proposal(access, request)
        now = time.time()
        with ctx.partition.db.write() as conn:
            core._check_owner()
            identifier = memory_id or uuid.uuid4().hex
            check_id(identifier)
            if ctx.records.get(conn, identifier) is not None or core._forgotten_id(conn, identifier):
                raise ValidationError("memory id already exists or was forgotten")
            record = MemoryRecord(
                id=identifier, revision=1, kind=request.kind, lifecycle=Lifecycle.CANDIDATE,
                scope=request.scope, title=request.title or request.content[:60], content=request.content,
                tags=request.tags, basis=basis, confidence=request.confidence,
                sources=request.sources, validity=request.validity,
                retention=Retention("durable", now + 30 * 86400, False),
                created_at=now, updated_at=now, event_time=now, ingested_at=now,
                reason=request.rationale,
                extra={"basis_attested_by": access.actor.value, "proposer": request.proposer,
                       **({"flags": ["instruction_like"]} if scan.injection else {})},
            )
            record = self._metadata_record(record, value)
            blocked = core._blocked(conn, record)
            if blocked:
                raise SuppressedError(f"candidate refused: {blocked}")
            record = core.write_internal(conn, record, change="proposed", actor=access.actor, expected=None)
            ctx.partition.event(conn, "proposal", "accepted")
        return record

    @staticmethod
    def _metadata_record(record, value):
        extra = dict(record.extra)
        sources = list(record.sources)
        for name, kind in (("source_session_id", SourceKind.SESSION), ("source_run_id", SourceKind.TASK_ATTEMPT)):
            if name in value:
                sources = [source for source in sources if source.locator.get("legacy_field") != name]
                ref = str(value[name] or "")[:160]
                if ref:
                    sources.append(SourceRef(kind, ref, actor=Actor.HOST,
                                             locator={"legacy_field": name}, available=False))
        if "provenance" in value:
            extra["legacy_provenance"] = check_mapping(value["provenance"] or {}, "provenance")
        changes = {"extra": extra, "sources": tuple(sources)}
        if "reason" in value:
            changes["reason"] = check_text(str(value["reason"] or ""), "reason", max_chars=2000, allow_empty=True)
        return dataclasses.replace(record, **changes)

    @_api
    def save(self, value: dict[str, Any], memory_id="", *, workspace=None, agent_id=None,
             default_status="approved", _created_at=None, **_):
        access, selected = self._access(workspace, agent_id)
        if _created_at is not None:
            _created_at = check_timestamp(_created_at, "created_at")
        if not isinstance(value, dict):
            raise ValidationError("memory input must be an object")
        existing = None
        if memory_id:
            check_id(memory_id)
            try:
                existing = self._get(access, selected, memory_id)
            except NotFound:
                # Unauthorized records must not be replaceable by guessed ids.
                ctx = self.engine.partition_context(self.partition)
                with ctx.partition.db.read() as conn:
                    if conn.execute("SELECT 1 FROM records WHERE id=?", (memory_id,)).fetchone():
                        raise
        requested_scope = str(value.get("scope") or
                              (self._scope_name(existing) if existing else "workspace"))
        if requested_scope not in selected:
            raise ValidationError("that memory scope is disabled for this caller")
        desired_status = str(value.get("status") or
                             (self._shape(existing)["status"] if existing else default_status))
        if desired_status not in {"approved", "candidate"}:
            raise ValidationError("memory status or scope is invalid")
        if self.actor == Actor.AGENT and (desired_status != "candidate" or memory_id):
            raise ValidationError("agents may only propose new memory candidates")
        kind = MemoryKind.parse(value.get("kind", existing.kind if existing else "fact"))
        if kind not in {MemoryKind.PREFERENCE, MemoryKind.FACT, MemoryKind.DECISION,
                        MemoryKind.RELATIONSHIP, MemoryKind.PROCEDURE}:
            raise ValidationError("unsupported memory type")
        raw_tags = value.get("tags") or []
        if not isinstance(raw_tags, (str, list, tuple)):
            raise ValidationError("memory tags must be a list")
        tags = (raw_tags,) if isinstance(raw_tags, str) else tuple(raw_tags)
        validity = Validity(value.get("valid_from", existing.validity.valid_from if existing else None),
                            value.get("valid_until", existing.validity.valid_until if existing else None))
        raw_confidence = value.get("confidence", existing.confidence.value if existing else 1.0)
        confidence = Confidence(None if raw_confidence is None else float(raw_confidence), False, "host_supplied")
        # Validate bounded metadata before the first durable content write.
        provenance = check_mapping(value.get("provenance") or {}, "provenance")
        for field, source_kind in (("source_session_id", SourceKind.SESSION), ("source_run_id", SourceKind.TASK_ATTEMPT)):
            if value.get(field):
                SourceRef(source_kind, str(value[field])[:160], actor=Actor.HOST, available=False)
        reason = check_text(str(value.get("reason") or ""), "reason", max_chars=2000, allow_empty=True)
        if safety.scan(json.dumps(provenance, sort_keys=True) + "\n" + reason).secrets:
            raise ValidationError("credentials are not stored in memory metadata")
        scope = self._target(requested_scope, workspace, agent_id)
        if existing is not None:
            if self._scope_name(existing) != requested_scope:
                raise ValidationError("moving an existing memory between scopes is not supported")
            scope = existing.scope
            if kind != existing.kind:
                raise ValidationError("changing an existing memory type is not supported")
            if desired_status == "candidate" and existing.lifecycle != Lifecycle.CANDIDATE:
                raise ValidationError("approved memories cannot become candidates")
            # A pin/metadata edit is not a re-confirmation of stale content.
            changes = {}
            for name in ("content", "title", "tags"):
                if name in value and (tuple(value[name]) if name == "tags" else value[name]) != getattr(existing, name):
                    changes[name] = tags if name == "tags" else value[name]
            if ("valid_from" in value or "valid_until" in value) and validity != existing.validity:
                changes["validity"] = validity
            if changes:
                existing = self.engine.correct(
                    access, memory_id, Correction(**changes, reason=str(value.get("reason") or ""),
                                                  allow_sensitive=value.get("allow_sensitive") is True),
                    expected_revision=existing.revision,
                ).record
            if desired_status == "approved" and existing.lifecycle == Lifecycle.CANDIDATE:
                existing = self.engine.approve(access, memory_id, expected_revision=existing.revision).record
            result = existing
        else:
            if kind == MemoryKind.PROCEDURE:
                raise ValidationError("new procedures require the procedure review API")
            text = str(value.get("content") or "").strip()
            title = str(value.get("title") or "Memory").strip()[:160]
            if desired_status == "candidate":
                identifier = uuid.uuid4().hex
                source = SourceRef(
                    SourceKind.DOCUMENT, f"{self.host_name}-proposal-" + identifier, actor=self.actor,
                    fingerprint=hashlib.sha256(text.encode()).hexdigest(),
                    locator={"host": self.host_name, "kind": "tool_proposal" if self.actor == Actor.AGENT else "user_proposal"},
                    observed_at=time.time(),
                )
                request = CandidateProposal(
                    content=text, title=title, kind=kind, scope=scope, tags=tags, validity=validity,
                    confidence=confidence, rationale=str(value.get("reason") or ""), sources=(source,),
                    basis=StatementBasis.MODEL_INTERPRETATION if self.actor == Actor.AGENT else StatementBasis.USER_STATED,
                    proposer=self.agent_id if self.actor == Actor.AGENT else f"{self.host_name}-user",
                )
                result = self._propose(access, request, value, memory_id)
            else:
                result = self.engine.remember(access, RememberRequest(
                    content=text, title=title, kind=kind, scope=scope, tags=tags, validity=validity,
                    confidence=confidence, reason=str(value.get("reason") or ""), memory_id=memory_id or None,
                    retention=Retention(pinned=bool(value.get("pinned"))),
                    allow_sensitive=value.get("allow_sensitive") is True,
                )).record
        if self.actor != Actor.AGENT:
            ctx = self.engine.partition_context(self.partition)
            with ctx.partition.db.write() as conn:
                policy.require_author(access)
                current = ctx.services.core.load_visible(conn, access, result.id)
                ctx.services.core._check_expected(current, result.revision)
                updated = self._metadata_record(current, value)
                if existing is None and _created_at is not None:
                    updated = dataclasses.replace(updated, created_at=_created_at)
                updated = dataclasses.replace(
                    updated,
                    confidence=confidence if "confidence" in value else current.confidence,
                    retention=dataclasses.replace(current.retention, pinned=bool(value["pinned"]))
                    if "pinned" in value else current.retention,
                )
                if updated != current:
                    result = ctx.services.core.write_internal(
                        conn, dataclasses.replace(updated, revision=current.revision + 1, updated_at=time.time()),
                        change=f"{self.host_name}_metadata", actor=access.actor, expected=current.revision,
                    )
        if value.get("stale") and result.lifecycle == Lifecycle.APPROVED:
            return self.feedback(result.id, "incorrect", workspace=workspace, agent_id=agent_id)
        shaped = self._shape(self.engine.get(access, result.id))
        shaped["conflicts"] = self.conflicts_for(shaped, workspace=workspace, agent_id=agent_id)
        return shaped

    @_api
    def approve(self, memory_id, *, workspace=None, agent_id=None, resolution="keep_both"):
        if resolution not in {"keep_both", "replace"}:
            raise ValidationError("memory conflict resolution must be keep_both or replace")
        access, selected = self._access(workspace, agent_id)
        current = self._get(access, selected, memory_id)
        result = self.engine.approve(access, memory_id, expected_revision=current.revision).record
        # Legacy conflict suggestions are textual hints. Replace is an explicit
        # user action; each retirement still passes the engine's authorization.
        if resolution == "replace":
            for conflict in self.conflicts_for(self._shape(current), workspace=workspace, agent_id=agent_id):
                other = self._get(access, selected, conflict["id"])
                self.engine.supersede(access, other.id, result.id, expected_revision=other.revision)
            result = self.engine.get(access, result.id)
        shaped = self._shape(self.engine.get(access, result.id))
        shaped["conflicts"] = self.conflicts_for(shaped, workspace=workspace, agent_id=agent_id)
        return shaped

    @_api
    def delete(self, memory_id, *, workspace=None, agent_id=None):
        access, selected = self._access(workspace, agent_id)
        try:
            self._get(access, selected, memory_id)
        except NotFound:
            return False
        self.control.assert_writer(self.partition.partition_id, "memories", "package")
        self.engine.forget(access, ForgetTarget("memory", memory_id))
        return True

    @_api
    def delete_all(self, *, workspace=None, agent_id=None, scopes=None):
        items = self.list(workspace=workspace, agent_id=agent_id, scopes=scopes)
        return sum(self.delete(item["id"], workspace=workspace, agent_id=agent_id) for item in items)

    @_api
    def feedback(self, memory_id, outcome, *, workspace=None, agent_id=None):
        if outcome not in {"helpful", "ignored", "incorrect"}:
            raise ValidationError("memory feedback must be helpful, ignored, or incorrect")
        access, selected = self._access(workspace, agent_id)
        policy.require_author(access)
        self._get(access, selected, memory_id)
        ctx = self.engine.partition_context(self.partition)
        with ctx.partition.db.write() as conn:
            current = ctx.services.core.load_visible(conn, access, memory_id)
            counts = dict(current.extra.get("legacy_feedback", {}))
            counts[outcome] = counts.get(outcome, 0) + 1
            lifecycle = (Lifecycle.STALE if outcome == "incorrect" and current.lifecycle == Lifecycle.APPROVED
                         else current.lifecycle)
            updated = dataclasses.replace(
                current, revision=current.revision + 1, updated_at=time.time(), lifecycle=lifecycle,
                extra={**current.extra, "legacy_feedback": counts},
            )
            ctx.services.core.write_internal(conn, updated, change=f"{self.host_name}_feedback", actor=access.actor,
                                             expected=current.revision)
            if lifecycle != current.lifecycle:
                ctx.services.core._stale_derived(conn, current.id)
            ctx.partition.event(conn, "feedback", outcome)
        return self._shape(self.engine.get(access, updated.id))

    def conflicts_for(self, memory, *, workspace=None, agent_id=None):
        def tokens(item):
            return set(re.findall(r"[a-z0-9_.-]{3,}", (str(item.get("title", "")) + " " + " ".join(item.get("tags", []))).lower()))
        topic = tokens(memory)
        if not topic:
            return []
        return [{k: item[k] for k in ("id", "title", "content", "kind", "confidence")}
                for item in self.list(workspace=workspace, agent_id=agent_id, status="approved", scopes=[memory["scope"]])
                if item["id"] != memory.get("id") and not item["stale"]
                and item["content"].strip().lower() != str(memory.get("content", "")).strip().lower()
                and len(topic & tokens(item)) / max(min(len(topic), len(tokens(item))), 1) >= 0.5][:12]

    @_api
    def record_event(self, stage, outcome, *, workspace=None, agent_id=None, session_id="", run_id="",
                     reason_code="", memory_id=""):
        # The engine records durable operation events. Host telemetry carries no
        # memory content, source text or user/model-supplied reason strings.
        allowed_stages = {"approval", "proposal", "recall", "rejection", "deletion", "feedback", "policy", "expiration"}
        allowed_outcomes = {"accepted", "rejected", "matched", "empty", "recorded", "evaluated", "expired"}
        if stage not in allowed_stages or outcome not in allowed_outcomes:
            return
        ctx = self.engine.partition_context(self.partition)
        with ctx.partition.db.write() as conn:
            self.control.assert_writer(self.partition.partition_id, "memories", "package")
            ctx.partition.event(conn, stage, outcome)

    def status(self, *, workspace=None, agent_id=None):
        items = self.list(workspace=workspace, agent_id=agent_id)
        return {"encrypted": True, "cipher": "AES-256-GCM", "semantic_encrypted": True,
                "memory_version": LEGACY_MEMORY_VERSION, "candidate_ttl_days": 30,
                "approved_count": sum(i["status"] == "approved" for i in items),
                "candidate_count": sum(i["status"] == "candidate" for i in items),
                "stale_count": sum(i["stale"] for i in items),
                "expired_count": sum(i["valid_until"] is not None and i["valid_until"] < time.time() for i in items),
                "conflict_count": sum(bool(self.conflicts_for(i, workspace=workspace, agent_id=agent_id)) for i in items)}

    def diagnostics(self, *, workspace=None, agent_id=None):
        # Existing partition events have no workspace attribution. Do not leak
        # another scope's activity by presenting them as this workspace's history.
        return {**self.status(workspace=workspace, agent_id=agent_id), "events": [], "counts": {},
                "last_proposal": None, "last_approval": None, "history_available": False}

    @_api
    def maintain(self, *, workspace=None, agent_id=None):
        access, _ = self._access(workspace, agent_id)
        policy.require_author(access)
        host = dataclasses.replace(access, actor=Actor.HOST, operations=frozenset({Operation.MAINTAIN}))
        result = self.engine.maintain(host)
        return {"ok": True, "expired_marked_stale": result.get("validity_marked_stale", 0),
                "conflict_count": 0, "conflicts": {}, "engine": result}

    def expire_candidates(self, *, workspace=None, agent_id=None):
        return self.maintain(workspace=workspace, agent_id=agent_id)["engine"].get("candidates_expired", 0)

    def export(self, *, workspace=None, agent_id=None):
        return {"format": "locus-memory-export", "version": 2, "exported_at": time.time(),
                "memories": self.list(workspace=workspace, agent_id=agent_id)}

    @_api
    def import_values(self, document, *, workspace=None, agent_id=None):
        if document.get("format") != "locus-memory-export" or document.get("version") not in {1, 2}:
            raise ValidationError("memory import format is not supported")
        items = document.get("memories")
        if not isinstance(items, list) or len(items) > 10000:
            raise ValidationError("memory import is malformed or too large")
        count = 0
        for item in items:
            if isinstance(item, dict):
                self.save(item, str(item.get("id") or ""), workspace=workspace, agent_id=agent_id)
                count += 1
        return count

    @_api
    def import_legacy_note(self, note, *, workspace):
        identifier = "legacy-" + hashlib.sha256(f"{Path(workspace).resolve()}|{note['id']}".encode()).hexdigest()[:40]
        access, selected = self._access(workspace)
        try:
            self._get(access, selected, identifier)
            return identifier, "already_migrated"
        except NotFound:
            pass
        self.save({**note, "scope": "workspace", "status": "approved"}, identifier, workspace=workspace,
                  _created_at=float(note.get("created_at") or time.time()))
        return identifier, "migrated"
