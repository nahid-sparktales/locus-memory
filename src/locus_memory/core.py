"""Canonical memory lifecycle: remember, propose, review, correct, supersede, expire.

Transitions (anything else raises InvalidTransition):

    candidate  -> approved | rejected | expired | superseded
    approved   -> approved (correction) | stale | superseded | expired
    stale      -> approved (re-confirm/correct) | superseded | expired
    superseded -> approved (explicit revert by a reviewer)
    rejected, expired -> (terminal; only forgetting removes them)

Forgetting is not a transition on a live row: it purges the row and records a
tombstone (see forgetting.py).
"""
from __future__ import annotations

import dataclasses
import re
import sqlite3
from typing import Any

from . import policy, safety
from .errors import (
    InvalidTransition,
    MemoryEngineError,
    NotFound,
    SensitiveContent,
    ValidationError,
)
from .models import (
    AccessContext,
    Actor,
    CandidateProposal,
    Confidence,
    Correction,
    Lifecycle,
    Links,
    MemoryKind,
    MemoryRecord,
    Operation,
    Receipt,
    RememberRequest,
    Retention,
    Scope,
    SourceKind,
    SourceRef,
    StatementBasis,
    WriteResult,
)
from .services import PartitionContext
from .storage.partition import new_id
from .validation import check_id, normalize_for_fingerprint

ALLOWED: dict[Lifecycle, frozenset[Lifecycle]] = {
    Lifecycle.CANDIDATE: frozenset({Lifecycle.APPROVED, Lifecycle.REJECTED, Lifecycle.EXPIRED, Lifecycle.SUPERSEDED}),
    Lifecycle.APPROVED: frozenset({Lifecycle.APPROVED, Lifecycle.STALE, Lifecycle.SUPERSEDED, Lifecycle.EXPIRED}),
    Lifecycle.STALE: frozenset({Lifecycle.APPROVED, Lifecycle.SUPERSEDED, Lifecycle.EXPIRED}),
    Lifecycle.SUPERSEDED: frozenset({Lifecycle.APPROVED}),
    Lifecycle.REJECTED: frozenset(),
    Lifecycle.EXPIRED: frozenset(),
    Lifecycle.FORGOTTEN: frozenset(),
}

# Source kinds an agent/provider proposer may cite only when a sibling service can verify them.
_VERIFIABLE_BY_SERVICE = {
    SourceKind.MESSAGE: "history", SourceKind.SESSION: "history",
    SourceKind.EPISODE: "episodes", SourceKind.TASK_ATTEMPT: "episodes",
    SourceKind.COMMIT: "repository", SourceKind.BLOB_RANGE: "repository",
}


class SuppressedError(MemoryEngineError):
    code = "suppressed"


def check_transition(current: Lifecycle, target: Lifecycle) -> None:
    if target not in ALLOWED[current]:
        raise InvalidTransition(f"cannot move memory from {current.value} to {target.value}")


def _topic_tokens(record: MemoryRecord) -> set[str]:
    text = " ".join((record.title or "", " ".join(record.tags)))
    return {t for t in re.findall(r"[a-z0-9_.-]+", text.lower()) if len(t) > 2}


class CoreService:
    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx
        self.p = ctx.partition
        self.records = ctx.records

    # ------------------------------------------------------------------ helpers
    @property
    def now(self) -> float:
        return self.ctx.clock()

    def load_visible(self, conn: sqlite3.Connection, access: AccessContext, record_id: str) -> MemoryRecord:
        check_id(record_id, "memory id")
        return policy.require_visible(access, self.records.get(conn, record_id))

    def _commit_write(self, conn: sqlite3.Connection, record: MemoryRecord, *, change: str,
                      actor: Actor, expected: int | None) -> MemoryRecord:
        generation = self.p.bump(conn)
        return self.records.write(conn, record, change=change, actor=actor,
                                  expected_revision=expected, generation=generation)

    def _check_expected(self, record: MemoryRecord, expected_revision: int | None) -> None:
        from .errors import RevisionConflict

        if expected_revision is not None and record.revision != expected_revision:
            raise RevisionConflict("the memory changed since it was read",
                                   details={"expected_revision": expected_revision,
                                            "current_revision": record.revision})

    def _replay(self, conn: sqlite3.Connection, key: str | None, operation: str, request: Any
                ) -> WriteResult | None:
        receipt_raw = self.p.idempotency_lookup(conn, key, operation, request)
        if receipt_raw is None:
            return None
        receipt = Receipt(**{**receipt_raw, "idempotent_replay": True,
                             "record_ids": tuple(receipt_raw.get("record_ids") or ()),
                             "revisions": tuple(receipt_raw.get("revisions") or ()),
                             "limitations": tuple(receipt_raw.get("limitations") or ())})
        record = self.records.get(conn, receipt.record_ids[0]) if receipt.record_ids else None
        if record is None:
            raise NotFound("the memory created by this idempotency key no longer exists")
        return WriteResult(record=record, receipt=receipt,
                           conflicts=tuple(receipt.details.get("conflicts") or ()))

    # ------------------------------------------------------------------ conflicts
    def structured_conflicts(self, conn: sqlite3.Connection, record: MemoryRecord) -> list[str]:
        token = self.records.subject_token(record)
        if token is None:
            return []
        content = self.records.content_token(record.content)
        rows = conn.execute(
            "SELECT id FROM records WHERE subject_token=? AND id<>? AND content_token<>?"
            " AND lifecycle IN ('approved','stale') ORDER BY id", (token, record.id, content),
        ).fetchall()
        return [r[0] for r in rows]

    def possible_conflicts(self, conn: sqlite3.Connection, access: AccessContext,
                           record: MemoryRecord) -> list[str]:
        """Legacy-compatible heuristic: same topic (title/tags overlap >= 50%), different content."""
        topic = _topic_tokens(record)
        if not topic:
            return []
        normalized = normalize_for_fingerprint(record.content)
        grants = policy.narrow(access.grants, record.scope) if access.grants.allows(record.scope) else access.grants
        out = []
        for other in self.records.authorized(conn, grants, lifecycles=(Lifecycle.APPROVED,)):
            if other.id == record.id or other.scope != record.scope:
                continue
            other_topic = _topic_tokens(other)
            overlap = len(topic & other_topic) / max(min(len(topic), len(other_topic)), 1)
            if overlap >= 0.5 and normalize_for_fingerprint(other.content) != normalized:
                out.append(other.id)
        return out[:12]

    # ------------------------------------------------------------------ evidence
    def verify_sources(self, conn: sqlite3.Connection, access: AccessContext,
                       sources: tuple[SourceRef, ...], *, derived_from: tuple[str, ...] = ()) -> None:
        host_attested = access.actor in (Actor.USER, Actor.HOST)
        for source in sources:
            if source.kind == SourceKind.USER_ACTION and not host_attested:
                raise ValidationError("only the host can attest a user action as evidence")
            if source.kind == SourceKind.LEGACY_IMPORT and Operation.ADMIN not in access.operations:
                raise ValidationError("legacy-import evidence requires a migration context")
            if source.kind == SourceKind.MEMORY:
                self.load_visible(conn, access, source.ref)
                continue
            if source.kind == SourceKind.VERIFICATION_RECEIPT:
                authority = self.ctx.host.verification
                result = authority.resolve(source.ref) if authority is not None else None
                if result is None or not result.trusted:
                    raise ValidationError("verification receipt evidence could not be confirmed by the host")
                continue
            service_name = _VERIFIABLE_BY_SERVICE.get(source.kind)
            service = getattr(self.ctx.services, service_name, None) if service_name else None
            verdict = None
            if service is not None and hasattr(service, "verify_source"):
                verdict = service.verify_source(conn, access, source)
            if verdict is False:
                raise ValidationError(f"{source.kind.value} evidence does not exist or is not authorized")
            if verdict is None and not host_attested:
                raise ValidationError(f"{source.kind.value} evidence cannot be verified for an agent proposal")
        for parent in derived_from:
            self.load_visible(conn, access, parent)

    def _blocked(self, conn: sqlite3.Connection, record: MemoryRecord,
                 observed_generation: int | None = None) -> str | None:
        forgetting = self.ctx.services.forgetting
        if forgetting is None:
            return None
        return forgetting.blocked_reason(conn, record, observed_generation=observed_generation)

    # ------------------------------------------------------------------ remember
    def remember(self, access: AccessContext, request: RememberRequest, *,
                 idempotency_key: str | None = None) -> WriteResult:
        policy.require_author(access)
        policy.require_scope(access, request.scope)
        scan = safety.scan(request.content + "\n" + request.title)
        if scan.secrets:
            raise SensitiveContent("credentials and secrets are not stored in memory; use the host keychain",
                                   details={"categories": list(scan.secrets)})
        if scan.sensitive and not request.allow_sensitive:
            raise SensitiveContent("this looks like sensitive personal information; the host must confirm"
                                   " the user explicitly asked to keep it", details={"categories": list(scan.sensitive)})
        now = self.now
        with self.p.db.write() as conn:
            replay = self._replay(conn, idempotency_key, "remember", request)
            if replay is not None:
                return replay
            sources = request.sources or (SourceRef(SourceKind.USER_ACTION, "remember-" + new_id(),
                                                    actor=access.actor, observed_at=now),)
            self.verify_sources(conn, access, sources)
            record_id = request.memory_id or new_id("m")
            record = MemoryRecord(
                id=record_id, revision=1, kind=request.kind, lifecycle=Lifecycle.APPROVED,
                scope=request.scope, title=request.title or request.content[:60], content=request.content,
                tags=request.tags, basis=request.basis,
                confidence=request.confidence if request.confidence.value is not None
                else Confidence(None, False, "user_asserted"),
                subject=request.subject, predicate=request.predicate, sources=sources,
                validity=request.validity, retention=request.retention, links=Links(),
                created_at=now, updated_at=now, event_time=now, ingested_at=now, reason=request.reason,
                extra={"flags": ["instruction_like"]} if scan.injection else {},
            )
            conflicts = self.structured_conflicts(conn, record)
            record = dataclasses.replace(record, links=Links(conflicts_with=tuple(conflicts)))
            record = self._commit_write(conn, record, change="created", actor=access.actor, expected=None)
            possible = self.possible_conflicts(conn, access, record)
            receipt = self.p.make_receipt(
                conn, "remember", "ok", record_ids=(record.id,), revisions=(record.revision,),
                details={"conflicts": conflicts, "possible_conflicts": possible,
                         "flags": list(record.extra.get("flags", []))},
            )
            self.p.idempotency_store(conn, idempotency_key, "remember", request, receipt)
            self.p.event(conn, "remember", "ok")
        return WriteResult(record=record, receipt=receipt, conflicts=tuple(conflicts))

    # ------------------------------------------------------------------ propose
    def propose(self, access: AccessContext, proposal: CandidateProposal, *,
                idempotency_key: str | None = None) -> WriteResult:
        policy.require(access, Operation.PROPOSE)
        policy.require_scope(access, proposal.scope)
        scan = safety.scan(proposal.content + "\n" + proposal.title)
        if scan.secrets:
            raise SensitiveContent("candidate contains credential-like content", details={"categories": list(scan.secrets)})
        if scan.sensitive and proposal.basis != StatementBasis.USER_STATED:
            raise SensitiveContent("sensitive personal information is never inferred into memory",
                                   details={"categories": list(scan.sensitive)})
        now = self.now
        with self.p.db.write() as conn:
            replay = self._replay(conn, idempotency_key, "propose", proposal)
            if replay is not None:
                return replay
            self.verify_sources(conn, access, proposal.sources, derived_from=proposal.derived_from)
            confidence = proposal.confidence
            if confidence.value is not None and not confidence.calibrated and confidence.method == "unknown":
                confidence = Confidence(confidence.value, False, "model_uncalibrated")
            record = MemoryRecord(
                id=new_id("m"), revision=1, kind=proposal.kind, lifecycle=Lifecycle.CANDIDATE,
                scope=proposal.scope, title=proposal.title or proposal.content[:60], content=proposal.content,
                tags=proposal.tags, basis=proposal.basis, confidence=confidence,
                subject=proposal.subject, predicate=proposal.predicate, sources=proposal.sources,
                validity=proposal.validity,
                retention=Retention("durable", now + self.ctx.config.candidate_ttl_seconds, False),
                links=Links(derived_from=proposal.derived_from), created_at=now, updated_at=now,
                event_time=min((s.observed_at for s in proposal.sources if s.observed_at), default=None),
                ingested_at=now, reason=proposal.rationale,
                extra={"proposer": proposal.proposer, **({"flags": ["instruction_like"]} if scan.injection else {})},
            )
            blocked = self._blocked(conn, record, proposal.observed_generation)
            if blocked:
                self.p.event(conn, "proposal", "suppressed", blocked)
                raise SuppressedError(f"candidate refused: {blocked}")
            duplicate = conn.execute(
                "SELECT id FROM records WHERE content_token=? AND scope_token=? AND lifecycle IN"
                " ('candidate','approved') LIMIT 1",
                (self.records.content_token(record.content), self.records.scope_token(record.scope)),
            ).fetchone()
            if duplicate is not None:
                existing = self.records.get(conn, duplicate[0])
                receipt = self.p.make_receipt(conn, "propose", "noop", record_ids=(existing.id,),
                                              revisions=(existing.revision,), details={"duplicate_of": existing.id})
                self.p.idempotency_store(conn, idempotency_key, "propose", proposal, receipt)
                return WriteResult(record=existing, receipt=receipt)
            conflicts = self.structured_conflicts(conn, record)
            record = dataclasses.replace(record, links=dataclasses.replace(record.links, conflicts_with=tuple(conflicts)))
            record = self._commit_write(conn, record, change="proposed", actor=access.actor, expected=None)
            receipt = self.p.make_receipt(conn, "propose", "ok", record_ids=(record.id,),
                                          revisions=(record.revision,),
                                          details={"conflicts": conflicts, "expires_at": record.retention.expires_at})
            self.p.idempotency_store(conn, idempotency_key, "propose", proposal, receipt)
            self.p.event(conn, "proposal", "accepted")
        return WriteResult(record=record, receipt=receipt, conflicts=tuple(conflicts))

    # ------------------------------------------------------------------ review
    def approve(self, access: AccessContext, record_id: str, *, expected_revision: int | None,
                resolution: str = "keep_both") -> WriteResult:
        policy.require_reviewer(access, self.ctx.host)
        if resolution not in {"keep_both", "supersede"}:
            raise ValidationError("resolution must be keep_both or supersede")
        now = self.now
        with self.p.db.write() as conn:
            record = self.load_visible(conn, access, record_id)
            self._check_expected(record, expected_revision)
            if record.lifecycle == Lifecycle.CANDIDATE and record.retention.expires_at is not None \
                    and record.retention.expires_at < now:
                raise InvalidTransition("this candidate has expired")
            check_transition(record.lifecycle, Lifecycle.APPROVED)
            blocked = self._blocked(conn, record)
            if blocked:
                raise SuppressedError(f"cannot approve: {blocked}")
            conflicts = self.structured_conflicts(conn, record)
            superseded: list[str] = []
            if resolution == "supersede":
                for other_id in conflicts:
                    other = self.records.get(conn, other_id)
                    if other is None or not policy.visible(access, other):
                        continue
                    check_transition(other.lifecycle, Lifecycle.SUPERSEDED)
                    updated = dataclasses.replace(
                        other, revision=other.revision + 1, lifecycle=Lifecycle.SUPERSEDED, updated_at=now,
                        links=dataclasses.replace(other.links, superseded_by=record.id),
                    )
                    self._commit_write(conn, updated, change="superseded", actor=access.actor, expected=other.revision)
                    superseded.append(other_id)
            remaining = tuple(c for c in conflicts if c not in superseded)
            approved = dataclasses.replace(
                record, revision=record.revision + 1, lifecycle=Lifecycle.APPROVED, updated_at=now,
                retention=dataclasses.replace(record.retention, expires_at=None),
                links=dataclasses.replace(record.links, supersedes=tuple(sorted(set(record.links.supersedes) | set(superseded))),
                                          conflicts_with=remaining),
                extra={**record.extra, "last_confirmed_at": now},
            )
            approved = self._commit_write(conn, approved, change="approved", actor=access.actor, expected=record.revision)
            receipt = self.p.make_receipt(conn, "approve", "ok", record_ids=(approved.id, *superseded),
                                          revisions=(approved.revision,),
                                          details={"superseded": superseded, "conflicts": list(remaining)})
            self.p.event(conn, "approval", "accepted")
        return WriteResult(record=approved, receipt=receipt, conflicts=remaining)

    def reject(self, access: AccessContext, record_id: str, *, expected_revision: int | None,
               reason: str = "") -> WriteResult:
        policy.require_reviewer(access, self.ctx.host)
        now = self.now
        with self.p.db.write() as conn:
            record = self.load_visible(conn, access, record_id)
            self._check_expected(record, expected_revision)
            check_transition(record.lifecycle, Lifecycle.REJECTED)
            rejected = dataclasses.replace(record, revision=record.revision + 1, lifecycle=Lifecycle.REJECTED,
                                           updated_at=now, reason=reason[:2000] or record.reason)
            rejected = self._commit_write(conn, rejected, change="rejected", actor=access.actor, expected=record.revision)
            forgetting = self.ctx.services.forgetting
            if forgetting is not None:
                forgetting.suppress(conn, rejected.content, rejected.sources)
            receipt = self.p.make_receipt(conn, "reject", "ok", record_ids=(rejected.id,), revisions=(rejected.revision,))
            self.p.event(conn, "approval", "rejected")
        return WriteResult(record=rejected, receipt=receipt)

    # ------------------------------------------------------------------ correct
    def correct(self, access: AccessContext, record_id: str, correction: Correction, *,
                expected_revision: int | None) -> WriteResult:
        policy.require_author(access)
        if correction.content is not None:
            scan = safety.scan(correction.content)
            if scan.secrets:
                raise SensitiveContent("credentials and secrets are not stored in memory")
        now = self.now
        with self.p.db.write() as conn:
            record = self.load_visible(conn, access, record_id)
            self._check_expected(record, expected_revision)
            target = Lifecycle.APPROVED if record.lifecycle in (Lifecycle.APPROVED, Lifecycle.STALE) else record.lifecycle
            if record.lifecycle not in (Lifecycle.APPROVED, Lifecycle.STALE, Lifecycle.CANDIDATE):
                raise InvalidTransition(f"cannot correct a {record.lifecycle.value} memory")
            correction_source = SourceRef(SourceKind.USER_ACTION, "correct-" + new_id(), actor=access.actor,
                                          observed_at=now)
            self.verify_sources(conn, access, correction.sources)
            content_changed = correction.content is not None and correction.content != record.content
            corrected = dataclasses.replace(
                record, revision=record.revision + 1, lifecycle=target, updated_at=now,
                content=correction.content if correction.content is not None else record.content,
                title=correction.title if correction.title is not None else record.title,
                tags=correction.tags if correction.tags is not None else record.tags,
                validity=correction.validity or record.validity,
                retention=correction.retention or record.retention,
                basis=StatementBasis.USER_STATED if content_changed else record.basis,
                confidence=Confidence(None, False, "user_asserted") if content_changed else record.confidence,
                sources=tuple(record.sources) + tuple(correction.sources) + (correction_source,),
                reason=correction.reason or record.reason,
                extra={**record.extra, "last_corrected_at": now},
            )
            corrected = self._commit_write(conn, corrected, change="corrected", actor=access.actor, expected=record.revision)
            forgetting = self.ctx.services.forgetting
            if content_changed and forgetting is not None:
                # Do not relearn the corrected-away statement from the same sources.
                forgetting.suppress(conn, record.content, record.sources)
            receipt = self.p.make_receipt(conn, "correct", "ok", record_ids=(corrected.id,),
                                          revisions=(corrected.revision,),
                                          details={"content_changed": content_changed})
            self.p.event(conn, "correction", "ok")
        return WriteResult(record=corrected, receipt=receipt)

    def set_pinned(self, access: AccessContext, record_id: str, pinned: bool, *,
                   expected_revision: int | None) -> WriteResult:
        policy.require_author(access)
        with self.p.db.write() as conn:
            record = self.load_visible(conn, access, record_id)
            self._check_expected(record, expected_revision)
            updated = dataclasses.replace(record, revision=record.revision + 1, updated_at=self.now,
                                          retention=dataclasses.replace(record.retention, pinned=bool(pinned)))
            updated = self._commit_write(conn, updated, change="pinned" if pinned else "unpinned",
                                         actor=access.actor, expected=record.revision)
            receipt = self.p.make_receipt(conn, "pin", "ok", record_ids=(updated.id,), revisions=(updated.revision,))
        return WriteResult(record=updated, receipt=receipt)

    def supersede(self, access: AccessContext, old_id: str, new_id_: str, *,
                  expected_revision: int | None) -> WriteResult:
        policy.require_reviewer(access, self.ctx.host)
        now = self.now
        with self.p.db.write() as conn:
            old = self.load_visible(conn, access, old_id)
            new = self.load_visible(conn, access, new_id_)
            self._check_expected(old, expected_revision)
            if new.lifecycle != Lifecycle.APPROVED:
                raise InvalidTransition("the superseding memory must be approved")
            check_transition(old.lifecycle, Lifecycle.SUPERSEDED)
            updated = dataclasses.replace(old, revision=old.revision + 1, lifecycle=Lifecycle.SUPERSEDED,
                                          updated_at=now, links=dataclasses.replace(old.links, superseded_by=new.id))
            updated = self._commit_write(conn, updated, change="superseded", actor=access.actor, expected=old.revision)
            new2 = dataclasses.replace(new, revision=new.revision + 1, updated_at=now,
                                       links=dataclasses.replace(new.links, supersedes=tuple(sorted(set(new.links.supersedes) | {old.id})),
                                                                 conflicts_with=tuple(c for c in new.links.conflicts_with if c != old.id)))
            self._commit_write(conn, new2, change="supersedes", actor=access.actor, expected=new.revision)
            receipt = self.p.make_receipt(conn, "supersede", "ok", record_ids=(old.id, new.id),
                                          revisions=(updated.revision, new2.revision))
        return WriteResult(record=updated, receipt=receipt)

    def transition_internal(self, conn: sqlite3.Connection, record: MemoryRecord, target: Lifecycle, *,
                            change: str, actor: Actor = Actor.SYSTEM, reason: str = "") -> MemoryRecord:
        """System transitions (stale on source change, expiry) inside the caller's transaction."""
        check_transition(record.lifecycle, target)
        updated = dataclasses.replace(record, revision=record.revision + 1, lifecycle=target, updated_at=self.now,
                                      extra={**record.extra, "last_transition_reason": reason[:200]})
        return self._commit_write(conn, updated, change=change, actor=actor, expected=record.revision)

    def write_internal(self, conn: sqlite3.Connection, record: MemoryRecord, *, change: str,
                       actor: Actor, expected: int | None) -> MemoryRecord:
        """Low-level write for sibling services (episodes, procedures, repository, migrations)."""
        return self._commit_write(conn, record, change=change, actor=actor, expected=expected)

    # ------------------------------------------------------------------ maintenance
    def expire_due(self, conn: sqlite3.Connection) -> dict[str, int]:
        now = self.now
        counts = {"candidates_expired": 0, "validity_marked_stale": 0, "transient_expired": 0}
        for row in conn.execute(
            "SELECT id FROM records WHERE lifecycle='candidate' AND expires_at IS NOT NULL AND expires_at < ?", (now,)
        ).fetchall():
            record = self.records.get(conn, row[0])
            self.transition_internal(conn, record, Lifecycle.EXPIRED, change="expired", reason="candidate_ttl")
            counts["candidates_expired"] += 1
        for row in conn.execute(
            "SELECT id FROM records WHERE lifecycle='approved' AND valid_until IS NOT NULL AND valid_until < ?", (now,)
        ).fetchall():
            record = self.records.get(conn, row[0])
            self.transition_internal(conn, record, Lifecycle.STALE, change="stale", reason="validity_ended")
            counts["validity_marked_stale"] += 1
        for row in conn.execute(
            "SELECT id FROM records WHERE lifecycle IN ('approved','stale') AND expires_at IS NOT NULL"
            " AND expires_at < ? AND pinned=0", (now,)
        ).fetchall():
            record = self.records.get(conn, row[0])
            if record.retention.policy == "durable":
                continue  # explicit durable memories never expire just from disuse
            self.transition_internal(conn, record, Lifecycle.EXPIRED, change="expired", reason="retention")
            counts["transient_expired"] += 1
        return counts

    # ------------------------------------------------------------------ reads
    def get(self, access: AccessContext, record_id: str) -> MemoryRecord:
        policy.require(access, Operation.READ)
        with self.p.db.read() as conn:
            return self.load_visible(conn, access, record_id)

    def list(self, access: AccessContext, *, lifecycles: tuple[Lifecycle, ...] | None = (Lifecycle.APPROVED,),
             kinds: tuple[MemoryKind, ...] = (), scope_filter: Scope | None = None,
             limit: int = 100, offset: int = 0) -> list[MemoryRecord]:
        policy.require(access, Operation.READ)
        grants = policy.narrow(access.grants, scope_filter)
        with self.p.db.read() as conn:
            items = self.records.authorized(conn, grants, lifecycles=lifecycles, kinds=kinds or None)
        now = self.now
        out = []
        for item in items:
            if item.lifecycle == Lifecycle.CANDIDATE and item.retention.expires_at and item.retention.expires_at < now:
                continue  # expired at read time even before maintenance runs
            out.append(item)
        return out[offset: offset + max(1, min(limit, 1000))]

    def explain(self, access: AccessContext, record_id: str) -> dict[str, Any]:
        policy.require(access, Operation.READ)
        with self.p.db.read() as conn:
            record = self.load_visible(conn, access, record_id)
            revisions = self.records.revisions(conn, record_id)
            visible_links = {}
            for name in ("supersedes", "conflicts_with", "derived_from"):
                ids = getattr(record.links, name)
                visible = self.records.authorized(conn, access.grants, lifecycles=None, ids=ids) if ids else []
                visible_links[name] = [r.id for r in visible]
                hidden = len(ids) - len(visible)
                if hidden:
                    visible_links[name + "_unavailable"] = hidden  # deleted or out of scope; count only
            if record.links.superseded_by:
                sup = self.records.authorized(conn, access.grants, lifecycles=None, ids=[record.links.superseded_by])
                visible_links["superseded_by"] = sup[0].id if sup else None
            structured = [c for c in self.structured_conflicts(conn, record)
                          if self.records.authorized(conn, access.grants, lifecycles=None, ids=[c])]
            derived = [d for d in self.records.ids_derived_from(conn, self.p.token("memory", record.id))
                       if self.records.authorized(conn, access.grants, lifecycles=None, ids=[d])]
        return {
            "record": record.to_dict(),
            "revisions": [r.to_dict() for r in revisions],
            "links": visible_links,
            "current_conflicts": structured,
            "derived_records": derived,
            "basis": record.basis.value,
            "confidence": record.confidence.to_dict(),
            "confidence_note": "unknown" if record.confidence.value is None else (
                "calibrated" if record.confidence.calibrated else "uncalibrated - not a probability of truth"),
            "sources": [s.to_dict() for s in record.sources],
        }
