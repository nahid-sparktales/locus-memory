"""Authorized forgetting that survives derived state, replay, restart and restore.

Protocol for one ``forget`` call:

1. Authorize the target against the trusted access context.
2. Append tombstone entries to the separate deletion ledger (write-ahead, durable).
3. In one main-database transaction: purge payloads (records, revisions, vectors,
   archive messages, repository rows, derived summaries), record tombstones and
   suppressions, advance ``deletion_generation`` and the cache ``generation``.
4. Checkpoint the WAL so purged pages do not linger in the log; update the host's
   ledger mirror; return a receipt.

If the process dies between 2 and 3, the next open re-applies the ledger entry
(``Partition.reconcile``) before serving any data. Derived writes that started
before a deletion are refused at commit time (``commit_guard`` / ``blocked_reason``).
"""
from __future__ import annotations

import dataclasses
import sqlite3
from collections import Counter
from typing import Any

from . import policy
from .errors import AccessDenied, StaleDerivation
from .models import (
    AccessContext,
    Actor,
    ForgetPolicy,
    ForgetReceipt,
    ForgetTarget,
    ForgetTargetKind,
    Lifecycle,
    MemoryKind,
    MemoryRecord,
    Operation,
    Receipt,
    SourceRef,
    StatementBasis,
)
from .services import PartitionContext
from .storage import schema
from .validation import normalize_for_fingerprint

_SCOPE_TARGETS = {
    ForgetTargetKind.PROJECT: "project",
    ForgetTargetKind.REPOSITORY: "repository",
    ForgetTargetKind.AGENT: "agent",
}
# Records whose existence depends entirely on their inputs (removed, not edited, when an input goes).
_DERIVED_KINDS = {MemoryKind.SUMMARY}
_DERIVED_BASES = {StatementBasis.MODEL_INTERPRETATION, StatementBasis.HYPOTHESIS}


class ForgettingService:
    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx
        self.p = ctx.partition
        self.records = ctx.records

    # ------------------------------------------------------------------ tokens
    def target_entry(self, target: ForgetTarget) -> tuple[str, str]:
        if target.kind == ForgetTargetKind.MEMORY:
            return "memory", target.ref
        if target.kind == ForgetTargetKind.SOURCE:
            return "source", self.records.source_token(target.ref)
        if target.kind == ForgetTargetKind.SESSION:
            return "session", self.p.token("session", target.ref)
        if target.kind in _SCOPE_TARGETS:
            dim = _SCOPE_TARGETS[target.kind]
            return f"scope:{dim}", self.records.scope_value_token(dim, target.ref)
        if target.kind == ForgetTargetKind.PROFILE:
            return "profile", self.p.partition_id
        raise AccessDenied("unsupported forget target")

    def _authorize(self, conn: sqlite3.Connection, access: AccessContext, target: ForgetTarget) -> None:
        policy.require(access, Operation.FORGET)
        if access.actor not in (Actor.USER, Actor.HOST):
            raise AccessDenied("forgetting is a user or host action")
        if target.kind == ForgetTargetKind.MEMORY:
            # Missing, already forgotten, and out-of-scope are indistinguishable (NotFound);
            # use an idempotency key to make retries of a successful forget return its receipt.
            policy.require_visible(access, self.records.get(conn, target.ref))
        elif target.kind in _SCOPE_TARGETS:
            dim = _SCOPE_TARGETS[target.kind]
            if target.ref not in access.grants.values_for(dim):
                raise AccessDenied(f"the {dim} is not granted to this caller")
        elif target.kind == ForgetTargetKind.PROFILE:
            policy.require(access, Operation.ADMIN)
            if target.ref != access.partition.profile:
                raise AccessDenied("a profile can only be forgotten from its own partition")
        elif target.kind in (ForgetTargetKind.SOURCE, ForgetTargetKind.SESSION):
            verifier = self.ctx.services.history
            if target.kind == ForgetTargetKind.SESSION:
                ok = verifier.session_visible(conn, access, target.ref) if verifier else None
            else:
                ok = self._source_visible(conn, access, target.ref)
            if ok is False:
                raise AccessDenied("the source is not visible to this caller")

    def _source_visible(self, conn: sqlite3.Connection, access: AccessContext, identity: str) -> bool | None:
        token = self.records.source_token(identity)
        ids = self.records.ids_for_source(conn, token)
        if ids and not self.records.authorized(conn, access.grants, lifecycles=None, ids=ids):
            return False
        history = self.ctx.services.history
        if history is not None and identity.startswith("message:"):
            return history.message_source_visible(conn, access, token)
        return True if ids else None

    def tombstone_generation(self, conn: sqlite3.Connection, kind: str, token: str) -> int | None:
        row = conn.execute(
            "SELECT generation FROM tombstones WHERE target_kind=? AND target_token=?", (kind, token)
        ).fetchone()
        return int(row[0]) if row else None

    # ------------------------------------------------------------------ forget
    def forget(self, access: AccessContext, target: ForgetTarget, forget_policy: ForgetPolicy, *,
               idempotency_key: str | None = None) -> ForgetReceipt:
        with self.p.db.read() as conn:
            self._authorize(conn, access, target)
            replay = self.p.idempotency_lookup(conn, idempotency_key, "forget", [target, forget_policy])
        if replay is not None:
            return ForgetReceipt(
                receipt=Receipt(**{**replay, "idempotent_replay": True,
                                   "record_ids": tuple(replay.get("record_ids") or ()),
                                   "revisions": tuple(replay.get("revisions") or ()),
                                   "limitations": tuple(replay.get("limitations") or ())}),
                target=target, deleted=dict(replay["details"].get("deleted", {})),
                suppressed_sources=int(replay["details"].get("suppressed_sources", 0)),
                regenerate_required=tuple(replay["details"].get("regenerate_required", ())),
                retained_by_policy=dict(replay["details"].get("retained_by_policy", {})),
                pending_external=tuple(replay["details"].get("pending_external", ())),
                deletion_generation=int(replay["details"].get("deletion_generation", 0)),
            )
        kind, token = self.target_entry(target)
        # (2) write-ahead: the ledger is durable before any main-database change.
        with self.p.db.read() as conn:
            floor = self.p.deletion_generation(conn)
        entry = self.p.ledger.append([(kind, token)], min_generation=floor)[0]
        # (3) apply.
        with self.p.db.write() as conn:
            outcome = self.apply_tombstone(conn, kind, token, entry.generation, forget_policy, access=access)
            conn.execute(
                "INSERT OR REPLACE INTO tombstones(target_kind, target_token, generation, created_at)"
                " VALUES(?,?,?,?)", (kind, token, entry.generation, entry.created_at),
            )
            schema.set_meta(conn, "deletion_generation", str(entry.generation))
            self.p.bump(conn)
            pending = self._queue_external_deletions(conn, kind, token)
            limitations = (
                "content already sent to a model provider in earlier prompts cannot be recalled",
                "copies outside application control (manual exports, backups) are not affected",
                "suppression matches the same normalized statement from the same sources, not arbitrary paraphrases",
            )
            details = {
                "deleted": outcome["deleted"], "suppressed_sources": outcome["suppressed"],
                "regenerate_required": outcome["regenerate"], "retained_by_policy": outcome["retained"],
                "pending_external": pending, "deletion_generation": entry.generation,
                "target_kind": target.kind.value,
            }
            receipt = self.p.make_receipt(conn, "forget", "ok", details=details, limitations=limitations)
            self.p.idempotency_store(conn, idempotency_key, "forget", [target, forget_policy], receipt)
            self.p.event(conn, "forget", "ok", target.kind.value)
        # (4) flush purged pages from the WAL; record the high-water mark with the host.
        self.p.db.checkpoint()
        if self.p.mirror is not None:
            head = self.p.ledger.head()
            self.p.mirror.write(self.p.partition_id, head[0], head[1])
        return ForgetReceipt(
            receipt=receipt, target=target, deleted=outcome["deleted"], suppressed_sources=outcome["suppressed"],
            regenerate_required=tuple(outcome["regenerate"]), retained_by_policy=outcome["retained"],
            pending_external=tuple(pending), deletion_generation=entry.generation,
        )

    def _queue_external_deletions(self, conn: sqlite3.Connection, kind: str, token: str) -> list[str]:
        hub = self.ctx.services.providers
        if hub is None or not hasattr(hub, "queue_deletion"):
            return []
        return hub.queue_deletion(conn, kind, token)

    # ------------------------------------------------------------------ apply (live + reconcile)
    def apply_tombstone(self, conn: sqlite3.Connection, kind: str, token: str, generation: int,
                        forget_policy: ForgetPolicy | None = None, *, access: AccessContext | None = None
                        ) -> dict[str, Any]:
        fp = forget_policy or ForgetPolicy()
        deleted: Counter[str] = Counter()
        retained: Counter[str] = Counter()
        regenerate: list[str] = []
        suppressed = 0
        record_ids: list[str] = []
        source_tokens: list[str] = []
        if kind == "memory":
            record_ids = [token]
        elif kind == "source":
            source_tokens = [token]
        elif kind == "session":
            history = self.ctx.services.history
            if history is not None:
                source_tokens = history.source_tokens_for_session(conn, token)
            source_tokens.append(token)
        elif kind.startswith("scope:"):
            dim = kind.split(":", 1)[1]
            record_ids = [r[0] for r in conn.execute(
                "SELECT record_id FROM record_scopes WHERE dim=? AND value_token=?", (dim, token))]
        elif kind == "profile":
            record_ids = [r[0] for r in conn.execute("SELECT id FROM records")]

        # Memories directly targeted.
        for record_id in record_ids:
            record = self.records.get(conn, record_id)
            if record is None:
                continue
            if fp.suppress_relearning and kind == "memory":
                suppressed += self.suppress(conn, record.content, record.sources)
            deleted.update(self.records.purge(conn, record_id))
            regenerate += self._cascade(conn, self.p.token("memory", record_id), deleted, retained, fp)
        # Memories learned from targeted sources.
        for source_token in source_tokens:
            for record_id in self.records.ids_for_source(conn, source_token):
                record = self.records.get(conn, record_id)
                if record is None:
                    continue
                others = [s for s in record.sources if self.records.source_token(s.identity()) != source_token
                          and not self._source_forgotten(conn, s)]
                if (others and record.kind not in _DERIVED_KINDS and record.basis not in _DERIVED_BASES
                        and record.lifecycle != Lifecycle.CANDIDATE):
                    # Independent evidence remains: keep the memory, drop the forgotten citation.
                    self._drop_source(conn, record, source_token)
                    retained["memories_with_other_evidence"] += 1
                    continue
                if fp.suppress_relearning:
                    suppressed += self.suppress(conn, record.content, record.sources)
                deleted.update(self.records.purge(conn, record_id))
                regenerate += self._cascade(conn, self.p.token("memory", record_id), deleted, retained, fp)
            if fp.include_derived:
                regenerate += self._cascade(conn, source_token, deleted, retained, fp)
        # Sibling services purge their own tables (archive, repository, vectors, jobs, ...).
        for service in self.ctx.services.all():
            if service is self or not hasattr(service, "purge"):
                continue
            counts = service.purge(conn, kind, token, fp)
            for key, value in (counts or {}).items():
                if key.startswith("retained_"):
                    retained[key[len("retained_"):]] += value
                else:
                    deleted[key] += value
        if kind == "profile":
            for table in ("record_revisions", "derivations", "suppressions", "idempotency", "receipts",
                          "embeddings", "events", "jobs"):
                deleted[f"{table}_rows"] += conn.execute(f"DELETE FROM {table}").rowcount
        # Jobs that observed pre-deletion state must not commit afterwards.
        conn.execute("UPDATE jobs SET state='invalidated', updated_at=? WHERE state IN ('pending','running')"
                     " AND observed_deletion_generation < ?", (self.ctx.clock(), generation))
        return {"deleted": {k: v for k, v in deleted.items() if v}, "retained": dict(retained),
                "regenerate": sorted(set(regenerate)), "suppressed": suppressed}

    def _source_forgotten(self, conn: sqlite3.Connection, source: SourceRef) -> bool:
        return self.tombstone_generation(conn, "source", self.records.source_token(source.identity())) is not None

    def _drop_source(self, conn: sqlite3.Connection, record: MemoryRecord, source_token: str) -> None:
        sources = tuple(s for s in record.sources if self.records.source_token(s.identity()) != source_token)
        updated = dataclasses.replace(record, revision=record.revision + 1, sources=sources,
                                      updated_at=self.ctx.clock())
        core = self.ctx.services.core
        core.write_internal(conn, updated, change="source_forgotten", actor=Actor.SYSTEM, expected=record.revision)
        # Older revisions still cite the forgotten source; purge their payloads.
        conn.execute(
            "UPDATE record_revisions SET purged=1, dek_id=NULL, nonce=NULL, ciphertext=NULL"
            " WHERE record_id=? AND revision<?", (record.id, updated.revision),
        )

    def _cascade(self, conn: sqlite3.Connection, input_token: str, deleted: Counter[str],
                 retained: Counter[str], fp: ForgetPolicy) -> list[str]:
        """Remove records derived from a forgotten input; mixed-source ones need regeneration."""
        if not fp.include_derived:
            return []
        regenerate: list[str] = []
        for derived_id in self.records.ids_derived_from(conn, input_token):
            record = self.records.get(conn, derived_id)
            if record is None:
                continue
            inputs = conn.execute(
                "SELECT COUNT(*) FROM derivations WHERE derived_id=? AND input_token<>?", (derived_id, input_token)
            ).fetchone()[0]
            if record.kind in _DERIVED_KINDS or record.basis in _DERIVED_BASES or record.lifecycle == Lifecycle.CANDIDATE:
                deleted.update({f"derived_{k}": v for k, v in self.records.purge(conn, derived_id).items()})
                if inputs:
                    regenerate.append(derived_id)
                regenerate += self._cascade(conn, self.p.token("memory", derived_id), deleted, retained, fp)
            else:
                retained["user_confirmed_derivations"] += 1
        return regenerate

    # ------------------------------------------------------------------ suppression / guards
    def suppress(self, conn: sqlite3.Connection, content: str, sources: tuple[SourceRef, ...]) -> int:
        fingerprint = self.p.token("suppress", normalize_for_fingerprint(content))
        generation = self.p.deletion_generation(conn)
        tokens = [self.records.source_token(s.identity()) for s in sources] or ["*"]
        for source_token in tokens:
            conn.execute(
                "INSERT OR IGNORE INTO suppressions(fingerprint_token, source_token, generation, created_at)"
                " VALUES(?,?,?,?)", (fingerprint, source_token, generation, self.ctx.clock()),
            )
        return len(tokens)

    def blocked_reason(self, conn: sqlite3.Connection, record: MemoryRecord, *,
                       observed_generation: int | None = None) -> str | None:
        for source in record.sources:
            if self._source_forgotten(conn, source):
                return "an evidence source was forgotten"
        for parent in record.links.derived_from:
            if self.tombstone_generation(conn, "memory", parent) is not None:
                return "derived from a forgotten memory"
        fingerprint = self.p.token("suppress", normalize_for_fingerprint(record.content))
        source_tokens = [self.records.source_token(s.identity()) for s in record.sources] + ["*"]
        row = conn.execute(
            f"SELECT 1 FROM suppressions WHERE fingerprint_token=? AND source_token IN ({','.join('?' * len(source_tokens))})",
            [fingerprint, *source_tokens],
        ).fetchone()
        if row is not None:
            return "suppressed by an earlier forget, rejection or correction"
        if observed_generation is not None:
            for dim, value in record.scope.constraints:
                gen = self.tombstone_generation(conn, f"scope:{dim}", self.records.scope_value_token(dim, value))
                if gen is not None and gen > observed_generation:
                    return f"the {dim} was forgotten after this work started"
            gen = self.tombstone_generation(conn, "profile", self.p.partition_id)
            if gen is not None and gen > observed_generation:
                return "the profile was forgotten after this work started"
        return None

    def commit_guard(self, conn: sqlite3.Connection, *, inputs: list[tuple[str, str]],
                     observed_deletion_generation: int) -> None:
        """Refuse a derived commit whose inputs were deleted after it observed state."""
        for kind, token in inputs:
            gen = self.tombstone_generation(conn, kind, token)
            if gen is not None and gen > observed_deletion_generation:
                raise StaleDerivation("an input of this derived result was forgotten after it was read")
        profile = self.tombstone_generation(conn, "profile", self.p.partition_id)
        if profile is not None and profile > observed_deletion_generation:
            raise StaleDerivation("the profile was forgotten after this work started")
