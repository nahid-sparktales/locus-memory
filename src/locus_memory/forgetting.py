"""Authorized forgetting that survives derived state, replay, restart and restore.

Protocol for one ``forget`` call:

1. Authorize the target against the trusted access context. (A retry carrying the
   idempotency key of a forget that already succeeded returns that receipt; the
   target no longer exists by then, so this lookup precedes target authorization.)
2. Append the tombstone entry, with the forget policy, to the separate deletion
   ledger (write-ahead, durable).
3. In one main-database transaction: apply any earlier ledger entries not yet
   applied (left by a crashed or concurrent forget), purge payloads (records,
   revisions, vectors, archive messages, repository rows, derived summaries),
   record tombstones and suppressions, advance ``deletion_generation`` (never
   backwards) and the cache ``generation``.
4. Checkpoint the WAL so purged pages do not linger in the log; update the host's
   ledger mirror; return a receipt.

If step 3 fails or the process dies between 2 and 3, the partition is marked
unreconciled and the ledger entry is re-applied (``Partition.reconcile``) before
any further data is served - by this process on its next call, by any other
process whose next call sees the ledger ahead of the store, and on every open.
Derived writes that started before a deletion are refused at commit time
(``commit_guard`` / ``blocked_reason``).

Damaged rows: a record that no longer authenticates (tampering, corruption, a lost
data key) is still deleted by every target that covers it - forgetting never needs
to read the content it removes. Such rows cannot contribute suppression
fingerprints and are counted as ``unreadable_memories``.

Authorization of broad targets: forgetting a project/repository/agent, a source or
a session that also covers memories outside the caller's grants requires an
``ADMIN`` access context. Receipts given to non-admin callers count only items the
caller is authorized to see (derived items in other scopes are still deleted).
"""
from __future__ import annotations

import dataclasses
import functools
import inspect
import sqlite3
from collections import Counter
from typing import Any

from . import policy
from .errors import AccessDenied, IntegrityError, StaleDerivation, ValidationError, WrongKey
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
    PartitionRef,
    Receipt,
    ScopeGrants,
    SourceKind,
    SourceRef,
    StatementBasis,
    canonical_identity,
    canonical_source,
)
from .services import PartitionContext
from .storage.partition import (
    GAP_ACKNOWLEDGED_KIND,
    caller_binding,
    encode_forget_policy,
    partition_bound,
)
from .validation import normalize_for_fingerprint

_SCOPE_TARGETS = {
    ForgetTargetKind.PROJECT: "project",
    ForgetTargetKind.REPOSITORY: "repository",
    ForgetTargetKind.AGENT: "agent",
}
# Records whose existence depends entirely on their inputs (removed, not edited, when an input goes).
_DERIVED_KINDS = {MemoryKind.SUMMARY}
_DERIVED_BASES = {StatementBasis.MODEL_INTERPRETATION, StatementBasis.HYPOTHESIS}
# Actors whose statement of a record's basis is trusted (an agent's or provider's claim of
# "user stated" is not; see CoreService.propose).
_BASIS_ATTESTERS = frozenset({Actor.USER.value, Actor.HOST.value, Actor.SYSTEM.value})


# Targets whose authorization does not depend on the target still existing (checked before
# any idempotent replay).
_EXISTENCE_INDEPENDENT = {ForgetTargetKind.PROJECT, ForgetTargetKind.REPOSITORY, ForgetTargetKind.AGENT,
                          ForgetTargetKind.PROFILE}
_FORGET_LIMITATIONS = (
    "content already sent to a model provider in earlier prompts cannot be recalled",
    "copies outside application control (manual exports, backups) are not affected",
    "suppression matches the same normalized statement from the same sources, not arbitrary paraphrases",
)
_APPLIED_ELSEWHERE = ("this deletion was applied by a concurrent reconciliation that recorded no receipt;"
                      " counts are unavailable (an empty count does not mean nothing was deleted)")
_PURGE_PENDING = ("a concurrent reader kept the write-ahead log busy: deleted pages may remain on disk until"
                  " the pending checkpoint completes (retried on later calls and on close)")


class _PreviewRollback(Exception):
    """Unwinds the transaction of a forget preview (which is always rolled back)."""


@functools.lru_cache(maxsize=64)
def _purge_accepts_access(cls: type) -> bool:
    try:
        params = inspect.signature(cls.purge).parameters
    except (TypeError, ValueError):
        return False
    return "access" in params or any(p.kind == p.VAR_KEYWORD for p in params.values())


@partition_bound
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
            return "source", self.records.source_token(canonical_identity(target.ref))
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
            record, damaged = self._load(conn, target.ref)
            if damaged:
                # Cannot decrypt: authorize on the SQL scope index so damaged data can still go.
                if target.ref not in self.records.visible_ids(conn, access.grants, [target.ref]):
                    policy.require_visible(access, None)
            else:
                policy.require_visible(access, record)
        elif target.kind in _SCOPE_TARGETS:
            dim = _SCOPE_TARGETS[target.kind]
            if target.ref not in access.grants.values_for(dim):
                raise AccessDenied(f"the {dim} is not granted to this caller")
            self._require_admin_for_hidden(conn, access, self.records.ids_for_scope_value(conn, dim, target.ref))
            history = self.ctx.services.history
            counter = getattr(type(history), "hidden_sessions_for_scope", None) if history is not None else None
            if callable(counter) and Operation.ADMIN not in access.operations and history.hidden_sessions_for_scope(
                    conn, access, dim, self.records.scope_value_token(dim, target.ref)):
                raise AccessDenied("this target also covers sessions outside the caller's grants;"
                                   " an admin access context is required")
            repository = self.ctx.services.repository
            hidden_repos = (getattr(type(repository), "hidden_registrations_for_scope", None)
                            if repository is not None else None)
            if callable(hidden_repos) and Operation.ADMIN not in access.operations and (
                    repository.hidden_registrations_for_scope(
                        conn, access, dim, self.records.scope_value_token(dim, target.ref))):
                raise AccessDenied("this target also covers repository registrations outside the caller's"
                                   " grants; an admin access context is required")
        elif target.kind == ForgetTargetKind.PROFILE:
            policy.require(access, Operation.ADMIN)
            if target.ref != access.partition.profile:
                raise AccessDenied("a profile can only be forgotten from its own partition")
        elif target.kind in (ForgetTargetKind.SOURCE, ForgetTargetKind.SESSION):
            verifier = self.ctx.services.history
            if target.kind == ForgetTargetKind.SESSION:
                ok = verifier.session_visible(conn, access, target.ref) if verifier else None
                ids = self.records.ids_for_source(conn, self.p.token("session", target.ref))
                if ok is not False and ids:
                    ok = self._ids_visible(conn, access, ids)
                if ok is None and Operation.ADMIN not in access.operations:
                    # A session nobody can verify (unknown here) would be tombstoned and suppressed by
                    # token alone - blocking another scope's future session - and a different answer
                    # than for a hidden session would reveal which sessions exist. Same denial as hidden.
                    ok = False
            else:
                ok = self._source_visible(conn, access, canonical_identity(target.ref))
            if ok is False:
                raise AccessDenied("the source is not visible to this caller")

    def _ids_visible(self, conn: sqlite3.Connection, access: AccessContext, ids: list[str]) -> bool:
        """False when none of ``ids`` is visible (whatever the operations: ADMIN does not
        widen grants); AccessDenied when only some are and the caller is not ADMIN."""
        visible = self.records.visible_ids(conn, access.grants, ids)
        if not visible:
            return False
        self._require_admin_for_hidden(conn, access, ids, visible=visible)
        return True

    def _require_admin_for_hidden(self, conn: sqlite3.Connection, access: AccessContext, ids: list[str],
                                  *, visible: set[str] | None = None) -> None:
        if not ids or Operation.ADMIN in access.operations:
            return
        visible = self.records.visible_ids(conn, access.grants, ids) if visible is None else visible
        if len(visible) < len(set(ids)):
            raise AccessDenied("this target also covers memories outside the caller's grants;"
                               " an admin access context is required")

    def _source_visible(self, conn: sqlite3.Connection, access: AccessContext, identity: str) -> bool | None:
        token = self.records.source_token(identity)
        ids = self.records.ids_for_source(conn, token)
        if ids and not self._ids_visible(conn, access, ids):
            return False
        history = self.ctx.services.history
        if history is not None and identity.startswith("message:"):
            verdict = history.message_source_visible(conn, access, token)
            if verdict is not None or not ids:
                if verdict is None and Operation.ADMIN not in access.operations:
                    raise AccessDenied("this source cannot be verified for the caller;"
                                       " an admin access context is required")
                return verdict
        if ids:
            return True
        # No memory cites this identity: ask the service that owns the source kind, so a
        # caller cannot tombstone (and thereby block) evidence that belongs to scopes it
        # cannot see.
        return self._owner_verdict(conn, access, identity)

    def _owner_verdict(self, conn: sqlite3.Connection, access: AccessContext, identity: str) -> bool:
        from .core import _VERIFIABLE_BY_SERVICE

        kind, _, ref = identity.partition(":")
        verdict = None
        try:
            source = SourceRef(SourceKind(kind), ref, actor=Actor.HOST)
        except (ValueError, ValidationError):
            source = None
        if source is not None:
            if source.kind == SourceKind.MEMORY:
                return bool(self.records.visible_ids(conn, access.grants, [ref]))
            service_name = _VERIFIABLE_BY_SERVICE.get(source.kind)
            service = getattr(self.ctx.services, service_name, None) if service_name else None
            if service is not None and hasattr(service, "verify_source"):
                verdict = service.verify_source(conn, access, source)
        if verdict is False:
            return False
        if verdict is None and Operation.ADMIN not in access.operations:
            raise AccessDenied("this source cannot be verified for the caller;"
                               " an admin access context is required")
        return True

    def _load(self, conn: sqlite3.Connection, record_id: str) -> tuple[MemoryRecord | None, bool]:
        """(record, damaged): damaged rows exist but no longer authenticate/decrypt."""
        try:
            return self.records.get(conn, record_id), False
        except (IntegrityError, WrongKey):
            return None, True

    def _purge_damaged(self, conn: sqlite3.Connection, record_id: str, access: AccessContext | None,
                       deleted: Counter[str], hidden: Counter[str], prefix: str = "") -> None:
        reportable = (access is None or Operation.ADMIN in access.operations
                      or record_id in self.records.visible_ids(conn, access.grants, [record_id]))
        counts = {f"{prefix}{k}": v for k, v in self.records.purge(conn, record_id).items()}
        counts["unreadable_memories"] = 1
        (deleted if reportable else hidden).update(counts)

    def tombstone_generation(self, conn: sqlite3.Connection, kind: str, token: str) -> int | None:
        row = conn.execute(
            "SELECT generation FROM tombstones WHERE target_kind=? AND target_token=?", (kind, token)
        ).fetchone()
        return int(row[0]) if row else None

    # ------------------------------------------------------------------ forget
    def _replay_receipt(self, replay: dict[str, Any], target: ForgetTarget, *,
                        idempotent_replay: bool = True) -> ForgetReceipt:
        details = replay.get("details") or {}
        return ForgetReceipt(
            receipt=Receipt(**{**replay, "idempotent_replay": idempotent_replay,
                               "record_ids": tuple(replay.get("record_ids") or ()),
                               "revisions": tuple(replay.get("revisions") or ()),
                               "limitations": tuple(replay.get("limitations") or ())}),
            target=target, deleted=dict(details.get("deleted", {})),
            suppressed_sources=int(details.get("suppressed_sources", 0)),
            regenerate_required=tuple(details.get("regenerate_required", ())),
            retained_by_policy=dict(details.get("retained_by_policy", {})),
            pending_external=tuple(details.get("pending_external", ())),
            deletion_generation=int(details.get("deletion_generation", 0)),
        )

    def _request_payload(self, access: AccessContext, target: ForgetTarget, forget_policy: ForgetPolicy,
                         key_token: str | None, request_hash: str) -> dict[str, Any]:
        return {
            "access": {"principal": access.principal, "edition": access.partition.edition,
                       "profile": access.partition.profile, "actor": access.actor.value,
                       "grants": {name: sorted(access.grants.values_for(dim))
                                  for dim, name in ScopeGrants._DIM_FIELDS.items()},
                       "operations": sorted(op.value for op in access.operations),
                       "purpose": access.purpose, "issuer": access.issuer},
            "target": target.to_dict(), "policy": forget_policy.to_dict(),
            "key_token": key_token, "request_hash": request_hash,
        }

    @staticmethod
    def _request_access(payload: dict[str, Any]) -> AccessContext | None:
        raw = payload.get("access")
        if not isinstance(raw, dict):
            return None
        try:
            return AccessContext(
                principal=raw["principal"], partition=PartitionRef(raw["edition"], raw["profile"]),
                actor=raw["actor"], grants=ScopeGrants.from_dict(raw.get("grants") or {}),
                operations=frozenset(raw.get("operations") or ()), purpose=raw.get("purpose") or "interactive",
                issuer=raw.get("issuer") or "host")
        except (KeyError, TypeError, ValueError, ValidationError):
            return None

    def _finish_receipt(self, conn: sqlite3.Connection, *, generation: int, kind: str, token: str,
                        target_kind: str, outcome: dict[str, Any], key_token: str | None,
                        request_hash: str | None) -> Receipt:
        """Receipt (+ idempotency row) for an applied forget, inside the applying transaction."""
        pending = self._queue_external_deletions(conn, kind, token)
        details = {
            "deleted": outcome["deleted"], "suppressed_sources": outcome["suppressed"],
            "regenerate_required": outcome["regenerate"], "retained_by_policy": outcome["retained"],
            "pending_external": pending, "deletion_generation": generation, "target_kind": target_kind,
        }
        receipt = self.p.make_receipt(conn, "forget", "ok", details=details, limitations=_FORGET_LIMITATIONS)
        if key_token and request_hash:
            self.p.idempotency_store_token(conn, key_token, "forget", request_hash, receipt)
        conn.execute("INSERT OR REPLACE INTO forget_outcomes(generation, receipt_id, created_at) VALUES(?,?,?)",
                     (int(generation), receipt.receipt_id, self.ctx.clock()))
        conn.execute("DELETE FROM forget_outcomes WHERE generation < ?", (int(generation) - 5_000,))
        self.p.event(conn, "forget", "ok", target_kind)
        return receipt

    def _outcome_receipt(self, conn: sqlite3.Connection, generation: int) -> dict[str, Any] | None:
        row = conn.execute("SELECT receipt_id FROM forget_outcomes WHERE generation=?", (int(generation),)
                           ).fetchone()
        if row is None:
            return None
        try:
            return self.p.load_receipt(conn, row[0])
        except IntegrityError:
            return None

    def forget(self, access: AccessContext, target: ForgetTarget, forget_policy: ForgetPolicy, *,
               idempotency_key: str | None = None) -> ForgetReceipt:
        policy.require(access, Operation.FORGET)
        if access.actor not in (Actor.USER, Actor.HOST):
            raise AccessDenied("forgetting is a user or host action")
        request = [target, forget_policy]
        # Idempotency rows are bound to the caller (principal, actor, grants, admin standing):
        # another caller's key never replays this caller's receipt.
        caller = caller_binding(access, grants=True)
        key_token = self.p.idempotency_token("forget", idempotency_key, caller=caller)
        request_hash = self.p.request_hash("forget", request)
        pending: tuple[int, dict[str, Any]] | None = None
        with self.p.db.read() as conn:
            if target.kind in _EXISTENCE_INDEPENDENT:
                # Authorization of these targets does not need the target to exist: it runs before
                # any replay, so a key can never return a receipt for an unauthorized target.
                self._authorize(conn, access, target)
            replay = self.p.idempotency_lookup(conn, idempotency_key, "forget", request, caller=caller)
            if replay is None:
                found = self.p.pending_forget_request(key_token)
                if found is not None and found[1].get("request_hash") == request_hash:
                    pending = found  # a retry of an attempt whose ledger entry is already written
                elif target.kind not in _EXISTENCE_INDEPENDENT:
                    self._authorize(conn, access, target)
                floor = self.p.deletion_generation(conn)
        if replay is not None:
            return self._replay_receipt(replay, target)
        kind, token = self.target_entry(target)
        encoded_policy = encode_forget_policy(forget_policy)
        applied_elsewhere = False
        # Hold the partition lock from the ledger append through the apply: an in-process
        # reconcile (any other call) must not apply this entry under us.
        with self.p._lock:
            if pending is not None:
                entries = [e for e in self.p.ledger.since(pending[0] - 1) if e.generation == pending[0]]
                entry = entries[0] if entries else None
            else:
                entry = None
            if entry is None:
                try:
                    marker = self.p.record_forget_request(kind, token, encoded_policy, key_token, self._request_payload(
                        access, target, forget_policy, key_token, request_hash))
                except Exception:  # the request record only improves receipts; never block a forget
                    marker = None
                # (2) write-ahead: the ledger is durable before any main-database change.
                entry = self.p.ledger.append([(kind, token, encoded_policy)], min_generation=floor)[0]
                try:
                    self.p.bind_forget_request(marker, entry.generation)
                except Exception:
                    pass
            try:
                # (3) apply.
                with self.p.db.write() as conn:
                    if entry.generation <= self.p.deletion_generation(conn):
                        # Someone else (a concurrent forget or reconcile, possibly in another
                        # process) applied this entry; it recorded the receipt for this request.
                        applied_elsewhere = True
                        replay = self.p.idempotency_lookup(conn, idempotency_key, "forget", request,
                                                           caller=caller)
                        stored = replay or self._outcome_receipt(conn, entry.generation)
                        if stored is None:
                            stored = self.p.make_receipt(
                                conn, "forget", "ok", details={
                                    "deleted": {}, "suppressed_sources": 0, "regenerate_required": [],
                                    "retained_by_policy": {}, "pending_external": [],
                                    "deletion_generation": entry.generation, "target_kind": target.kind.value,
                                    "applied_elsewhere": True},
                                limitations=(*_FORGET_LIMITATIONS, _APPLIED_ELSEWHERE)).to_dict()
                        replay = stored
                    else:
                        # Entries appended before ours but never applied (a crashed or concurrent
                        # forget) must not be skipped when deletion_generation moves past them.
                        earlier = [e for e in self.p.ledger.since(self.p.deletion_generation(conn))
                                   if e.generation < entry.generation]
                        self.p.apply_ledger_entries(conn, self.apply_tombstone, earlier)
                        outcome = self.apply_tombstone(conn, kind, token, entry.generation, forget_policy,
                                                       access=access)
                        self.p.record_tombstone(conn, kind, token, entry.generation, entry.created_at,
                                                encoded_policy)
                        self.p.advance_deletion_generation(conn, entry.generation)
                        self.p.bump(conn)
                        # A concurrent forget with the same idempotency key may have committed first.
                        replay = self.p.idempotency_lookup(conn, idempotency_key, "forget", request,
                                                           caller=caller)
                        if replay is None:
                            receipt = self._finish_receipt(
                                conn, generation=entry.generation, kind=kind, token=token,
                                target_kind=target.kind.value, outcome=outcome, key_token=key_token,
                                request_hash=request_hash)
            except BaseException:
                # The ledger holds an entry the store may not have applied: reconcile before serving.
                self.p.reconciled = False
                raise
        self.p.drop_forget_requests(upto=entry.generation)
        self._after_commit()
        # (4) flush purged pages from the WAL; record the high-water mark with the host.
        purged = self.p.flush_purged()
        if self.p.mirror is not None:
            head = self.p.ledger.head()
            self.p.mirror.write(self.p.partition_id, head[0], head[1])
        if replay is not None:
            result = self._replay_receipt(replay, target, idempotent_replay=not applied_elsewhere)
        else:
            result = ForgetReceipt(
                receipt=receipt, target=target, deleted=outcome["deleted"], suppressed_sources=outcome["suppressed"],
                regenerate_required=tuple(outcome["regenerate"]), retained_by_policy=outcome["retained"],
                pending_external=tuple(receipt.details["pending_external"]), deletion_generation=entry.generation,
            )
        if not purged:
            result = dataclasses.replace(
                result, physical_purge_pending=True,
                receipt=dataclasses.replace(result.receipt,
                                            limitations=(*result.receipt.limitations, _PURGE_PENDING)))
        return result

    def _after_commit(self) -> None:
        """Drop in-memory derived copies again after commit: a search that ran concurrently with
        the deletion transaction could have re-cached a pre-deletion view."""
        services = self.ctx.services
        for name in ("retrieval", "context"):
            service = getattr(services, name, None)
            for method in ("invalidate", "clear_cache"):
                hook = getattr(service, method, None) if service is not None else None
                if callable(hook):
                    try:
                        hook()
                    except Exception:
                        pass
                    break

    # ------------------------------------------------------------------ preview (dry run)
    def preview(self, access: AccessContext, target: ForgetTarget, forget_policy: ForgetPolicy | None = None
                ) -> dict[str, Any]:
        """What ``forget(target)`` would delete and retain right now. Deletes nothing.

        Same authorization as ``forget``. ``apply_tombstone`` runs inside a write
        transaction that is always rolled back: nothing is appended to the deletion
        ledger and no tombstone, suppression, receipt, event or generation change is
        kept. Counts are scoped to the caller exactly like a receipt's and describe the
        store at this moment; the receipt of a later ``forget`` is authoritative. Purge
        hooks drop in-memory caches (search projections, compiled packets), which are
        rebuilt on demand.
        """
        policy.require(access, Operation.FORGET)
        if access.actor not in (Actor.USER, Actor.HOST):
            raise AccessDenied("forgetting is a user or host action")
        fp = forget_policy or ForgetPolicy()
        kind, token = self.target_entry(target)
        # A profile purge also empties the provider hub's in-memory usage buffer. The hub keeps
        # what this (rolled-back) purge drops and puts it back afterwards, through its public
        # snapshot API; no hub lock is held across the transaction (writers take the store's
        # write lock first and the hub's lock inside it, so holding it here would stall them).
        hub = self.ctx.services.providers if kind == "profile" else None
        snapshot_usage = getattr(hub, "snapshot_usage_buffer", None)
        restore_usage = getattr(hub, "restore_usage_buffer", None)
        usage_snapshot = snapshot_usage() if callable(snapshot_usage) and callable(restore_usage) else None
        result: dict[str, Any] = {}
        try:
            with self.p.db.write() as conn:
                self._authorize(conn, access, target)
                generation = self.p.deletion_generation(conn)
                outcome = self.apply_tombstone(conn, kind, token, generation + 1, fp, access=access)
                pending = self._queue_external_deletions(conn, kind, token)
                result = {
                    "preview": True, "target": target.to_dict(), "policy": fp.to_dict(),
                    "deleted": outcome["deleted"], "retained_by_policy": outcome["retained"],
                    "regenerate_required": outcome["regenerate"], "suppressed_sources": outcome["suppressed"],
                    "pending_external": len(pending), "deletion_generation": generation,
                    "limitations": [
                        "a preview describes the store now; the receipt of the actual forget is authoritative",
                        "counts include only items the caller is authorized to see",
                    ],
                }
                raise _PreviewRollback
        except _PreviewRollback:
            pass
        finally:
            if usage_snapshot is not None:  # after the rollback: the purge never happened
                restore_usage(usage_snapshot)
        return result

    def _queue_external_deletions(self, conn: sqlite3.Connection, kind: str, token: str) -> list[str]:
        hub = self.ctx.services.providers
        if hub is None or not hasattr(hub, "queue_deletion"):
            return []
        return hub.queue_deletion(conn, kind, token)

    # ------------------------------------------------------------------ apply (live + reconcile)
    @staticmethod
    def _reportable(access: AccessContext | None, record: MemoryRecord) -> bool:
        """Receipt counts include only items the caller may see (all of them for admin/replay)."""
        return access is None or Operation.ADMIN in access.operations or access.grants.allows(record.scope)

    def apply_tombstone(self, conn: sqlite3.Connection, kind: str, token: str, generation: int,
                        forget_policy: ForgetPolicy | None = None, *, access: AccessContext | None = None
                        ) -> dict[str, Any]:
        if access is None and kind != GAP_ACKNOWLEDGED_KIND:
            # Replay (reconcile, or a forget applying earlier entries): when the forget that wrote
            # this entry recorded its request, apply with that caller's access and record its
            # receipt (and idempotency row), so the caller or its retry gets the real receipt.
            request = self.p.forget_request(generation, kind, token, encode_forget_policy(forget_policy))
            requester = self._request_access(request) if request is not None else None
            if requester is not None:
                outcome = self._apply(conn, kind, token, generation, forget_policy, access=requester)
                target_kind = (request.get("target") or {}).get("kind") if isinstance(request, dict) else None
                self._finish_receipt(conn, generation=generation, kind=kind, token=token,
                                     target_kind=str(target_kind or kind), outcome=outcome,
                                     key_token=request.get("key_token"), request_hash=request.get("request_hash"))
                return outcome
        return self._apply(conn, kind, token, generation, forget_policy, access=access)

    def _episode_alias_tokens(self, conn: sqlite3.Connection, record_id: str,
                              record: MemoryRecord | None) -> list[str]:
        """Source tokens under which other records may cite an episode record (``episode:<id>``
        and its task attempts). Resolved before the purge (the record is unreadable afterwards);
        a damaged record falls back to the episode index."""
        episode_id = None
        state: dict[str, Any] = {}
        if record is not None:
            if record.kind != MemoryKind.EPISODE:
                return []
            state = record.extra.get("episode") if isinstance(record.extra.get("episode"), dict) else {}
            episode_id = state.get("episode_id")
        if not isinstance(episode_id, str):
            row = conn.execute("SELECT episode_id FROM episodes WHERE record_id=?", (record_id,)).fetchone()
            episode_id = row[0] if row else None
        if not isinstance(episode_id, str):
            return []
        tokens = [self.records.source_token(f"{SourceKind.EPISODE.value}:{episode_id}")]
        for attempt in state.get("attempts") or ():
            ref = attempt.get("source_ref") if isinstance(attempt, dict) else None
            if isinstance(ref, str):
                tokens.append(self.records.source_token(f"{SourceKind.TASK_ATTEMPT.value}:{ref}"))
        return tokens

    def _forget_aliases(self, conn: sqlite3.Connection, tokens: list[str], generation: int) -> None:
        """Remember source identities that died with a forgotten record (e.g. ``episode:<id>``) so
        later evidence citing them is refused (kept on a profile wipe, like tombstones)."""
        conn.executemany(
            "INSERT OR IGNORE INTO tombstone_aliases(source_token, generation, created_at) VALUES(?,?,?)",
            [(t, int(generation), self.ctx.clock()) for t in tokens])

    @staticmethod
    def _attested(record: MemoryRecord) -> bool:
        """Whether the record's basis was attested by a trusted actor (``extra.basis_attested_by``,
        set by core.remember/propose). Records without the field (written by sibling services, or
        before attestation was recorded) keep the basis-only rule."""
        attested = record.extra.get("basis_attested_by") if isinstance(record.extra, dict) else None
        return attested in _BASIS_ATTESTERS if isinstance(attested, str) else True

    def _evidence_dependent(self, record: MemoryRecord) -> bool:
        """Removed (not edited) when its evidence/inputs go: derived kinds, model interpretations,
        candidates, and anything whose basis no user or host attested."""
        return (record.kind in _DERIVED_KINDS or record.basis in _DERIVED_BASES
                or record.lifecycle == Lifecycle.CANDIDATE or not self._attested(record))

    def _apply(self, conn: sqlite3.Connection, kind: str, token: str, generation: int,
               forget_policy: ForgetPolicy | None = None, *, access: AccessContext | None = None
               ) -> dict[str, Any]:
        fp = forget_policy or ForgetPolicy()
        deleted: Counter[str] = Counter()
        hidden: Counter[str] = Counter()  # deleted but outside the caller's grants: not reported
        retained: Counter[str] = Counter()
        regenerate: list[str] = []
        suppressed = 0
        if kind == GAP_ACKNOWLEDGED_KIND:
            return {"deleted": {}, "retained": {}, "regenerate": [], "suppressed": 0}
        record_ids: list[str] = []
        source_tokens: list[str] = []
        if kind == "memory":
            record_ids = [token]
            # Records that cite the memory as evidence (SourceRef(kind=memory)).
            source_tokens = [self.records.source_token(f"{SourceKind.MEMORY.value}:{token}")]
        elif kind == "source":
            source_tokens = [token]
        elif kind == "session":
            history = self.ctx.services.history
            if history is not None:
                source_tokens = list(history.source_tokens_for_session(conn, token) or [])
            source_tokens.append(token)  # records citing SourceRef(kind=session) (alias index)
        elif kind.startswith("scope:"):
            dim = kind.split(":", 1)[1]
            record_ids = [r[0] for r in conn.execute(
                "SELECT record_id FROM record_scopes WHERE dim=? AND value_token=?", (dim, token))]
        elif kind == "profile":
            record_ids = [r[0] for r in conn.execute("SELECT id FROM records")]

        alias_tokens: set[str] = set()

        def remove(record_id: str, record: MemoryRecord | None, *, suppress: bool) -> None:
            nonlocal suppressed, regenerate
            # A forgotten episode takes its citable identities with it: records citing
            # ``episode:<id>`` (or its attempts) go too, and later citations are refused.
            aliases = self._episode_alias_tokens(conn, record_id, record) if kind != "profile" else []
            if record is None:
                self._purge_damaged(conn, record_id, access, deleted, hidden)
            else:
                if suppress:
                    suppressed += self.suppress(conn, record.content, record.sources)
                counts = self.records.purge(conn, record_id)
                (deleted if self._reportable(access, record) else hidden).update(counts)
            regenerate += self._cascade(conn, self.p.token("memory", record_id), deleted, retained, fp,
                                        access=access, hidden=hidden)
            if aliases:
                self._forget_aliases(conn, aliases, generation)
                alias_tokens.update(aliases)
                source_tokens.extend(t for t in aliases if t not in source_tokens)

        # Memories directly targeted.
        for record_id in record_ids:
            record, damaged = self._load(conn, record_id)
            if record is None and not damaged:
                continue
            remove(record_id, record, suppress=fp.suppress_relearning and kind == "memory" and not damaged)
        # Memories learned from targeted sources (the list grows with forgotten episode aliases).
        for source_token in source_tokens:
            for record_id in self.records.ids_for_source(conn, source_token):
                record, damaged = self._load(conn, record_id)
                if damaged:  # cannot tell whether other evidence remains: privacy wins
                    remove(record_id, None, suppress=False)
                    continue
                if record is None:
                    continue
                if source_token in alias_tokens and record.kind == MemoryKind.PROCEDURE:
                    continue  # procedures re-assess their evidence episodes themselves (revocation)
                others = [s for s in record.sources if source_token not in self.records.source_index_tokens(s)
                          and not self._source_forgotten(conn, s)]
                if record.kind == MemoryKind.EPISODE and not any(s.kind == SourceKind.TASK_ATTEMPT for s in others):
                    # An episode whose last attempt is forgotten is gone (receipts alone are not an
                    # episode): removed here so its lessons and derivations cascade.
                    others = []
                if others and not self._evidence_dependent(record):
                    # Independent evidence remains: keep the memory, drop the forgotten citation.
                    self._drop_source(conn, record, source_token)
                    if self._reportable(access, record):
                        retained["memories_with_other_evidence"] += 1
                    continue
                remove(record_id, record, suppress=fp.suppress_relearning)
            if fp.include_derived and source_token not in alias_tokens:
                regenerate += self._cascade(conn, source_token, deleted, retained, fp,
                                            access=access, hidden=hidden)
        # Sibling services purge their own tables (archive, repository, vectors, jobs, ...).
        # Those whose purge accepts ``access`` scope their reported counts to the caller.
        for service in self.ctx.services.all():
            if service is self or not hasattr(service, "purge"):
                continue
            if access is not None and _purge_accepts_access(type(service)):
                counts = service.purge(conn, kind, token, fp, access=access)
            else:
                counts = service.purge(conn, kind, token, fp)
            for key, value in (counts or {}).items():
                if key.startswith("retained_"):
                    retained[key[len("retained_"):]] += value
                else:
                    deleted[key] += value
        if kind == "profile":
            # Suppressions (keyed fingerprints) are kept, like tombstones: a broader forget must
            # never undo an earlier "do not relearn".
            for table in ("record_revisions", "derivations", "idempotency", "receipts",
                          "embeddings", "events", "jobs"):
                deleted[f"{table}_rows"] += conn.execute(f"DELETE FROM {table}").rowcount
            conn.execute("DELETE FROM idempotency_records")
            conn.execute("DELETE FROM forget_outcomes")
        else:
            self.p.detach_forgotten_idempotency(conn)
        # Jobs that observed pre-deletion state must not commit afterwards.
        conn.execute("UPDATE jobs SET state='invalidated', updated_at=? WHERE state IN ('pending','running')"
                     " AND observed_deletion_generation < ?", (self.ctx.clock(), generation))
        return {"deleted": {k: v for k, v in deleted.items() if v}, "retained": dict(retained),
                "regenerate": sorted(set(regenerate)), "suppressed": suppressed}

    def source_forgotten(self, conn: sqlite3.Connection, source: SourceRef) -> bool:
        """Whether ``source`` (any spelling) was forgotten (source, session, memory or alias)."""
        return self._source_forgotten(conn, source)

    def _source_forgotten(self, conn: sqlite3.Connection, source: SourceRef) -> bool:
        source = canonical_source(source)
        source_token = self.records.source_token(source.identity())
        if self.tombstone_generation(conn, "source", source_token) is not None:
            return True
        if conn.execute("SELECT 1 FROM tombstone_aliases WHERE source_token=?", (source_token,)).fetchone():
            return True
        if source.kind == SourceKind.SESSION and self.tombstone_generation(
                conn, "session", self.p.token("session", source.ref)) is not None:
            return True
        if source.kind == SourceKind.MEMORY and self.tombstone_generation(conn, "memory", source.ref) is not None:
            return True
        return False

    def _drop_source(self, conn: sqlite3.Connection, record: MemoryRecord, source_token: str) -> None:
        sources = tuple(s for s in record.sources if source_token not in self.records.source_index_tokens(s))
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
                 retained: Counter[str], fp: ForgetPolicy, *, access: AccessContext | None = None,
                 hidden: Counter[str] | None = None) -> list[str]:
        """Remove records derived from a forgotten input; mixed-source ones need regeneration."""
        if not fp.include_derived:
            return []
        hidden = Counter() if hidden is None else hidden
        regenerate: list[str] = []
        for derived_id in self.records.ids_derived_from(conn, input_token):
            record, damaged = self._load(conn, derived_id)
            if damaged:
                self._purge_damaged(conn, derived_id, access, deleted, hidden, prefix="derived_")
                continue
            if record is None:
                continue
            inputs = conn.execute(
                "SELECT COUNT(*) FROM derivations WHERE derived_id=? AND input_token<>?", (derived_id, input_token)
            ).fetchone()[0]
            reportable = self._reportable(access, record)
            if self._evidence_dependent(record):
                counts = {f"derived_{k}": v for k, v in self.records.purge(conn, derived_id).items()}
                (deleted if reportable else hidden).update(counts)
                if inputs and reportable:
                    regenerate.append(derived_id)
                regenerate += self._cascade(conn, self.p.token("memory", derived_id), deleted, retained, fp,
                                            access=access, hidden=hidden)
            elif reportable:
                retained["user_confirmed_derivations"] += 1
        return regenerate

    # ------------------------------------------------------------------ suppression / guards
    def suppress(self, conn: sqlite3.Connection, content: str, sources: tuple[SourceRef, ...]) -> int:
        fingerprint = self.p.token("suppress", normalize_for_fingerprint(content))
        generation = self.p.deletion_generation(conn)
        tokens = [self.records.source_token(canonical_source(s).identity()) for s in sources] or ["*"]
        for source_token in tokens:
            conn.execute(
                "INSERT OR IGNORE INTO suppressions(fingerprint_token, source_token, generation, created_at)"
                " VALUES(?,?,?,?)", (fingerprint, source_token, generation, self.ctx.clock()),
            )
        return len(tokens)

    def blocked_reason(self, conn: sqlite3.Connection, record: MemoryRecord, *,
                       observed_generation: int | None = None) -> str | None:
        sources = [canonical_source(s) for s in record.sources]
        for source in sources:
            if self._source_forgotten(conn, source):
                return "an evidence source was forgotten"
            if source.kind == SourceKind.EPISODE and conn.execute(
                    "SELECT 1 FROM episodes WHERE episode_id=?", (source.ref,)).fetchone() is None:
                return "an evidence episode no longer exists"
        for parent in record.links.derived_from:
            if self.tombstone_generation(conn, "memory", parent) is not None:
                return "derived from a forgotten memory"
            if parent != record.id and self.records.get_row(conn, parent) is None:
                return "derived from a memory that no longer exists"
        fingerprint = self.p.token("suppress", normalize_for_fingerprint(record.content))
        source_tokens = [self.records.source_token(s.identity()) for s in sources] + ["*"]
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
