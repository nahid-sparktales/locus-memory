"""Canonical memory lifecycle: remember, propose, review, correct, supersede, expire.

Transitions (anything else raises InvalidTransition):

    candidate  -> approved | rejected | expired | superseded
    approved   -> approved (correction) | stale | superseded | expired
    stale      -> approved (re-confirm/correct) | superseded | expired
    superseded -> approved (explicit revert by a reviewer; a candidate superseded without ever
                            being approved is approved as a candidate: its TTL still applies)
    rejected, expired -> (terminal; only forgetting removes them)

Forgetting is not a transition on a live row: it purges the row and records a
tombstone (see forgetting.py).

Read-time expiry: a candidate whose TTL has passed is *presented* as ``expired``
by get/list/explain and cannot be approved, rejected, corrected or superseded, even
before ``expire_due`` persists the transition; a superseding record must be current
(not stale or expired) at read time. Nothing silently becomes approved.

Read results (get/list/explain) are presentations for the caller: link ids and
memory-evidence ids that point at records outside the caller's grants are removed
(explain reports how many as ``*_unavailable`` counts). Never write a presented
record back; sibling services load records with ``RecordStore.get`` inside their
write transaction and use ``write_internal``.
"""
from __future__ import annotations

import collections
import contextvars
import dataclasses
import re
import sqlite3
from typing import Any

from . import policy, safety
from .errors import (
    IntegrityError,
    InvalidTransition,
    NotFound,
    OwnershipFenced,
    RevisionConflict,
    SensitiveContent,
    StaleDerivation,
    SuppressedError,
    ValidationError,
    WrongKey,
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
    canonical_source,
)
from .services import PartitionContext
from .storage.partition import caller_binding, new_id, partition_bound
from .validation import check_bool, check_id, check_int, normalize_for_fingerprint

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


# Actors whose own confidence claims are trusted as calibrated; a model/agent/tool
# cannot assert calibration (that is host knowledge), so theirs is downgraded.
_CALIBRATION_ATTESTERS = frozenset({Actor.USER, Actor.HOST, Actor.SYSTEM})
# The same actors are the only ones whose statement of a record's *basis* is trusted: an agent or
# provider claiming "user stated" / "observed" would otherwise pass the sensitive-inference gate
# and survive forgetting of its inputs as a "user-confirmed" record.
_BASIS_ATTESTERS = _CALIBRATION_ATTESTERS
_UNATTESTED_BASES = frozenset({StatementBasis.MODEL_INTERPRETATION, StatementBasis.HYPOTHESIS,
                               StatementBasis.SOURCE_ATTRIBUTED})
_TERMINAL = frozenset({Lifecycle.REJECTED, Lifecycle.EXPIRED, Lifecycle.FORGOTTEN})
# Writes that are not fenced by canonical ownership: deletion-driven rewrites (forgetting is
# never fenced).
_UNFENCED_CHANGES = frozenset({"source_forgotten", "evidence_revoked", "derivation_severed"})
# Migration writes carry the *inverse* fence, checked inside the write transaction: the legacy
# importer's writes only while the legacy store is the authority (or during the Migrator's final
# cutover delta, under its legacy write barrier), a rollback's adoption of written-back records
# only during the rollback. Never while the package is the authoritative writer.
_MIGRATION_CHANGES: dict[str, frozenset[str]] = {
    "imported": frozenset({"legacy_authoritative", "shadow_prepared", "validated"}),
    "legacy_delta": frozenset({"legacy_authoritative", "shadow_prepared", "validated"}),
    "legacy_adopted": frozenset({"rollback_in_progress"}),
    # Repair of a rollback whose adoptions an earlier build lost (Migrator._repair_rollback_commit).
    "legacy_readopted": frozenset({"legacy_authoritative"}),
}
# Set (in its own thread/context) only around the Migrator's final cutover delta, which runs in
# ``cutover_in_progress`` under the legacy write barrier. Any other importer is fenced in that
# state: it may have read legacy rows before the barrier, and its write could land after verify.
CUTOVER_IMPORT: contextvars.ContextVar[bool] = contextvars.ContextVar("locus_memory_cutover_import",
                                                                     default=False)
# Kinds whose records a sibling service owns (payload, state machine, derived outcome): they are
# never created, approved, corrected, pinned or superseded through the generic lifecycle API.
MANAGED_KINDS = frozenset({MemoryKind.EPISODE, MemoryKind.PROCEDURE})
# Kinds an agent or provider may propose (mirrors providers.hub._EXTRACTABLE_KINDS plus summaries).
PROPOSABLE_KINDS = frozenset({MemoryKind.PREFERENCE, MemoryKind.FACT, MemoryKind.DECISION, MemoryKind.CONSTRAINT,
                              MemoryKind.RELATIONSHIP, MemoryKind.SUMMARY})

__all__ = ["ALLOWED", "CoreService", "SuppressedError", "check_transition"]  # SuppressedError: compat


def check_transition(current: Lifecycle, target: Lifecycle) -> None:
    if target not in ALLOWED[current]:
        raise InvalidTransition(f"cannot move memory from {current.value} to {target.value}")


def managed(record: MemoryRecord) -> bool:
    """A record owned by the episode / procedure services (legacy, ungoverned procedure-kind
    memories imported from Locus are ordinary memories)."""
    return record.kind in MANAGED_KINDS and not (
        isinstance(record.extra, dict) and record.extra.get("legacy_ungoverned_procedure"))


def _refuse_managed(record: MemoryRecord) -> None:
    if managed(record):
        raise InvalidTransition(f"{record.kind.value} records are managed by their own service; use the"
                                f" {record.kind.value} API (e.g. approve_procedure / reject_procedure)")


def _merge_scopes(scopes: list[Scope]) -> Scope | None:
    """Union of constraints (visible only where every input is visible); None on conflict."""
    merged: dict[str, str] = {}
    for scope in scopes:
        for dim, value in scope.constraints:
            if merged.setdefault(dim, value) != value:
                return None
    return Scope(tuple(merged.items()))


def _earliest_ending(records: Any) -> Retention | None:
    """The retention of the earliest-ending input whose retention can end (non-durable, unpinned,
    with an expiry; the rule :func:`retention_ended` applies), or None."""
    ending = [r.retention for r in records if r.retention.expires_at is not None and not r.retention.pinned
              and r.retention.policy != "durable"]
    if not ending:
        return None
    first = min(ending, key=lambda retention: float(retention.expires_at or 0.0))
    return Retention(first.policy, first.expires_at, False)


def gate_scan(rendered: Any, stored: Any = (), identifiers: Any = ()) -> safety.ScanResult:
    """The secret / sensitive-category gate of a write, over every free-text field it stores.

    ``rendered`` (content, title, tags) is what context and search show; it alone decides the
    ``instruction_like`` flag. ``stored`` (reason / rationale, subject, predicate) is kept on the
    record too and returned by get, explain and export, so a credential or a sensitive category
    there is refused exactly as in the content. ``identifiers`` (a proposer label) are checked for
    credentials only: a name is not a statement about the user. One helper for remember, propose
    and correct, so the gates cannot drift apart.
    """
    main = safety.scan("\n".join(rendered))
    other_text = "\n".join(text for text in stored if text)
    label_text = "\n".join(text for text in identifiers if text)
    if not other_text and not label_text:
        return main
    other = safety.scan(other_text) if other_text else safety.ScanResult((), False, ())
    labels = safety.scan(label_text).secrets if label_text else ()
    return safety.ScanResult(tuple(sorted(set(main.secrets) | set(other.secrets) | set(labels))), main.injection,
                             tuple(sorted(set(main.sensitive) | set(other.sensitive))))


def retention_ended(record: MemoryRecord, now: float) -> bool:
    """Retention of a non-candidate record has passed (what ``expire_due`` persists)."""
    retention = record.retention
    return (retention.expires_at is not None and retention.expires_at < now and not retention.pinned
            and retention.policy != "durable")


# possible_conflicts runs inside remember's write transaction: it decrypts at most this many of
# the most recently updated approved records of the new record's exact scope.
CONFLICT_SCAN_LIMIT = 200
CONFLICT_SCAN_LIMITATION = ("possible_conflicts compared only the most recently updated approved memories of"
                            " this scope (bounded scan; CONFLICT_SCAN_LIMIT)")


def _topic_tokens(record: MemoryRecord) -> set[str]:
    text = " ".join((record.title or "", " ".join(record.tags)))
    return {t for t in re.findall(r"[a-z0-9_.-]+", text.lower()) if len(t) > 2}


@partition_bound
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

    @staticmethod
    def ttl_expired(record: MemoryRecord, now: float) -> bool:
        return (record.lifecycle == Lifecycle.CANDIDATE and record.retention.expires_at is not None
                and record.retention.expires_at < now)

    @staticmethod
    def _candidate_ttl_passed(record: MemoryRecord, now: float) -> bool:
        return record.retention.expires_at is not None and record.retention.expires_at < now

    def never_approved(self, conn: sqlite3.Connection, record: MemoryRecord) -> bool:
        """A superseded record that never went through approval: a candidate resolved by
        supersede (its retention still carries the candidate TTL)."""
        if record.lifecycle != Lifecycle.SUPERSEDED:
            return False
        if isinstance(record.extra, dict) and record.extra.get("legacy_status") == "approved":
            return False
        return not any(rev.lifecycle in (Lifecycle.APPROVED, Lifecycle.STALE)
                       for rev in self.records.revisions(conn, record.id))

    def effective_lifecycle(self, record: MemoryRecord, now: float | None = None) -> Lifecycle:
        """The lifecycle a record has *now* - exactly what ``expire_due`` would persist - so reads
        never present an expired or validity-ended record as current before maintenance runs."""
        now = self.now if now is None else now
        if self.ttl_expired(record, now):
            return Lifecycle.EXPIRED
        if record.lifecycle in (Lifecycle.APPROVED, Lifecycle.STALE) and retention_ended(record, now):
            return Lifecycle.EXPIRED
        if (record.lifecycle == Lifecycle.APPROVED and record.validity.valid_until is not None
                and record.validity.valid_until < now):
            return Lifecycle.STALE
        return record.lifecycle

    def present(self, conn: sqlite3.Connection, access: AccessContext, records: list[MemoryRecord],
                now: float | None = None) -> list[MemoryRecord]:
        """Caller-facing view: read-time expiry and no references to out-of-scope records."""
        now = self.now if now is None else now
        refs: set[str] = set()
        for record in records:
            refs.update(record.links.supersedes, record.links.conflicts_with, record.links.derived_from)
            if record.links.superseded_by:
                refs.add(record.links.superseded_by)
            refs.update(s.ref for s in record.sources if s.kind == SourceKind.MEMORY)
        visible = self.records.visible_ids(conn, access.grants, refs) if refs else set()
        history = self.ctx.services.history
        archived = [s for r in records for s in r.sources if s.kind in (SourceKind.MESSAGE, SourceKind.SESSION)]
        hidden_history: set[str] = set()
        if archived and history is not None and hasattr(history, "hidden_sources"):
            # Transcript references the reader cannot see are removed like memory references.
            hidden_history = history.hidden_sources(conn, access.grants, archived)
        out = []
        for record in records:
            links = record.links
            shown = Links(
                supersedes=tuple(i for i in links.supersedes if i in visible),
                superseded_by=links.superseded_by if links.superseded_by in visible else None,
                conflicts_with=tuple(i for i in links.conflicts_with if i in visible),
                derived_from=tuple(i for i in links.derived_from if i in visible),
            )
            sources = tuple(s for s in record.sources
                            if (s.kind != SourceKind.MEMORY or s.ref in visible) and s.identity() not in hidden_history)
            changes: dict[str, Any] = {}
            if shown != links:
                changes["links"] = shown
            if sources != record.sources:
                changes["sources"] = sources
            effective = self.effective_lifecycle(record, now)
            if effective != record.lifecycle:
                changes["lifecycle"] = effective
            out.append(dataclasses.replace(record, **changes) if changes else record)
        return out

    def _commit_write(self, conn: sqlite3.Connection, record: MemoryRecord, *, change: str,
                      actor: Actor, expected: int | None) -> MemoryRecord:
        if change in _MIGRATION_CHANGES:
            self._check_migration_state(change)
        elif change not in _UNFENCED_CHANGES:
            self._check_owner()
        generation = self.p.bump(conn)
        return self.records.write(conn, record, change=change, actor=actor,
                                  expected_revision=expected, generation=generation)

    def _check_owner(self) -> None:
        """Ownership fence, inside the write transaction (see ``MemoryEngine._fence``): a write that
        passed the up-front check just before a migrator fenced the package cannot commit after
        it (the migrator takes this store's write lock before reading it)."""
        control = getattr(self.ctx.host, "ownership", None)
        if control is not None:
            control.assert_writer(self.p.partition_id, "memories", "package")

    def _check_migration_state(self, change: str) -> None:
        """Inverse fence of migration writes (see ``_MIGRATION_CHANGES``), inside the write
        transaction: a cutover's final transition holds this store's write lock, so an importer
        that checked the state before it cannot commit after it."""
        control = getattr(self.ctx.host, "ownership", None)
        if control is None:
            return
        state = control.get(self.p.partition_id, "memories").state
        if state == "cutover_in_progress" and change in ("imported", "legacy_delta") and CUTOVER_IMPORT.get():
            return
        if state not in _MIGRATION_CHANGES[change]:
            raise OwnershipFenced(f"migration writes ({change}) are fenced while ownership is {state}",
                                  details={"state": state, "change": change})

    def _check_expected(self, record: MemoryRecord, expected_revision: int | None) -> None:
        if expected_revision is not None and record.revision != expected_revision:
            raise RevisionConflict("the memory changed since it was read",
                                   details={"expected_revision": expected_revision,
                                            "current_revision": record.revision})

    def _replay(self, conn: sqlite3.Connection, access: AccessContext, key: str | None, operation: str,
                request: Any) -> WriteResult | None:
        receipt_raw = self.p.idempotency_lookup(conn, key, operation, request, caller=caller_binding(access))
        if receipt_raw is None:
            return None
        receipt = Receipt(**{**receipt_raw, "idempotent_replay": True,
                             "record_ids": tuple(receipt_raw.get("record_ids") or ()),
                             "revisions": tuple(receipt_raw.get("revisions") or ()),
                             "limitations": tuple(receipt_raw.get("limitations") or ())})
        record = self.records.get(conn, receipt.record_ids[0]) if receipt.record_ids else None
        if record is None or not policy.visible(access, record):
            raise NotFound("the memory created by this idempotency key no longer exists")
        return WriteResult(record=self.present(conn, access, [record])[0], receipt=receipt,
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

    def possible_conflicts(self, conn: sqlite3.Connection, access: AccessContext, record: MemoryRecord, *,
                           limitations: list[str] | None = None) -> list[str]:
        """Legacy-compatible heuristic: same topic (title/tags overlap >= 50%), different content.

        Bounded, because it runs inside the write transaction (every other writer waits): only
        approved records of exactly ``record.scope`` are selected (in SQL, by scope token), and
        at most ``CONFLICT_SCAN_LIMIT`` of the most recently updated ones are decrypted and
        compared. When the scope holds more, ``CONFLICT_SCAN_LIMITATION`` is appended to
        ``limitations`` (the receipt says the scan was partial). At most 12 ids are returned.
        """
        topic = _topic_tokens(record)
        if not topic:
            return []
        normalized = normalize_for_fingerprint(record.content)
        grants = policy.narrow(access.grants, record.scope) if access.grants.allows(record.scope) else access.grants
        out: list[str] = []
        scanned = 0
        others = self.records.iter_authorized(conn, grants, lifecycles=(Lifecycle.APPROVED,), scope=record.scope,
                                              order="updated_at DESC, id", limit=CONFLICT_SCAN_LIMIT + 2)
        try:
            for other in others:
                if other.id == record.id:
                    continue
                if scanned >= CONFLICT_SCAN_LIMIT:
                    if limitations is not None and CONFLICT_SCAN_LIMITATION not in limitations:
                        limitations.append(CONFLICT_SCAN_LIMITATION)
                    break
                scanned += 1
                if other.scope != record.scope:  # defence in depth: the token selected this scope
                    continue
                other_topic = _topic_tokens(other)
                overlap = len(topic & other_topic) / max(min(len(topic), len(other_topic)), 1)
                if overlap >= 0.5 and normalize_for_fingerprint(other.content) != normalized:
                    out.append(other.id)
                    if len(out) >= 12:
                        break
        finally:
            others.close()
        return out

    # ------------------------------------------------------------------ evidence
    def verify_sources(self, conn: sqlite3.Connection, access: AccessContext,
                       sources: tuple[SourceRef, ...], *, derived_from: tuple[str, ...] = ()) -> tuple[SourceRef, ...]:
        """Verify evidence for this caller; returns the sources in canonical spelling (what is
        stored, indexed, tombstoned and suppressed - an alias must never miss a tombstone)."""
        host_attested = access.actor in (Actor.USER, Actor.HOST)
        sources = tuple(canonical_source(s) for s in sources)
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
        return sources

    def source_scope(self, conn: sqlite3.Connection, source: SourceRef) -> Scope | None:
        """The authoritative scope of the data a source names: a memory's own scope, or what the
        sibling service that owns the source kind reports (``source_scope``: the session of a
        message, the episode of an attempt, the registration of a repository object). None when
        nothing here holds it (e.g. a document, or an object of an unregistered repository)."""
        if source.kind == SourceKind.MEMORY:
            try:
                record = self.records.get(conn, source.ref)
            except (IntegrityError, WrongKey):
                return None
            return None if record is None else record.scope
        service_name = _VERIFIABLE_BY_SERVICE.get(source.kind)
        service = getattr(self.ctx.services, service_name, None) if service_name else None
        hook = getattr(service, "source_scope", None) if service is not None else None
        return hook(conn, source) if callable(hook) else None

    def evidence_scope(self, conn: sqlite3.Connection, access: AccessContext, declared: Scope,
                       sources: tuple[SourceRef, ...], *, derived_from: tuple[str, ...] = ()) -> Scope:
        """The declared scope reconciled with the scopes of every input: the memories it is derived
        from (``derived_from``) and every cited source whose owner knows its scope (memories,
        messages and sessions, episodes and task attempts, repository commits and blobs - see
        :meth:`source_scope`).

        A record derived from evidence must be at least as narrow as that evidence (otherwise a
        P2 transcript could surface as a profile-global candidate): the declared scope is
        narrowed to the union of constraints, and a conflicting declaration is refused.
        """
        scopes = [declared]
        for parent in derived_from:
            try:
                record = self.records.get(conn, parent)
            except (IntegrityError, WrongKey):
                record = None
            if record is not None:
                scopes.append(record.scope)
        for source in sources:
            scope = self.source_scope(conn, source)
            if scope is not None:
                scopes.append(scope)
        merged = _merge_scopes(scopes)
        if merged is None:
            raise ValidationError("the declared scope conflicts with the scope of its evidence")
        policy.require_scope(access, merged)
        return merged

    def _forgotten_id(self, conn: sqlite3.Connection, record_id: str) -> bool:
        forgetting = self.ctx.services.forgetting
        return forgetting is not None and forgetting.tombstone_generation(conn, "memory", record_id) is not None

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
        if request.kind in MANAGED_KINDS:
            raise ValidationError("episodes and procedures are recorded through record_episode /"
                                  " nominate_procedure, not remember")
        scan = gate_scan((request.content, request.title, " ".join(request.tags)),
                         (request.reason, request.subject, request.predicate))
        if scan.secrets:
            raise SensitiveContent("credentials and secrets are not stored in memory; use the host keychain",
                                   details={"categories": list(scan.secrets)})
        if scan.sensitive and not request.allow_sensitive:
            raise SensitiveContent("this looks like sensitive personal information; the host must confirm"
                                   " the user explicitly asked to keep it", details={"categories": list(scan.sensitive)})
        now = self.now
        with self.p.db.write() as conn:
            replay = self._replay(conn, access, idempotency_key, "remember", request)
            if replay is not None:
                return replay
            if request.memory_id is not None and self._forgotten_id(conn, request.memory_id):
                # A forgotten id is never silently re-created at revision 1: caches elsewhere hold
                # (id, revision) of the forgotten content.
                raise ValidationError("this memory id belongs to a forgotten memory; use a new id")
            sources = request.sources or (SourceRef(SourceKind.USER_ACTION, "remember-" + new_id(),
                                                    actor=access.actor, observed_at=now),)
            sources = self.verify_sources(conn, access, sources)
            # An explicit remember keeps the user's chosen scope: its content is the user's own
            # statement (sources are provenance; reads hide references the reader cannot see).
            scope = request.scope
            record_id = request.memory_id or new_id("m")
            extra: dict[str, Any] = {"basis_attested_by": access.actor.value}
            if scan.injection:
                extra["flags"] = ["instruction_like"]
            record = MemoryRecord(
                id=record_id, revision=1, kind=request.kind, lifecycle=Lifecycle.APPROVED,
                scope=scope, title=request.title or request.content[:60], content=request.content,
                tags=request.tags, basis=request.basis,
                confidence=request.confidence if request.confidence.value is not None
                else Confidence(None, False, "user_asserted"),
                subject=request.subject, predicate=request.predicate, sources=sources,
                validity=request.validity, retention=request.retention, links=Links(),
                created_at=now, updated_at=now, event_time=now, ingested_at=now, reason=request.reason,
                extra=extra,
            )
            conflicts = self.structured_conflicts(conn, record)
            record = dataclasses.replace(record, links=Links(conflicts_with=tuple(conflicts)))
            record = self._commit_write(conn, record, change="created", actor=access.actor, expected=None)
            limitations: list[str] = []
            possible = self.possible_conflicts(conn, access, record, limitations=limitations)
            receipt = self.p.make_receipt(
                conn, "remember", "ok", record_ids=(record.id,), revisions=(record.revision,),
                details={"conflicts": conflicts, "possible_conflicts": possible,
                         "flags": list(record.extra.get("flags", []))},
                limitations=tuple(limitations),
            )
            self.p.idempotency_store(conn, idempotency_key, "remember", request, receipt,
                                     caller=caller_binding(access))
            self.p.event(conn, "remember", "ok")
            shown = self.present(conn, access, [record], now)[0]
        return WriteResult(record=shown, receipt=receipt, conflicts=tuple(conflicts))

    # ------------------------------------------------------------------ propose
    def _check_proposal(self, access: AccessContext, proposal: CandidateProposal) -> tuple[StatementBasis, Any]:
        """Content-independent checks of a proposal; returns (effective basis, safety scan)."""
        policy.require(access, Operation.PROPOSE)
        policy.require_scope(access, proposal.scope)
        if proposal.kind in MANAGED_KINDS:
            raise ValidationError("episodes and procedures are recorded through record_episode /"
                                  " nominate_procedure, not propose")
        attester = access.actor in _BASIS_ATTESTERS
        if not attester and proposal.kind not in PROPOSABLE_KINDS:
            raise ValidationError(f"an {access.actor.value} cannot propose {proposal.kind.value} records")
        # A proposer that is not a trusted attester cannot claim the user stated (or that it
        # observed) something: its claim is downgraded to a model interpretation.
        basis = proposal.basis if attester or proposal.basis in _UNATTESTED_BASES \
            else StatementBasis.MODEL_INTERPRETATION
        scan = gate_scan((proposal.content, proposal.title, " ".join(proposal.tags)),
                         (proposal.rationale, proposal.subject, proposal.predicate), (proposal.proposer,))
        if scan.secrets:
            raise SensitiveContent("candidate contains credential-like content", details={"categories": list(scan.secrets)})
        if scan.sensitive and basis != StatementBasis.USER_STATED:
            raise SensitiveContent("sensitive personal information is never inferred into memory",
                                   details={"categories": list(scan.sensitive)})
        return basis, scan

    def propose(self, access: AccessContext, proposal: CandidateProposal, *,
                idempotency_key: str | None = None) -> WriteResult:
        basis, scan = self._check_proposal(access, proposal)
        with self.p.db.write() as conn:
            return self._propose_in(conn, access, proposal, basis, scan, idempotency_key=idempotency_key)

    def propose_in(self, conn: sqlite3.Connection, access: AccessContext, proposal: CandidateProposal) -> WriteResult:
        """``propose`` inside the caller's write transaction (sibling services that must commit a
        record and the candidates derived from it atomically, e.g. episode lessons)."""
        basis, scan = self._check_proposal(access, proposal)
        return self._propose_in(conn, access, proposal, basis, scan, idempotency_key=None)

    def _propose_in(self, conn: sqlite3.Connection, access: AccessContext, proposal: CandidateProposal,
                    basis: StatementBasis, scan: Any, *, idempotency_key: str | None) -> WriteResult:
        now = self.now
        replay = self._replay(conn, access, idempotency_key, "propose", proposal)
        if replay is not None:
            return replay
        sources = self.verify_sources(conn, access, proposal.sources, derived_from=proposal.derived_from)
        scope = self.evidence_scope(conn, access, proposal.scope, sources, derived_from=proposal.derived_from)
        # A record derived from memories restates them: it is never derived from one that is no
        # longer servable, and it never outlives them (inherited retention, capped candidate TTL).
        # A memory it cites as its evidence counts as such an input whenever the record follows that
        # citation (the rule a forget applies to citers, see :meth:`followed_citations`).
        inputs, cited = self._derivation_inputs(conn, proposal.derived_from, sources, now)
        if cited:
            probe = MemoryRecord(
                id="m-probe", revision=1, kind=proposal.kind, lifecycle=Lifecycle.APPROVED, scope=scope,
                title="", content=proposal.content, basis=basis, sources=sources,
                links=Links(derived_from=proposal.derived_from), created_at=now, updated_at=now,
                extra={"basis_attested_by": access.actor.value})
            followed = set(self.followed_citations(conn, probe))
            inputs = [*inputs, *(r for r in cited if r.id in followed and r.id not in proposal.derived_from)]
        inherited = _earliest_ending(inputs)
        confidence = proposal.confidence
        if confidence.value is not None and confidence.calibrated and access.actor not in _CALIBRATION_ATTESTERS:
            # A proposer cannot attest its own calibration; keep the value, drop the claim.
            confidence = Confidence(confidence.value, False, "model_uncalibrated")
        if confidence.value is not None and not confidence.calibrated and confidence.method == "unknown":
            confidence = Confidence(confidence.value, False, "model_uncalibrated")
        record = MemoryRecord(
            id=new_id("m"), revision=1, kind=proposal.kind, lifecycle=Lifecycle.CANDIDATE,
            scope=scope, title=proposal.title or proposal.content[:60], content=proposal.content,
            tags=proposal.tags, basis=basis, confidence=confidence,
            subject=proposal.subject, predicate=proposal.predicate, sources=sources,
            validity=proposal.validity,
            retention=Retention("durable", now + self.ctx.config.candidate_ttl_seconds
                                if inherited is None else min(now + self.ctx.config.candidate_ttl_seconds,
                                                              float(inherited.expires_at or 0.0)), False),
            links=Links(derived_from=proposal.derived_from), created_at=now, updated_at=now,
            event_time=min((s.observed_at for s in sources if s.observed_at), default=None),
            ingested_at=now, reason=proposal.rationale,
            extra={"proposer": proposal.proposer, "basis_attested_by": access.actor.value,
                   **({"flags": ["instruction_like"]} if scan.injection else {}),
                   **({"inherited_retention": {"policy": inherited.policy, "expires_at": inherited.expires_at}}
                      if inherited is not None else {})},
        )
        blocked = self._blocked(conn, record, proposal.observed_generation)
        if blocked:
            self.p.event(conn, "proposal", "suppressed", blocked)
            raise SuppressedError(f"candidate refused: {blocked}")
        # A candidate past its TTL is expired (read-time) and must not swallow a new proposal.
        duplicate = conn.execute(
            "SELECT id FROM records WHERE content_token=? AND scope_token=? AND (lifecycle='approved'"
            " OR (lifecycle='candidate' AND (expires_at IS NULL OR expires_at >= ?))) LIMIT 1",
            (self.records.content_token(record.content), self.records.scope_token(record.scope), now),
        ).fetchone()
        if duplicate is not None:
            existing = self.records.get(conn, duplicate[0])
            receipt = self.p.make_receipt(conn, "propose", "noop", record_ids=(existing.id,),
                                          revisions=(existing.revision,), details={"duplicate_of": existing.id})
            self.p.idempotency_store(conn, idempotency_key, "propose", proposal, receipt,
                                     caller=caller_binding(access))
            return WriteResult(record=self.present(conn, access, [existing], now)[0], receipt=receipt)
        conflicts = self.structured_conflicts(conn, record)
        record = dataclasses.replace(record, links=dataclasses.replace(record.links, conflicts_with=tuple(conflicts)))
        record = self._commit_write(conn, record, change="proposed", actor=access.actor, expected=None)
        receipt = self.p.make_receipt(conn, "propose", "ok", record_ids=(record.id,),
                                      revisions=(record.revision,),
                                      details={"conflicts": conflicts, "expires_at": record.retention.expires_at})
        self.p.idempotency_store(conn, idempotency_key, "propose", proposal, receipt,
                                 caller=caller_binding(access))
        self.p.event(conn, "proposal", "accepted")
        shown = self.present(conn, access, [record], now)[0]
        return WriteResult(record=shown, receipt=receipt, conflicts=tuple(conflicts))

    # ------------------------------------------------------------------ review
    def approve(self, access: AccessContext, record_id: str, *, expected_revision: int | None,
                resolution: str = "keep_both", expected_conflicts: tuple[str, ...] | None = None) -> WriteResult:
        """Approve a candidate (or re-confirm a stale / revert a superseded record).

        ``resolution="supersede"`` retires only the conflicts the reviewer saw: those recorded on
        the candidate (``links.conflicts_with``), or exactly ``expected_conflicts`` when given (a
        :class:`RevisionConflict` if the current visible conflict set differs). Conflicts that
        appeared after review are kept (reported as ``new_conflicts``), never silently retired.
        """
        policy.require_reviewer(access, self.ctx.host)
        if resolution not in {"keep_both", "supersede"}:
            raise ValidationError("resolution must be keep_both or supersede")
        if expected_conflicts is not None:
            expected_conflicts = tuple(check_id(c, "expected conflict id") for c in expected_conflicts)
        now = self.now
        with self.p.db.write() as conn:
            record = self.load_visible(conn, access, record_id)
            _refuse_managed(record)
            self._check_expected(record, expected_revision)
            # A candidate superseded without ever being reviewed is still a candidate to approve:
            # its TTL applies (an expired candidate is never revived through the revert path) and
            # approval drops that TTL rather than keeping a stale candidate expiry.
            unreviewed = record.lifecycle == Lifecycle.CANDIDATE or self.never_approved(conn, record)
            if self.ttl_expired(record, now) or (unreviewed and self._candidate_ttl_passed(record, now)):
                raise InvalidTransition("this candidate has expired")
            check_transition(record.lifecycle, Lifecycle.APPROVED)
            if not unreviewed and retention_ended(record, now):
                raise InvalidTransition("this memory's retention period has ended")
            blocked = self._blocked(conn, record)
            if blocked:
                raise SuppressedError(f"cannot approve: {blocked}")
            inputs = self._check_inputs(conn, record)
            conflicts = self.structured_conflicts(conn, record)
            visible = self.records.visible_ids(conn, access.grants, conflicts)
            visible_conflicts = [c for c in conflicts if c in visible]
            if expected_conflicts is not None and set(visible_conflicts) != set(expected_conflicts):
                raise RevisionConflict("the conflicting memories changed since they were reviewed",
                                       details={"current_conflicts": visible_conflicts})
            reviewed = set(record.links.conflicts_with) if expected_conflicts is None else set(expected_conflicts)
            superseded: list[str] = []
            if resolution == "supersede":
                for other_id in conflicts:
                    if other_id not in reviewed:
                        continue  # appeared after review: never retired without being seen
                    other = self.records.get(conn, other_id)
                    if other is None or not policy.visible(access, other):
                        continue
                    _refuse_managed(other)
                    check_transition(other.lifecycle, Lifecycle.SUPERSEDED)
                    updated = dataclasses.replace(
                        other, revision=other.revision + 1, lifecycle=Lifecycle.SUPERSEDED, updated_at=now,
                        links=dataclasses.replace(other.links, superseded_by=record.id),
                    )
                    self._commit_write(conn, updated, change="superseded", actor=access.actor, expected=other.revision)
                    # The record being approved replaces ``other``: it is not a restatement of what
                    # ``other`` used to say, even when it is derived from it (an update of it).
                    self._stale_derived(conn, other_id, exclude={record.id})
                    superseded.append(other_id)
            remaining = tuple(c for c in conflicts if c not in superseded)
            new_conflicts = [c for c in remaining if c not in record.links.conflicts_with]
            links = dataclasses.replace(
                record.links, supersedes=tuple(sorted(set(record.links.supersedes) | set(superseded))),
                conflicts_with=remaining)
            unsuperseded = None
            if record.lifecycle == Lifecycle.SUPERSEDED:
                # An explicit revert: the record is current again, so it is no longer superseded,
                # and the former superseder no longer claims to supersede it.
                unsuperseded = record.links.superseded_by
                links = dataclasses.replace(links, superseded_by=None)
            validity = record.validity
            extra = {**record.extra, "last_confirmed_at": now}
            if validity.valid_until is not None and validity.valid_until < now:
                # Re-confirming a statement whose validity ended makes it current again: an ended
                # validity would otherwise keep it stale on every read and the next maintenance.
                extra["reconfirmed_after_valid_until"] = validity.valid_until
                validity = dataclasses.replace(validity, valid_until=None)
            retention = record.retention
            if unreviewed:
                # Only a candidate's TTL is dropped; a transient memory keeps its retention. A
                # record derived from transient inputs (a summary, an extraction, a proposal with
                # derived_from) takes over their retention instead (it restates them, so it must
                # not outlive them).
                retention = self._approved_retention(record, now, inputs)
            approved = dataclasses.replace(
                record, revision=record.revision + 1, lifecycle=Lifecycle.APPROVED, updated_at=now,
                retention=retention, validity=validity, links=links, extra=extra,
            )
            approved = self._commit_write(conn, approved, change="approved", actor=access.actor, expected=record.revision)
            if unsuperseded:
                self._unlink_superseder(conn, unsuperseded, record.id, access, now)
            details: dict[str, Any] = {"superseded": superseded, "conflicts": list(remaining)}
            if new_conflicts:
                details["new_conflicts"] = new_conflicts
            if unsuperseded and unsuperseded in self.records.visible_ids(conn, access.grants, [unsuperseded]):
                details["reverted_from"] = unsuperseded
            receipt = self.p.make_receipt(conn, "approve", "ok", record_ids=(approved.id, *superseded),
                                          revisions=(approved.revision,), details=details)
            self.p.event(conn, "approval", "accepted")
            shown = self.present(conn, access, [approved], now)[0]
        return WriteResult(record=shown, receipt=receipt, conflicts=remaining)

    def _unlink_superseder(self, conn: sqlite3.Connection, superseder_id: str, reverted_id: str,
                           access: AccessContext, now: float) -> None:
        try:
            superseder = self.records.get(conn, superseder_id)
        except (IntegrityError, WrongKey):
            return
        if superseder is None or reverted_id not in superseder.links.supersedes:
            return
        updated = dataclasses.replace(
            superseder, revision=superseder.revision + 1, updated_at=now,
            links=dataclasses.replace(superseder.links,
                                      supersedes=tuple(i for i in superseder.links.supersedes if i != reverted_id)))
        self._commit_write(conn, updated, change="unsuperseded", actor=access.actor, expected=superseder.revision)

    @staticmethod
    def inherited_retention(record: MemoryRecord) -> Retention | None:
        """The retention a derived record (consolidation summary) inherits from its transient
        inputs (``extra.inherited_retention``: the policy and expiry of the earliest-ending
        input), or None when every input was durable or pinned."""
        raw = record.extra.get("inherited_retention") if isinstance(record.extra, dict) else None
        if not isinstance(raw, dict):
            return None
        try:
            retention = Retention(str(raw.get("policy") or "transient"), raw.get("expires_at"), False)
        except (ValidationError, TypeError, ValueError):
            return Retention("transient", 0.0, False)  # malformed: treat as already ended
        if retention.expires_at is None or retention.policy == "durable":
            return Retention("transient", 0.0, False)
        return retention

    def _approved_retention(self, candidate: MemoryRecord, now: float,
                            inputs: list[MemoryRecord] | None = None) -> Retention:
        """The retention an approved candidate keeps: its own without the candidate TTL, or - for a
        record derived from transient inputs - theirs (the earliest-ending of the retention
        recorded when it was proposed and the inputs' current one)."""
        ending = [r for r in (self.inherited_retention(candidate), _earliest_ending(inputs or ()))
                  if r is not None]
        if not ending:
            return dataclasses.replace(candidate.retention, expires_at=None)
        inherited = min(ending, key=lambda retention: float(retention.expires_at or 0.0))
        if inherited.expires_at is not None and inherited.expires_at < now:
            raise StaleDerivation("the retention period of this record's inputs has ended; it cannot be approved")
        return dataclasses.replace(inherited, pinned=candidate.retention.pinned)

    @staticmethod
    def _detached(record: MemoryRecord) -> bool:
        """A derived record the user or host restated in their own words (``correct`` with new
        content): it no longer follows its inputs' lifecycle (forgetting still applies its own
        rules, see ``ForgettingService._attested``)."""
        return isinstance(record.extra, dict) and bool(record.extra.get("inputs_detached"))

    def _derivation_inputs(self, conn: sqlite3.Connection, derived_from: tuple[str, ...],
                           sources: tuple[SourceRef, ...], now: float
                           ) -> tuple[list[MemoryRecord], list[MemoryRecord]]:
        """The memories a proposal is derived from (``derived_from``) and the memories it cites as
        evidence (``SourceRef(kind=memory)``), refused when one of them is no longer servable:
        rejected, expired (also at read time), forgotten, or an observation of a now-excluded path.
        (Visibility was checked by ``verify_sources``.)"""
        cited_ids = [s.ref for s in sources if s.kind == SourceKind.MEMORY]
        inputs: list[MemoryRecord] = []
        cited: list[MemoryRecord] = []
        checked: list[MemoryRecord] = []
        for record_id in dict.fromkeys((*derived_from, *cited_ids)):
            try:
                record = self.records.get(conn, record_id)
            except (IntegrityError, WrongKey):
                record = None
            if record is None:
                continue  # missing parents are refused by blocked_reason; damaged evidence by forgetting
            if self.effective_lifecycle(record, now) in _TERMINAL:
                raise StaleDerivation("a memory this proposal is derived from or cites is no longer current"
                                      " (rejected, expired or forgotten)")
            checked.append(record)
            if record_id in derived_from:
                inputs.append(record)
            if record_id in cited_ids:
                cited.append(record)
        if checked and self._excluded(conn, checked):
            raise NotFound("memory not found")  # an observation of a now-excluded path (as get())
        return inputs, cited

    def _other_evidence(self, conn: sqlite3.Connection, record: MemoryRecord, input_id: str) -> bool:
        """Whether ``record`` has live evidence besides its citation of memory ``input_id``: a source
        that was not forgotten (a cited memory must still exist)."""
        forgetting = self.ctx.services.forgetting
        for source in record.sources:
            if source.kind == SourceKind.MEMORY:
                if source.ref == input_id or self.records.get_row(conn, source.ref) is None:
                    continue
            if forgetting is not None and forgetting.source_forgotten(conn, source):
                continue
            return True
        return False

    def followed_citations(self, conn: sqlite3.Connection, record: MemoryRecord) -> list[str]:
        """Ids of the memories ``record`` cites as evidence (``SourceRef(kind=memory)``) whose lifecycle
        it follows like a derivation input (``derived_from``): retention inheritance, expiry and staling
        when the input expires, is corrected or superseded, and hiding / purging with an observation of
        a now-excluded path. The rule a forget applies to citers (``ForgettingService``): an
        evidence-dependent record (a model interpretation, a summary, an unattested proposal - judged
        as approved: approval is not attestation) follows every memory it cites; an attested one
        follows a cited memory only when it has no other live evidence. A record the user restated in
        their own words (:meth:`_detached`) follows nothing."""
        cited = list(dict.fromkeys(s.ref for s in record.sources if s.kind == SourceKind.MEMORY and s.ref != record.id))
        if not cited or self._detached(record):
            return []
        forgetting = self.ctx.services.forgetting
        approved = record if record.lifecycle == Lifecycle.APPROVED else dataclasses.replace(
            record, lifecycle=Lifecycle.APPROVED)
        if forgetting is None or forgetting.evidence_dependent(approved):
            return cited
        return [cited_id for cited_id in cited if not self._other_evidence(conn, record, cited_id)]

    def _check_inputs(self, conn: sqlite3.Connection, record: MemoryRecord) -> list[MemoryRecord]:
        """A derived record (a consolidation summary, an extraction, any proposal with
        ``derived_from``) is approvable only while every input is still approved *now* (not expired
        at read time - retention or TTL passed before maintenance persisted it - nor stale, nor an
        observation of a now-excluded path) and, when the record names them, at the revisions it
        was generated from. Returns the inputs (empty for a record that derives from nothing or
        that the user restated in their own words)."""
        if self._detached(record):
            return []
        revisions = record.extra.get("input_revisions") if isinstance(record.extra, dict) else None
        revisions = revisions if isinstance(revisions, dict) else {}
        parents = list(dict.fromkeys((*record.links.derived_from, *(str(i) for i in revisions))))
        parents = [p for p in parents if p != record.id]
        # Memories it cites and follows (:meth:`followed_citations`): their retention is inherited
        # too, and one that is no longer current (rejected, expired, stale, superseded) or gone makes
        # the record unapprovable - a pending citation (a candidate) is still a citation.
        citations = [c for c in self.followed_citations(conn, record) if c not in parents]
        if not parents and not citations:
            return []
        now = self.now
        what = "summary" if record.kind == MemoryKind.SUMMARY else "derived record"
        inputs: list[MemoryRecord] = []
        for input_id in parents:
            try:
                current = self.records.get(conn, input_id)
            except (IntegrityError, WrongKey):
                current = None
            revision = revisions.get(input_id, revisions.get(str(input_id)))
            if (current is None or self.effective_lifecycle(current, now) != Lifecycle.APPROVED
                    or (input_id in revisions and (not isinstance(revision, int) or current.revision != revision))):
                raise StaleDerivation(f"the inputs of this {what} changed since it was generated; regenerate it")
            inputs.append(current)
        for input_id in citations:
            try:
                current = self.records.get(conn, input_id)
            except (IntegrityError, WrongKey):
                current = None
            if current is None or self.effective_lifecycle(current, now) not in (Lifecycle.APPROVED,
                                                                                   Lifecycle.CANDIDATE):
                raise StaleDerivation(f"a memory this {what} cites as its evidence is no longer current;"
                                      " regenerate it")
            inputs.append(current)
        if self._excluded(conn, inputs):
            raise StaleDerivation(f"an input of this {what} is an observation of a now-excluded path")
        return inputs

    def _stale_derived(self, conn: sqlite3.Connection, input_id: str, *, expired: bool = False,
                       changed_ids: set[str] | None = None, exclude: set[str] | None = None) -> list[str]:
        """An input was corrected, superseded or went stale: approved records derived from it
        (summaries, extractions, proposals with ``derived_from``, and records that cite it as their
        evidence and follow it - :meth:`followed_citations`) go stale and pending ones expire (they
        restate what the input used to say).

        ``expired``: the input's retention (or TTL) ended - every record derived from it expires,
        approved ones included: it restates content whose retention is over, so it must leave
        search and listing as well as context. A derived record the user restated in their own
        words (:meth:`_detached`) no longer follows its inputs.

        Transitive: a record moved here is itself an input that changed, so what is derived from
        it moves the same way, at any depth (an iterative work list, never recursion; a record the
        user restated is never descended through).

        The record that supersedes the input (``exclude``: the one being approved over it or named
        by ``supersede``; also any record already recording that it supersedes the input) is its
        replacement, not a restatement of its old content: it never goes stale or expires because
        the input it replaces was superseded (unless the input's retention ended)."""
        changed: list[str] = []
        pending = collections.deque([input_id])
        queued = {input_id}
        while pending:
            current_id = pending.popleft()
            derived_ids = self.records.ids_derived_from(conn, self.p.token("memory", current_id))
            citer_ids = self.records.ids_for_source(
                conn, self.records.source_token(f"{SourceKind.MEMORY.value}:{current_id}"))
            for derived_id in dict.fromkeys((*derived_ids, *citer_ids)):
                try:
                    derived = self.records.get(conn, derived_id)
                except (IntegrityError, WrongKey):
                    continue
                if derived is None or derived.id in (input_id, current_id) or self._detached(derived):
                    continue
                if not expired and ((exclude is not None and current_id == input_id and derived.id in exclude)
                                    or current_id in derived.links.supersedes):
                    continue
                revisions = derived.extra.get("input_revisions") if isinstance(derived.extra, dict) else None
                derives = current_id in derived.links.derived_from or (
                    isinstance(revisions, dict) and current_id in revisions)
                if not derives and current_id not in self.followed_citations(conn, derived):
                    continue  # (an attested record with other live evidence keeps its statement)
                if expired and derived.lifecycle in (Lifecycle.APPROVED, Lifecycle.STALE, Lifecycle.CANDIDATE):
                    self.transition_internal(conn, derived, Lifecycle.EXPIRED, change="expired",
                                             reason="input_retention_ended")
                elif derived.lifecycle == Lifecycle.APPROVED:
                    self.transition_internal(conn, derived, Lifecycle.STALE, change="stale", reason="input_changed")
                elif derived.lifecycle == Lifecycle.CANDIDATE:
                    self.transition_internal(conn, derived, Lifecycle.EXPIRED, change="expired",
                                             reason="input_changed")
                else:
                    continue
                changed.append(derived_id)
                if changed_ids is not None:
                    changed_ids.add(derived_id)
                if derived_id not in queued:
                    queued.add(derived_id)
                    pending.append(derived_id)
        return changed

    def reject(self, access: AccessContext, record_id: str, *, expected_revision: int | None,
               reason: str = "") -> WriteResult:
        policy.require_reviewer(access, self.ctx.host)
        now = self.now
        with self.p.db.write() as conn:
            record = self.load_visible(conn, access, record_id)
            _refuse_managed(record)
            self._check_expected(record, expected_revision)
            check_transition(self.effective_lifecycle(record, now), Lifecycle.REJECTED)
            # The reviewer's free text is stored on the record (and exported): a credential in it is
            # redacted rather than refused, so a rejection is never blocked (nor is a retained old
            # reason re-stored with one).
            reason = safety.redact_secrets(reason[:2000])[0] if isinstance(reason, str) else ""
            rejected = dataclasses.replace(record, revision=record.revision + 1, lifecycle=Lifecycle.REJECTED,
                                           updated_at=now,
                                           reason=reason or safety.redact_secrets(record.reason)[0])
            rejected = self._commit_write(conn, rejected, change="rejected", actor=access.actor, expected=record.revision)
            forgetting = self.ctx.services.forgetting
            if forgetting is not None:
                forgetting.suppress(conn, rejected.content, rejected.sources)
            receipt = self.p.make_receipt(conn, "reject", "ok", record_ids=(rejected.id,), revisions=(rejected.revision,))
            self.p.event(conn, "approval", "rejected")
            shown = self.present(conn, access, [rejected], now)[0]
        return WriteResult(record=shown, receipt=receipt)

    # ------------------------------------------------------------------ correct
    def correct(self, access: AccessContext, record_id: str, correction: Correction, *,
                expected_revision: int | None) -> WriteResult:
        policy.require_author(access)
        scan = gate_scan((correction.content or "", correction.title or "", " ".join(correction.tags or ())),
                         (correction.reason,))
        if scan.secrets:
            raise SensitiveContent("credentials and secrets are not stored in memory",
                                   details={"categories": list(scan.secrets)})
        if scan.sensitive and not correction.allow_sensitive:
            # Same gate as remember(): a correction cannot bring in sensitive personal data unconfirmed.
            raise SensitiveContent("this looks like sensitive personal information; the host must confirm"
                                   " the user explicitly asked to keep it", details={"categories": list(scan.sensitive)})
        now = self.now
        with self.p.db.write() as conn:
            record = self.load_visible(conn, access, record_id)
            _refuse_managed(record)
            self._check_expected(record, expected_revision)
            current = self.effective_lifecycle(record, now)
            target = Lifecycle.APPROVED if current in (Lifecycle.APPROVED, Lifecycle.STALE) else current
            if current not in (Lifecycle.APPROVED, Lifecycle.STALE, Lifecycle.CANDIDATE):
                raise InvalidTransition(f"cannot correct a {current.value} memory")
            correction_source = SourceRef(SourceKind.USER_ACTION, "correct-" + new_id(), actor=access.actor,
                                          observed_at=now)
            cited = self.verify_sources(conn, access, correction.sources)
            content_changed = correction.content is not None and correction.content != record.content
            content = correction.content if correction.content is not None else record.content
            if correction.title is not None:
                title = correction.title
            elif content_changed and record.title == record.content[:60]:
                # Heuristic: remember/propose derived this title from the old content, so keeping
                # it would keep the corrected-away statement visible and searchable.
                title = content[:60]
            else:
                title = record.title
            tags = correction.tags if correction.tags is not None else record.tags
            extra = {**record.extra, "last_corrected_at": now}
            if content_changed:
                # The corrector restates the content in their own words: the new basis
                # (user_stated) is theirs - a user or host (require_author) - not the original
                # proposer's. Forgetting reads this attestation (ForgettingService._attested).
                # An unchanged content keeps both the basis and who attested it.
                extra["basis_attested_by"] = access.actor.value
                if record.links.derived_from or "input_revisions" in extra or "inherited_retention" in extra:
                    # A derived record restated by the user no longer restates its inputs: it stops
                    # following their lifecycle (corrections, expiry, retention).
                    extra["inputs_detached"] = True
                    extra.pop("input_revisions", None)
                    extra.pop("inherited_retention", None)
            if safety.scan(content + "\n" + title + "\n" + " ".join(tags)).injection:
                # Same rule as remember(); an existing flag is kept (it may come from source data).
                flags = extra.get("flags")
                flags = list(flags) if isinstance(flags, (list, tuple)) else []
                extra["flags"] = flags if "instruction_like" in flags else [*flags, "instruction_like"]
            corrected = dataclasses.replace(
                record, revision=record.revision + 1, lifecycle=target, updated_at=now,
                content=content, title=title, tags=tags,
                validity=correction.validity or record.validity,
                retention=correction.retention or record.retention,
                basis=StatementBasis.USER_STATED if content_changed else record.basis,
                confidence=Confidence(None, False, "user_asserted") if content_changed else record.confidence,
                sources=tuple(record.sources) + cited + (correction_source,),
                # A retained reason was stored before every field was scanned: it is not re-stored
                # with a credential in the new revision.
                reason=correction.reason or safety.redact_secrets(record.reason)[0],
                extra=extra,
            )
            # Conflicts are a property of the content: recompute them (a correction can create a
            # contradiction or resolve one; stale links would mislead context assembly).
            conflicts = tuple(self.structured_conflicts(conn, corrected))
            corrected = dataclasses.replace(corrected, links=dataclasses.replace(corrected.links,
                                                                                 conflicts_with=conflicts))
            corrected = self._commit_write(conn, corrected, change="corrected", actor=access.actor, expected=record.revision)
            stale_derived = self._stale_derived(conn, record.id) if content_changed else []
            forgetting = self.ctx.services.forgetting
            if content_changed and forgetting is not None:
                # Do not relearn the corrected-away statement from the same sources.
                forgetting.suppress(conn, record.content, record.sources)
            history = self.ctx.services.history
            if content_changed and history is not None and hasattr(history, "note_correction"):
                # Archived messages/sessions the old content cited are now superseded evidence.
                history.note_correction(conn, record, cited)
            visible = self.records.visible_ids(conn, access.grants, list(conflicts) + stale_derived)
            receipt = self.p.make_receipt(conn, "correct", "ok", record_ids=(corrected.id,),
                                          revisions=(corrected.revision,),
                                          details={"content_changed": content_changed,
                                                   "conflicts": [c for c in conflicts if c in visible],
                                                   "derived_marked_stale": len([d for d in stale_derived
                                                                                if d in visible])})
            self.p.event(conn, "correction", "ok")
            shown = self.present(conn, access, [corrected], now)[0]
        return WriteResult(record=shown, receipt=receipt, conflicts=tuple(c for c in conflicts if c in visible))

    def set_pinned(self, access: AccessContext, record_id: str, pinned: bool, *,
                   expected_revision: int | None) -> WriteResult:
        policy.require_author(access)
        check_bool(pinned, "pinned")  # bool("false") is True: a pinned record never expires
        with self.p.db.write() as conn:
            record = self.load_visible(conn, access, record_id)
            _refuse_managed(record)
            self._check_expected(record, expected_revision)
            current = self.effective_lifecycle(record)
            if current in _TERMINAL:
                raise InvalidTransition(f"cannot pin a {current.value} memory")
            updated = dataclasses.replace(record, revision=record.revision + 1, updated_at=self.now,
                                          retention=dataclasses.replace(record.retention, pinned=pinned))
            updated = self._commit_write(conn, updated, change="pinned" if pinned else "unpinned",
                                         actor=access.actor, expected=record.revision)
            receipt = self.p.make_receipt(conn, "pin", "ok", record_ids=(updated.id,), revisions=(updated.revision,))
            shown = self.present(conn, access, [updated])[0]
        return WriteResult(record=shown, receipt=receipt)

    def supersede(self, access: AccessContext, old_id: str, new_id_: str, *,
                  expected_revision: int | None) -> WriteResult:
        policy.require_reviewer(access, self.ctx.host)
        if old_id == new_id_:
            raise ValidationError("a memory cannot supersede itself")
        now = self.now
        with self.p.db.write() as conn:
            old = self.load_visible(conn, access, old_id)
            new = self.load_visible(conn, access, new_id_)
            _refuse_managed(old)
            _refuse_managed(new)
            self._check_expected(old, expected_revision)
            # Read-time lifecycles, as reject/correct/pin use: a superseding memory that is stale
            # or expired *now* is not current, and an expired candidate is not supersedable (a
            # later revert would otherwise approve it without review).
            if self.effective_lifecycle(new, now) != Lifecycle.APPROVED:
                raise InvalidTransition("the superseding memory must be approved and current")
            if self.ttl_expired(old, now):
                raise InvalidTransition("this candidate has expired")
            check_transition(self.effective_lifecycle(old, now), Lifecycle.SUPERSEDED)
            updated = dataclasses.replace(old, revision=old.revision + 1, lifecycle=Lifecycle.SUPERSEDED,
                                          updated_at=now, links=dataclasses.replace(old.links, superseded_by=new.id))
            updated = self._commit_write(conn, updated, change="superseded", actor=access.actor, expected=old.revision)
            new2 = dataclasses.replace(new, revision=new.revision + 1, updated_at=now,
                                       links=dataclasses.replace(new.links, supersedes=tuple(sorted(set(new.links.supersedes) | {old.id})),
                                                                 conflicts_with=tuple(c for c in new.links.conflicts_with if c != old.id)))
            self._commit_write(conn, new2, change="supersedes", actor=access.actor, expected=new.revision)
            self._stale_derived(conn, old.id, exclude={new.id})
            receipt = self.p.make_receipt(conn, "supersede", "ok", record_ids=(old.id, new.id),
                                          revisions=(updated.revision, new2.revision))
            shown = self.present(conn, access, [updated], now)[0]
        return WriteResult(record=shown, receipt=receipt)

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
    def _maintainable(self, conn: sqlite3.Connection, record_id: str, counts: dict[str, int]) -> MemoryRecord | None:
        """Load for maintenance; a row that fails authentication is skipped (never re-sealed)."""
        try:
            return self.records.get(conn, record_id)
        except (IntegrityError, WrongKey):
            counts["unreadable_skipped"] = counts.get("unreadable_skipped", 0) + 1
            return None

    def expire_due(self, conn: sqlite3.Connection, *, changed: set[str] | None = None) -> dict[str, int]:
        """Persist time-based transitions. One damaged row never blocks the others.

        When an input's retention (or candidate TTL) ends, the records derived from it expire
        too (``derived_expired``); when its validity ends, approved ones go stale and pending ones
        expire (``derived_stale``). ``changed`` (optional) collects the id of every record moved."""
        now = self.now
        counts = {"candidates_expired": 0, "validity_marked_stale": 0, "transient_expired": 0, "derived_expired": 0,
                  "derived_stale": 0}
        touched: set[str] = set()

        def derived(record_id: str) -> None:
            counts["derived_expired"] += len(self._stale_derived(conn, record_id, expired=True, changed_ids=touched))

        for row in conn.execute(
            "SELECT id FROM records WHERE lifecycle='candidate' AND expires_at IS NOT NULL AND expires_at < ?", (now,)
        ).fetchall():
            record = self._maintainable(conn, row[0], counts)
            if record is None or record.lifecycle != Lifecycle.CANDIDATE:
                continue  # (moved by an earlier step of this run, e.g. a derived summary)
            self.transition_internal(conn, record, Lifecycle.EXPIRED, change="expired", reason="candidate_ttl")
            touched.add(record.id)
            counts["candidates_expired"] += 1
            derived(record.id)
        for row in conn.execute(
            "SELECT id FROM records WHERE lifecycle='approved' AND valid_until IS NOT NULL AND valid_until < ?", (now,)
        ).fetchall():
            record = self._maintainable(conn, row[0], counts)
            if record is None or record.lifecycle != Lifecycle.APPROVED:
                continue
            self.transition_internal(conn, record, Lifecycle.STALE, change="stale", reason="validity_ended")
            touched.add(record.id)
            counts["validity_marked_stale"] += 1
            # What was derived from it restated a statement that is no longer valid: approved
            # derivations go stale, pending ones expire (as when an input is corrected).
            counts["derived_stale"] += len(self._stale_derived(conn, record.id, changed_ids=touched))
        for row in conn.execute(
            "SELECT id FROM records WHERE lifecycle IN ('approved','stale') AND expires_at IS NOT NULL"
            " AND expires_at < ? AND pinned=0", (now,)
        ).fetchall():
            record = self._maintainable(conn, row[0], counts)
            if record is None or record.lifecycle not in (Lifecycle.APPROVED, Lifecycle.STALE):
                continue
            if record.retention.policy == "durable":
                continue  # explicit durable memories never expire just from disuse
            self.transition_internal(conn, record, Lifecycle.EXPIRED, change="expired", reason="retention")
            touched.add(record.id)
            counts["transient_expired"] += 1
            derived(record.id)
        if changed is not None:
            changed.update(touched)
        return counts

    # ------------------------------------------------------------------ reads
    def get(self, access: AccessContext, record_id: str) -> MemoryRecord:
        policy.require(access, Operation.READ)
        with self.p.db.read() as conn:
            record = self.load_visible(conn, access, record_id)
            if self._excluded(conn, [record]):
                raise NotFound("memory not found")  # an observation of a now-excluded path
            return self.present(conn, access, [record])[0]

    def _excluded(self, conn: sqlite3.Connection, records: list[MemoryRecord]) -> set[str]:
        repository = self.ctx.services.repository
        if not records or repository is None or not hasattr(repository, "excluded_observations"):
            return set()
        return repository.excluded_observations(conn, records)

    def unservable(self, conn: sqlite3.Connection, records: Any, now: float | None = None) -> dict[str, str]:
        """``{record id: reason}`` for records that must not be served or leave the store *now*.

        The one "servable now" predicate of every read and egress path (external sync, embedding,
        reranking, summarization): ``"excluded"`` - an observation of a path the current
        exclusion set (registration plus host) covers, even if it was ingested before the
        exclusion; ``"expired"`` - expired at read time (candidate TTL or retention passed,
        :meth:`effective_lifecycle`) before maintenance persisted it; ``"unbacked"`` - an approved
        procedure whose evidence episode no longer exists.
        """
        records = [r for r in records if isinstance(r, MemoryRecord)]
        now = self.now if now is None else now
        out = {r.id: "expired" for r in records if self.effective_lifecycle(r, now) == Lifecycle.EXPIRED}
        for record_id in self._excluded(conn, records):
            out[record_id] = "excluded"
        procedures = self.ctx.services.procedures
        if procedures is not None and hasattr(procedures, "unbacked"):
            for record_id in procedures.unbacked(conn, [r for r in records if r.id not in out]):
                out[record_id] = "unbacked"  # an approved procedure whose evidence episode is gone
        return out

    def list(self, access: AccessContext, *, lifecycles: tuple[Lifecycle, ...] | None = (Lifecycle.APPROVED,),
             kinds: tuple[MemoryKind, ...] = (), scope_filter: Scope | None = None,
             limit: int = 100, offset: int = 0) -> list[MemoryRecord]:
        policy.require(access, Operation.READ)
        check_int(limit, "limit", lo=1, hi=1_000_000)
        check_int(offset, "offset", lo=0, hi=2**31)
        grants = policy.narrow(access.grants, scope_filter)
        wanted = None if lifecycles is None else {Lifecycle.parse(lc, "lifecycle") for lc in lifecycles}
        query = wanted
        if wanted is not None and Lifecycle.EXPIRED in wanted:
            # TTL-expired candidates and retention-ended records are expired at read time.
            query = query | {Lifecycle.CANDIDATE, Lifecycle.APPROVED, Lifecycle.STALE}
        if wanted is not None and Lifecycle.STALE in wanted:
            query = query | {Lifecycle.APPROVED}  # validity ended: stale at read time
        now = self.now
        with self.p.db.read() as conn:
            items = self.records.authorized(conn, grants, lifecycles=query, kinds=kinds or None)
            if wanted is not None:
                items = [i for i in items if self.effective_lifecycle(i, now) in wanted]
            hidden = self._excluded(conn, items)
            if hidden:
                items = [i for i in items if i.id not in hidden]
            page = items[offset: offset + min(limit, 1000)]
            return self.present(conn, access, page, now)

    def _servable_ids(self, conn: sqlite3.Connection, access: AccessContext, ids: list[str]) -> list[str]:
        """``ids`` (order kept) the caller may see and that are not observations of now-excluded
        paths (the read rule of get/list)."""
        unique = list(dict.fromkeys(ids))
        found: list[MemoryRecord] = []
        for start in range(0, len(unique), 500):
            found += self.records.authorized(conn, access.grants, lifecycles=None, ids=unique[start:start + 500])
        hidden = self._excluded(conn, found)
        allowed = {r.id for r in found if r.id not in hidden}
        return [i for i in ids if i in allowed]

    def _lifecycle_note(self, record: MemoryRecord) -> str:
        now = self.now
        if self.ttl_expired(record, now):
            return "expired at read time (candidate TTL passed)"
        effective = self.effective_lifecycle(record, now)
        if effective == Lifecycle.EXPIRED and effective != record.lifecycle:
            return "expired at read time (retention period ended)"
        if effective == Lifecycle.STALE and effective != record.lifecycle:
            return "stale at read time (validity ended)"
        return ""

    def explain(self, access: AccessContext, record_id: str) -> dict[str, Any]:
        policy.require(access, Operation.READ)
        with self.p.db.read() as conn:
            stored = self.load_visible(conn, access, record_id)
            if self._excluded(conn, [stored]):
                raise NotFound("memory not found")  # same answer as get(): a now-excluded path
            record = self.present(conn, access, [stored])[0]
            revisions = self.records.revisions(conn, record_id)
            visible_links: dict[str, Any] = {}
            for name in ("supersedes", "conflicts_with", "derived_from"):
                ids = getattr(stored.links, name)
                shown = list(getattr(record.links, name))
                visible_links[name] = shown
                hidden = len(ids) - len(shown)
                if hidden:
                    visible_links[name + "_unavailable"] = hidden  # deleted or out of scope; count only
            if stored.links.superseded_by:
                visible_links["superseded_by"] = record.links.superseded_by
                if record.links.superseded_by is None:
                    visible_links["superseded_by_unavailable"] = 1
            hidden_sources = len(stored.sources) - len(record.sources)
            structured = self._servable_ids(conn, access, self.structured_conflicts(conn, record))
            derived = self._servable_ids(conn, access,
                                         self.records.ids_derived_from(conn, self.p.token("memory", record.id)))
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
            **({"sources_unavailable": hidden_sources} if hidden_sources else {}),
            "lifecycle_note": self._lifecycle_note(stored),
        }
