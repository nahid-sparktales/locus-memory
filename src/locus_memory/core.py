"""Canonical memory lifecycle: remember, propose, review, correct, supersede, expire.

Transitions (anything else raises InvalidTransition):

    candidate  -> approved | rejected | expired | superseded
    approved   -> approved (correction) | stale | superseded | expired
    stale      -> approved (re-confirm/correct) | superseded | expired
    superseded -> approved (explicit revert by a reviewer)
    rejected, expired -> (terminal; only forgetting removes them)

Forgetting is not a transition on a live row: it purges the row and records a
tombstone (see forgetting.py).

Read-time expiry: a candidate whose TTL has passed is *presented* as ``expired``
by get/list/explain and cannot be approved, rejected or corrected, even before
``expire_due`` persists the transition. Nothing silently becomes approved.

Read results (get/list/explain) are presentations for the caller: link ids and
memory-evidence ids that point at records outside the caller's grants are removed
(explain reports how many as ``*_unavailable`` counts). Never write a presented
record back; sibling services load records with ``RecordStore.get`` inside their
write transaction and use ``write_internal``.
"""
from __future__ import annotations

import dataclasses
import re
import sqlite3
from typing import Any

from . import policy, safety
from .errors import (
    IntegrityError,
    InvalidTransition,
    NotFound,
    RevisionConflict,
    SensitiveContent,
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
)
from .services import PartitionContext
from .storage.partition import new_id
from .validation import check_id, check_int, normalize_for_fingerprint

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
_TERMINAL = frozenset({Lifecycle.REJECTED, Lifecycle.EXPIRED, Lifecycle.FORGOTTEN})

__all__ = ["ALLOWED", "CoreService", "SuppressedError", "check_transition"]  # SuppressedError: compat


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

    @staticmethod
    def ttl_expired(record: MemoryRecord, now: float) -> bool:
        return (record.lifecycle == Lifecycle.CANDIDATE and record.retention.expires_at is not None
                and record.retention.expires_at < now)

    def effective_lifecycle(self, record: MemoryRecord, now: float | None = None) -> Lifecycle:
        return Lifecycle.EXPIRED if self.ttl_expired(record, self.now if now is None else now) else record.lifecycle

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
        out = []
        for record in records:
            links = record.links
            shown = Links(
                supersedes=tuple(i for i in links.supersedes if i in visible),
                superseded_by=links.superseded_by if links.superseded_by in visible else None,
                conflicts_with=tuple(i for i in links.conflicts_with if i in visible),
                derived_from=tuple(i for i in links.derived_from if i in visible),
            )
            sources = tuple(s for s in record.sources if s.kind != SourceKind.MEMORY or s.ref in visible)
            changes: dict[str, Any] = {}
            if shown != links:
                changes["links"] = shown
            if sources != record.sources:
                changes["sources"] = sources
            if self.ttl_expired(record, now):
                changes["lifecycle"] = Lifecycle.EXPIRED
            out.append(dataclasses.replace(record, **changes) if changes else record)
        return out

    def _commit_write(self, conn: sqlite3.Connection, record: MemoryRecord, *, change: str,
                      actor: Actor, expected: int | None) -> MemoryRecord:
        generation = self.p.bump(conn)
        return self.records.write(conn, record, change=change, actor=actor,
                                  expected_revision=expected, generation=generation)

    def _check_expected(self, record: MemoryRecord, expected_revision: int | None) -> None:
        if expected_revision is not None and record.revision != expected_revision:
            raise RevisionConflict("the memory changed since it was read",
                                   details={"expected_revision": expected_revision,
                                            "current_revision": record.revision})

    def _replay(self, conn: sqlite3.Connection, access: AccessContext, key: str | None, operation: str,
                request: Any) -> WriteResult | None:
        receipt_raw = self.p.idempotency_lookup(conn, key, operation, request)
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
        scan = safety.scan(request.content + "\n" + request.title + "\n" + " ".join(request.tags))
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
            shown = self.present(conn, access, [record], now)[0]
        return WriteResult(record=shown, receipt=receipt, conflicts=tuple(conflicts))

    # ------------------------------------------------------------------ propose
    def propose(self, access: AccessContext, proposal: CandidateProposal, *,
                idempotency_key: str | None = None) -> WriteResult:
        policy.require(access, Operation.PROPOSE)
        policy.require_scope(access, proposal.scope)
        scan = safety.scan(proposal.content + "\n" + proposal.title + "\n" + " ".join(proposal.tags))
        if scan.secrets:
            raise SensitiveContent("candidate contains credential-like content", details={"categories": list(scan.secrets)})
        if scan.sensitive and proposal.basis != StatementBasis.USER_STATED:
            raise SensitiveContent("sensitive personal information is never inferred into memory",
                                   details={"categories": list(scan.sensitive)})
        now = self.now
        with self.p.db.write() as conn:
            replay = self._replay(conn, access, idempotency_key, "propose", proposal)
            if replay is not None:
                return replay
            self.verify_sources(conn, access, proposal.sources, derived_from=proposal.derived_from)
            confidence = proposal.confidence
            if confidence.value is not None and confidence.calibrated and access.actor not in _CALIBRATION_ATTESTERS:
                # A proposer cannot attest its own calibration; keep the value, drop the claim.
                confidence = Confidence(confidence.value, False, "model_uncalibrated")
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
                self.p.idempotency_store(conn, idempotency_key, "propose", proposal, receipt)
                return WriteResult(record=self.present(conn, access, [existing], now)[0], receipt=receipt)
            conflicts = self.structured_conflicts(conn, record)
            record = dataclasses.replace(record, links=dataclasses.replace(record.links, conflicts_with=tuple(conflicts)))
            record = self._commit_write(conn, record, change="proposed", actor=access.actor, expected=None)
            receipt = self.p.make_receipt(conn, "propose", "ok", record_ids=(record.id,),
                                          revisions=(record.revision,),
                                          details={"conflicts": conflicts, "expires_at": record.retention.expires_at})
            self.p.idempotency_store(conn, idempotency_key, "propose", proposal, receipt)
            self.p.event(conn, "proposal", "accepted")
            shown = self.present(conn, access, [record], now)[0]
        return WriteResult(record=shown, receipt=receipt, conflicts=tuple(conflicts))

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
            if self.ttl_expired(record, now):
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
            shown = self.present(conn, access, [approved], now)[0]
        return WriteResult(record=shown, receipt=receipt, conflicts=remaining)

    def reject(self, access: AccessContext, record_id: str, *, expected_revision: int | None,
               reason: str = "") -> WriteResult:
        policy.require_reviewer(access, self.ctx.host)
        now = self.now
        with self.p.db.write() as conn:
            record = self.load_visible(conn, access, record_id)
            self._check_expected(record, expected_revision)
            check_transition(self.effective_lifecycle(record, now), Lifecycle.REJECTED)
            rejected = dataclasses.replace(record, revision=record.revision + 1, lifecycle=Lifecycle.REJECTED,
                                           updated_at=now, reason=reason[:2000] or record.reason)
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
        scan = safety.scan((correction.content or "") + "\n" + (correction.title or "")
                           + "\n" + " ".join(correction.tags or ()))
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
            self._check_expected(record, expected_revision)
            current = self.effective_lifecycle(record, now)
            target = Lifecycle.APPROVED if current in (Lifecycle.APPROVED, Lifecycle.STALE) else current
            if current not in (Lifecycle.APPROVED, Lifecycle.STALE, Lifecycle.CANDIDATE):
                raise InvalidTransition(f"cannot correct a {current.value} memory")
            correction_source = SourceRef(SourceKind.USER_ACTION, "correct-" + new_id(), actor=access.actor,
                                          observed_at=now)
            self.verify_sources(conn, access, correction.sources)
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
                sources=tuple(record.sources) + tuple(correction.sources) + (correction_source,),
                reason=correction.reason or record.reason,
                extra=extra,
            )
            corrected = self._commit_write(conn, corrected, change="corrected", actor=access.actor, expected=record.revision)
            forgetting = self.ctx.services.forgetting
            if content_changed and forgetting is not None:
                # Do not relearn the corrected-away statement from the same sources.
                forgetting.suppress(conn, record.content, record.sources)
            history = self.ctx.services.history
            if content_changed and history is not None and hasattr(history, "note_correction"):
                # Archived messages/sessions the old content cited are now superseded evidence.
                history.note_correction(conn, record, correction.sources)
            receipt = self.p.make_receipt(conn, "correct", "ok", record_ids=(corrected.id,),
                                          revisions=(corrected.revision,),
                                          details={"content_changed": content_changed})
            self.p.event(conn, "correction", "ok")
            shown = self.present(conn, access, [corrected], now)[0]
        return WriteResult(record=shown, receipt=receipt)

    def set_pinned(self, access: AccessContext, record_id: str, pinned: bool, *,
                   expected_revision: int | None) -> WriteResult:
        policy.require_author(access)
        with self.p.db.write() as conn:
            record = self.load_visible(conn, access, record_id)
            self._check_expected(record, expected_revision)
            current = self.effective_lifecycle(record)
            if current in _TERMINAL:
                raise InvalidTransition(f"cannot pin a {current.value} memory")
            updated = dataclasses.replace(record, revision=record.revision + 1, updated_at=self.now,
                                          retention=dataclasses.replace(record.retention, pinned=bool(pinned)))
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

    def expire_due(self, conn: sqlite3.Connection) -> dict[str, int]:
        """Persist time-based transitions. One damaged row never blocks the others."""
        now = self.now
        counts = {"candidates_expired": 0, "validity_marked_stale": 0, "transient_expired": 0}
        for row in conn.execute(
            "SELECT id FROM records WHERE lifecycle='candidate' AND expires_at IS NOT NULL AND expires_at < ?", (now,)
        ).fetchall():
            record = self._maintainable(conn, row[0], counts)
            if record is None:
                continue
            self.transition_internal(conn, record, Lifecycle.EXPIRED, change="expired", reason="candidate_ttl")
            counts["candidates_expired"] += 1
        for row in conn.execute(
            "SELECT id FROM records WHERE lifecycle='approved' AND valid_until IS NOT NULL AND valid_until < ?", (now,)
        ).fetchall():
            record = self._maintainable(conn, row[0], counts)
            if record is None:
                continue
            self.transition_internal(conn, record, Lifecycle.STALE, change="stale", reason="validity_ended")
            counts["validity_marked_stale"] += 1
        for row in conn.execute(
            "SELECT id FROM records WHERE lifecycle IN ('approved','stale') AND expires_at IS NOT NULL"
            " AND expires_at < ? AND pinned=0", (now,)
        ).fetchall():
            record = self._maintainable(conn, row[0], counts)
            if record is None:
                continue
            if record.retention.policy == "durable":
                continue  # explicit durable memories never expire just from disuse
            self.transition_internal(conn, record, Lifecycle.EXPIRED, change="expired", reason="retention")
            counts["transient_expired"] += 1
        return counts

    # ------------------------------------------------------------------ reads
    def get(self, access: AccessContext, record_id: str) -> MemoryRecord:
        policy.require(access, Operation.READ)
        with self.p.db.read() as conn:
            return self.present(conn, access, [self.load_visible(conn, access, record_id)])[0]

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
            query = wanted | {Lifecycle.CANDIDATE}  # TTL-expired candidates are expired at read time
        now = self.now
        with self.p.db.read() as conn:
            items = self.records.authorized(conn, grants, lifecycles=query, kinds=kinds or None)
            if wanted is not None:
                items = [i for i in items if self.effective_lifecycle(i, now) in wanted]
            page = items[offset: offset + min(limit, 1000)]
            return self.present(conn, access, page, now)

    def explain(self, access: AccessContext, record_id: str) -> dict[str, Any]:
        policy.require(access, Operation.READ)
        with self.p.db.read() as conn:
            stored = self.load_visible(conn, access, record_id)
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
            **({"sources_unavailable": hidden_sources} if hidden_sources else {}),
            "lifecycle_note": "expired at read time (candidate TTL passed)" if self.ttl_expired(stored, self.now) else "",
        }
