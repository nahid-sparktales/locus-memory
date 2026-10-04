"""Task episodes: factual, encrypted logs of agent work whose outcome is derived, not claimed.

An agent (or host) reports what it attempted; the engine decides the outcome:

* ``verified_success`` only when the host's :class:`~locus_memory.host.VerificationAuthority`
  resolves *every* referenced receipt as trusted, every result that names a task
  names this task, at least one required check exists and all required checks passed.
* ``failure`` when a trusted, task-matching receipt reports a failed required check.
* Claimed ``failure`` / ``partial`` / ``cancelled`` / ``interrupted`` are recorded as
  reported - admitting a negative outcome needs no verification.
* Anything else (including "done!" without trusted receipts) is ``unknown``.

Each logical episode is one ``MemoryRecord(kind=episode, lifecycle=approved)``. A
resumed attempt that reuses the ``episode_id`` adds a revision and an attempt; the
episode's outcome is the outcome of its most recently recorded attempt, so retries
never become a second independent success.

Index rows (``episodes``, ``episode_attempts``, ``episode_sources``) carry only ids,
outcomes, timestamps and keyed tokens. Everything the report said lives inside the
record ciphertext.
"""
from __future__ import annotations

import dataclasses
import hashlib
import sqlite3
import unicodedata
from collections.abc import Iterable
from typing import Any

from .. import policy, safety
from ..errors import (
    AccessDenied,
    IdempotencyConflict,
    MemoryEngineError,
    SuppressedError,
    ValidationError,
)
from ..models import (
    AccessContext,
    Actor,
    CandidateProposal,
    Confidence,
    Episode,
    EpisodeOutcome,
    EpisodeReport,
    Lifecycle,
    Links,
    MemoryKind,
    MemoryRecord,
    Operation,
    Receipt,
    Retention,
    Scope,
    SourceKind,
    SourceRef,
    StatementBasis,
    Validity,
    VerificationRef,
    VerificationResult,
    VerifiedCheck,
)
from ..services import PartitionContext
from ..storage.partition import new_id
from ..validation import MAX_CONTENT_CHARS, check_id, check_int, check_ref
from ._common import authorized_by_ids

MAX_RECEIPTS_PER_REPORT = 64
MAX_ATTEMPTS_PER_EPISODE = 256
MAX_LESSONS_PER_REPORT = 32
MAX_PATH_CHARS_TOTAL = 64_000
_NEGATIVE = frozenset({EpisodeOutcome.FAILURE, EpisodeOutcome.PARTIAL, EpisodeOutcome.CANCELLED,
                       EpisodeOutcome.INTERRUPTED})
_LIMITATIONS = (
    "the outcome is derived from host verification receipts, never from the agent's claim",
    "narrative fields (objective, approach, failure modes, lessons) are agent-reported data",
    "proposed lessons are unapproved candidates until a reviewer approves them",
)


# --------------------------------------------------------------------------- pure helpers
def attempt_source_ref(task_ref: str, attempt_ref: str) -> str:
    """Canonical, unambiguous TASK_ATTEMPT source ref for (task_ref, attempt_ref)."""
    check_ref(task_ref, "task_ref")
    check_ref(attempt_ref, "attempt_ref")
    digest = hashlib.sha256(f"{task_ref}\x00{attempt_ref}".encode()).hexdigest()
    return "attempt-" + digest[:48]


def _result_dict(receipt_id: str, result: VerificationResult | None, *, error: str = "") -> dict[str, Any]:
    if result is None:
        return {"receipt_id": receipt_id, "trusted": False, "resolved": False, "checks": [],
                "issued_at": None, "task_ref": None, "error": error}
    return {
        "receipt_id": receipt_id, "trusted": result.trusted is True, "resolved": True,
        "checks": [{"name": c.name, "passed": c.passed is True, "required": c.required is not False,
                    "detail": c.detail} for c in result.checks],
        "issued_at": result.issued_at, "task_ref": result.task_ref, "error": "",
    }


def _result_from_dict(raw: dict[str, Any]) -> VerificationResult:
    return VerificationResult(
        receipt_id=raw["receipt_id"], trusted=bool(raw.get("trusted")),
        checks=tuple(VerifiedCheck(c["name"], bool(c["passed"]), bool(c.get("required", True)),
                                   c.get("detail") or "") for c in raw.get("checks") or ()),
        issued_at=raw.get("issued_at"), task_ref=raw.get("task_ref"),
    )


def derive_outcome(claimed: EpisodeOutcome, task_ref: str, results: list[dict[str, Any]], *,
                   authority_available: bool = True, forgotten_receipts: int = 0
                   ) -> tuple[EpisodeOutcome, str, bool]:
    """Return (outcome, outcome_basis, receipt_backed). Pure and deterministic."""
    trusted = [r for r in results if r.get("trusted") is True]
    matching = [r for r in trusted if r.get("task_ref") in (None, task_ref)]
    failed = sorted({c["name"] for r in matching for c in r["checks"] if c["required"] and not c["passed"]})
    if failed:
        return (EpisodeOutcome.FAILURE,
                f"host receipts report {len(failed)} failed required check(s)", True)
    if claimed in _NEGATIVE:
        return (claimed, f"reported {claimed.value} by the agent; a negative outcome needs no"
                         " verification", False)
    prefix = ("claimed success without host verification" if claimed == EpisodeOutcome.VERIFIED_SUCCESS
              else "outcome not established by host verification")
    total = len(results) + forgotten_receipts
    if total == 0:
        return EpisodeOutcome.UNKNOWN, f"{prefix}: no verification receipts were referenced", False
    if forgotten_receipts:
        return EpisodeOutcome.UNKNOWN, f"{prefix}: {forgotten_receipts} receipt(s) were forgotten", False
    if not authority_available:
        return EpisodeOutcome.UNKNOWN, f"{prefix}: no verification authority is configured", False
    unconfirmed = len(results) - len(trusted)
    if unconfirmed:
        return (EpisodeOutcome.UNKNOWN,
                f"{prefix}: {unconfirmed} of {len(results)} receipt(s) could not be confirmed as trusted",
                False)
    mismatched = len(trusted) - len(matching)
    if mismatched:
        return (EpisodeOutcome.UNKNOWN,
                f"{prefix}: {mismatched} receipt(s) belong to a different task", False)
    required = [c for r in matching for c in r["checks"] if c["required"]]
    if not required:
        return EpisodeOutcome.UNKNOWN, f"{prefix}: host receipts contain no required checks", False
    return (EpisodeOutcome.VERIFIED_SUCCESS,
            f"host receipts: {len(required)}/{len(required)} required checks passed across"
            f" {len(results)} receipt(s)", True)


def _has_control(text: str) -> bool:
    return any(unicodedata.category(ch).startswith("C") for ch in text)


class _Cleaner:
    """Redacts secrets and neutralizes prompt-wrapper markup in untrusted report text."""

    def __init__(self) -> None:
        self.redactions: set[str] = set()

    def text(self, value: str) -> str:
        redacted, found = safety.redact_secrets(value)
        self.redactions.update(found)
        return safety.neutralize_markup(redacted)

    def many(self, values: Iterable[str]) -> list[str]:
        return [self.text(v) for v in values]

    def mapping(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {k: self.mapping(item) for k, item in value.items()}
        if isinstance(value, list):
            return [self.mapping(item) for item in value]
        return value


def _merge(existing: list[str], new: list[str], cap: int = 256) -> list[str]:
    out = list(existing)
    seen = set(out)
    for item in new:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out[:cap]


# --------------------------------------------------------------------------- service
class EpisodeService:
    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx
        self.p = ctx.partition
        self.records = ctx.records

    # ------------------------------------------------------------------ tokens
    def task_token(self, task_ref: str) -> str:
        return self.p.token("episode-task", task_ref)

    def attempt_token(self, task_ref: str, attempt_ref: str) -> str:
        return self.records.source_token(f"{SourceKind.TASK_ATTEMPT.value}:{attempt_source_ref(task_ref, attempt_ref)}")

    def receipt_token(self, receipt_id: str) -> str:
        return self.records.source_token(f"{SourceKind.VERIFICATION_RECEIPT.value}:{receipt_id}")

    @staticmethod
    def attempt_source(task_ref: str, attempt_ref: str) -> SourceRef:
        """The SourceRef a host can cite as TASK_ATTEMPT evidence for a recorded attempt."""
        return SourceRef(SourceKind.TASK_ATTEMPT, attempt_source_ref(task_ref, attempt_ref),
                         actor=Actor.HOST, locator={"task_ref": task_ref, "attempt_ref": attempt_ref})

    # ------------------------------------------------------------------ validation
    def _check_report(self, report: EpisodeReport) -> None:
        if not isinstance(report, EpisodeReport) or not isinstance(report.scope, Scope):
            raise ValidationError("an EpisodeReport with a Scope is required")
        if not all(isinstance(ref, VerificationRef) for ref in report.verification):
            raise ValidationError("verification entries must be VerificationRef objects")
        if len(report.verification) > MAX_RECEIPTS_PER_REPORT:
            raise ValidationError(f"at most {MAX_RECEIPTS_PER_REPORT} verification receipts per report")
        if len(report.proposed_lessons) > MAX_LESSONS_PER_REPORT:
            raise ValidationError(f"at most {MAX_LESSONS_PER_REPORT} proposed lessons per report")
        if sum(len(p) for p in report.affected_paths) > MAX_PATH_CHARS_TOTAL:
            raise ValidationError("affected paths are too large")
        for path in report.affected_paths:
            if _has_control(path):
                raise ValidationError("affected paths contain control characters")
        for name in ("run_ref", "repository_snapshot"):
            value = getattr(report, name)
            if value is not None:
                check_ref(value, name)
        # Identifiers cannot be redacted, so a credential-shaped identifier is refused outright.
        for value in (report.task_ref, report.attempt_ref, report.run_ref or "",
                      *(ref.receipt_id for ref in report.verification)):
            if safety.scan(value).secrets:
                raise ValidationError("an identifier in the report looks like a credential")

    @staticmethod
    def _require_report_permission(access: AccessContext) -> None:
        if Operation.WRITE not in access.operations and Operation.INGEST not in access.operations:
            raise AccessDenied("recording an episode requires the write or ingest operation")

    # ------------------------------------------------------------------ verification
    def _resolve(self, report: EpisodeReport) -> tuple[list[dict[str, Any]], bool]:
        """Resolve receipt ids with the host authority (outside any transaction)."""
        authority = self.ctx.host.verification
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for ref in report.verification:
            if ref.receipt_id in seen:
                continue
            seen.add(ref.receipt_id)
            if authority is None:
                out.append(_result_dict(ref.receipt_id, None, error="no_authority"))
                continue
            try:
                result = authority.resolve(ref.receipt_id)
            except Exception as exc:  # the authority is host code; never trust a crash as success
                out.append(_result_dict(ref.receipt_id, None, error=type(exc).__name__[:64]))
                continue
            if result is None:
                out.append(_result_dict(ref.receipt_id, None, error="unknown_receipt"))
            elif (not isinstance(result, VerificationResult) or result.receipt_id != ref.receipt_id
                  or not isinstance(result.checks, tuple)
                  or not all(isinstance(c, VerifiedCheck) and isinstance(c.name, str)
                             and isinstance(c.passed, bool) for c in result.checks)):
                out.append(_result_dict(ref.receipt_id, None, error="malformed_result"))
            else:
                entry = _result_dict(ref.receipt_id, result)
                for check in entry["checks"]:
                    check["name"] = str(check["name"])[:200]
                    check["detail"] = safety.redact_secrets(str(check["detail"] or ""))[0][:500]
                out.append(entry)
        return out, authority is not None

    # ------------------------------------------------------------------ record
    def record(self, access: AccessContext, report: EpisodeReport) -> tuple[Episode, Receipt]:
        self._require_report_permission(access)
        self._check_report(report)
        policy.require_scope(access, report.scope)
        results, authority_available = self._resolve(report)
        now = self.ctx.clock()
        cleaner = _Cleaner()
        fields = {
            "objective": cleaner.text(report.objective),
            "approach": cleaner.text(report.approach),
            "affected_paths": cleaner.many(report.affected_paths),
            "failure_modes": cleaner.many(report.failure_modes),
            "uncertainties": cleaner.many(report.uncertainties),
            "proposed_lessons": cleaner.many(report.proposed_lessons),
            "context_receipts": cleaner.many(report.context_receipts),
            "environment": cleaner.mapping(report.environment),
            "usage": cleaner.mapping(report.usage),
        }
        outcome, basis_text, receipt_backed = derive_outcome(
            report.claimed_outcome, report.task_ref, results, authority_available=authority_available)
        attempt = {
            "attempt_ref": report.attempt_ref,
            "source_ref": attempt_source_ref(report.task_ref, report.attempt_ref),
            "claimed_outcome": report.claimed_outcome.value, "verification": results,
            "authority_available": authority_available, "forgotten_receipts": 0,
            "outcome": outcome.value, "outcome_basis": basis_text, "receipt_backed": receipt_backed,
            "recorded_at": now, "run_ref": report.run_ref, "started_at": report.started_at,
            "ended_at": report.ended_at, "usage": fields["usage"], "reported_by": access.actor.value,
        }
        scan = safety.scan("\n".join([fields["objective"], fields["approach"], *fields["failure_modes"],
                                      *fields["uncertainties"], *fields["proposed_lessons"]]))
        flags = ["instruction_like"] if scan.injection else []
        flags += [f"sensitive:{name}" for name in scan.sensitive]
        new_lessons: list[str] = []
        with self.p.db.write() as conn:
            attempt_token = self.attempt_token(report.task_ref, report.attempt_ref)
            dup = conn.execute(
                "SELECT episode_id FROM episode_attempts WHERE attempt_token=? AND episode_id<>? LIMIT 1",
                (attempt_token, report.episode_id),
            ).fetchone()
            if dup is not None:
                raise IdempotencyConflict("this task attempt is already recorded under a different episode")
            row = conn.execute("SELECT * FROM episodes WHERE episode_id=?", (report.episode_id,)).fetchone()
            existing = self.records.get(conn, row["record_id"]) if row is not None else None
            if row is not None and existing is None:
                self._drop_index(conn, report.episode_id)  # orphaned index row (record already purged)
                row = None
            if existing is not None:
                if not policy.visible(access, existing) or existing.kind != MemoryKind.EPISODE:
                    raise IdempotencyConflict("this episode id is already in use")
                state = dict(existing.extra.get("episode") or {})
                if state.get("task_ref") != report.task_ref:
                    raise IdempotencyConflict("this episode id belongs to a different task")
                if existing.scope != report.scope:
                    raise ValidationError("a resumed attempt must keep the episode's scope")
                attempts = [a for a in state.get("attempts", []) if a["attempt_ref"] != report.attempt_ref]
                if len(attempts) >= MAX_ATTEMPTS_PER_EPISODE:
                    raise ValidationError(f"an episode holds at most {MAX_ATTEMPTS_PER_EPISODE} attempts")
                attempts.append(attempt)
                new_lessons = [x for x in fields["proposed_lessons"] if x not in state.get("proposed_lessons", [])]
                state.update({
                    "objective": fields["objective"],
                    "approach": fields["approach"] or state.get("approach", ""),
                    "affected_paths": _merge(state.get("affected_paths", []), fields["affected_paths"]),
                    "failure_modes": _merge(state.get("failure_modes", []), fields["failure_modes"]),
                    "uncertainties": _merge(state.get("uncertainties", []), fields["uncertainties"]),
                    "proposed_lessons": _merge(state.get("proposed_lessons", []), fields["proposed_lessons"]),
                    "context_receipts": _merge(state.get("context_receipts", []), fields["context_receipts"]),
                    "environment": fields["environment"] or state.get("environment", {}),
                    "usage": fields["usage"] or state.get("usage", {}),
                    "repository_snapshot": report.repository_snapshot or state.get("repository_snapshot"),
                    "attempts": attempts,
                })
            else:
                new_lessons = list(fields["proposed_lessons"])
                state = {
                    "episode_id": report.episode_id, "task_ref": report.task_ref,
                    "repository_snapshot": report.repository_snapshot, "attempts": [attempt],
                    "lesson_candidates": [], **fields,
                }
            redactions = sorted(set(existing.extra.get("redactions", []) if existing else ()) | cleaner.redactions)
            prior_flags = list(existing.extra.get("flags", [])) if existing else []
            record = self._build_record(existing, state, report.scope, now,
                                        flags=sorted(set(prior_flags) | set(flags)), redactions=redactions,
                                        event_time=report.ended_at or report.started_at)
            forgetting = self.ctx.services.forgetting
            blocked = forgetting.blocked_reason(conn, record) if forgetting is not None else None
            if blocked:
                self.p.event(conn, "episode", "suppressed", "forgotten_evidence")
                raise SuppressedError(f"episode refused: {blocked}")
            self._write(conn, record, existing, access.actor)
            was_verified = existing is not None and \
                existing.extra["episode"].get("outcome") == EpisodeOutcome.VERIFIED_SUCCESS.value
            procedures = self.ctx.services.procedures
            if was_verified and state["outcome"] != EpisodeOutcome.VERIFIED_SUCCESS.value and \
                    procedures is not None and hasattr(procedures, "revoke_evidence"):
                # The logical episode is no longer a verified success: re-assess dependent procedures.
                procedures.revoke_evidence(conn, [report.episode_id], report_to=access)
            self.p.event(conn, "episode", "recorded", record.extra["episode"]["outcome"])
        lesson_ids, lessons_skipped = self._propose_lessons(access, record, new_lessons)
        episode = self._to_episode(record)
        with self.p.db.write() as conn:
            if lesson_ids:
                current = self.records.get(conn, record.id)
                if current is not None:  # remember lesson ids (for explain); no content change
                    state = dict(current.extra["episode"])
                    state["lesson_candidates"] = _merge(state.get("lesson_candidates", []), lesson_ids)
                    updated = dataclasses.replace(current, revision=current.revision + 1,
                                                  extra={**current.extra, "episode": state})
                    record = self.ctx.services.core.write_internal(
                        conn, updated, change="lessons_linked", actor=Actor.SYSTEM, expected=current.revision)
                    episode = self._to_episode(record)
            receipt = self.p.make_receipt(
                conn, "record_episode", "ok", record_ids=(record.id, *lesson_ids), revisions=(record.revision,),
                details={"episode_id": episode.episode_id, "outcome": episode.outcome.value,
                         "claimed_outcome": report.claimed_outcome.value,
                         "outcome_basis": episode.outcome_basis, "resumed": existing is not None,
                         "attempts": len(episode.attempts), "lesson_candidates": lesson_ids,
                         "lessons_skipped": lessons_skipped, "redactions": redactions, "flags": flags},
                limitations=_LIMITATIONS,
            )
        return episode, receipt

    def _build_record(self, existing: MemoryRecord | None, state: dict[str, Any], scope: Scope, now: float,
                      *, flags: list[str], redactions: list[str], event_time: float | None) -> MemoryRecord:
        latest = state["attempts"][-1]
        state["outcome"] = latest["outcome"]
        state["claimed_outcome"] = latest["claimed_outcome"]
        state["outcome_basis"] = latest["outcome_basis"]
        state["receipt_backed"] = bool(latest["receipt_backed"])
        basis = StatementBasis.OBSERVED if state["receipt_backed"] else StatementBasis.SOURCE_ATTRIBUTED
        sources = [SourceRef(SourceKind.TASK_ATTEMPT, a["source_ref"], actor=Actor.HOST,
                             locator={"task_ref": state["task_ref"], "attempt_ref": a["attempt_ref"]},
                             observed_at=a["recorded_at"]) for a in state["attempts"]]
        # Every referenced receipt is cited (trusted or not): forgetting authorizes a source purge
        # against the records that cite it, so anything purge() acts on must be a cited source.
        receipts: dict[str, bool] = {}
        for a in state["attempts"]:
            for r in a["verification"]:
                receipts[r["receipt_id"]] = receipts.get(r["receipt_id"], False) or bool(r["trusted"])
        sources += [SourceRef(SourceKind.VERIFICATION_RECEIPT, rid, actor=Actor.HOST, locator={"trusted": trusted})
                    for rid, trusted in receipts.items()]
        field_basis = {
            "outcome": basis.value, "verification": StatementBasis.OBSERVED.value,
            "objective": StatementBasis.SOURCE_ATTRIBUTED.value, "approach": StatementBasis.SOURCE_ATTRIBUTED.value,
            "failure_modes": StatementBasis.SOURCE_ATTRIBUTED.value,
            "proposed_lessons": StatementBasis.SOURCE_ATTRIBUTED.value,
        }
        title = f"Episode ({state['outcome']}): {state['objective']}"[:160]
        content = self._render(state)
        extra = {"episode": state, "field_basis": field_basis, "flags": flags, "redactions": redactions}
        if existing is None:
            return MemoryRecord(
                id=new_id("m"), revision=1, kind=MemoryKind.EPISODE, lifecycle=Lifecycle.APPROVED, scope=scope,
                title=title, content=content, tags=("episode", f"outcome-{state['outcome']}"), basis=basis,
                confidence=Confidence.unknown(), sources=tuple(sources), validity=Validity(),
                retention=Retention("durable", None, False), links=Links(), created_at=now, updated_at=now,
                event_time=event_time or now, ingested_at=now, reason="episode report", extra=extra,
            )
        return dataclasses.replace(
            existing, revision=existing.revision + 1, title=title, content=content,
            tags=("episode", f"outcome-{state['outcome']}"), basis=basis, sources=tuple(sources),
            updated_at=now, event_time=event_time or existing.event_time, extra={**existing.extra, **extra},
        )

    @staticmethod
    def _render(state: dict[str, Any]) -> str:
        lines = [f"Episode: {state['objective']}",
                 f"Outcome: {state['outcome']} ({state['outcome_basis']})",
                 f"Attempts: {len(state['attempts'])}"]
        if state.get("approach"):
            lines.append(f"Approach (agent-reported): {state['approach']}")
        for label, key in (("Failure modes", "failure_modes"), ("Uncertainties", "uncertainties"),
                           ("Proposed lessons (unapproved)", "proposed_lessons")):
            if state.get(key):
                lines.append(f"{label}: " + "; ".join(state[key]))
        paths = state.get("affected_paths") or []
        if paths:
            more = f" (+{len(paths) - 20} more)" if len(paths) > 20 else ""
            lines.append("Affected paths: " + ", ".join(paths[:20]) + more)
        text = "\n".join(lines)
        return text if len(text) <= MAX_CONTENT_CHARS else text[: MAX_CONTENT_CHARS - 1] + "…"

    def _write(self, conn: sqlite3.Connection, record: MemoryRecord, existing: MemoryRecord | None,
               actor: Actor) -> MemoryRecord:
        core = self.ctx.services.core
        record = core.write_internal(conn, record, change="episode_resumed" if existing else "episode_recorded",
                                     actor=actor, expected=existing.revision if existing else None)
        self._index(conn, record)
        return record

    def _index(self, conn: sqlite3.Connection, record: MemoryRecord) -> None:
        state = record.extra["episode"]
        episode_id = state["episode_id"]
        conn.execute(
            "INSERT OR REPLACE INTO episodes(episode_id, record_id, task_token, outcome, updated_at)"
            " VALUES(?,?,?,?,?)",
            (episode_id, record.id, self.task_token(state["task_ref"]), state["outcome"], record.updated_at),
        )
        conn.execute("DELETE FROM episode_attempts WHERE episode_id=?", (episode_id,))
        conn.executemany(
            "INSERT OR IGNORE INTO episode_attempts(episode_id, attempt_token, recorded_at) VALUES(?,?,?)",
            [(episode_id, self.attempt_token(state["task_ref"], a["attempt_ref"]), a["recorded_at"])
             for a in state["attempts"]],
        )
        tokens: set[str] = set()
        for a in state["attempts"]:
            tokens.add(self.attempt_token(state["task_ref"], a["attempt_ref"]))
            tokens.update(self.receipt_token(r["receipt_id"]) for r in a["verification"])
        conn.execute("DELETE FROM episode_sources WHERE episode_id=?", (episode_id,))
        conn.executemany("INSERT OR IGNORE INTO episode_sources(episode_id, source_token) VALUES(?,?)",
                         [(episode_id, t) for t in sorted(tokens)])

    def _drop_index(self, conn: sqlite3.Connection, episode_id: str) -> None:
        conn.execute("DELETE FROM episodes WHERE episode_id=?", (episode_id,))
        conn.execute("DELETE FROM episode_attempts WHERE episode_id=?", (episode_id,))
        conn.execute("DELETE FROM episode_sources WHERE episode_id=?", (episode_id,))

    # ------------------------------------------------------------------ lessons
    def _propose_lessons(self, access: AccessContext, record: MemoryRecord, lessons: list[str]
                         ) -> tuple[list[str], dict[str, int]]:
        skipped: dict[str, int] = {}
        if not lessons:
            return [], skipped
        if Operation.PROPOSE not in access.operations:
            return [], {"propose_not_permitted": len(lessons)}
        core = self.ctx.services.core
        state = record.extra["episode"]
        ids: list[str] = []
        for lesson in lessons:
            proposal = CandidateProposal(
                content=lesson, sources=(SourceRef(SourceKind.EPISODE, state["episode_id"], actor=access.actor),),
                kind=MemoryKind.FACT, scope=record.scope, title=f"Lesson: {lesson}"[:160], tags=("lesson",),
                basis=StatementBasis.MODEL_INTERPRETATION, confidence=Confidence.unknown(),
                rationale=f"proposed lesson from episode outcome {state['outcome']}",
                proposer=f"episode-{access.actor.value}", derived_from=(record.id,),
            )
            try:
                result = core.propose(access, proposal)
            except MemoryEngineError as exc:  # sensitive, suppressed, invalid: skip, never store
                skipped[exc.code] = skipped.get(exc.code, 0) + 1
                continue
            if result.record.lifecycle == Lifecycle.CANDIDATE and result.record.id not in ids:
                ids.append(result.record.id)
            elif result.record.lifecycle != Lifecycle.CANDIDATE:
                skipped["already_known"] = skipped.get("already_known", 0) + 1
        return ids, skipped

    # ------------------------------------------------------------------ reads
    def _to_episode(self, record: MemoryRecord) -> Episode:
        s = record.extra["episode"]
        latest = s["attempts"][-1]
        return Episode(
            episode_id=s["episode_id"], record_id=record.id, revision=record.revision, task_ref=s["task_ref"],
            attempts=tuple(a["attempt_ref"] for a in s["attempts"]), objective=s["objective"], scope=record.scope,
            outcome=EpisodeOutcome(s["outcome"]), claimed_outcome=EpisodeOutcome(s["claimed_outcome"]),
            outcome_basis=s["outcome_basis"],
            verification=tuple(_result_from_dict(r) for r in latest["verification"]),
            approach=s.get("approach", ""), affected_paths=tuple(s.get("affected_paths", ())),
            failure_modes=tuple(s.get("failure_modes", ())), uncertainties=tuple(s.get("uncertainties", ())),
            proposed_lessons=tuple(s.get("proposed_lessons", ())), usage=dict(s.get("usage") or {}),
            context_receipts=tuple(s.get("context_receipts", ())),
            repository_snapshot=s.get("repository_snapshot"), environment=dict(s.get("environment") or {}),
            updated_at=record.updated_at,
        )

    def load(self, conn: sqlite3.Connection, episode_id: str) -> MemoryRecord | None:
        """Episode record by episode id (no authorization - callers must check visibility)."""
        row = conn.execute("SELECT record_id FROM episodes WHERE episode_id=?", (episode_id,)).fetchone()
        if row is None:
            return None
        record = self.records.get(conn, row[0])
        if record is None or record.kind != MemoryKind.EPISODE or "episode" not in record.extra:
            return None
        return record

    def episode_from_record(self, record: MemoryRecord) -> Episode:
        return self._to_episode(record)

    def get(self, access: AccessContext, episode_id: str) -> Episode:
        policy.require(access, Operation.READ)
        check_id(episode_id, "episode_id")
        with self.p.db.read() as conn:
            record = policy.require_visible(access, self.load(conn, episode_id))
        return self._to_episode(record)

    def list(self, access: AccessContext, *, task_ref: str | None = None,
             outcome: EpisodeOutcome | str | None = None, limit: int = 50) -> list[Episode]:
        policy.require(access, Operation.READ)
        check_int(limit, "limit", lo=1, hi=1000)
        clauses, params = [], []
        if task_ref is not None:
            check_ref(task_ref, "task_ref")
            clauses.append("task_token=?")
            params.append(self.task_token(task_ref))
        if outcome is not None:
            clauses.append("outcome=?")
            params.append(EpisodeOutcome.parse(outcome, "outcome").value)
        with self.p.db.read() as conn:
            if clauses:
                ids = [r[0] for r in conn.execute(
                    "SELECT record_id FROM episodes WHERE " + " AND ".join(clauses), params)]
                records = authorized_by_ids(self.records, conn, access.grants, ids, kinds=(MemoryKind.EPISODE,),
                                            limit=limit)
            else:
                records = self.records.authorized(conn, access.grants, lifecycles=None, kinds=(MemoryKind.EPISODE,),
                                                  limit=limit, order="updated_at DESC, id")
        return [self._to_episode(r) for r in records if "episode" in r.extra]

    # ------------------------------------------------------------------ evidence verification
    def verify_source(self, conn: sqlite3.Connection, access: AccessContext, source: SourceRef) -> bool | None:
        if source.kind == SourceKind.EPISODE:
            try:
                check_id(source.ref, "episode id")
            except ValidationError:
                return False
            record = self.load(conn, source.ref)
            return record is not None and policy.visible(access, record)
        if source.kind == SourceKind.TASK_ATTEMPT:
            ref = source.ref
            task_ref = source.locator.get("task_ref") if isinstance(source.locator, dict) else None
            if not ref.startswith("attempt-") and isinstance(task_ref, str):
                try:
                    ref = attempt_source_ref(task_ref, source.ref)
                except ValidationError:
                    return False
            token = self.records.source_token(f"{SourceKind.TASK_ATTEMPT.value}:{ref}")
            ids = self.records.ids_for_source(conn, token)
            if not ids:
                return False
            visible = self.records.authorized(conn, access.grants, lifecycles=None,
                                              kinds=(MemoryKind.EPISODE,), ids=ids)
            if isinstance(task_ref, str):
                visible = [r for r in visible if r.extra.get("episode", {}).get("task_ref") == task_ref]
            return bool(visible)
        return None

    # ------------------------------------------------------------------ forgetting
    def purge(self, conn: sqlite3.Connection, target_kind: str, target_token: str, forget_policy: Any, *,
              access: AccessContext | None = None) -> dict[str, int]:
        """Index cleanup and outcome recomputation after a deletion (works from the token alone).

        Counts include only episodes/procedures ``access`` may see (everything for admin or
        ledger replay); index rows of already-purged records carry no scope, so they are
        reported to admin/replay only.
        """
        full_report = access is None or Operation.ADMIN in access.operations
        counts: dict[str, int] = {}
        changed: list[str] = []
        if target_kind == "source":
            for (episode_id,) in conn.execute(
                "SELECT DISTINCT episode_id FROM episode_sources WHERE source_token=?", (target_token,)
            ).fetchall():
                result, record = self._forget_cited_source(conn, episode_id, target_token)
                if result:
                    changed.append(episode_id)
                    if full_report or policy.visible(access, record):
                        counts[result] = counts.get(result, 0) + 1
        gone = [r[0] for r in conn.execute(
            "SELECT episode_id FROM episodes WHERE record_id NOT IN (SELECT id FROM records)").fetchall()]
        for episode_id in gone:
            self._drop_index(conn, episode_id)
        orphans = conn.execute(
            "DELETE FROM episode_attempts WHERE episode_id NOT IN (SELECT episode_id FROM episodes)").rowcount
        conn.execute("DELETE FROM episode_sources WHERE episode_id NOT IN (SELECT episode_id FROM episodes)")
        if full_report and gone:
            counts["episode_index_rows"] = len(gone)
        if full_report and orphans:
            counts["episode_attempt_rows"] = orphans
        affected = sorted(set(gone) | set(changed))
        procedures = self.ctx.services.procedures
        if affected and procedures is not None and hasattr(procedures, "revoke_evidence"):
            for key, value in procedures.revoke_evidence(conn, affected, report_to=access).items():
                counts[key] = counts.get(key, 0) + value
        return counts

    def _forget_cited_source(self, conn: sqlite3.Connection, episode_id: str, token: str
                             ) -> tuple[str | None, MemoryRecord | None]:
        """Remove a forgotten (cited) attempt or receipt from an episode; recompute its outcome.

        Only tokens of sources the episode record cites are acted on, so the forgetting
        service's authorization (against the citing records) covers every change made here.
        """
        record = self.load(conn, episode_id)
        if record is None:
            return None, None
        state = dict(record.extra["episode"])
        attempts = [a for a in state["attempts"]
                    if self.attempt_token(state["task_ref"], a["attempt_ref"]) != token]
        if not attempts:
            self.records.purge(conn, record.id)
            return "episodes", record
        new_attempts = []
        for a in attempts:
            kept = [r for r in a["verification"] if self.receipt_token(r["receipt_id"]) != token]
            if len(kept) != len(a["verification"]):
                forgotten = int(a.get("forgotten_receipts", 0)) + len(a["verification"]) - len(kept)
                outcome, basis_text, backed = derive_outcome(
                    EpisodeOutcome(a["claimed_outcome"]), state["task_ref"], kept,
                    authority_available=bool(a.get("authority_available", True)), forgotten_receipts=forgotten)
                a = {**a, "verification": kept, "forgotten_receipts": forgotten, "outcome": outcome.value,
                     "outcome_basis": basis_text, "receipt_backed": backed}
            new_attempts.append(a)
        state["attempts"] = new_attempts
        updated = self._build_record(record, state, record.scope, self.ctx.clock(),
                                     flags=list(record.extra.get("flags", [])),
                                     redactions=list(record.extra.get("redactions", [])),
                                     event_time=record.event_time)
        updated = self.ctx.services.core.write_internal(conn, updated, change="source_forgotten",
                                                         actor=Actor.SYSTEM, expected=record.revision)
        # Earlier revisions still cite the forgotten reference; purge their payloads.
        conn.execute(
            "UPDATE record_revisions SET purged=1, dek_id=NULL, nonce=NULL, ciphertext=NULL"
            " WHERE record_id=? AND revision<?", (updated.id, updated.revision),
        )
        self._index(conn, updated)
        return "episodes_updated", updated


__all__ = ["EpisodeService", "attempt_source_ref", "derive_outcome"]
