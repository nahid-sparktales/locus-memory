"""Bounded maintenance and consolidation jobs. No background threads, timers or schedulers.

``maintain`` is one bounded unit of housekeeping the host calls when it chooses:
expire due candidates/validity, process the provider outbox (if the provider hub
offers one), verify the deletion-ledger MAC chain.

``run`` is a resumable consolidation job with durable progress in ``jobs``:

1. exact-duplicate detection among the caller's authorized *approved* records in the
   same scope (keyed content tokens, confirmed on normalized plaintext) - reported as
   supersession suggestions for a reviewer; nothing is merged, superseded or approved;
2. optional summarization, only when requested *and* the provider hub hands out a
   consented summarizer. Output becomes ``candidate`` ``summary`` records derived from
   their inputs (forgetting an input removes the summary). Every summary commit runs
   ``forgetting.commit_guard`` against the deletion generation the job observed, so
   work that started before a deletion can never commit an obsolete summary.

Job rows carry only ids, states, generations and timestamps in clear; the job's
grants, cursor, suggestions and counts are sealed in ``job_state`` (a sealed table,
so data-key rotation re-encrypts it through :meth:`ConsolidationService.reencrypt`).

Provider hub protocol used here (duck-typed, optional):

* ``hub.summarizer(access) -> obj | None`` - returns an object with
  ``summarize(items: list[dict], *, scope: Scope, deadline_s: float | None) -> str``
  only when a consented extractor is configured (or raises ``ConsentRequired``); the
  summarizer must re-check consent for ``scope`` on every call. Items carry
  ``id, kind, basis, title, content``. (The current ``ProviderHub`` does not offer this,
  so summarization reports ``no_consented_extractor`` until it does.)
* ``hub.process_outbox(access, *, budget=...)`` - bounded provider outbox processing.
"""
from __future__ import annotations

import inspect
import sqlite3
from collections import Counter
from dataclasses import dataclass
from typing import Any

from .. import policy, safety
from ..errors import (
    ConsentRequired,
    IntegrityError,
    InvalidTransition,
    MemoryEngineError,
    NotFound,
    ProviderError,
    StaleDerivation,
    ValidationError,
)
from ..host import CancellationToken, Deadline
from ..models import (
    AccessContext,
    Actor,
    Confidence,
    Lifecycle,
    Links,
    MemoryKind,
    MemoryRecord,
    Operation,
    Retention,
    Scope,
    ScopeGrants,
    SourceKind,
    SourceRef,
    StatementBasis,
)
from ..services import PartitionContext
from ..storage.partition import new_id
from ..validation import check_id, check_int, check_text, normalize_for_fingerprint
from ._common import chunked, existing_ids

JOB_KIND = "consolidation"
JOB_STATE_TABLE = "job_state"
DEFAULT_MAX_RECORDS = 500
MAX_JOBS_KEPT = 200
MAX_SUGGESTIONS = 1_000
MAX_SUMMARY_CHARS = 4_000
STALE_RUNNING_SECONDS = 600.0
_REQUEST_KEYS = frozenset({"job_id", "max_records", "deadline_ms", "cancel", "summarize", "scope_filter",
                           "min_group", "group_size"})
_RESUME_FORBIDDEN = frozenset({"summarize", "scope_filter", "min_group", "group_size"})
_RESUMABLE = frozenset({"pending", "cancelled"})
_BASIS_RANK = {StatementBasis.USER_STATED: 0, StatementBasis.OBSERVED: 1, StatementBasis.SOURCE_ATTRIBUTED: 2,
               StatementBasis.LEGACY: 3, StatementBasis.MODEL_INTERPRETATION: 4, StatementBasis.HYPOTHESIS: 5}
_LIMITATIONS = (
    "duplicate detection is exact (normalized text) within one scope; paraphrases are not detected",
    "suggestions are for a reviewer; nothing is merged, superseded or approved automatically",
    "summaries are unapproved model interpretations derived from their inputs",
)


@dataclass
class _Options:
    job_id: str | None
    max_records: int
    deadline_ms: int | None
    cancel: CancellationToken | None
    summarize: bool
    scope_filter: Scope | None
    min_group: int
    group_size: int


@dataclass
class _Step:
    examined: int = 0
    stop: str | None = None  # job state to stop in (cancelled / invalidated / pending)
    reason: str | None = None


def _covers(outer: ScopeGrants, inner: ScopeGrants) -> bool:
    """True when every grant in ``inner`` is also in ``outer``."""
    return all(inner.values_for(dim) <= outer.values_for(dim) for dim in ScopeGrants._DIM_FIELDS)


class ConsolidationService:
    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx
        self.p = ctx.partition
        self.records = ctx.records

    @property
    def now(self) -> float:
        return self.ctx.clock()

    # ------------------------------------------------------------------ maintain
    def maintain(self, access: AccessContext) -> dict[str, Any]:
        policy.require(access, Operation.MAINTAIN)
        admin = Operation.ADMIN in access.operations
        out: dict[str, Any] = {}
        now = self.now
        with self.p.db.write() as conn:
            due = {r[0]: int(r[1]) for r in conn.execute(
                "SELECT id, revision FROM records WHERE (lifecycle='candidate' AND expires_at IS NOT NULL"
                " AND expires_at < ?) OR (lifecycle='approved' AND valid_until IS NOT NULL AND valid_until < ?)"
                " OR (lifecycle IN ('approved','stale') AND expires_at IS NOT NULL AND expires_at < ? AND pinned=0)",
                (now, now, now))}
            counts = self.ctx.services.core.expire_due(conn)
            changed = []
            for record_id, revision in due.items():
                row = conn.execute("SELECT revision FROM records WHERE id=?", (record_id,)).fetchone()
                if row is not None and int(row[0]) != revision:
                    changed.append(record_id)
            # Only changes to records the caller may see are reported (no cross-scope statistics).
            visible = self.records.visible_ids(conn, access.grants, changed) if changed else set()
            states = self._lifecycles(conn, visible)
            out["expired"] = sum(1 for lc in states.values() if lc == Lifecycle.EXPIRED.value)
            out["marked_stale"] = sum(1 for lc in states.values() if lc == Lifecycle.STALE.value)
            trimmed = self._trim_jobs(conn)
            if admin:
                out["partition"] = {**counts, "jobs_trimmed": trimmed}
            self.p.event(conn, "maintain", "ok")
        out["provider_outbox"] = self._process_outbox(access, admin)
        try:
            entries = self.p.ledger.verify()
            out["ledger"] = {"verified": True, **({"entries": entries} if admin else {})}
        except IntegrityError:
            out["ledger"] = {"verified": False, "error": "integrity_error"}
            with self.p.db.write() as conn:
                self.p.event(conn, "maintain", "ledger_failed", "integrity_error")
        with self.p.db.read() as conn:
            out["generation"] = self.p.generation(conn)
        return out

    def _process_outbox(self, access: AccessContext, admin: bool) -> dict[str, Any]:
        hub = self.ctx.services.providers
        process = getattr(hub, "process_outbox", None) if hub is not None else None
        if not callable(process):
            return {"status": "unavailable"}
        try:
            params = inspect.signature(process).parameters
        except (TypeError, ValueError):
            params = {}
        kwargs: dict[str, Any] = {}
        for name in ("budget", "limit"):  # bounded unit of work
            if name in params:
                kwargs[name] = 50
                break
        positional = [p for p in params.values()
                      if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) and p.name not in kwargs]
        try:
            result = process(access, **kwargs) if positional else process(**kwargs)
        except MemoryEngineError as exc:
            return {"status": "error", "error": exc.code}
        if not admin:  # partition-wide queue: details only for admin callers
            return {"status": "ran"}
        out: dict[str, Any] = {"status": "ran"}
        if isinstance(result, dict):
            for key, value in result.items():
                if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
                    out[str(key)] = value
                elif isinstance(value, (list, tuple, set, frozenset)):
                    out[str(key)] = len(value)  # ids are reduced to counts
        elif isinstance(result, (int, float)) and not isinstance(result, bool):
            out["result"] = result
        return out

    # ------------------------------------------------------------------ job storage
    # Job state that is not content-free (grants, cursor tokens, suggestions) lives in the
    # sealed ``job_state`` table, so data-key rotation sees it and re-encrypts it (reencrypt).
    def _seal(self, conn: sqlite3.Connection, job_id: str, state: dict[str, Any]) -> None:
        dek, nonce, ct = self.p.seal_json(JOB_STATE_TABLE, job_id, {"kind": JOB_KIND}, state)
        conn.execute("INSERT OR REPLACE INTO job_state(job_id, dek_id, nonce, ciphertext) VALUES(?,?,?,?)",
                     (job_id, dek, nonce, ct))

    def _open(self, conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        sealed = conn.execute("SELECT * FROM job_state WHERE job_id=?", (row["id"],)).fetchone()
        if sealed is None:
            raise IntegrityError("a stored job has no state")
        state = self.p.open_json(JOB_STATE_TABLE, row["id"], {"kind": row["kind"]}, sealed["dek_id"],
                                 sealed["nonce"], sealed["ciphertext"])
        if not isinstance(state, dict) or "grants" not in state:
            raise IntegrityError("a stored job is malformed")
        return state

    def _persist(self, conn: sqlite3.Connection, job_id: str, state: dict[str, Any], job_state: str) -> None:
        conn.execute("UPDATE jobs SET state=?, updated_at=? WHERE id=?", (job_state, self.now, job_id))
        self._seal(conn, job_id, state)

    @staticmethod
    def _delete_job(conn: sqlite3.Connection, job_id: str) -> None:
        conn.execute("DELETE FROM job_state WHERE job_id=?", (job_id,))
        conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))

    def reencrypt(self, conn: sqlite3.Connection, old_dek_ids: frozenset[str], limit: int) -> int:
        """Data-key rotation hook (admin.rotate_data_key): re-seal job state under the current DEK."""
        from ..admin import reencrypt_table

        return reencrypt_table(conn, self.p, JOB_STATE_TABLE, key_columns=("job_id",),
                               row_id=lambda r: r["job_id"], fields=lambda r: {"kind": JOB_KIND},
                               old_dek_ids=old_dek_ids, limit=limit)

    @staticmethod
    def _job_guard(conn: sqlite3.Connection, job_id: str) -> str | None:
        row = conn.execute("SELECT state FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            return "invalidated"
        return None if row[0] == "running" else str(row[0])

    def _trim_jobs(self, conn: sqlite3.Connection) -> int:
        trimmed = conn.execute(
            "DELETE FROM jobs WHERE kind=? AND state IN ('completed','cancelled','invalidated') AND id NOT IN"
            " (SELECT id FROM jobs WHERE kind=? ORDER BY updated_at DESC, id LIMIT ?)",
            (JOB_KIND, JOB_KIND, MAX_JOBS_KEPT)).rowcount
        conn.execute("DELETE FROM job_state WHERE job_id NOT IN (SELECT id FROM jobs)")
        return trimmed

    def _load_job(self, conn: sqlite3.Connection, access: AccessContext, job_id: str
                  ) -> tuple[sqlite3.Row, dict[str, Any], ScopeGrants]:
        check_id(job_id, "job_id")
        row = conn.execute("SELECT * FROM jobs WHERE id=? AND kind=?", (job_id, JOB_KIND)).fetchone()
        if row is None:
            raise NotFound("job not found")
        state = self._open(conn, row)
        grants = ScopeGrants.from_dict(state["grants"])
        if not _covers(access.grants, grants):
            raise NotFound("job not found")  # a job over scopes the caller cannot see does not exist for it
        return row, state, grants

    # ------------------------------------------------------------------ request
    @staticmethod
    def _parse(request: Any) -> _Options:
        request = {} if request is None else request
        if not isinstance(request, dict):
            raise ValidationError("a consolidation request must be an object")
        unknown = set(request) - _REQUEST_KEYS
        if unknown:
            raise ValidationError("unsupported consolidation option", details={"unsupported": len(unknown)})
        job_id = request.get("job_id")
        if job_id is not None:
            check_id(job_id, "job_id")
            if set(request) & _RESUME_FORBIDDEN:
                raise ValidationError("a resumed job keeps its original options")
        cancel = request.get("cancel")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise ValidationError("cancel must be a CancellationToken")
        summarize = request.get("summarize", False)
        if not isinstance(summarize, bool):
            raise ValidationError("summarize must be a boolean")
        deadline_ms = request.get("deadline_ms")
        if deadline_ms is not None:
            check_int(deadline_ms, "deadline_ms", lo=1, hi=3_600_000)
        raw_scope = request.get("scope_filter")
        return _Options(
            job_id=job_id,
            max_records=check_int(request.get("max_records", DEFAULT_MAX_RECORDS), "max_records", lo=1, hi=100_000),
            deadline_ms=deadline_ms, cancel=cancel, summarize=summarize,
            scope_filter=Scope.from_dict(raw_scope) if raw_scope is not None else None,
            min_group=check_int(request.get("min_group", 3), "min_group", lo=2, hi=64),
            group_size=check_int(request.get("group_size", 12), "group_size", lo=2, hi=64),
        )

    # ------------------------------------------------------------------ run
    def run(self, access: AccessContext, request: dict[str, Any] | None) -> dict[str, Any]:
        policy.require(access, Operation.MAINTAIN)
        opts = self._parse(request)
        now = self.now
        early: str | None = None
        if opts.job_id is not None:
            job_id = opts.job_id
            with self.p.db.write() as conn:
                row, state, grants = self._load_job(conn, access, job_id)
                current = str(row["state"])
                if current == "completed":
                    early = "already_completed"
                elif current == "invalidated":
                    raise InvalidTransition("this job was invalidated; start a new job")
                elif current == "running" and now - float(row["updated_at"]) < STALE_RUNNING_SECONDS:
                    raise InvalidTransition("this job is already running")
                elif self.p.deletion_generation(conn) > int(row["observed_deletion_generation"]):
                    # Something was forgotten while the job was paused: its progress may cite it.
                    self._persist(conn, job_id, state, "invalidated")
                    early = "deleted_since_observed"
                else:
                    self._persist(conn, job_id, state, "running")
                observed_deletion = int(row["observed_deletion_generation"])
        else:
            grants = policy.narrow(access.grants, opts.scope_filter)
            job_id = new_id("job")
            state = {"grants": grants.to_dict(), "summarize": opts.summarize, "min_group": opts.min_group,
                     "group_size": opts.group_size, "phase": "duplicates", "cursor": None, "counts": {},
                     "suggestions": [], "summaries": [], "summary_status": None,
                     "created_by": access.actor.value}
            with self.p.db.write() as conn:
                observed_deletion = self.p.deletion_generation(conn)
                conn.execute(
                    "INSERT INTO jobs(id, kind, state, observed_generation, observed_deletion_generation,"
                    " created_at, updated_at, progress) VALUES(?,?,?,?,?,?,?,'{}')",
                    (job_id, JOB_KIND, "running", self.p.generation(conn), observed_deletion, now, now))
                self._seal(conn, job_id, state)
                self._trim_jobs(conn)
                self.p.event(conn, "consolidation", "started")
        if early is not None:
            with self.p.db.read() as conn:
                return self._result(conn, access, job_id, state, processed=0, stop_reason=early)
        deadline = Deadline(opts.deadline_ms)
        processed = 0
        final, reason = "completed", None
        summarizer: Any = None
        while True:
            if opts.cancel is not None and opts.cancel.cancelled:
                final, reason = "cancelled", "cancelled"
                break
            if deadline.expired:
                final, reason = "pending", "deadline"
                break
            if processed >= opts.max_records:
                final, reason = "pending", "budget"
                break
            phase = state["phase"]
            if phase == "done":
                final, reason = "completed", None
                break
            if phase == "duplicates":
                step = self._step_duplicates(job_id, grants, state)
            else:
                if summarizer is None and state.get("summary_status") in (None, "ok"):
                    summarizer, status = self._summarizer(access)
                    state["summary_status"] = status
                step = self._step_summarize(job_id, grants, state, summarizer, observed_deletion, deadline)
            processed += step.examined
            if step.stop is not None:
                final, reason = step.stop, step.reason
                break
        with self.p.db.write() as conn:
            external = self._job_guard(conn, job_id)
            if external is not None and external != "running":
                final, reason = external, reason or f"job {external} externally"
            if conn.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone() is not None:
                self._persist(conn, job_id, state, final)
            self.p.event(conn, "consolidation", final, reason or "")
            return self._result(conn, access, job_id, state, processed=processed, stop_reason=reason)

    # ------------------------------------------------------------------ authorization in SQL
    def _auth_clause(self, grants: ScopeGrants) -> tuple[str, list[str]]:
        pairs = self.records.allowed_pairs(grants)
        if pairs:
            return ("NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id AND "
                    f"(s.dim || ':' || s.value_token) NOT IN ({','.join('?' * len(pairs))}))", pairs)
        return "NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id)", []

    # ------------------------------------------------------------------ duplicates
    def _step_duplicates(self, job_id: str, grants: ScopeGrants, state: dict[str, Any]) -> _Step:
        auth, auth_params = self._auth_clause(grants)
        cursor = state["cursor"] or ["", "", ""]
        with self.p.db.read() as conn:
            group = conn.execute(
                "SELECT r.scope_token, r.kind, r.content_token FROM records r"
                " WHERE r.lifecycle='approved' AND r.content_token IS NOT NULL"
                f" AND r.kind NOT IN ('episode','procedure') AND {auth}"
                " AND (r.scope_token, r.kind, r.content_token) > (?,?,?)"
                " GROUP BY r.scope_token, r.kind, r.content_token HAVING COUNT(*) > 1"
                " ORDER BY r.scope_token, r.kind, r.content_token LIMIT 1",
                [*auth_params, *cursor]).fetchone()
            records: list[MemoryRecord] = []
            if group is not None:
                ids = [r[0] for r in conn.execute(
                    "SELECT r.id FROM records r WHERE r.lifecycle='approved' AND r.scope_token=? AND r.kind=?"
                    f" AND r.content_token=? AND {auth} ORDER BY r.id LIMIT 200",
                    [group[0], group[1], group[2], *auth_params])]
                records = self.records.authorized(conn, grants, lifecycles=(Lifecycle.APPROVED,), ids=ids)
        counts = Counter(state["counts"])
        if group is None:
            state["phase"] = "summarize" if state["summarize"] else "done"
            state["cursor"] = None
        else:
            state["cursor"] = [group[0], group[1], group[2]]
            counts["records_examined"] += len(records)
            by_text: dict[str, list[MemoryRecord]] = {}
            for record in records:  # confirm on plaintext (token collisions are not trusted)
                by_text.setdefault(normalize_for_fingerprint(record.content), []).append(record)
            for members in by_text.values():
                if len(members) < 2:
                    continue
                members.sort(key=lambda r: (_BASIS_RANK.get(r.basis, 9), not r.pinned, r.created_at, r.id))
                keep, rest = members[0], members[1:]
                counts["duplicate_groups"] += 1
                counts["duplicate_records"] += len(rest)
                if len(state["suggestions"]) >= MAX_SUGGESTIONS:
                    counts["suggestions_truncated"] += 1
                    continue
                state["suggestions"].append({
                    "type": "duplicate", "action": "supersede", "keep": keep.id,
                    "supersede": [r.id for r in rest][:50], "kind": keep.kind.value,
                    "bases_differ": len({r.basis for r in members}) > 1, "requires_review": True,
                    "reason": "identical normalized content in the same scope",
                })
        state["counts"] = dict(counts)
        with self.p.db.write() as conn:
            stop = self._job_guard(conn, job_id)
            if stop is not None:
                return _Step(len(records), stop=stop, reason=f"job {stop} externally")
            self._persist(conn, job_id, state, "running")
        return _Step(max(len(records), 1 if group is not None else 0))

    # ------------------------------------------------------------------ summaries
    def _summarizer(self, access: AccessContext) -> tuple[Any, str]:
        hub = self.ctx.services.providers
        factory = getattr(hub, "summarizer", None) if hub is not None else None
        if not callable(factory):
            return None, "no_consented_extractor"
        try:
            summarizer = factory(access)
        except ConsentRequired:
            return None, "consent_required"
        except MemoryEngineError as exc:
            return None, exc.code
        if summarizer is None or not callable(getattr(summarizer, "summarize", None)):
            return None, "no_consented_extractor"
        return summarizer, "ok"

    def _next_chunk(self, conn: sqlite3.Connection, grants: ScopeGrants, state: dict[str, Any]
                    ) -> tuple[str, list[str]] | None:
        auth, auth_params = self._auth_clause(grants)
        base = (" FROM records r WHERE r.lifecycle='approved'"
                f" AND r.kind NOT IN ('episode','procedure','summary') AND {auth}")
        scope_token, last_id = state["cursor"] or ["", ""]
        if scope_token:
            ids = [r[0] for r in conn.execute(
                f"SELECT r.id{base} AND r.scope_token=? AND r.id>? ORDER BY r.id LIMIT ?",
                [*auth_params, scope_token, last_id, state["group_size"]])]
            if len(ids) >= state["min_group"]:
                return scope_token, ids
        row = conn.execute(
            f"SELECT r.scope_token{base} AND r.scope_token>? GROUP BY r.scope_token HAVING COUNT(*)>=?"
            " ORDER BY r.scope_token LIMIT 1", [*auth_params, scope_token, state["min_group"]]).fetchone()
        if row is None:
            return None
        ids = [r[0] for r in conn.execute(
            f"SELECT r.id{base} AND r.scope_token=? ORDER BY r.id LIMIT ?",
            [*auth_params, row[0], state["group_size"]])]
        return row[0], ids

    def _existing_summary(self, conn: sqlite3.Connection, ids: list[str]) -> bool:
        tokens = [self.p.token("memory", i) for i in ids]
        row = conn.execute(
            "SELECT d.derived_id FROM derivations d JOIN records r ON r.id=d.derived_id"
            " WHERE r.kind='summary' AND r.lifecycle IN ('candidate','approved') AND d.derived_kind='memory'"
            f" AND d.input_token IN ({','.join('?' * len(tokens))})"
            " GROUP BY d.derived_id HAVING COUNT(*)=? LIMIT 1", [*tokens, len(tokens)]).fetchone()
        return row is not None

    def _guard_inputs(self, records: list[MemoryRecord]) -> list[tuple[str, str]]:
        inputs: list[tuple[str, str]] = []
        for record in records:
            inputs.append(("memory", record.id))
            for source in record.sources:
                inputs.append(("source", self.records.source_token(source.identity())))
                if source.kind == SourceKind.SESSION:
                    inputs.append(("session", self.p.token("session", source.ref)))
            for dim, value in record.scope.constraints:
                inputs.append((f"scope:{dim}", self.records.scope_value_token(dim, value)))
        return list(dict.fromkeys(inputs))

    @staticmethod
    def _clean_summary(raw: Any) -> tuple[str | None, str, list[str]]:
        """Validate untrusted provider output. Returns (text | None, refusal_reason, flags)."""
        if not isinstance(raw, str):
            return None, "invalid_output", []
        text = raw.strip()
        if not text or len(text) > MAX_SUMMARY_CHARS or "\x00" in text:
            return None, "invalid_output", []
        scan = safety.scan(text)
        if scan.secrets:
            return None, "secret_in_output", []
        if scan.sensitive:
            return None, "sensitive_in_output", []
        return safety.neutralize_markup(text), "", (["instruction_like"] if scan.injection else [])

    def _step_summarize(self, job_id: str, grants: ScopeGrants, state: dict[str, Any], summarizer: Any,
                        observed_deletion: int, deadline: Deadline) -> _Step:
        counts = Counter(state["counts"])
        if summarizer is None:
            state["phase"], state["cursor"] = "done", None
            with self.p.db.write() as conn:
                stop = self._job_guard(conn, job_id)
                if stop is None:
                    self._persist(conn, job_id, state, "running")
            return _Step(0, stop=stop, reason=f"job {stop} externally" if stop else None)
        with self.p.db.read() as conn:
            chunk = self._next_chunk(conn, grants, state)
            inputs: list[MemoryRecord] = []
            existing = False
            if chunk is not None:
                inputs = self.records.authorized(conn, grants, lifecycles=(Lifecycle.APPROVED,), ids=chunk[1])
                inputs.sort(key=lambda r: r.id)
                existing = self._existing_summary(conn, chunk[1])
        if chunk is None:
            state["phase"], state["cursor"] = "done", None
            with self.p.db.write() as conn:
                stop = self._job_guard(conn, job_id)
                if stop is None:
                    self._persist(conn, job_id, state, "running")
            return _Step(0, stop=stop, reason=f"job {stop} externally" if stop else None)
        next_cursor = [chunk[0], chunk[1][-1]]
        text, refusal, flags = None, "", []
        if existing or len(inputs) < state["min_group"]:
            counts["summaries_skipped_existing" if existing else "summaries_skipped_small"] += 1
        else:
            items = [{"id": r.id, "kind": r.kind.value, "basis": r.basis.value, "title": r.title,
                      "content": r.content} for r in inputs]
            try:  # outside any transaction: a slow provider never holds the write lock
                raw = summarizer.summarize(items, scope=inputs[0].scope, deadline_s=deadline.remaining_s())
            except MemoryEngineError as exc:
                counts["summaries_provider_errors"] += 1
                state["counts"] = dict(counts)
                return self._stop_pending(job_id, state, len(inputs), exc.code)
            except Exception:  # noqa: BLE001 - provider code; content never echoed
                counts["summaries_provider_errors"] += 1
                state["counts"] = dict(counts)
                return self._stop_pending(job_id, state, len(inputs), ProviderError.code)
            text, refusal, flags = self._clean_summary(raw)
            if text is None:
                counts[f"summaries_refused_{refusal}"] += 1
        counts["records_examined"] += len(inputs)
        with self.p.db.write() as conn:
            if text is not None:
                forgetting = self.ctx.services.forgetting
                try:
                    forgetting.commit_guard(conn, inputs=self._guard_inputs(inputs),
                                            observed_deletion_generation=observed_deletion)
                except StaleDerivation:
                    counts["summaries_refused_stale"] += 1
                    state["counts"] = dict(counts)
                    self._persist(conn, job_id, state, "invalidated")
                    self.p.event(conn, "consolidation", "stale_derivation_refused")
                    return _Step(len(inputs), stop="invalidated", reason="input_forgotten_during_job")
            stop = self._job_guard(conn, job_id)
            if stop is not None:
                return _Step(len(inputs), stop=stop, reason=f"job {stop} externally")
            if text is not None:
                created = self._commit_summary(conn, job_id, grants, inputs, text, flags, counts)
                if created:
                    state["summaries"].append(created)
            state["cursor"] = next_cursor
            state["counts"] = dict(counts)
            self._persist(conn, job_id, state, "running")
        return _Step(max(len(inputs), 1))

    def _stop_pending(self, job_id: str, state: dict[str, Any], examined: int, reason: str) -> _Step:
        with self.p.db.write() as conn:
            stop = self._job_guard(conn, job_id)
            if stop is not None:
                return _Step(examined, stop=stop, reason=f"job {stop} externally")
            self._persist(conn, job_id, state, "running")
        return _Step(examined, stop="pending", reason=reason)

    def _commit_summary(self, conn: sqlite3.Connection, job_id: str, grants: ScopeGrants,
                        inputs: list[MemoryRecord], text: str, flags: list[str], counts: Counter[str]) -> str | None:
        current = self.records.authorized(conn, grants, lifecycles=(Lifecycle.APPROVED,), ids=[r.id for r in inputs])
        if {(r.id, r.revision) for r in current} != {(r.id, r.revision) for r in inputs}:
            counts["summaries_skipped_changed_inputs"] += 1
            return None
        now = self.now
        scope = inputs[0].scope
        record = MemoryRecord(
            id=new_id("m"), revision=1, kind=MemoryKind.SUMMARY, lifecycle=Lifecycle.CANDIDATE, scope=scope,
            title=f"Summary of {len(inputs)} memories", content=text, tags=("summary",),
            basis=StatementBasis.MODEL_INTERPRETATION, confidence=Confidence.unknown(),
            sources=tuple(SourceRef(SourceKind.MEMORY, r.id, actor=Actor.PROVIDER, observed_at=now) for r in inputs),
            retention=Retention("durable", now + self.ctx.config.candidate_ttl_seconds, False),
            links=Links(derived_from=tuple(r.id for r in inputs)), created_at=now, updated_at=now,
            event_time=None, ingested_at=now, reason="consolidation summary (unapproved model interpretation)",
            extra={"proposer": "consolidation", "job_id": job_id,
                   "input_revisions": {r.id: r.revision for r in inputs},
                   "input_bases": sorted({r.basis.value for r in inputs}),
                   **({"flags": flags} if flags else {})},
        )
        forgetting = self.ctx.services.forgetting
        if forgetting is not None and forgetting.blocked_reason(conn, record):
            counts["summaries_refused_suppressed"] += 1
            return None
        duplicate = conn.execute(
            "SELECT 1 FROM records WHERE content_token=? AND scope_token=? AND lifecycle IN ('candidate','approved')",
            (self.records.content_token(text), self.records.scope_token(scope))).fetchone()
        if duplicate is not None:
            counts["summaries_skipped_duplicate"] += 1
            return None
        self.ctx.services.core.write_internal(conn, record, change="consolidated", actor=Actor.SYSTEM, expected=None)
        counts["summaries_proposed"] += 1
        return record.id

    # ------------------------------------------------------------------ results
    @staticmethod
    def _lifecycles(conn: sqlite3.Connection, ids: set[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for batch in chunked(sorted(ids)):
            out.update((r[0], r[1]) for r in conn.execute(
                f"SELECT id, lifecycle FROM records WHERE id IN ({','.join('?' * len(batch))})", batch))
        return out

    def _result(self, conn: sqlite3.Connection, access: AccessContext, job_id: str, state: dict[str, Any], *,
                processed: int, stop_reason: str | None) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        job_state = str(row["state"]) if row is not None else "invalidated"
        mentioned = {i for s in state["suggestions"] for i in [s["keep"], *s["supersede"]]}
        visible = self.records.visible_ids(conn, access.grants, mentioned) if mentioned else set()
        present = {i for i, lc in self._lifecycles(conn, visible).items() if lc == Lifecycle.APPROVED.value}
        suggestions = []
        for s in state["suggestions"]:
            rest = [i for i in s["supersede"] if i in present]
            if s["keep"] in present and rest:
                suggestions.append({**s, "supersede": rest})
        visible_summaries = self.records.visible_ids(conn, access.grants, state["summaries"])
        summaries = [i for i in state["summaries"] if i in visible_summaries]
        status = {"completed": "complete", "pending": "partial", "running": "partial"}.get(job_state, job_state)
        return {
            "job_id": job_id, "kind": JOB_KIND, "state": job_state, "status": status, "stop_reason": stop_reason,
            "resumable": job_state in _RESUMABLE, "phase": state["phase"],
            "observed_generation": int(row["observed_generation"]) if row is not None else None,
            "observed_deletion_generation": int(row["observed_deletion_generation"]) if row is not None else None,
            "generation": self.p.generation(conn), "processed_this_run": processed,
            "counts": dict(state["counts"]), "suggestions": suggestions, "summaries": summaries,
            "summary_status": state.get("summary_status") if state.get("summarize") else "not_requested",
            "limitations": list(_LIMITATIONS),
        }

    def _job_view(self, row: sqlite3.Row, state: dict[str, Any]) -> dict[str, Any]:
        return {"job_id": row["id"], "kind": row["kind"], "state": row["state"], "phase": state["phase"],
                "created_at": float(row["created_at"]), "updated_at": float(row["updated_at"]),
                "observed_generation": int(row["observed_generation"]),
                "observed_deletion_generation": int(row["observed_deletion_generation"]),
                "resumable": row["state"] in _RESUMABLE, "counts": dict(state["counts"]),
                "summarize": bool(state.get("summarize"))}

    # ------------------------------------------------------------------ job control
    def jobs(self, access: AccessContext) -> list[dict[str, Any]]:
        policy.require(access, Operation.MAINTAIN)
        out = []
        with self.p.db.read() as conn:
            for row in conn.execute("SELECT * FROM jobs WHERE kind=? ORDER BY created_at DESC, id", (JOB_KIND,)):
                state = self._open(conn, row)
                if _covers(access.grants, ScopeGrants.from_dict(state["grants"])):
                    out.append(self._job_view(row, state))
        return out

    def cancel(self, access: AccessContext, job_id: str) -> dict[str, Any]:
        policy.require(access, Operation.MAINTAIN)
        with self.p.db.write() as conn:
            row, state, _ = self._load_job(conn, access, job_id)
            if row["state"] in ("pending", "running"):
                conn.execute("UPDATE jobs SET state='cancelled', updated_at=? WHERE id=?", (self.now, job_id))
                self.p.event(conn, "consolidation", "cancelled")
            elif row["state"] != "cancelled":
                raise InvalidTransition(f"cannot cancel a {row['state']} job")
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            return self._job_view(row, state)

    def invalidate(self, access: AccessContext, reason: str) -> int:
        """Host signal (scope or consent changed): bump the cache generation, stop affected jobs."""
        policy.require(access, Operation.MAINTAIN)
        check_text(reason, "reason", max_chars=2_000, allow_empty=True)
        with self.p.db.write() as conn:
            generation = self.p.bump(conn)
            # Paused jobs are invalidated too: their sealed grants/consent predate the change.
            conn.execute("UPDATE jobs SET state='invalidated', updated_at=? WHERE kind=? AND state IN"
                         " ('pending','running','cancelled')", (self.now, JOB_KIND))
            self.p.make_receipt(conn, "invalidate", "ok", details={"generation": generation})
            self.p.event(conn, "invalidate", "ok", "host_signal")
        return generation

    # ------------------------------------------------------------------ forgetting
    def purge(self, conn: sqlite3.Connection, target_kind: str, target_token: str, forget_policy: Any, *,
              access: AccessContext | None = None) -> dict[str, int]:
        """Drop jobs bound to a forgotten scope; scrub ids of purged records from job progress.

        Counts include only jobs ``access`` could list (everything for admin/replay).
        """
        full_report = access is None or Operation.ADMIN in access.operations
        counts: dict[str, int] = {}

        def note(key: str, grants: ScopeGrants | None) -> None:
            if full_report or (grants is not None and _covers(access.grants, grants)):
                counts[key] = counts.get(key, 0) + 1

        dim = target_kind.split(":", 1)[1] if target_kind.startswith("scope:") else None
        for row in conn.execute("SELECT * FROM jobs WHERE kind=?", (JOB_KIND,)).fetchall():
            try:
                state = self._open(conn, row)
            except (IntegrityError, MemoryEngineError):
                self._delete_job(conn, row["id"])
                note("consolidation_jobs", None)
                continue
            grants = ScopeGrants.from_dict(state["grants"])
            if dim is not None and dim in ScopeGrants._DIM_FIELDS:
                if any(self.records.scope_value_token(dim, v) == target_token for v in grants.values_for(dim)):
                    self._delete_job(conn, row["id"])
                    note("consolidation_jobs", grants)
                    continue
            mentioned = {i for s in state["suggestions"] for i in [s["keep"], *s["supersede"]]} | set(state["summaries"])
            if not mentioned:
                continue
            alive = existing_ids(conn, "records", "id", sorted(mentioned))
            if alive == mentioned:
                continue
            state["summaries"] = [i for i in state["summaries"] if i in alive]
            state["suggestions"] = [
                {**s, "supersede": [i for i in s["supersede"] if i in alive]} for s in state["suggestions"]
                if s["keep"] in alive and any(i in alive for i in s["supersede"])]
            self._seal(conn, row["id"], state)
            note("consolidation_jobs_scrubbed", grants)
        return counts


__all__ = ["ConsolidationService", "JOB_KIND"]
