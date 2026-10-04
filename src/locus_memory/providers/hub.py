"""ProviderHub: optional model providers and external memory services for one partition.

Separation of concerns:

* **Storage** (``embeddings.py``) - versioned, encrypted vectors; a derived index that
  is never canonical memory and never mixes model keys.
* **Retrieval enrichment** (:meth:`ProviderHub.semantic_scores`, :meth:`ProviderHub.rerank`)
  - optional ranking signals. ``None`` means "not available"; callers keep working
  without them. Scores are labelled (``cosine``, ``provider_relevance``) and are
  never probabilities.
* **Model extraction** (:meth:`ProviderHub.extract_candidates`) - provider output is
  validated and enters memory only as CANDIDATE proposals made with a provider
  access context (``actor=PROVIDER``, operations ``{PROPOSE, READ}``): providers can
  never approve, and suppression/forgetting apply as for any proposer.
* **Summarization** (:meth:`ProviderHub.summarizer` / :meth:`ProviderHub.summarize`) -
  returns validated text only; the hub persists nothing but usage receipts. The caller
  (consolidation) stores it as an unapproved, derived ``summary`` candidate.
* **Lifecycle governance** - consent (no egress without a host consent policy that
  covers provider + scope + data class), capability negotiation, guarded calls
  (deadline, cancellation, bounded retries, rate limit, circuit breaker), usage
  receipts, and the external-deletion outbox (forgetting queues deletions at every
  external service that received the data; ``done`` only on provider confirmation;
  a third party can never resurrect a forgotten or rejected record).

Outages never change *where* data goes: provider selection is deterministic
(registration order, local before egress, consent) and independent of health, so a
failing provider makes the call fail or degrade - it never fails over to another
provider or account, and the outbox only ever calls the provider that holds the data.
"""
from __future__ import annotations

import dataclasses
import functools
import math
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .. import policy, safety
from .. import validation as v
from ..errors import (
    AccessDenied,
    Cancelled,
    ConsentRequired,
    DeadlineExceeded,
    InvalidTransition,
    MemoryEngineError,
    NotFound,
    ProviderError,
    RevisionConflict,
    SensitiveContent,
    StaleDerivation,
    SuppressedError,
    UnsupportedCapability,
    ValidationError,
)
from ..host import Deadline
from ..models import (
    AccessContext,
    Actor,
    CandidateProposal,
    Confidence,
    Lifecycle,
    MemoryKind,
    MemoryRecord,
    Operation,
    Scope,
    SourceKind,
    SourceRef,
    StatementBasis,
    WriteResult,
    canonical_json,
)
from ..services import PartitionContext
from ..storage.partition import new_id, partition_bound
from .base import (
    CAPABILITY_METHODS,
    DATA_CLASSES,
    DATA_MEMORY_TEXT,
    DEFAULT_DEADLINE_MS,
    EMBED,
    EXTERNAL_DELETE,
    EXTERNAL_SYNC,
    EXTRACT,
    MAX_SUMMARY_CHARS,
    RERANK,
    SUMMARIZE,
    CircuitBreaker,
    CircuitOpen,
    ConsentGrant,
    GuardedCall,
    ProviderDescriptor,
    ProviderRateLimited,
    TokenBucket,
    UsageRecord,
    as_list,
    finite_number,
    validate_confirmations,
    validate_listing,
    validate_scores,
    validate_summary,
    validate_vectors,
)
from .embeddings import EmbeddingStore, StoredVector, cosine

# How the hub turns a record into provider input. Part of every embedding model key.
HUB_PREPROCESSING = "hub-text-1"  # title (unless a prefix of content) + content, secrets redacted
SCORE_KIND_SEMANTIC = "cosine"  # cosine similarity in [-1, 1]; not a probability
SCORE_KIND_RERANK = "provider_relevance"  # opaque provider ordering value; not a probability

_SYNC_ACCEPTED = frozenset({"stored"})
_DELETE_CONFIRMED = frozenset({"deleted", "not_found"})
_LIVE_SYNC_STATES = ("sending", "synced", "unconfirmed")
_REMOVED_LIFECYCLES = ("rejected", "expired", "forgotten")
_PROPOSAL_KEYS = frozenset({"content", "evidence_ids", "kind", "title", "tags", "confidence", "subject",
                            "predicate", "basis", "rationale"})
_EXTRACTABLE_KINDS = frozenset({MemoryKind.PREFERENCE, MemoryKind.FACT, MemoryKind.DECISION,
                                MemoryKind.CONSTRAINT, MemoryKind.RELATIONSHIP})
_EXTRACTED_BASES = frozenset({StatementBasis.MODEL_INTERPRETATION, StatementBasis.HYPOTHESIS})
_SUMMARY_ITEM_KEYS = frozenset({"id", "kind", "basis", "title", "content"})
# Per-proposal refusals by the core lifecycle (the provider output was well-formed).
_REFUSALS: tuple[type[MemoryEngineError], ...] = (
    SuppressedError, SensitiveContent, ValidationError, NotFound, AccessDenied, StaleDerivation,
    InvalidTransition, RevisionConflict,
)


class ScoreMap(dict):
    """``record id -> score`` plus what the numbers are. Absent ids were not scored."""

    def __init__(self, scores: dict[str, float], *, score_kind: str, provider: str,
                 model_key: str | None = None, coverage: dict[str, int] | None = None) -> None:
        super().__init__(scores)
        self.score_kind = score_kind
        self.provider = provider
        self.model_key = model_key
        self.coverage = dict(coverage or {})


@dataclass
class _Registered:
    name: str
    provider: Any
    descriptor: ProviderDescriptor
    capabilities: frozenset[str]
    declared_without_methods: tuple[str, ...]
    breaker: CircuitBreaker
    bucket: TokenBucket


@dataclass(frozen=True)
class _Evidence:
    id: str
    text: str
    source: SourceRef
    scope: Scope
    data_class: str


def _merge_scopes(scopes: Iterable[Scope]) -> Scope | None:
    """Union of constraints (visible only where every input is visible); None on conflict."""
    merged: dict[str, str] = {}
    for scope in scopes:
        for dim, value in scope.constraints:
            if merged.setdefault(dim, value) != value:
                return None
    return Scope(tuple(merged.items()))


def _record_text(record: MemoryRecord) -> str:
    title = (record.title or "").strip()
    content = record.content
    text = content if not title or content.startswith(title) else f"{title}\n{content}"
    return safety.redact_secrets(text)[0]


def _cancelled(cancel: Any) -> bool:
    return cancel is not None and bool(getattr(cancel, "cancelled", False))


def evidence_from_memories(records: Iterable[MemoryRecord]) -> list[dict[str, Any]]:
    """Extraction evidence for memory records (data class ``memory_text``)."""
    out = []
    for record in records:
        title = (record.title or "").strip()
        text = record.content if not title or record.content.startswith(title) else f"{title}\n{record.content}"
        out.append({"id": record.id, "text": text, "source": SourceRef(SourceKind.MEMORY, record.id),
                    "scope": record.scope, "data_class": DATA_MEMORY_TEXT})
    return out


class UsageBufferSnapshot:
    """Opaque handle from :meth:`ProviderHub.snapshot_usage_buffer`; hand it back to
    :meth:`ProviderHub.restore_usage_buffer` on the same thread."""

    __slots__ = ("_held", "_purges")

    def __init__(self, purges: int) -> None:
        self._held: list[UsageRecord] = []  # receipts a rolled-back purge on this thread dropped
        self._purges = purges


class HubSummarizer:
    """Summarization handle returned by :meth:`ProviderHub.summarizer`.

    It holds only the caller's trusted access context and a provider name. Every call goes
    back through :meth:`ProviderHub.summarize`, which re-checks operations, scope and
    consent, verifies the items against the store and runs the guarded call; holding a
    handle grants nothing once consent is withdrawn.
    """

    def __init__(self, hub: ProviderHub, access: AccessContext, provider: str) -> None:
        self._hub = hub
        self._access = access
        self.provider = provider

    def summarize(self, items: list[dict[str, Any]], *, scope: Scope, deadline_s: float | None = None,
                  cancel: Any = None) -> str:
        return self._hub.summarize(self._access, items, scope=scope, provider=self.provider,
                                   deadline_s=deadline_s, cancel=cancel)


@partition_bound
class ProviderHub:
    MAX_SEMANTIC_RECORDS = 10_000  # records considered per semantic_scores call (rest unscored)
    MAX_LAZY_EMBED = 32  # missing/stale vectors computed per call (bounded batch)
    MAX_RERANK = 64
    MAX_EVIDENCE = 64
    MAX_PROPOSALS = 32
    MAX_SUMMARY_ITEMS = 64
    MAX_SUMMARY_CHARS = MAX_SUMMARY_CHARS
    MAX_SYNC_BATCH = 100
    MAX_DELETE_ATTEMPTS = 8
    MAX_LIST_ITEMS = 10_000
    MAX_USAGE_BUFFER = 10_000
    OUTBOX_DONE_RETENTION_S = 30 * 86_400

    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx
        self.p = ctx.partition
        self.records = ctx.records
        self.embeddings = EmbeddingStore(ctx.partition)
        # Backoff sleeper for retries (hosts and tests may replace it).
        self.sleep: Callable[[float], None] = time.sleep
        self._lock = threading.RLock()
        self._usage_buffer: list[UsageRecord] = []
        # Profile purges that emptied the buffer outside a snapshot (they may commit): receipts
        # buffered before one of them belong to a forgotten profile and are never persisted.
        self._usage_purges = 0
        self._snapshots = threading.local()  # per thread: active UsageBufferSnapshot stack
        self._providers: dict[str, _Registered] = {}
        self._rejected: dict[str, str] = {}
        self._register(getattr(ctx.host, "providers", None) or {})

    # ------------------------------------------------------------------ registration
    def _now(self) -> float:
        return float(self.ctx.clock())

    def _register(self, providers: dict[str, Any]) -> None:
        for index, (name, provider) in enumerate(dict(providers).items()):
            if not isinstance(name, str) or not v.ID_PATTERN.fullmatch(name):
                self._rejected[f"#{index}"] = "invalid_name"
                continue
            try:
                descriptor = getattr(provider, "descriptor", None)
            except Exception:
                descriptor = None
            if not isinstance(descriptor, ProviderDescriptor):
                self._rejected[name] = "missing_descriptor"
                continue
            if descriptor.name != name:
                self._rejected[name] = "descriptor_name_mismatch"
                continue
            supported = []
            for capability in sorted(descriptor.capabilities):
                try:
                    ok = all(callable(getattr(provider, m, None)) for m in CAPABILITY_METHODS[capability])
                except Exception:
                    ok = False
                if ok:
                    supported.append(capability)
            if not supported:
                self._rejected[name] = "no_supported_capability"
                continue
            self._providers[name] = _Registered(
                name=name, provider=provider, descriptor=descriptor, capabilities=frozenset(supported),
                declared_without_methods=tuple(sorted(descriptor.capabilities - set(supported))),
                breaker=CircuitBreaker(self._now, threshold=descriptor.failure_threshold,
                                       cooldown_s=descriptor.cooldown_s),
                bucket=TokenBucket(self._now, rate_per_s=descriptor.rate_limit_per_s, burst=descriptor.rate_burst),
            )

    def _get(self, name: Any, capability: str, data_class: str | None = None) -> _Registered:
        reg = self._providers.get(name) if isinstance(name, str) else None
        if reg is None:
            raise UnsupportedCapability("no registered provider by that name offers this capability",
                                        details={"capability": capability})
        if capability not in reg.capabilities:
            raise UnsupportedCapability("the provider does not offer this capability",
                                        details={"provider": reg.name, "capability": capability})
        if data_class is not None and data_class not in reg.descriptor.data_classes_accepted:
            raise UnsupportedCapability("the provider does not accept this data class",
                                        details={"provider": reg.name, "data_class": data_class})
        return reg

    def _auto(self, capability: str, data_class: str, access: AccessContext) -> _Registered | None:
        """Deterministic choice: first local provider, else first egress provider with consent.

        Health is deliberately ignored: an outage must never move data to another provider.
        """
        candidates = [r for r in self._providers.values()
                      if capability in r.capabilities and data_class in r.descriptor.data_classes_accepted]
        for reg in candidates:
            if not reg.descriptor.egress:
                return reg
        for reg in candidates:
            try:
                self._query_consent(access, reg)
            except ConsentRequired:
                continue
            return reg
        return None

    # ------------------------------------------------------------------ consent
    def _grants(self, access: AccessContext, reg: _Registered) -> list[ConsentGrant]:
        consent = self.ctx.host.consent
        if consent is None:
            return []
        try:
            raw = consent.grants(access, reg.name)
        except Exception:  # a failing policy grants nothing (fail closed)
            self.ctx.metrics.incr("provider.consent_policy_error")
            return []
        now = self._now()
        return [g for g in (raw or ()) if isinstance(g, ConsentGrant) and g.provider == reg.name and g.active(now)]

    def _require_consent(self, access: AccessContext, reg: _Registered,
                         needs: Iterable[tuple[Scope, str]]) -> list[ConsentGrant] | None:
        """None for local providers; otherwise the active grants (every need must be covered)."""
        if not reg.descriptor.egress:
            return None
        if self.ctx.host.consent is None:
            raise ConsentRequired("external providers are disabled: the host supplied no consent policy",
                                  details={"provider": reg.name})
        grants = self._grants(access, reg)
        for scope, data_class in needs:
            if not any(g.covers(scope, data_class) for g in grants):
                raise ConsentRequired("no active consent covers sending this data to this provider",
                                      details={"provider": reg.name, "data_class": data_class})
        return grants

    def _query_consent(self, access: AccessContext, reg: _Registered) -> list[ConsentGrant] | None:
        """A query may be sent under an active ``memory_text`` grant that is profile-wide or
        for a scope the caller holds."""
        if not reg.descriptor.egress:
            return None
        if self.ctx.host.consent is None:
            raise ConsentRequired("external providers are disabled: the host supplied no consent policy",
                                  details={"provider": reg.name})
        grants = self._grants(access, reg)
        for g in grants:
            if g.covers(g.scope or Scope(), DATA_MEMORY_TEXT) and (g.scope is None or access.grants.allows(g.scope)):
                return grants
        raise ConsentRequired("no active consent covers sending a query to this provider",
                              details={"provider": reg.name, "data_class": DATA_MEMORY_TEXT})

    @staticmethod
    def _covers(grants: list[ConsentGrant] | None, scope: Scope, data_class: str) -> bool:
        return grants is None or any(g.covers(scope, data_class) for g in grants)

    # ------------------------------------------------------------------ guarded calls & usage
    def _deadline(self, deadline_ms: int | None) -> Deadline:
        ms = DEFAULT_DEADLINE_MS if deadline_ms is None else v.check_int(deadline_ms, "deadline_ms", lo=1, hi=600_000)
        return Deadline(ms, clock=self._now)

    def _guard(self, reg: _Registered) -> GuardedCall:
        return GuardedCall(reg.descriptor, reg.breaker, reg.bucket, clock=self._now,
                           usage=self._buffer_usage, sleep=lambda seconds: self.sleep(seconds))

    def _buffer_usage(self, record: UsageRecord) -> None:
        with self._lock:
            self._usage_buffer.append(record)
            overflow = len(self._usage_buffer) - self.MAX_USAGE_BUFFER
            if overflow > 0:
                del self._usage_buffer[:overflow]
                self.ctx.metrics.incr("provider.usage_dropped", overflow)

    def _flush_usage(self, conn: Any = None) -> None:
        """Persist buffered usage receipts (in ``conn`` when given, else in a short write).

        Receipts taken before a profile purge that ran meanwhile (on another thread, while
        this one waited for the write lock) are dropped, never persisted or requeued."""
        with self._lock:
            rows, self._usage_buffer = self._usage_buffer, []
            purges = self._usage_purges
        if not rows:
            return
        try:
            if conn is not None:
                self._insert_usage(conn, rows)
                return
            if self.p.db.conn.in_transaction:  # the caller holds a transaction: flush later
                raise _Deferred
            with self.p.db.write() as wconn:
                if self._usage_purges == purges:
                    self._insert_usage(wconn, rows)
                else:
                    self.ctx.metrics.incr("provider.usage_dropped", len(rows))
        except _Deferred:
            self._requeue_usage(rows, purges)
        except Exception:
            self._requeue_usage(rows, purges)
            if conn is not None:
                raise
            self.ctx.metrics.incr("provider.usage_flush_deferred")

    def _requeue_usage(self, rows: list[UsageRecord], purges: int) -> None:
        with self._lock:
            if self._usage_purges != purges:  # taken before a profile purge: forgotten with it
                self.ctx.metrics.incr("provider.usage_dropped", len(rows))
                return
            self._usage_buffer = (rows + self._usage_buffer)[-self.MAX_USAGE_BUFFER:]

    def _drop_buffered_usage(self) -> None:
        """Profile purge: every buffered receipt belongs to the profile being forgotten."""
        with self._lock:
            dropped, self._usage_buffer = self._usage_buffer, []
            active = getattr(self._snapshots, "stack", None)
            if active:  # a dry run on this thread (rolled back): kept for restore_usage_buffer
                active[-1]._held.extend(dropped)
                active[-1]._purges = self._usage_purges
            else:  # this purge may commit
                self._usage_purges += 1

    def snapshot_usage_buffer(self) -> UsageBufferSnapshot:
        """Start a dry run of a purge on this thread (a forget preview, whose transaction is
        always rolled back). Until :meth:`restore_usage_buffer` is called with the returned
        snapshot, the usage receipts that a profile purge on this thread drops from the
        in-memory buffer are kept in the snapshot instead of being discarded.

        Takes the hub's lock only briefly and never holds it across the caller's
        transaction, so it imposes no lock order on writers (which take the store's write
        lock first and the hub's lock inside it). Other threads keep buffering and flushing
        receipts meanwhile; nothing they do is undone by the restore.
        """
        with self._lock:
            snapshot = UsageBufferSnapshot(self._usage_purges)
            stack = getattr(self._snapshots, "stack", None)
            if stack is None:
                stack = self._snapshots.stack = []
            stack.append(snapshot)
        return snapshot

    def restore_usage_buffer(self, snapshot: UsageBufferSnapshot) -> int:
        """End the dry run ``snapshot`` began (call it after the rollback, on the same thread):
        put back, ahead of receipts buffered since, the receipts its purge dropped. Returns
        how many were put back.

        Receipts are never resurrected past a purge that may have committed: if a profile
        purge outside any snapshot emptied the buffer after this dry run's purge, the held
        receipts are dropped (counted in ``provider.usage_dropped``). Idempotent.
        """
        if not isinstance(snapshot, UsageBufferSnapshot):
            raise ValidationError("not a usage buffer snapshot")
        with self._lock:
            stack = getattr(self._snapshots, "stack", None) or []
            if snapshot in stack:
                stack.remove(snapshot)
            held, snapshot._held = snapshot._held, []
            if not held:
                return 0
            if self._usage_purges != snapshot._purges:
                self.ctx.metrics.incr("provider.usage_dropped", len(held))
                return 0
            merged = held + self._usage_buffer
            overflow = len(merged) - self.MAX_USAGE_BUFFER
            if overflow > 0:
                del merged[:overflow]
                self.ctx.metrics.incr("provider.usage_dropped", overflow)
            self._usage_buffer = merged
            return max(0, len(held) - max(overflow, 0))

    @staticmethod
    def _insert_usage(conn: Any, rows: list[UsageRecord]) -> None:
        conn.executemany(
            "INSERT INTO usage_log(id, provider, operation, created_at, units, cost_micros, cost_known, outcome)"
            " VALUES(?,?,?,?,?,?,?,?)",
            [(new_id("u"), r.provider, r.operation, r.created_at, r.units, r.cost_micros, int(r.cost_known),
              r.outcome) for r in rows],
        )

    @staticmethod
    def _require_maintenance(access: AccessContext) -> None:
        if Operation.MAINTAIN not in access.operations and Operation.ADMIN not in access.operations:
            raise AccessDenied("this provider operation requires maintenance or admin rights")

    # ------------------------------------------------------------------ record verification
    def _verify_records(self, access: AccessContext, records: Iterable[Any]
                        ) -> tuple[list[MemoryRecord], dict[str, int], int]:
        """Caller-supplied records that are authorized *and* match the store (SQL only).

        A record is kept when its claimed scope is granted and the stored row has the same
        revision, scope token and content token - so a stale or forged object can never
        steer what is sent to a provider or cached as a vector.
        """
        stats: Counter[str] = Counter()
        candidates: list[MemoryRecord] = []
        seen: set[str] = set()
        for record in records or ():
            if not isinstance(record, MemoryRecord) or record.id in seen:
                continue
            seen.add(record.id)
            if not access.grants.allows(record.scope):
                self.ctx.metrics.incr("provider.unauthorized_input_dropped")
                continue
            if len(candidates) >= self.MAX_SEMANTIC_RECORDS:
                stats["over_bound"] += 1
                continue
            candidates.append(record)
        rows: dict[str, tuple[int, str, str]] = {}
        with self.p.db.read() as conn:
            observed = self.p.deletion_generation(conn)
            ids = [r.id for r in candidates]
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                for row in conn.execute(
                    f"SELECT id, revision, scope_token, content_token FROM records"
                    f" WHERE id IN ({','.join('?' * len(chunk))})", chunk,
                ):
                    rows[row[0]] = (int(row[1]), row[2], row[3])
        verified = []
        scope_tokens: dict[str, str] = {}
        for record in candidates:
            row = rows.get(record.id)
            if row is None or row[0] != record.revision:
                stats["stale_or_unknown"] += 1
                continue
            key = record.scope.key()
            if key not in scope_tokens:
                scope_tokens[key] = self.records.scope_token(record.scope)
            if row[1] != scope_tokens[key] or row[2] != self.records.content_token(record.content):
                stats["stale_or_unknown"] += 1
                continue
            verified.append(record)
        return verified, dict(stats), observed

    def _commit_vector(self, conn: Any, record: MemoryRecord, model_key: str, text_token: str,
                       vector: tuple[float, ...], dimensions: int, observed: int) -> bool:
        forgetting = self.ctx.services.forgetting
        if forgetting is not None:
            inputs = [("memory", record.id)] + [
                (f"scope:{dim}", self.records.scope_value_token(dim, value)) for dim, value in record.scope.constraints
            ]
            try:
                forgetting.commit_guard(conn, inputs=inputs, observed_deletion_generation=observed)
            except StaleDerivation:
                return False
        return self.embeddings.put(conn, record_id=record.id, model_key=model_key,
                                   expected_revision=record.revision, text_token=text_token,
                                   vector=vector, dimensions=dimensions)

    # ------------------------------------------------------------------ enrichment: embeddings
    def model_key(self, provider: str) -> str:
        reg = self._get(provider, EMBED)
        return self.embeddings.model_key(reg.descriptor, HUB_PREPROCESSING)

    def semantic_available(self, access: AccessContext) -> bool:
        """Whether :meth:`semantic_scores` (enrichment mode) has a provider it may use for this
        caller, judged from registration and consent alone: an embedding provider accepting
        ``memory_text`` is registered and is local (no consent needed), or holds an active
        ``memory_text`` grant that is profile-wide or for a scope the caller holds. Health is
        not considered (an outage is reported by :meth:`status` and degrades searches)."""
        policy.require(access, Operation.READ)
        return self._auto(EMBED, DATA_MEMORY_TEXT, access) is not None

    def semantic_scores(self, access: AccessContext, query: str, records: Iterable[MemoryRecord], *,
                        deadline_ms: int | None = None, cancel: Any = None,
                        provider: str | None = None, strict: bool = False) -> ScoreMap | None:
        """Cosine similarity (``score_kind="cosine"``, in [-1, 1], NOT a probability) between the
        query and each authorized record, from one embedding model.

        Stored vectors are reused when they were computed from the record's current text;
        missing or stale ones are embedded in the same bounded call (at most
        ``MAX_LAZY_EMBED``; the rest stay unscored this time). Data class ``memory_text``.
        Consent gates egress only: the query needs an active grant, and a record's text is
        sent only when a grant covers its scope; vectors already stored locally are used
        for ranking without sending anything.

        ``provider=None`` (enrichment): returns ``None`` when no embedding provider or consent
        is available or the provider fails - callers continue without semantic scores.
        An explicit ``provider`` raises instead (UnsupportedCapability, ConsentRequired,
        ProviderError, DeadlineExceeded). ``strict=True`` (used by retrieval) keeps the
        enrichment choice but raises ProviderError/DeadlineExceeded when the chosen provider
        fails, so the caller can report degraded results instead of mistaking an outage for
        "not configured". Cancellation always raises ``Cancelled``.
        Call it outside an open transaction on this thread; inside one it only scores
        records whose vectors are already stored.
        """
        policy.require(access, Operation.READ)
        explicit = provider is not None
        text = v.check_text(query if isinstance(query, str) else "", "query", max_chars=v.MAX_QUERY_CHARS,
                            allow_empty=True)
        if not text:
            if explicit:
                raise ValidationError("query cannot be empty")
            return None
        try:
            reg = self._get(provider, EMBED, DATA_MEMORY_TEXT) if explicit else self._auto(EMBED, DATA_MEMORY_TEXT, access)
            if reg is None:
                return None
            grants = self._query_consent(access, reg)
        except (UnsupportedCapability, ConsentRequired):
            if explicit:
                raise
            return None
        if _cancelled(cancel):
            raise Cancelled("semantic scoring was cancelled")
        deadline = self._deadline(deadline_ms)
        desc = reg.descriptor
        dims = int(desc.dimensions or 0)
        mk = self.embeddings.model_key(desc, HUB_PREPROCESSING)
        records = list(records or ())
        verified, stats, observed = self._verify_records(access, records)
        coverage: dict[str, int] = {"requested": len(records), "verified": len(verified), **stats}
        if not verified:
            return ScoreMap({}, score_kind=SCORE_KIND_SEMANTIC, provider=reg.name, model_key=mk,
                            coverage={**coverage, "scored": 0})
        with self.p.db.read() as conn:
            stored = self.embeddings.load(conn, mk, [r.id for r in verified], dimensions=dims)
        usable: dict[str, tuple[float, ...]] = {}
        rebase: list[tuple[MemoryRecord, StoredVector]] = []
        missing: list[tuple[MemoryRecord, str, str]] = []
        for record in verified:
            vector = stored.get(record.id)
            if vector is not None and vector.revision == record.revision:
                usable[record.id] = vector.vector  # same revision => same text (verified above)
                continue
            rtext = _record_text(record)
            token = self.embeddings.text_token(rtext)
            if vector is not None and vector.text_token == token:
                usable[record.id] = vector.vector
                rebase.append((record, vector))  # same text, newer revision: still valid
            else:
                missing.append((record, rtext, token))
        can_write = not self.p.db.conn.in_transaction
        eligible = []
        for item in missing:
            if not self._covers(grants, item[0].scope, DATA_MEMORY_TEXT):
                coverage["not_consented"] = coverage.get("not_consented", 0) + 1
                continue
            eligible.append(item)
        budget = max(0, min(self.MAX_LAZY_EMBED, desc.max_batch - 1)) if can_write else 0
        batch, deferred = eligible[:budget], eligible[budget:]
        coverage["deferred"] = len(deferred)
        texts = [safety.redact_secrets(text)[0]] + [t for _, t, _ in batch]
        try:
            vectors = self._guard(reg).run(
                "embed", lambda remaining: reg.provider.embed(list(texts), deadline_s=remaining),
                units=len(texts), deadline=deadline, cancel=cancel,
                validate=lambda raw: validate_vectors(raw, count=len(texts), dimensions=dims),
            )
        except Cancelled:
            self._flush_usage()
            raise
        except (ProviderError, DeadlineExceeded):
            self._flush_usage()
            if explicit or strict:
                raise
            return None
        written = discarded = 0
        if can_write and (batch or rebase):
            with self.p.db.write() as conn:
                for (record, _text, token), vector in zip(batch, vectors[1:], strict=True):
                    if self._commit_vector(conn, record, mk, token, vector, dims, observed):
                        usable[record.id] = vector
                        written += 1
                    else:
                        discarded += 1  # edited or forgotten while the provider worked
                for record, stored_vector in rebase:
                    if not self._commit_vector(conn, record, mk, stored_vector.text_token, stored_vector.vector,
                                               dims, observed):
                        usable.pop(record.id, None)
                        discarded += 1
                self._flush_usage(conn)
                if written or discarded:
                    self.p.event(conn, "provider_embed", "ok", f"written={written};discarded={discarded}")
        else:
            self._flush_usage()
        query_vector = vectors[0]
        scores = {rid: cosine(query_vector, vec) for rid, vec in usable.items()}
        coverage.update({"scored": len(scores), "embedded_now": written, "discarded_changed": discarded})
        return ScoreMap(scores, score_kind=SCORE_KIND_SEMANTIC, provider=reg.name, model_key=mk, coverage=coverage)

    # ------------------------------------------------------------------ enrichment: rerank
    def rerank(self, access: AccessContext, query: str, records: Iterable[MemoryRecord], *,
               deadline_ms: int | None = None, cancel: Any = None,
               provider: str | None = None) -> ScoreMap | None:
        """Provider relevance values (``score_kind="provider_relevance"``; an ordering signal,
        NOT a probability) for at most ``MAX_RERANK`` authorized records. Nothing is stored.
        Same ``provider=None`` / explicit semantics as :meth:`semantic_scores`."""
        policy.require(access, Operation.READ)
        explicit = provider is not None
        text = v.check_text(query if isinstance(query, str) else "", "query", max_chars=v.MAX_QUERY_CHARS,
                            allow_empty=True)
        if not text:
            if explicit:
                raise ValidationError("query cannot be empty")
            return None
        try:
            reg = self._get(provider, RERANK, DATA_MEMORY_TEXT) if explicit else self._auto(RERANK, DATA_MEMORY_TEXT, access)
            if reg is None:
                return None
            grants = self._query_consent(access, reg)
        except (UnsupportedCapability, ConsentRequired):
            if explicit:
                raise
            return None
        if _cancelled(cancel):
            raise Cancelled("reranking was cancelled")
        deadline = self._deadline(deadline_ms)
        records = list(records or ())
        verified, stats, _observed = self._verify_records(access, records)
        coverage: dict[str, int] = {"requested": len(records), "verified": len(verified), **stats}
        allowed = []
        for record in verified:
            if self._covers(grants, record.scope, DATA_MEMORY_TEXT):
                allowed.append(record)
            else:
                coverage["not_consented"] = coverage.get("not_consented", 0) + 1
        bound = min(self.MAX_RERANK, reg.descriptor.max_batch)
        batch = allowed[:bound]
        coverage["deferred"] = len(allowed) - len(batch)
        if not batch:
            return ScoreMap({}, score_kind=SCORE_KIND_RERANK, provider=reg.name, coverage={**coverage, "scored": 0})
        texts = [_record_text(r) for r in batch]
        sent_query = safety.redact_secrets(text)[0]
        try:
            scores = self._guard(reg).run(
                "rerank", lambda remaining: reg.provider.rerank(sent_query, list(texts), deadline_s=remaining),
                units=len(texts), deadline=deadline, cancel=cancel,
                validate=lambda raw: validate_scores(raw, count=len(texts)),
            )
        except Cancelled:
            self._flush_usage()
            raise
        except (ProviderError, DeadlineExceeded):
            self._flush_usage()
            if explicit:
                raise
            return None
        self._flush_usage()
        coverage["scored"] = len(batch)
        return ScoreMap({r.id: s for r, s in zip(batch, scores, strict=True)}, score_kind=SCORE_KIND_RERANK,
                        provider=reg.name, coverage=coverage)

    # ------------------------------------------------------------------ extraction
    def _parse_evidence(self, access: AccessContext, evidence: Any) -> list[_Evidence]:
        if isinstance(evidence, (str, bytes, dict)) or not isinstance(evidence, (list, tuple)) or not evidence:
            raise ValidationError("evidence must be a non-empty list")
        if len(evidence) > self.MAX_EVIDENCE:
            raise ValidationError(f"at most {self.MAX_EVIDENCE} evidence items per extraction")
        out: list[_Evidence] = []
        seen: set[str] = set()
        for raw in evidence:
            if not isinstance(raw, dict):
                raise ValidationError("evidence items must be objects")
            evidence_id = v.check_id(raw.get("id"), "evidence id")
            if evidence_id in seen:
                raise ValidationError("evidence ids must be unique")
            seen.add(evidence_id)
            text = v.check_text(raw.get("text"), "evidence text", max_chars=v.MAX_CONTENT_CHARS)
            if raw.get("source") is None:
                raise ValidationError("evidence requires a source")
            source = SourceRef.from_dict(raw.get("source"))
            scope = Scope.from_dict(raw.get("scope"))
            data_class = raw.get("data_class", DATA_MEMORY_TEXT)
            if data_class not in DATA_CLASSES:
                raise ValidationError("unknown evidence data class")
            policy.require_scope(access, scope)
            out.append(_Evidence(evidence_id, text, source, scope, data_class))
        return out

    def _validate_proposals(self, raw: Any, items: list[_Evidence], reg: _Registered,
                            observed: int) -> list[CandidateProposal | None]:
        entries = as_list(raw, "extractor output")
        if len(entries) > self.MAX_PROPOSALS:
            raise ProviderError("the extractor returned too many proposals", details={"max": self.MAX_PROPOSALS})
        index = {e.id: e for e in items}
        desc = reg.descriptor
        version = f"{reg.name}:{desc.model}@{desc.version}"[:128]
        out: list[CandidateProposal | None] = []
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict) or not all(isinstance(k, str) for k in entry):
                raise ProviderError("each proposal must be an object", details={"index": i})
            if set(entry) - _PROPOSAL_KEYS:
                # e.g. lifecycle/approved/scope/sources: providers cannot set them.
                raise ProviderError("a proposal sets fields a provider may not set", details={"index": i})
            cited = entry.get("evidence_ids")
            if not isinstance(cited, (list, tuple)) or not cited or len(cited) > self.MAX_EVIDENCE:
                raise ProviderError("a proposal must cite the evidence ids it was derived from", details={"index": i})
            ids: list[str] = []
            for evidence_id in cited:
                if not isinstance(evidence_id, str) or evidence_id not in index:
                    raise ProviderError("a proposal cites evidence that was not supplied", details={"index": i})
                if evidence_id not in ids:
                    ids.append(evidence_id)
            try:
                kind = MemoryKind.parse(entry.get("kind", "fact"), "kind")
                basis = StatementBasis.parse(entry.get("basis", "model_interpretation"), "basis")
            except ValidationError:
                raise ProviderError("a proposal has an invalid kind or basis", details={"index": i}) from None
            if kind not in _EXTRACTABLE_KINDS or basis not in _EXTRACTED_BASES:
                raise ProviderError("a proposal claims a kind or basis a provider may not assign",
                                    details={"index": i})
            raw_confidence = entry.get("confidence")
            confidence = Confidence()
            if raw_confidence is not None:
                number = finite_number(raw_confidence)
                if number is None or not 0.0 <= number <= 1.0:
                    raise ProviderError("proposal confidence must be a number in [0, 1]", details={"index": i})
                confidence = Confidence(number, False, "model_uncalibrated")
            tags = entry.get("tags") or ()
            if not isinstance(tags, (list, tuple)) or not all(isinstance(t, str) for t in tags):
                raise ProviderError("proposal tags must be a list of strings", details={"index": i})
            cited_evidence = [index[c] for c in ids]
            scope = _merge_scopes(e.scope for e in cited_evidence)
            if scope is None:
                out.append(None)  # evidence from incompatible scopes: refused, never widened
                continue
            sources: dict[str, SourceRef] = {}
            for e in cited_evidence:
                s = e.source
                sources.setdefault(s.identity(), SourceRef(
                    kind=s.kind, ref=s.ref, actor=s.actor, locator=dict(s.locator), fingerprint=s.fingerprint,
                    observed_at=s.observed_at, extraction_version=version, available=s.available,
                ))
            derived = tuple(dict.fromkeys(e.source.ref for e in cited_evidence if e.source.kind == SourceKind.MEMORY))
            try:
                proposal = CandidateProposal(
                    content=entry.get("content"), sources=tuple(sources.values()), kind=kind, scope=scope,
                    title=entry.get("title") or "", tags=tuple(tags), basis=basis, confidence=confidence,
                    subject=entry.get("subject"), predicate=entry.get("predicate"),
                    rationale=entry.get("rationale") or "", proposer=f"provider:{reg.name}"[:128],
                    derived_from=derived, observed_generation=observed,
                )
            except (ValidationError, TypeError, ValueError):
                raise ProviderError("a proposal failed validation", details={"index": i}) from None
            out.append(proposal)
        return out

    def extract_candidates(self, access: AccessContext, evidence: list[dict[str, Any]], *, provider: str,
                           deadline_ms: int | None = None, cancel: Any = None) -> list[WriteResult]:
        """Ask an extractor for candidate memories from caller-supplied, authorized evidence.

        Evidence items: ``{"id", "text", "source": SourceRef|dict, "scope", "data_class"}``.
        Every evidence scope must be granted, every source must verify for a provider
        proposer (memory sources must be visible; message/session sources must exist in
        an authorized session; anything unverifiable is refused *before* egress), and
        consent must cover provider + scope + data class. Output is validated strictly
        (a fabricated evidence id or forbidden field fails the whole batch with
        ProviderError and nothing is persisted). Valid proposals go through
        ``core.propose`` as ``actor=PROVIDER`` with only ``{PROPOSE, READ}``: they land as
        CANDIDATE or are refused (suppressed, forgotten, sensitive, duplicate). Returns the
        newly created candidates only.
        """
        policy.require(access, Operation.PROPOSE)
        policy.require(access, Operation.READ)
        reg = self._get(provider, EXTRACT)
        items = self._parse_evidence(access, evidence)
        for data_class in sorted({e.data_class for e in items}):
            if data_class not in reg.descriptor.data_classes_accepted:
                raise UnsupportedCapability("the provider does not accept this data class",
                                            details={"provider": reg.name, "data_class": data_class})
        # Consent on the declared scopes first (nothing is read before this check) ...
        self._require_consent(access, reg, [(e.scope, e.data_class) for e in items])
        provider_access = dataclasses.replace(
            access, actor=Actor.PROVIDER, operations=frozenset({Operation.PROPOSE, Operation.READ}),
        )
        core = self.ctx.services.core
        resolved: list[_Evidence] = []
        with self.p.db.read() as conn:
            observed = self.p.deletion_generation(conn)
            history = self.ctx.services.history
            for e in items:
                (source,) = core.verify_sources(conn, provider_access, (e.source,))
                scope = e.scope
                authoritative: Scope | None = None
                if source.kind == SourceKind.MEMORY:
                    record = core.load_visible(conn, provider_access, source.ref)
                    if e.text not in record.content and e.text not in f"{record.title}\n{record.content}":
                        # A citation must point at what was actually said, not at arbitrary text.
                        raise ValidationError("memory evidence text must be an excerpt of its source memory")
                    authoritative = record.scope
                elif source.kind in (SourceKind.MESSAGE, SourceKind.SESSION) and history is not None:
                    # A transcript's scope is its session's: a declared scope can only narrow it,
                    # never move it (consent is checked again on this authoritative scope).
                    authoritative = history.source_scope(conn, source)
                if authoritative is not None:
                    merged = _merge_scopes([scope, authoritative])
                    if merged is None:
                        raise ValidationError("evidence scope does not match its source")
                    scope = merged
                policy.require_scope(access, scope)
                resolved.append(dataclasses.replace(e, scope=scope, source=source))
        # ... and again on the authoritative scopes.
        self._require_consent(access, reg, [(e.scope, e.data_class) for e in resolved])
        payload = [{"id": e.id, "text": safety.neutralize_markup(safety.redact_secrets(e.text)[0]),
                    "data_class": e.data_class} for e in resolved]
        deadline = self._deadline(deadline_ms)
        try:
            proposals = self._guard(reg).run(
                "extract", lambda remaining: reg.provider.extract([dict(p) for p in payload], deadline_s=remaining),
                units=len(payload), deadline=deadline, cancel=cancel,
                validate=lambda raw: self._validate_proposals(raw, resolved, reg, observed),
            )
        finally:
            self._flush_usage()
        results: list[WriteResult] = []
        outcomes: Counter[str] = Counter()
        for proposal in proposals:
            if proposal is None:
                outcomes["scope_conflict"] += 1
                continue
            if _cancelled(cancel):
                outcomes["cancelled"] += 1
                continue
            try:
                result = core.propose(provider_access, proposal)
            except _REFUSALS as exc:
                outcomes[exc.code] += 1
                continue
            if result.receipt.status != "ok" or result.record.lifecycle != Lifecycle.CANDIDATE:
                outcomes["duplicate"] += 1
                continue
            results.append(result)
        outcomes["created"] = len(results)
        for code, count in outcomes.items():
            self.ctx.metrics.incr(f"provider.extract.{code}", count)
        return results

    # ------------------------------------------------------------------ summarization
    def summarizer(self, access: AccessContext, *, provider: str | None = None) -> HubSummarizer | None:
        """A summarization handle for ``access`` (the object consolidation duck-types), or
        ``None`` when no registered provider offers ``summarize`` for ``memory_text`` with
        consent this caller could use.

        Selection is deterministic and health-blind, as for every capability: the first
        local provider, else the first egress provider with an active ``memory_text`` grant
        that is profile-wide or for a scope the caller holds. That grant only makes the
        handle available; every call checks consent for the items' scope again. An explicit
        ``provider`` raises UnsupportedCapability / ConsentRequired instead of returning None.
        """
        policy.require(access, Operation.READ)
        if provider is not None:
            reg = self._get(provider, SUMMARIZE, DATA_MEMORY_TEXT)
            self._query_consent(access, reg)
        else:
            found = self._auto(SUMMARIZE, DATA_MEMORY_TEXT, access)
            if found is None:
                return None
            reg = found
        return HubSummarizer(self, access, reg.name)

    @staticmethod
    def _summary_deadline_ms(deadline_s: Any) -> int | None:
        if deadline_s is None:
            return None
        seconds = finite_number(deadline_s)
        if seconds is None or seconds < 0:
            raise ValidationError("deadline_s must be a non-negative finite number")
        if seconds == 0:
            raise DeadlineExceeded("the deadline passed before the provider call")
        return max(1, math.ceil(min(seconds, 600.0) * 1000))  # capped first: 1e308 * 1000 is inf

    def _parse_summary_items(self, items: Any) -> list[dict[str, Any]]:
        if isinstance(items, (str, bytes, dict)) or not isinstance(items, (list, tuple)) or not items:
            raise ValidationError("summary items must be a non-empty list")
        if len(items) > self.MAX_SUMMARY_ITEMS:
            raise ValidationError(f"at most {self.MAX_SUMMARY_ITEMS} items per summary")
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw in items:
            if not isinstance(raw, dict) or not all(isinstance(k, str) for k in raw):
                raise ValidationError("summary items must be objects")
            if set(raw) - _SUMMARY_ITEM_KEYS:
                raise ValidationError("summary items may carry only id, kind, basis, title and content")
            record_id = v.check_id(raw.get("id"), "memory id")
            if record_id in seen:
                raise ValidationError("summary item ids must be unique")
            seen.add(record_id)
            content, title = raw.get("content"), raw.get("title")
            if not isinstance(content, str) or (title is not None and not isinstance(title, str)):
                raise ValidationError("summary items need text content (and an optional text title)")
            out.append({
                "id": record_id, "content": content, "title": title,
                "kind": None if raw.get("kind") is None else MemoryKind.parse(raw["kind"], "kind"),
                "basis": None if raw.get("basis") is None else StatementBasis.parse(raw["basis"], "basis"),
            })
        return out

    def _summary_records(self, access: AccessContext, wanted: list[dict[str, Any]],
                         scope: Scope) -> list[MemoryRecord]:
        """The stored records behind ``wanted``: visible to ``access`` (missing and
        unauthorized are the same NotFound), in exactly ``scope``, approved, and unchanged
        since the caller read them (otherwise StaleDerivation)."""
        core = self.ctx.services.core
        out: list[MemoryRecord] = []
        with self.p.db.read() as conn:
            for item in wanted:
                record = core.load_visible(conn, access, item["id"])
                if record.scope != scope:
                    raise ValidationError("every summary item must belong to the requested scope")
                if (record.lifecycle != Lifecycle.APPROVED or record.content != item["content"]
                        or item["title"] not in (None, record.title)
                        or item["kind"] not in (None, record.kind)
                        or item["basis"] not in (None, record.basis)):
                    raise StaleDerivation("a summary input changed or is no longer approved since it was read")
                out.append(record)
        return out

    def summarize(self, access: AccessContext, items: Any, *, scope: Scope, provider: str,
                  deadline_s: float | None = None, cancel: Any = None) -> str:
        """Summarize approved memories of one scope with ``provider``; returns validated text.

        ``items``: ``[{"id", "content", "title"?, "kind"?, "basis"?}]`` (at most
        ``MAX_SUMMARY_ITEMS``). Each must name a record visible to ``access`` (NotFound
        otherwise) whose scope is exactly ``scope`` (ValidationError otherwise) and that is
        still approved with the same content, title, kind and basis (StaleDerivation
        otherwise) - all checked before anything is sent. Consent must cover ``scope`` for
        ``memory_text`` on every call (local providers need none). The provider receives
        only kind, basis, title and content from the store, secrets redacted and markup
        neutralized - no ids, scopes or sources. The reply must pass
        :func:`~locus_memory.providers.base.validate_summary` (else ProviderError, recorded
        as ``invalid_output``). Runs under the guarded call (deadline, cancellation, rate
        limit, circuit breaker, bounded retries); persists nothing but usage receipts.
        """
        policy.require(access, Operation.READ)
        reg = self._get(provider, SUMMARIZE, DATA_MEMORY_TEXT)
        if scope is None:
            raise ValidationError("summarize requires the items' scope")
        scope = Scope.from_dict(scope)
        policy.require_scope(access, scope)
        wanted = self._parse_summary_items(items)
        deadline_ms = self._summary_deadline_ms(deadline_s)
        # Consent on the declared scope first (nothing is read before this check) ...
        self._require_consent(access, reg, [(scope, DATA_MEMORY_TEXT)])
        if _cancelled(cancel):
            raise Cancelled("summarization was cancelled")
        records = self._summary_records(access, wanted, scope)
        # ... and again on the authoritative scopes, just before egress.
        self._require_consent(access, reg, [(r.scope, DATA_MEMORY_TEXT) for r in records])
        payload = [{"kind": r.kind.value, "basis": r.basis.value,
                    "title": safety.neutralize_markup(safety.redact_secrets(r.title or "")[0]),
                    "content": safety.neutralize_markup(safety.redact_secrets(r.content)[0])} for r in records]
        deadline = self._deadline(deadline_ms)
        try:
            text = self._guard(reg).run(
                "summarize",
                lambda remaining: reg.provider.summarize([dict(p) for p in payload], deadline_s=remaining),
                units=len(payload), deadline=deadline, cancel=cancel,
                validate=lambda raw: validate_summary(raw, max_chars=self.MAX_SUMMARY_CHARS),
            )
        finally:
            self._flush_usage()
        self.ctx.metrics.incr("provider.summarize.ok")
        return text

    # ------------------------------------------------------------------ external sync
    def _external_ref(self, provider: str, record_id: str) -> str:
        """Provider-specific opaque ref (refs cannot be correlated across providers)."""
        return "x" + self.p.token(f"external-ref:{provider}", record_id)[:32]

    def sync_external(self, access: AccessContext, provider: str, *, scope_filter: Scope | None = None,
                      limit: int = 50, deadline_ms: int | None = None, cancel: Any = None) -> dict[str, Any]:
        """Send approved, authorized, consent-covered records to an external memory service.

        The mapping is written *before* the call (a forget during the call still queues
        deletion); records are marked ``synced`` only on provider confirmation.
        Requires READ and EXPORT. Data class ``memory_text``; scope values and sources are
        never sent (payload: opaque ref, kind, title, content with secrets redacted, revision).
        """
        policy.require(access, Operation.READ)
        policy.require(access, Operation.EXPORT)
        reg = self._get(provider, EXTERNAL_SYNC, DATA_MEMORY_TEXT)
        limit = v.check_int(limit, "limit", lo=1, hi=self.MAX_SYNC_BATCH)
        limit = min(limit, reg.descriptor.max_batch)
        grants = policy.narrow(access.grants, scope_filter)
        consent = self._require_consent(access, reg, [])
        if consent is not None and not any(DATA_MEMORY_TEXT in g.data_classes for g in consent):
            raise ConsentRequired("no active consent covers sending memory to this provider",
                                  details={"provider": reg.name, "data_class": DATA_MEMORY_TEXT})
        skipped: Counter[str] = Counter()
        with self.p.db.read() as conn:
            ids = [r[0] for r in conn.execute(
                "SELECT r.id FROM records r WHERE r.lifecycle='approved' AND NOT EXISTS ("
                " SELECT 1 FROM provider_sync s WHERE s.provider=? AND s.record_id=r.id"
                " AND s.state='synced' AND s.revision=r.revision) ORDER BY r.updated_at, r.id", (reg.name,))]
            selected: list[MemoryRecord] = []
            for start in range(0, len(ids), 500):
                if len(selected) >= limit:
                    break
                selected += self.records.authorized(conn, grants, lifecycles=(Lifecycle.APPROVED,),
                                                    ids=ids[start:start + 500], limit=limit - len(selected))
        items: list[tuple[MemoryRecord, dict[str, Any]]] = []
        for record in selected:
            if not self._covers(consent, record.scope, DATA_MEMORY_TEXT):
                skipped["not_consented"] += 1
                continue
            items.append((record, {
                "external_ref": self._external_ref(reg.name, record.id), "kind": record.kind.value,
                "title": safety.redact_secrets(record.title or "")[0],
                "content": safety.redact_secrets(record.content)[0], "revision": record.revision,
            }))
        sent: list[dict[str, Any]] = []
        if items:
            now = self._now()
            with self.p.db.write() as conn:  # write-ahead mapping
                for record, item in items:
                    row = conn.execute("SELECT revision, lifecycle FROM records WHERE id=?", (record.id,)).fetchone()
                    if row is None or int(row[0]) != record.revision or row[1] != "approved":
                        skipped["changed"] += 1
                        continue
                    existing = conn.execute("SELECT state FROM provider_sync WHERE provider=? AND external_ref=?",
                                            (reg.name, item["external_ref"])).fetchone()
                    if existing is not None and existing[0] == "deleting":
                        skipped["pending_deletion"] += 1
                        continue
                    conn.execute(
                        "INSERT INTO provider_sync(provider, external_ref, record_id, revision, state, cause_token,"
                        " created_at, updated_at) VALUES(?,?,?,?,'sending',NULL,?,?)"
                        " ON CONFLICT(provider, external_ref) DO UPDATE SET record_id=excluded.record_id,"
                        " revision=excluded.revision, state='sending', cause_token=NULL, updated_at=excluded.updated_at",
                        (reg.name, item["external_ref"], record.id, record.revision, now, now),
                    )
                    sent.append(item)
        report: dict[str, Any] = {"provider": reg.name, "sent": len(sent), "confirmed": 0, "unconfirmed": 0,
                                  "skipped": dict(skipped)}
        if not sent:
            return report
        refs = [item["external_ref"] for item in sent]
        key = "s" + self.p.token("provider-idempotency", canonical_json(
            [reg.name, sorted((i["external_ref"], i["revision"]) for i in sent)]))[:32]
        deadline = self._deadline(deadline_ms)
        try:
            confirmed = self._guard(reg).run(
                "sync", lambda remaining: reg.provider.sync([dict(i) for i in sent], idempotency_key=key,
                                                             deadline_s=remaining),
                units=len(sent), deadline=deadline, cancel=cancel,
                validate=lambda raw: validate_confirmations(raw, refs, accepted=_SYNC_ACCEPTED),
            )
        except MemoryEngineError:
            # The provider may hold the data anyway: keep the mapping as 'unconfirmed'.
            with self.p.db.write() as conn:
                self._mark_sync(conn, reg.name, sent, set())
                self._flush_usage(conn)
            raise
        with self.p.db.write() as conn:
            self._mark_sync(conn, reg.name, sent, confirmed)
            self._flush_usage(conn)
            self.p.event(conn, "provider_sync", "ok", f"sent={len(sent)};confirmed={len(confirmed)}")
        report["confirmed"] = len(confirmed & set(refs))
        report["unconfirmed"] = len(sent) - report["confirmed"]
        return report

    def _mark_sync(self, conn: Any, provider: str, sent: list[dict[str, Any]], confirmed: set[str]) -> None:
        now = self._now()
        for item in sent:
            state = "synced" if item["external_ref"] in confirmed else "unconfirmed"
            # Compare-and-swap: a record forgotten meanwhile stays 'deleting'.
            conn.execute(
                "UPDATE provider_sync SET state=?, updated_at=? WHERE provider=? AND external_ref=?"
                " AND revision=? AND state IN ('sending','unconfirmed')",
                (state, now, provider, item["external_ref"], item["revision"]),
            )

    # ------------------------------------------------------------------ deletion propagation
    def _ensure_outbox(self, conn: Any, provider: str, ref: str, now: float) -> str:
        row = conn.execute(
            "SELECT id FROM provider_outbox WHERE provider=? AND target_token=? AND operation='delete'"
            " AND state IN ('pending','failed') ORDER BY created_at, id LIMIT 1", (provider, ref),
        ).fetchone()
        if row is not None:
            return str(row[0])
        outbox_id = new_id("ob")
        conn.execute(
            "INSERT INTO provider_outbox(id, provider, operation, target_token, state, attempts, created_at,"
            " updated_at, last_error) VALUES(?,?,'delete',?,'pending',0,?,?,NULL)",
            (outbox_id, provider, ref, now, now),
        )
        return outbox_id

    def _mark_deleting(self, conn: Any, rows: Iterable[tuple[str, str]], cause: str) -> list[str]:
        now = self._now()
        ids = []
        for provider, ref in rows:
            conn.execute(
                "UPDATE provider_sync SET state='deleting', record_id='', cause_token=?, updated_at=?"
                " WHERE provider=? AND external_ref=?", (cause, now, provider, ref),
            )
            ids.append(self._ensure_outbox(conn, provider, ref, now))
        return ids

    def _orphans(self, conn: Any) -> list[tuple[str, str]]:
        """Synced items whose local record is gone, rejected, expired or forgotten."""
        return [(r[0], r[1]) for r in conn.execute(
            "SELECT s.provider, s.external_ref FROM provider_sync s LEFT JOIN records r ON r.id = s.record_id"
            f" WHERE s.state IN ({','.join('?' * len(_LIVE_SYNC_STATES))})"
            f" AND (r.id IS NULL OR r.lifecycle IN ({','.join('?' * len(_REMOVED_LIFECYCLES))}))",
            [*_LIVE_SYNC_STATES, *_REMOVED_LIFECYCLES],
        )]

    def queue_deletion(self, conn: Any, kind: str, token: str) -> list[str]:
        """Queue external deletions for a forget target, from the target token alone.

        Called inside the forget transaction (after local purging). Every external item
        whose local record no longer exists (or is rejected/expired) is moved to
        ``deleting`` with an outbox row per provider that received it; for ``profile``
        everything held externally is queued. Returns the pending outbox ids attributable
        to this target. Idempotent.
        """
        cause = self.p.token("provider-cause", f"{kind}|{token}")
        if kind == "profile":
            rows = [(r[0], r[1]) for r in conn.execute(
                f"SELECT provider, external_ref FROM provider_sync"
                f" WHERE state IN ({','.join('?' * len(_LIVE_SYNC_STATES))})", _LIVE_SYNC_STATES)]
        else:
            rows = self._orphans(conn)
        self._mark_deleting(conn, rows, cause)
        if kind == "profile":
            return [r[0] for r in conn.execute(
                "SELECT id FROM provider_outbox WHERE operation='delete' AND state IN ('pending','failed')"
                " ORDER BY created_at, id")]
        return [r[0] for r in conn.execute(
            "SELECT o.id FROM provider_outbox o JOIN provider_sync s"
            " ON s.provider=o.provider AND s.external_ref=o.target_token"
            " WHERE s.cause_token=? AND s.state='deleting' AND o.operation='delete'"
            " AND o.state IN ('pending','failed') ORDER BY o.created_at, o.id", (cause,))]

    def purge(self, conn: Any, target_kind: str, target_token: str, forget_policy: Any = None) -> dict[str, int]:
        """Forgetting hook (live forget and ledger replay): drop vectors of purged records and
        queue external deletions; pending ones are reported as ``retained_pending_external``.
        A profile purge also drops the buffered usage receipts (a dry run on this thread keeps
        them in its :meth:`snapshot_usage_buffer` snapshot)."""
        counts: Counter[str] = Counter()
        if target_kind == "memory":
            counts["embeddings"] += self.embeddings.delete_record(conn, target_token)
        if target_kind == "profile":
            counts["embeddings"] += self.embeddings.delete_all(conn)
            counts["provider_usage_rows"] += conn.execute("DELETE FROM usage_log").rowcount
            counts["provider_outbox_done_rows"] += conn.execute(
                "DELETE FROM provider_outbox WHERE state='done'").rowcount
            counts["provider_sync_deleted_rows"] += conn.execute(
                "DELETE FROM provider_sync WHERE state='deleted'").rowcount
            self._drop_buffered_usage()
        counts["embeddings"] += self.embeddings.delete_orphans(conn)
        if target_kind != "profile":
            counts["embeddings"] += self._drop_forgotten_revisions(conn)
        counts["retained_pending_external"] += len(self.queue_deletion(conn, target_kind, target_token))
        return {k: n for k, n in counts.items() if n}

    def _drop_forgotten_revisions(self, conn: Any) -> int:
        """A record rewritten by forgetting (a dropped citation, a forgotten episode attempt) no
        longer says what its older revisions said: drop vectors computed from those revisions and
        withdraw external copies of them (a later sync sends the current revision)."""
        rewritten = [r[0] for r in conn.execute(
            "SELECT r.id FROM records r JOIN record_revisions v ON v.record_id=r.id AND v.revision=r.revision"
            " WHERE v.change='source_forgotten'")]
        if not rewritten:
            return 0
        dropped = 0
        cause = self.p.token("provider-cause", "source_forgotten")
        for batch in [rewritten[i:i + 400] for i in range(0, len(rewritten), 400)]:
            marks = ",".join("?" * len(batch))
            dropped += conn.execute(
                f"DELETE FROM embeddings WHERE record_id IN ({marks}) AND revision <"
                " (SELECT revision FROM records WHERE id=embeddings.record_id)", batch).rowcount
            stale = [(r[0], r[1]) for r in conn.execute(
                f"SELECT s.provider, s.external_ref FROM provider_sync s JOIN records r ON r.id=s.record_id"
                f" WHERE s.record_id IN ({marks}) AND s.revision < r.revision"
                f" AND s.state IN ({','.join('?' * len(_LIVE_SYNC_STATES))})", [*batch, *_LIVE_SYNC_STATES])]
            self._mark_deleting(conn, stale, cause)
        return dropped

    def reencrypt(self, conn: Any, old_dek_ids: frozenset[str], limit: int) -> int:
        """Data-key rotation hook (``admin.rotate_data_key``) for the sealed ``embeddings`` table."""
        return self.embeddings.reencrypt(conn, old_dek_ids, limit)

    def withdraw_external(self, access: AccessContext, provider: str) -> list[str]:
        """Queue deletion of what this partition sent to ``provider`` (e.g. after the user revoked
        consent). Deleting external copies is forgetting: it requires FORGET (or ADMIN) and a user
        or host actor. Without ADMIN only items whose local record the caller may see are
        withdrawn, and only when nothing outside the caller's grants (or no longer attributable
        to a local record) is held there - otherwise AccessDenied, like a broad forget. Returns the
        outbox ids this call queued (never a partition-wide count)."""
        if Operation.FORGET not in access.operations and Operation.ADMIN not in access.operations:
            raise AccessDenied("withdrawing data from a provider requires forget or admin rights")
        if access.actor not in (Actor.USER, Actor.HOST):
            raise AccessDenied("forgetting is a user or host action")
        name = v.check_id(provider, "provider")
        admin = Operation.ADMIN in access.operations
        cause = self.p.token("provider-cause", f"withdraw|{access.principal}|{name}|{new_id()}")
        with self.p.db.write() as conn:
            live = [(r[0], r[1]) for r in conn.execute(
                f"SELECT external_ref, record_id FROM provider_sync WHERE provider=?"
                f" AND state IN ({','.join('?' * len(_LIVE_SYNC_STATES))})", [name, *_LIVE_SYNC_STATES])]
            if not admin:
                visible = self.records.visible_ids(conn, access.grants, {rid for _, rid in live if rid})
                if any(rid not in visible for _, rid in live):
                    raise AccessDenied("this provider also holds items outside the caller's grants;"
                                       " an admin access context is required")
            rows = [(name, ref) for ref, _ in live]
            self._mark_deleting(conn, rows, cause)
            ids = [r[0] for r in conn.execute(
                "SELECT o.id FROM provider_outbox o JOIN provider_sync s"
                " ON s.provider=o.provider AND s.external_ref=o.target_token"
                " WHERE s.cause_token=? AND o.operation='delete' AND o.state IN ('pending','failed')"
                " ORDER BY o.created_at, o.id", (cause,))]
            self.p.event(conn, "provider_withdraw", "queued", f"{len(ids)}")
        return ids

    def process_outbox(self, access: AccessContext, *, budget: int = 20, include_failed: bool = False,
                       deadline_ms: int | None = None, cancel: Any = None) -> dict[str, Any]:
        """Send queued external deletions (bounded). An item becomes ``done`` only when its
        provider confirms ``deleted``/``not_found``; outages and unconfirmed replies keep it
        pending (``failed`` after ``MAX_DELETE_ATTEMPTS``, still reported as unconfirmed).
        Deletions go only to the provider that received the data - never elsewhere. Deletion
        calls send only opaque refs and are allowed even after consent is withdrawn."""
        self._require_maintenance(access)
        v.check_int(budget, "budget", lo=1, hi=500)
        deadline = self._deadline(deadline_ms)
        states = ("pending", "failed") if include_failed else ("pending",)
        with self.p.db.write() as conn:
            self._mark_deleting(conn, self._orphans(conn), self.p.token("provider-cause", "sweep"))
            rows = conn.execute(
                f"SELECT id, provider, target_token, attempts FROM provider_outbox WHERE operation='delete'"
                f" AND state IN ({','.join('?' * len(states))}) ORDER BY created_at, id LIMIT ?",
                [*states, budget],
            ).fetchall()
        report: dict[str, Any] = {"attempted": 0, "confirmed": [], "pending": [], "gave_up": [],
                                  "deferred": 0, "provider_unavailable": 0, "not_attempted": 0}
        updates: list[tuple[str, str, int, str | None, str, str]] = []
        stop = False
        for outbox_id, name, ref, attempts in rows:
            attempts = int(attempts)
            if stop or _cancelled(cancel) or deadline.expired:
                report["not_attempted"] += 1
                continue
            reg = self._providers.get(name)
            if reg is None or EXTERNAL_DELETE not in reg.capabilities:
                report["provider_unavailable"] += 1
                report["pending"].append(outbox_id)
                updates.append((outbox_id, "pending", attempts, "provider_unavailable", name, ref))
                continue
            report["attempted"] += 1
            try:
                confirmed = self._guard(reg).run(
                    "delete", functools.partial(self._call_delete, reg, ref, outbox_id), units=1,
                    deadline=deadline, cancel=cancel,
                    validate=functools.partial(validate_confirmations, refs=[ref], accepted=_DELETE_CONFIRMED),
                )
            except Cancelled:
                report["not_attempted"] += 1
                stop = True
                continue
            except (CircuitOpen, ProviderRateLimited):
                report["deferred"] += 1
                report["pending"].append(outbox_id)
                continue
            except (ProviderError, DeadlineExceeded) as exc:
                confirmed, error = set(), exc.code
            else:
                error = None if ref in confirmed else "unconfirmed"
            if ref in confirmed:
                report["confirmed"].append(outbox_id)
                updates.append((outbox_id, "done", attempts + 1, None, name, ref))
                continue
            attempts += 1
            state = "failed" if attempts >= self.MAX_DELETE_ATTEMPTS else "pending"
            report["gave_up" if state == "failed" else "pending"].append(outbox_id)
            updates.append((outbox_id, state, attempts, error, name, ref))
        with self.p.db.write() as conn:
            now = self._now()
            for outbox_id, state, attempts, error, name, ref in updates:
                changed = conn.execute(
                    "UPDATE provider_outbox SET state=?, attempts=?, last_error=?, updated_at=?"
                    " WHERE id=? AND state IN ('pending','failed')", (state, attempts, error, now, outbox_id),
                ).rowcount
                if changed and state == "done":
                    conn.execute(
                        "UPDATE provider_sync SET state='deleted', record_id='', updated_at=?"
                        " WHERE provider=? AND external_ref=? AND state='deleting'", (now, name, ref),
                    )
            conn.execute("DELETE FROM provider_outbox WHERE state='done' AND updated_at < ?",
                         (now - self.OUTBOX_DONE_RETENTION_S,))
            report["remaining"] = int(conn.execute(
                "SELECT COUNT(*) FROM provider_outbox WHERE operation='delete' AND state IN ('pending','failed')"
            ).fetchone()[0])
            self._flush_usage(conn)
            self.p.event(conn, "provider_outbox", "processed",
                         f"confirmed={len(report['confirmed'])};pending={len(report['pending'])}")
        return report

    @staticmethod
    def _call_delete(reg: _Registered, ref: str, idempotency_key: str, remaining: float | None) -> Any:
        return reg.provider.delete([ref], idempotency_key=idempotency_key, deadline_s=remaining)

    def reconcile_external(self, access: AccessContext, provider: str, *, deadline_ms: int | None = None,
                           cancel: Any = None) -> dict[str, Any]:
        """Compare what an external service reports with local state. Nothing reported is ever
        imported or used to change a local record: items whose local record is forgotten,
        rejected, expired or already deleted are queued for deletion (again) and ignored;
        unknown items are ignored."""
        self._require_maintenance(access)
        reg = self._get(provider, EXTERNAL_SYNC)
        deadline = self._deadline(deadline_ms)
        try:
            refs = self._guard(reg).run(
                "list", lambda remaining: reg.provider.list_items(deadline_s=remaining), units=1,
                deadline=deadline, cancel=cancel,
                validate=lambda raw: validate_listing(raw, max_items=self.MAX_LIST_ITEMS),
            )
        except MemoryEngineError:
            self._flush_usage()
            raise
        report: Counter[str] = Counter()
        queued: list[str] = []
        cause = self.p.token("provider-cause", f"reconcile|{reg.name}")
        with self.p.db.write() as conn:
            known = {r[0]: (r[1], r[2], int(r[3])) for r in conn.execute(
                "SELECT external_ref, record_id, state, revision FROM provider_sync WHERE provider=?", (reg.name,))}
            reported: set[str] = set()
            refuse: list[tuple[str, str]] = []
            for ref in refs:
                if ref in reported:
                    continue
                reported.add(ref)
                row = known.get(ref)
                if row is None:
                    report["unknown_ignored"] += 1
                    continue
                record_id, state, revision = row
                if state == "deleting":
                    report["deletion_pending"] += 1
                    queued.append(self._ensure_outbox(conn, reg.name, ref, self._now()))
                    continue
                if state == "deleted":
                    report["resurrection_refused"] += 1
                    refuse.append((reg.name, ref))
                    continue
                local = conn.execute("SELECT lifecycle, revision FROM records WHERE id=?", (record_id,)).fetchone()
                if local is None or local[0] in _REMOVED_LIFECYCLES:
                    report["locally_removed_refused"] += 1
                    refuse.append((reg.name, ref))
                    continue
                report["in_sync" if state == "synced" and int(local[1]) == revision else "out_of_date"] += 1
            queued += self._mark_deleting(conn, refuse, cause)
            report["missing_remotely"] = sum(1 for ref, row in known.items() if row[1] == "synced" and ref not in reported)
            self._flush_usage(conn)
            self.p.event(conn, "provider_reconcile", "ok", f"refused={len(refuse)}")
        return {"provider": reg.name, "imported": 0, "queued_deletions": sorted(set(queued)), **dict(report)}

    # ------------------------------------------------------------------ reporting & hygiene
    def usage(self, access: AccessContext, *, limit: int = 200) -> list[dict[str, Any]]:
        """Usage receipts, newest first. ``cost_micros`` is None when the cost is unknown
        (``cost_known=False``) - unknown is never reported as zero."""
        self._require_maintenance(access)
        v.check_int(limit, "limit", lo=1, hi=10_000)
        self._flush_usage()
        with self.p.db.read() as conn:
            rows = conn.execute(
                "SELECT id, provider, operation, created_at, units, cost_micros, cost_known, outcome FROM usage_log"
                " ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,),
            ).fetchall()
        return [{"id": r[0], "provider": r[1], "operation": r[2], "created_at": float(r[3]),
                 "units": None if r[4] is None else int(r[4]),
                 "cost_micros": None if not r[6] or r[5] is None else int(r[5]),
                 "cost_known": bool(r[6]), "outcome": r[7]} for r in rows]

    def drop_unregistered_models(self, access: AccessContext) -> int:
        """Delete vectors whose model key belongs to no registered embedding provider."""
        self._require_maintenance(access)
        keep = {self.embeddings.model_key(r.descriptor, HUB_PREPROCESSING)
                for r in self._providers.values() if EMBED in r.capabilities}
        with self.p.db.write() as conn:
            return self.embeddings.delete_models_except(conn, keep)

    def _consent_state(self, access: AccessContext, reg: _Registered) -> dict[str, Any]:
        if not reg.descriptor.egress:
            return {"state": "not_required", "reason": "local provider (no egress)"}
        if self.ctx.host.consent is None:
            return {"state": "disabled", "reason": "no consent policy supplied by the host"}
        grants = self._grants(access, reg)
        if not grants:
            return {"state": "none"}
        classes = sorted({dc for g in grants for dc in g.data_classes
                          if (dc != "transcripts" or g.allow_transcripts)
                          and (dc != "repository_source" or g.allow_source)})
        return {"state": "granted", "data_classes": classes,
                "profile_wide": any(g.scope is None for g in grants),
                "scoped_grants": sum(1 for g in grants if g.scope is not None),
                "expires_at": min((g.expires_at for g in grants if g.expires_at is not None), default=None)}

    def status(self, access: AccessContext) -> dict[str, Any]:
        """Registered providers, negotiated capabilities, consent, circuit and egress state.

        No secrets (only host-registered descriptor fields) and no counts outside the
        caller's grants; the partition-wide external-deletion backlog needs MAINTAIN/ADMIN.
        """
        policy.require(access, Operation.READ)
        providers: dict[str, Any] = {}
        with self.p.db.read() as conn:
            for name, reg in self._providers.items():
                d = reg.descriptor
                entry: dict[str, Any] = {
                    "capabilities": sorted(reg.capabilities), "egress": d.egress, "model": d.model,
                    "version": d.version, "dimensions": d.dimensions,
                    "preprocessing_version": d.preprocessing_version,
                    "data_classes_accepted": sorted(d.data_classes_accepted),
                    "cost": "unknown" if d.cost_per_unit_micros is None else "per_unit_micros",
                    "cost_per_unit_micros": d.cost_per_unit_micros,
                    "notes": d.notes, "circuit": reg.breaker.snapshot(), "consent": self._consent_state(access, reg),
                }
                if reg.declared_without_methods:
                    entry["unsupported_declared"] = list(reg.declared_without_methods)
                if EMBED in reg.capabilities:
                    mk = self.embeddings.model_key(d, HUB_PREPROCESSING)
                    entry["embeddings"] = {"model_key": mk, "score_kind": SCORE_KIND_SEMANTIC,
                                           **self.embeddings.count_authorized(conn, self.records, access.grants, mk)}
                providers[name] = entry
            backlog = None
            if Operation.MAINTAIN in access.operations or Operation.ADMIN in access.operations:
                backlog = {r[0]: int(r[1]) for r in conn.execute(
                    "SELECT provider, COUNT(*) FROM provider_outbox WHERE operation='delete'"
                    " AND state IN ('pending','failed') GROUP BY provider")}
        out: dict[str, Any] = {
            "external_egress": "disabled" if self.ctx.host.consent is None else "consent_policy",
            "registered": providers,
            "rejected_registrations": dict(self._rejected),
            "score_kinds": {"semantic": f"{SCORE_KIND_SEMANTIC} (similarity in [-1, 1]; not a probability)",
                            "rerank": f"{SCORE_KIND_RERANK} (provider ordering value; not a probability)"},
            "limitations": [
                "provider deadlines are cooperative: a late reply is discarded, a hung call is not preempted",
                "content already sent to an external provider cannot be recalled; deletion is requested and"
                " counted as done only on provider confirmation",
                "fake providers (model names starting with 'fake-') are deterministic test doubles,"
                " not semantic models",
            ],
        }
        if backlog is not None:
            out["pending_external_deletions"] = backlog
        return out


class _Deferred(Exception):
    """Internal: usage flush postponed until no transaction is open on this thread."""
