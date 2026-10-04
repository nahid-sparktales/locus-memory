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
  external service that received the data - by the mapping, and by each deleting
  service's own replica ref of every forgotten record, so a lost or tampered mapping
  never cancels one; ``done`` only on provider confirmation; a third party can never
  resurrect a forgotten or rejected record).

Outages never change *where* data goes: provider selection is deterministic
(registration order, local before egress, consent) and independent of health, so a
failing provider makes the call fail or degrade - it never fails over to another
provider or account, and the outbox only ever sends a provider its own refs.
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
    DATA_REPOSITORY_SOURCE,
    DATA_TRANSCRIPTS,
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

# How the hub turns a record into provider input. Part of every embedding model key. Version 2: the
# text is always built from the authenticated stored record (never from a caller-supplied object), so
# vectors an earlier build cached under version 1 - possibly from a forged title - are never reused.
HUB_PREPROCESSING = "hub-text-2"  # title (unless a prefix of content) + content, secrets redacted
SCORE_KIND_SEMANTIC = "cosine"  # cosine similarity in [-1, 1]; not a probability
SCORE_KIND_RERANK = "provider_relevance"  # opaque provider ordering value; not a probability

_SYNC_ACCEPTED = frozenset({"stored"})
_DELETE_CONFIRMED = frozenset({"deleted", "not_found"})
_LIVE_SYNC_STATES = ("sending", "synced", "unconfirmed")
_REMOVED_LIFECYCLES = ("rejected", "expired", "forgotten")
# Local lifecycles whose external replica is withdrawn: removed, and no longer current (superseded,
# stale) - an external service keeps no lifecycle and would present it as current. A record that
# becomes approved again (revert, revalidation) is re-sent by the next sync.
_WITHDRAW_LIFECYCLES = (*_REMOVED_LIFECYCLES, "superseded", "stale")
# The withdrawal sweep (process_outbox, reconcile_external) decrypts at most this many synced records
# per lane and call, outside the store's write lock (see ProviderHub._sweep_plan): read-time expiry
# or validity end (selected by the time columns), every live replica round-robin (no plaintext column
# alone ever decides that a replica stays) and - after the exclusion set changed - the records an
# exclusion can hide.
SWEEP_BATCH = 64
SWEEP_EXCLUSION_BATCH = 256
_SWEEP_META = "provider_sweep:"
_EXCLUSION_INPUT_KINDS = (SourceKind.MEMORY.value, SourceKind.COMMIT.value, SourceKind.BLOB_RANGE.value)


@dataclass
class _SweepPlan:
    """What the withdrawal sweep read outside the write lock: record id -> (row stamp it judged,
    ``"withdraw"`` | ``"unreadable"``) for the replicas to withdraw, and the cursor updates."""

    flagged: dict[str, tuple[tuple[int, str, bytes], str]]
    meta: dict[str, str]
# Memory evidence an extractor may receive (read-time lifecycle).
_EXTRACTABLE_LIFECYCLES = frozenset({Lifecycle.APPROVED, Lifecycle.CANDIDATE})
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
    # The authoritative scope of the data the text comes from (the cited memory, session or
    # repository registration); consent must cover it, not only the narrowed candidate scope.
    data_scope: Scope | None = None


# The data class of extraction evidence follows from the kind of source it cites - never from the
# caller's label alone, which may only make it stricter (consent for transcripts and repository
# source needs the grant's explicit flags). Evidence of any other kind is refused before egress:
# its text cannot be checked against what the source said.
_EVIDENCE_DATA_CLASS = {
    SourceKind.MEMORY: DATA_MEMORY_TEXT,
    SourceKind.MESSAGE: DATA_TRANSCRIPTS, SourceKind.SESSION: DATA_TRANSCRIPTS,
    SourceKind.COMMIT: DATA_REPOSITORY_SOURCE, SourceKind.BLOB_RANGE: DATA_REPOSITORY_SOURCE,
}


# Source kinds whose citation makes a record repository content (see ProviderHub._record_data_class).
_REPOSITORY_SOURCE_KINDS = frozenset({SourceKind.COMMIT, SourceKind.BLOB_RANGE})
# How far the restatement of repository content is followed through derived_from / cited memories.
_DATA_CLASS_DEPTH = 8


def _stricter_class(declared: str, actual: str) -> str:
    """The class evidence is sent under once the cited record's own class is known: never looser
    than the record's (a memory_text label on repository content is raised to it)."""
    if actual == DATA_MEMORY_TEXT or declared == actual:
        return declared
    if declared == DATA_MEMORY_TEXT:
        return actual
    raise ValidationError("the evidence data class does not match its source")


def _evidence_data_class(source: SourceRef, declared: Any) -> str:
    derived = _EVIDENCE_DATA_CLASS.get(source.kind)
    if derived is None:
        raise ValidationError("evidence of this source kind cannot be sent to an extractor")
    if declared is None or declared == derived:
        return derived
    if declared not in DATA_CLASSES:
        raise ValidationError("unknown evidence data class")
    if derived == DATA_MEMORY_TEXT:
        return declared  # stricter than memory text: the stricter consent applies
    if declared == DATA_MEMORY_TEXT:
        return derived  # a looser label never lowers the consent a transcript or source file needs
    raise ValidationError("the evidence data class does not match its source")


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

    def admissible(self, records: list[MemoryRecord]) -> list[MemoryRecord]:
        """The records whose data class this provider may receive (:meth:`ProviderHub.summary_admissible`);
        a caller such as consolidation leaves the others out instead of having the whole call refused."""
        return self._hub.summary_admissible(self._access, self.provider, records)


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

    def _admissible(self, reg: _Registered, grants: list[ConsentGrant] | None, scope: Scope,
                    data_class: str) -> bool:
        """Whether a stored record of ``scope`` and ``data_class`` may be sent to ``reg``: an egress
        provider must accept the class and hold consent covering scope and class; a local provider
        (nothing leaves the device) receives what it is registered for."""
        if not reg.descriptor.egress:
            return True
        return data_class in reg.descriptor.data_classes_accepted and self._covers(grants, scope, data_class)

    def _record_data_class(self, conn: Any, record: MemoryRecord, cache: dict[str, str] | None = None,
                           depth: int = 0) -> str:
        """The data class of a stored record's text (from the authenticated record, never a caller's
        object): ``repository_source`` for repository content - an observation, an interchange import
        (``extra.repository_id``), a record citing commits or blob ranges - and for what restates it
        (``links.derived_from`` parents and cited memories, followed a few levels; a parent that no
        longer authenticates counts as repository content: fail closed); ``memory_text`` otherwise.
        Source-derived text never leaves under a memory_text grant just because it was restated."""
        cache = {} if cache is None else cache
        if record.id in cache:
            return cache[record.id]
        extra = record.extra if isinstance(record.extra, dict) else {}
        if (record.kind == MemoryKind.REPOSITORY_OBSERVATION or isinstance(extra.get("repository_id"), str)
                or any(s.kind in _REPOSITORY_SOURCE_KINDS for s in record.sources)):
            cache[record.id] = DATA_REPOSITORY_SOURCE
            return DATA_REPOSITORY_SOURCE
        cache[record.id] = DATA_MEMORY_TEXT  # cycle guard (and the answer when no parent is repository content)
        if depth >= _DATA_CLASS_DEPTH:
            return DATA_MEMORY_TEXT
        parents = list(record.links.derived_from) + [s.ref for s in record.sources if s.kind == SourceKind.MEMORY]
        for parent_id in dict.fromkeys(p for p in parents if p != record.id):
            if parent_id in cache:
                verdict = cache[parent_id]
            else:
                try:
                    parent = self.records.get(conn, parent_id)
                except MemoryEngineError:
                    parent, verdict = None, DATA_REPOSITORY_SOURCE
                else:
                    verdict = DATA_MEMORY_TEXT
                if parent is not None:
                    verdict = self._record_data_class(conn, parent, cache, depth + 1)
                cache[parent_id] = verdict
            if verdict == DATA_REPOSITORY_SOURCE:
                cache[record.id] = DATA_REPOSITORY_SOURCE
                return DATA_REPOSITORY_SOURCE
        return DATA_MEMORY_TEXT

    def _authoritative(self, conn: Any, record: MemoryRecord) -> MemoryRecord | None:
        """The stored, authenticated record behind a verified caller-supplied one (same revision), or
        None (changed since, gone, or no longer authenticating). What is sent to a provider or cached
        as a vector is built from it, never from the caller's object (whose title, sources and extra
        nothing verified)."""
        try:
            stored = self.records.get(conn, record.id)
        except MemoryEngineError:
            return None
        if stored is None or stored.revision != record.revision or stored.kind != record.kind:
            return None
        return stored

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

        A record is kept when its claimed scope is granted, the stored row has the same
        revision, kind, scope token and content token - so a stale or forged object can never
        steer what is sent to a provider or cached as a vector - and it is servable now
        (``core.unservable``: not an observation of a now-excluded path, not expired at read
        time; counted as ``excluded`` / ``expired``).
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
        rows: dict[str, tuple[int, str, str, str]] = {}
        with self.p.db.read() as conn:
            observed = self.p.deletion_generation(conn)
            ids = [r.id for r in candidates]
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                for row in conn.execute(
                    f"SELECT id, revision, scope_token, content_token, kind FROM records"
                    f" WHERE id IN ({','.join('?' * len(chunk))})", chunk,
                ):
                    rows[row[0]] = (int(row[1]), row[2], row[3], row[4])
            # Observations of now-excluded paths and records expired at read time never leave the
            # store (embedding, reranking), whoever supplied them.
            hidden = self._unservable(conn, candidates)
        stats.update(hidden.values())
        candidates = [r for r in candidates if r.id not in hidden]
        verified = []
        scope_tokens: dict[str, str] = {}
        for record in candidates:
            row = rows.get(record.id)
            if row is None or row[0] != record.revision or row[3] != record.kind.value:
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

    def _unservable(self, conn: Any, records: list[MemoryRecord]) -> dict[str, str]:
        """``core.unservable``: {id: "excluded" | "expired"} for records that must not be sent."""
        core = self.ctx.services.core
        check = getattr(core, "unservable", None) if core is not None else None
        return check(conn, records, self._now()) if callable(check) and records else {}

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
        can_write = not self.p.db.conn.in_transaction
        budget = max(0, min(self.MAX_LAZY_EMBED, desc.max_batch - 1)) if can_write else 0
        usable: dict[str, tuple[float, ...]] = {}
        rebase: list[tuple[MemoryRecord, StoredVector]] = []
        batch: list[tuple[MemoryRecord, str, str]] = []
        deferred = 0
        with self.p.db.read() as conn:
            stored = self.embeddings.load(conn, mk, [r.id for r in verified], dimensions=dims)
            classes: dict[str, str] = {}
            for record in verified:
                vector = stored.get(record.id)
                if vector is not None and vector.revision == record.revision:
                    # Every vector is computed from the authenticated stored text at its revision
                    # (below), so a vector at the record's revision is the vector of its text.
                    usable[record.id] = vector.vector
                    continue
                if vector is None and len(batch) >= budget:
                    deferred += 1  # nothing to reuse and no room this call: not read at all
                    continue
                # What is embedded (and cached) or rebased is the stored record's own text - never a
                # caller-supplied object's (only its revision, kind, scope and content are verified).
                authentic = self._authoritative(conn, record)
                if authentic is None:
                    coverage["stale_or_unknown"] = coverage.get("stale_or_unknown", 0) + 1
                    continue
                rtext = _record_text(authentic)
                token = self.embeddings.text_token(rtext)
                if vector is not None and vector.text_token == token:
                    usable[record.id] = vector.vector
                    rebase.append((authentic, vector))  # same text, newer revision: still valid
                    continue
                if not self._admissible(reg, grants, authentic.scope,
                                        self._record_data_class(conn, authentic, classes)):
                    coverage["not_consented"] = coverage.get("not_consented", 0) + 1
                    continue
                if len(batch) >= budget:
                    deferred += 1
                    continue
                batch.append((authentic, rtext, token))
        coverage["deferred"] = deferred
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
        bound = min(self.MAX_RERANK, reg.descriptor.max_batch)
        batch: list[MemoryRecord] = []
        deferred = 0
        with self.p.db.read() as conn:
            classes: dict[str, str] = {}
            for record in verified:
                if len(batch) >= bound:
                    deferred += 1
                    continue
                # The text sent is the stored record's (never a caller-supplied title), and its data
                # class decides the consent it needs.
                authentic = self._authoritative(conn, record)
                if authentic is None:
                    coverage["stale_or_unknown"] = coverage.get("stale_or_unknown", 0) + 1
                elif self._admissible(reg, grants, authentic.scope, self._record_data_class(conn, authentic, classes)):
                    batch.append(authentic)
                else:
                    coverage["not_consented"] = coverage.get("not_consented", 0) + 1
        coverage["deferred"] = deferred
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
            data_class = _evidence_data_class(source, raw.get("data_class"))
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
        an authorized session; anything unverifiable is refused *before* egress), the text
        must be an excerpt of what the cited source says, and consent must cover provider +
        scope + data class. The data class follows from the source kind (message/session:
        transcripts; commit/blob_range: repository source; memory: memory text); the caller's
        ``data_class`` may only make it stricter, and other source kinds are refused. Output is validated strictly
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
            classes: dict[str, str] = {}
            for e in items:
                (source,) = core.verify_sources(conn, provider_access, (e.source,))
                scope = e.scope
                data_class = e.data_class
                authoritative: Scope | None = None
                if source.kind == SourceKind.MEMORY:
                    record = core.load_visible(conn, provider_access, source.ref)
                    # The "servable now" rule of every other egress path, before anything is sent:
                    # an observation of a now-excluded path is not found (as get()); a record expired
                    # at read time, or rejected, superseded, stale or forgotten, is no evidence to
                    # extract from (its statement would be re-proposed in new wording).
                    reason = self._unservable(conn, [record]).get(record.id)
                    if reason == "excluded":
                        raise NotFound("memory not found")
                    if reason is not None or core.effective_lifecycle(record, self._now()) not in _EXTRACTABLE_LIFECYCLES:
                        raise StaleDerivation("memory evidence is no longer current (expired, rejected, superseded"
                                              " or stale); nothing was sent")
                    if e.text not in record.content and e.text not in f"{record.title}\n{record.content}":
                        # A citation must point at what was actually said, not at arbitrary text.
                        raise ValidationError("memory evidence text must be an excerpt of its source memory")
                    authoritative = record.scope
                    # The data class is the cited record's: a repository observation (or anything
                    # restating repository content) quoted through its memory record is repository
                    # source, exactly as when the blob is cited (consent and acceptance below).
                    data_class = _stricter_class(e.data_class, self._record_data_class(conn, record, classes))
                else:
                    # The same rule for transcripts and repository objects: the text must be what
                    # the cited message, session or object says (read under the provider context,
                    # scope filtered before decryption), or the citation would lend invented text
                    # transcript or source provenance. Unverifiable is refused before egress.
                    owner = history if source.kind in (SourceKind.MESSAGE, SourceKind.SESSION) \
                        else self.ctx.services.repository
                    checker = getattr(owner, "evidence_excerpt", None) if owner is not None else None
                    if not callable(checker) or checker(conn, provider_access, source, e.text) is not True:
                        raise ValidationError("evidence text must be an excerpt of its cited source")
                    # A transcript's scope is its session's, a repository object's its registration's:
                    # a declared scope can only narrow it, never move it (consent is checked again on
                    # this authoritative scope).
                    authoritative = core.source_scope(conn, source)
                if authoritative is not None:
                    merged = _merge_scopes([scope, authoritative])
                    if merged is None:
                        raise ValidationError("evidence scope does not match its source")
                    scope = merged
                policy.require_scope(access, scope)
                resolved.append(dataclasses.replace(e, scope=scope, source=source, data_scope=authoritative,
                                                    data_class=data_class))
        for data_class in sorted({e.data_class for e in resolved}):
            if data_class not in reg.descriptor.data_classes_accepted:
                raise UnsupportedCapability("the provider does not accept this data class",
                                            details={"provider": reg.name, "data_class": data_class})
        # ... and again on the authoritative scopes and classes: the scope of the data actually sent (a
        # grant for an unrelated scope never covers a source just because the caller declared a narrower
        # scope inside the granted one), the candidate's scope, and the cited record's data class.
        self._require_consent(access, reg, [(e.scope, e.data_class) for e in resolved]
                              + [(e.data_scope, e.data_class) for e in resolved if e.data_scope is not None])
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

    def summary_admissible(self, access: AccessContext, provider: str, records: Iterable[Any]) -> list[MemoryRecord]:
        """Of ``records`` (stored records the caller may see), those whose data class ``provider`` may
        receive for summarization: memory text, and repository content (``_record_data_class``) only
        when an egress provider accepts that class and holds consent for it in the record's scope.
        (Consent for the scope of memory text is checked by every :meth:`summarize` call itself.)
        The order is kept."""
        policy.require(access, Operation.READ)
        reg = self._get(provider, SUMMARIZE, DATA_MEMORY_TEXT)
        records = [r for r in records if isinstance(r, MemoryRecord) and access.grants.allows(r.scope)]
        if not reg.descriptor.egress or not records:
            return records
        grants = self._grants(access, reg) if self.ctx.host.consent is not None else []
        out: list[MemoryRecord] = []
        with self.p.db.read() as conn:
            classes: dict[str, str] = {}
            for record in records:
                authentic = self._authoritative(conn, record)
                if authentic is None:
                    continue
                data_class = self._record_data_class(conn, authentic, classes)
                if data_class == DATA_MEMORY_TEXT or self._admissible(reg, grants, authentic.scope, data_class):
                    out.append(record)
        return out

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
                reason = self._unservable(conn, [record]).get(record.id)
                if reason == "excluded":
                    raise NotFound("memory not found")  # an observation of a now-excluded path
                if reason is not None:
                    raise StaleDerivation("a summary input expired since it was read")
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
        # ... and again on the authoritative scopes and each record's data class, just before egress
        # (repository content - an observation, or what restates one - needs repository_source).
        with self.p.db.read() as conn:
            classes: dict[str, str] = {}
            needs = [(r.scope, self._record_data_class(conn, r, classes)) for r in records]
        if reg.descriptor.egress:
            for data_class in sorted({c for _scope, c in needs}):
                if data_class not in reg.descriptor.data_classes_accepted:
                    raise UnsupportedCapability("the provider does not accept this data class",
                                                details={"provider": reg.name, "data_class": data_class})
        self._require_consent(access, reg, needs)
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
        Requires READ and EXPORT. Consent is checked per record for its scope and its data class
        (``memory_text``, or ``repository_source`` for repository content and what restates it:
        :meth:`_record_data_class`); scope values and sources are never sent (payload: opaque ref,
        kind, title, content with secrets redacted, revision)."""
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
        classes: dict[str, str] = {}
        with self.p.db.read() as conn:
            ids = [r[0] for r in conn.execute(
                "SELECT r.id FROM records r WHERE r.lifecycle='approved' AND NOT EXISTS ("
                " SELECT 1 FROM provider_sync s WHERE s.provider=? AND s.record_id=r.id"
                " AND s.state='synced' AND s.revision=r.revision) ORDER BY r.updated_at, r.id", (reg.name,))]
            selected: list[MemoryRecord] = []
            for start in range(0, len(ids), 500):
                if len(selected) >= limit:
                    break
                batch = self.records.authorized(conn, grants, lifecycles=(Lifecycle.APPROVED,),
                                                ids=ids[start:start + 500])
                # Never sent: observations of now-excluded paths and records whose retention ended
                # (read-time expiry, before maintenance persists it) or whose validity ended (stale at
                # read time: it would be withdrawn again). Paging continues past them.
                hidden = self._unservable(conn, batch)
                core = self.ctx.services.core
                now = self._now()
                hidden.update({r.id: "stale" for r in batch if r.id not in hidden and core is not None
                               and core.effective_lifecycle(r, now) != Lifecycle.APPROVED})
                for record in batch:
                    if len(selected) >= limit:
                        break
                    if record.id in hidden:
                        skipped[hidden[record.id]] += 1
                        continue
                    # Consent per record: its scope and its data class (repository observations and
                    # what restates them are repository source, never sent under memory_text alone).
                    if not self._admissible(reg, consent, record.scope,
                                            self._record_data_class(conn, record, classes)):
                        skipped["not_consented"] += 1
                        continue
                    selected.append(record)
        items: list[tuple[MemoryRecord, dict[str, Any]]] = []
        for record in selected:
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
                    late = self._unservable(conn, [record]).get(record.id)
                    if late is not None:  # expired (or excluded) since it was selected
                        skipped[late] += 1
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

    def _orphans(self, conn: Any, lifecycles: tuple[str, ...] = _REMOVED_LIFECYCLES) -> list[tuple[str, str]]:
        """Synced items whose local record is gone or has one of ``lifecycles`` (default: rejected,
        expired or forgotten)."""
        return [(r[0], r[1]) for r in conn.execute(
            "SELECT s.provider, s.external_ref FROM provider_sync s LEFT JOIN records r ON r.id = s.record_id"
            f" WHERE s.state IN ({','.join('?' * len(_LIVE_SYNC_STATES))})"
            f" AND (r.id IS NULL OR r.lifecycle IN ({','.join('?' * len(lifecycles))}))",
            [*_LIVE_SYNC_STATES, *lifecycles],
        )]

    @staticmethod
    def _row_stamp(conn: Any, record_id: str) -> tuple[int, str, bytes] | None:
        """(revision, lifecycle column, nonce) of a record row: any rewrite of the row changes it."""
        row = conn.execute("SELECT revision, lifecycle, nonce FROM records WHERE id=?", (record_id,)).fetchone()
        return None if row is None else (int(row[0]), str(row[1]), bytes(row[2] or b""))

    def _judge(self, conn: Any, record_ids: Iterable[str], now: float
               ) -> dict[str, tuple[tuple[int, str, bytes], str]]:
        """Record id -> (row stamp, verdict) judged on the *authenticated* record: ``"current"``,
        ``"withdraw"`` (not approved now - expired, stale or superseded at read time - or not servable:
        an observation of a now-excluded path or what restates one, an unbacked procedure) or
        ``"unreadable"`` (the row no longer authenticates: a plaintext column edited outside the
        store, e.g. its lifecycle or expiry). Rows that no longer exist are left out."""
        out: dict[str, tuple[tuple[int, str, bytes], str]] = {}
        records: dict[str, MemoryRecord] = {}
        for record_id in dict.fromkeys(record_ids):
            stamp = self._row_stamp(conn, record_id)
            if stamp is None:
                continue
            try:
                record = self.records.get(conn, record_id)
            except MemoryEngineError:
                out[record_id] = (stamp, "unreadable")
                continue
            if record is None:
                continue
            records[record_id] = record
            out[record_id] = (stamp, "current")
        core = self.ctx.services.core
        gone = set(self._unservable(conn, list(records.values())))
        gone |= {rid for rid, record in records.items()
                 if core is not None and core.effective_lifecycle(record, now) != Lifecycle.APPROVED}
        for record_id in gone:
            out[record_id] = (out[record_id][0], "withdraw")
        return out

    def _exclusion_state(self, conn: Any) -> str | None:
        repository = self.ctx.services.repository
        state = getattr(repository, "exclusion_state", None) if repository is not None else None
        return state(conn) if callable(state) else None

    def _sweep_plan(self) -> _SweepPlan:
        """The decrypting part of the withdrawal sweep, in a read snapshot - never under the write lock.

        Which replicas the plaintext columns cannot decide is judged on the authenticated record
        (:meth:`_judge`), in bounded batches per call (keyset cursors in ``meta``):

        * ``time`` - approved rows whose time columns say retention or validity ended (expired or
          stale at read time before maintenance persists it), ``SWEEP_BATCH`` per call;
        * ``exclusion`` - only while the repository exclusion set differs from the one the last
          complete pass checked: observations, summaries and records derived from a memory or citing
          repository objects, ``SWEEP_EXCLUSION_BATCH`` per call;
        * ``all`` - every live replica of a record stored as approved, round-robin, ``SWEEP_BATCH`` per
          call: a row whose plaintext columns were edited (expiry cleared, pinned set, a superseded
          lifecycle relabelled approved) fails authentication here and is withdrawn within
          ceil(replicas / SWEEP_BATCH) calls.

        Rows the plaintext columns already condemn (gone, or stored with a non-current lifecycle) need
        no decryption: :meth:`_sweep_apply` marks them under the write lock."""
        now = self._now()
        live = f"s.state IN ({','.join('?' * len(_LIVE_SYNC_STATES))})"
        meta: dict[str, str] = {}
        ids: list[str] = []
        with self.p.db.read() as conn:

            def get(key: str) -> str:
                row = conn.execute("SELECT value FROM meta WHERE key=?", (_SWEEP_META + key,)).fetchone()
                return str(row[0]) if row is not None else ""

            def lane(name: str, condition: str, params: list[Any], limit: int, cursor: str | None = None) -> bool:
                start = get(f"cursor:{name}") if cursor is None else cursor
                rows = [r[0] for r in conn.execute(
                    "SELECT DISTINCT s.record_id FROM provider_sync s JOIN records r ON r.id = s.record_id"
                    f" WHERE {live} AND r.lifecycle='approved' AND s.record_id > ? AND ({condition})"
                    " ORDER BY s.record_id LIMIT ?", [*_LIVE_SYNC_STATES, start, *params, limit])]
                ids.extend(rows)
                done = len(rows) < limit
                meta[f"cursor:{name}"] = "" if done else rows[-1]
                return done

            lane("time", "(r.expires_at IS NOT NULL AND r.expires_at < ? AND r.pinned=0)"
                 " OR (r.valid_until IS NOT NULL AND r.valid_until < ?)", [now, now], SWEEP_BATCH)
            state = self._exclusion_state(conn)
            if state is not None and state != get("exclusions_checked"):
                restart = get("exclusions_pass") != state
                meta["exclusions_pass"] = state
                marks = ",".join("?" * len(_EXCLUSION_INPUT_KINDS))
                if lane("exclusion", f"r.kind IN (?, ?) OR EXISTS (SELECT 1 FROM derivations d WHERE"
                        f" d.derived_id = r.id AND d.input_kind IN ({marks}))",
                        [MemoryKind.REPOSITORY_OBSERVATION.value, MemoryKind.SUMMARY.value, *_EXCLUSION_INPUT_KINDS],
                        SWEEP_EXCLUSION_BATCH, cursor="" if restart else None):
                    meta["exclusions_checked"] = state
            lane("all", "1=1", [], SWEEP_BATCH)
            judged = self._judge(conn, ids, now)
        return _SweepPlan({rid: verdict for rid, verdict in judged.items() if verdict[1] != "current"}, meta)

    def _sweep_apply(self, conn: Any, plan: _SweepPlan) -> list[tuple[str, str]]:
        """Inside a write transaction: the replicas to withdraw - synced items whose local record is
        gone or stored with a non-current lifecycle (``_WITHDRAW_LIFECYCLES``; SQL only) and those
        :meth:`_sweep_plan` condemned whose record row is still exactly the one it judged (a row
        rewritten since is judged again by a later sweep) - and the sweep cursors."""
        rows = self._orphans(conn, _WITHDRAW_LIFECYCLES)
        live = ",".join("?" * len(_LIVE_SYNC_STATES))
        for record_id, (stamp, _verdict) in sorted(plan.flagged.items()):
            if self._row_stamp(conn, record_id) != stamp:
                continue
            rows += [(r[0], r[1]) for r in conn.execute(
                f"SELECT provider, external_ref FROM provider_sync WHERE record_id=? AND state IN ({live})",
                [record_id, *_LIVE_SYNC_STATES])]
        for key, value in plan.meta.items():
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (_SWEEP_META + key, value))
        return list(dict.fromkeys(rows))

    def queue_deletion(self, conn: Any, kind: str, token: str) -> list[str]:
        """Queue external deletions for a forget target, from the target token alone.

        Called inside the forget transaction (after local purging). Every external item
        whose local record no longer exists (or is rejected/expired) is moved to
        ``deleting`` with an outbox row per provider that received it; for ``profile``
        everything held externally is queued. Returns the pending outbox ids attributable
        to this target (including the derived-ref deletions :meth:`queue_removed_records`
        queued for it). Idempotent.
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

    def _delete_capable(self) -> list[str]:
        return sorted(reg.name for reg in self._providers.values() if EXTERNAL_DELETE in reg.capabilities)

    def queue_removed_records(self, conn: Any, kind: str, token: str, record_ids: Iterable[str]) -> int:
        """Inside a forget (live or replayed), before :meth:`purge`: queue the external deletion of
        every record the forget removed, at every registered provider that deletes, by the replica
        ref derived from the record id (:meth:`_external_ref`) - whether or not a ``provider_sync``
        row maps it. That table is plaintext: rows deleted by a tamperer, or lost to the restore of
        a backup taken before a sync, must never cancel the deletion of a replica. A provider that
        never held the ref answers not_found (harmless). The deletions are attributed to this
        target (its receipt's ``pending_external``). Returns the number of refs newly queued."""
        providers = self._delete_capable()
        ids = sorted({str(i) for i in record_ids if i})
        if not providers or not ids:
            return 0
        cause = self.p.token("provider-cause", f"{kind}|{token}")
        now = self._now()
        queued = 0
        for name in providers:
            for record_id in ids:
                ref = self._external_ref(name, record_id)
                row = conn.execute("SELECT state FROM provider_sync WHERE provider=? AND external_ref=?",
                                   (name, ref)).fetchone()
                if row is not None and row[0] == "deleted":
                    continue  # the provider already confirmed its deletion
                if row is None:
                    conn.execute(
                        "INSERT INTO provider_sync(provider, external_ref, record_id, revision, state, cause_token,"
                        " created_at, updated_at) VALUES(?,?,'',0,'deleting',?,?,?)", (name, ref, cause, now, now))
                else:
                    conn.execute("UPDATE provider_sync SET state='deleting', record_id='', cause_token=?, updated_at=?"
                                 " WHERE provider=? AND external_ref=?", (cause, now, name, ref))
                self._ensure_outbox(conn, name, ref, now)
                queued += 1
        return queued

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
        A deletion goes only to the provider whose ref it is (the one that received the data, or that
        may hold a replica of a forgotten record) - never elsewhere, never failed over. Deletion
        calls send only opaque refs and are allowed even after consent is withdrawn.

        First the withdrawal sweep queues replicas of records that are no longer current (see
        :meth:`_sweep_plan` / :meth:`_sweep_apply`): its decryption is bounded per call and runs
        before the write lock is taken; under the lock only SQL and a compare-and-swap run."""
        self._require_maintenance(access)
        v.check_int(budget, "budget", lo=1, hi=500)
        deadline = self._deadline(deadline_ms)
        states = ("pending", "failed") if include_failed else ("pending",)
        plan = self._sweep_plan()  # decrypts (bounded) before the write lock is taken
        with self.p.db.write() as conn:
            self._mark_deleting(conn, self._sweep_apply(conn, plan), self.p.token("provider-cause", "sweep"))
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

    def _forgotten_refs(self, conn: Any, provider: str) -> dict[str, str]:
        """Replica ref at ``provider`` -> id, for every record a forget removed: memory tombstones and
        the removals the authenticated deletion ledger proves (a tombstone row may be gone)."""
        ids = {str(r[0]) for r in conn.execute("SELECT target_token FROM tombstones WHERE target_kind='memory'")}
        try:
            ids |= set(self.p.deletion_view().removed_records())
        except MemoryEngineError:
            pass
        return {self._external_ref(provider, record_id): record_id for record_id in ids}

    @staticmethod
    def _call_delete(reg: _Registered, ref: str, idempotency_key: str, remaining: float | None) -> Any:
        return reg.provider.delete([ref], idempotency_key=idempotency_key, deadline_s=remaining)

    def reconcile_external(self, access: AccessContext, provider: str, *, deadline_ms: int | None = None,
                           cancel: Any = None) -> dict[str, Any]:
        """Compare what an external service reports with local state. Nothing reported is ever
        imported or used to change a local record: items whose local record is forgotten,
        rejected, expired, superseded, stale (also at read time), excluded or already deleted are
        queued for deletion (again) and ignored; an item the local mapping does not know whose ref
        is this provider's ref of a forgotten record is queued for deletion (``forgotten_refused``);
        other unknown items are ignored. ``out_of_date`` counts approved records changed since they
        were sent (the next ``sync_external`` re-sends them). A mapped item is judged on its
        authenticated local record (decrypted outside the write lock); one whose row no longer
        authenticates is withdrawn (``locally_unreadable_refused``)."""
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
        plan = self._sweep_plan()
        # Every reported item the mapping ties to a local record is judged on the authenticated record
        # (read-time lifecycle, servability, authentication) - never on the plaintext lifecycle column
        # alone - and outside the write lock (bounded by the provider's listing).
        with self.p.db.read() as conn:
            mapped = {r[0]: str(r[1]) for r in conn.execute(
                "SELECT external_ref, record_id FROM provider_sync WHERE provider=?"
                f" AND state IN ({','.join('?' * len(_LIVE_SYNC_STATES))})", [reg.name, *_LIVE_SYNC_STATES])}
            judged = self._judge(conn, [mapped[ref] for ref in dict.fromkeys(refs) if ref in mapped and mapped[ref]],
                                 self._now())
        with self.p.db.write() as conn:
            # Replicas of records that are no longer current are withdrawn first (as by process_outbox).
            withdraw = self._sweep_apply(conn, plan)
            if withdraw:
                ids = self._mark_deleting(conn, withdraw, self.p.token("provider-cause", "sweep"))
                ours = [outbox for (name, _ref), outbox in zip(withdraw, ids, strict=True) if name == reg.name]
                queued += ours
                if ours:
                    report["withdrawn_not_current"] += len(ours)
            known = {r[0]: (r[1], r[2], int(r[3])) for r in conn.execute(
                "SELECT external_ref, record_id, state, revision FROM provider_sync WHERE provider=?", (reg.name,))}
            # Refs the mapping does not know may still be replicas of forgotten records (the mapping is
            # plaintext: lost to a restore or deleted by a tamperer, or the provider was registered
            # after the forget): refs derived from the ids of forgotten records are deleted. Refs that
            # match nothing are left alone (another partition's, on a shared provider).
            forgotten = self._forgotten_refs(conn, reg.name) if any(ref not in known for ref in refs) else {}
            reported: set[str] = set()
            refuse: list[tuple[str, str]] = []
            for ref in refs:
                if ref in reported:
                    continue
                reported.add(ref)
                row = known.get(ref)
                if row is None and ref in forgotten:
                    report["forgotten_refused"] += 1
                    now = self._now()
                    conn.execute(
                        "INSERT OR IGNORE INTO provider_sync(provider, external_ref, record_id, revision, state,"
                        " cause_token, created_at, updated_at) VALUES(?,?,'',0,'deleting',?,?,?)",
                        (reg.name, ref, cause, now, now))
                    queued.append(self._ensure_outbox(conn, reg.name, ref, now))
                    continue
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
                stamp = self._row_stamp(conn, record_id)
                verdict = judged.get(record_id)
                if verdict is not None and verdict[0] != stamp:
                    verdict = None  # rewritten since it was judged: only what SQL proves counts this time
                if stamp is None or stamp[1] in _WITHDRAW_LIFECYCLES or (
                        verdict is not None and verdict[1] == "withdraw"):
                    report["locally_removed_refused"] += 1
                    refuse.append((reg.name, ref))
                    continue
                if verdict is not None and verdict[1] == "unreadable":
                    # The local row no longer authenticates (edited outside the store): what it says
                    # cannot be trusted to keep the replica - withdrawn, and never re-sent while damaged.
                    report["locally_unreadable_refused"] += 1
                    refuse.append((reg.name, ref))
                    continue
                # An approved record at a newer revision: the next sync_external re-sends it.
                report["in_sync" if state == "synced" and stamp[0] == revision else "out_of_date"] += 1
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
