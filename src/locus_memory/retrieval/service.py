"""Memory retrieval: scoped, explainable, bounded search over encrypted records.

Pipeline (each arrow is a stage boundary where cancellation and the deadline are
checked; an interrupted search returns what completed, with PARTIAL/CANCELLED):

1. **Authorized namespace** -- ``policy.require(READ)``, grants narrowed by the
   query's scope filter (never widened), then ``RecordStore.authorized`` filters
   by scope *in SQL*. Unauthorized rows are never decrypted, ranked or counted.
2. **Exact structured lookups** -- query tokens that are syntactically memory ids
   are looked up directly (authorized SQL, independent of projection bounds); an
   exact id match is placed first. Whole identifiers/paths/dates in the query
   (``src/foo_bar.py``, ``MemoryVault.save``, ``PR-123``) form the ``exact`` ranker.
3. **Lexical retrieval** over an in-memory projection (``index.py``): FTS5 BM25 on
   natural text, on whole identifiers, on the exact phrase and on term prefixes;
   or the pure-Python BM25 fallback (``bm25_python``) when FTS5 is unavailable.
4. **Semantic enrichment (optional)** -- ``ctx.services.providers.semantic_scores``
   when the hub provides it. Absent / ``None`` means "not configured" and is not
   a coverage gap; an exception or malformed result is noted in
   ``coverage.partial_reasons`` (``semantic_unavailable:<code>``) and never fails
   the lexical path. Provider scores for ids outside the authorized candidate set
   are ignored.
5. **Reciprocal Rank Fusion** (k = 60, see ``ranking.py``) of the ranked lists.
   BM25 values and cosine similarities are never added together.
6. **Validity** -- future ``valid_from`` excluded; passed ``valid_until`` and
   stale/superseded/expired/rejected lifecycles are historical (``current=False``)
   and demoted below current hits. Stale records are excluded unless
   ``include_stale`` (or STALE is explicitly listed in ``lifecycles``); candidates
   and rejected records only appear when their lifecycle is requested; a
   candidate past its TTL is never returned, even before maintenance runs.
7. **De-duplication** by normalized content (copies are not independent support).
8. **Diversity** -- MMR selection with token Jaccard (heuristic).
9. **Bounded result** -- at most ``limit`` hits; hits are re-verified (still
   present, same revision, still authorized) if the partition changed while the
   search ran, annotated with conflicts the caller is allowed to see, and returned
   as ``core.present`` views (link/evidence ids outside the grants removed).
   Snippets are secret-redacted and markup-neutralized.

Status: CANCELLED when the token fired; UNAVAILABLE when authorized records exist
but none could be indexed (e.g. projection bound 0, every record unreadable);
PARTIAL whenever ``coverage`` is incomplete (projection bound, deadline,
unreadable records, failed ranker or semantic provider, lexical fallback,
truncated query terms); otherwise COMPLETE when at least one hit is a lexical or
exact match, and INSUFFICIENT_EVIDENCE when there is no hit or every hit is weak.
A locked vault raises ``VaultLocked`` (typed), never "no results".

Weak hits. A hit that only the semantic ranker returned (no exact, identifier,
text, phrase or prefix match) carries the reason ``weak_match``: a positive cosine
is a heuristic floor, not a calibrated relevance threshold, so such a hit is
returned but never by itself makes the result COMPLETE. (Real embeddings can match
true paraphrases; the label says "no lexical evidence", not "irrelevant".)

Reproducibility. Every ordering, including ties between equal cosine similarities
or equal fused scores, is broken by ``ranking.tiebreak_key`` (pinned, most recently
updated, content, id), so fresh stores built from the same inputs return the same
order even though record ids are random.

Retrieval never writes: it does not bump use counts, confidence or timestamps
(retrieval frequency must not inflate confidence). Only content-free counters and
timings go to ``ctx.metrics``.

Projection cache: keyed by (partition generation, grants fingerprint, lifecycle
set, kind set, backend, bounds). Any write/correction/forget bumps the generation,
so a stale projection is never served; entries for older generations are dropped
on the next lookup and all entries are dropped eagerly by ``purge``. Projections
are bounded by ``EngineConfig.max_projection_records`` / ``max_projection_bytes``:
the most recently updated (pinned first) records are projected and the rest are
reported in ``coverage.missing`` with status PARTIAL -- never silently omitted.
A rebuild for a newer generation reuses documents whose (id, revision) is
unchanged (membership is always re-derived from the authorized SQL listing), so a
search after a write decrypts and tokenizes only new or changed records.
"""
from __future__ import annotations

import dataclasses
import inspect
import math
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, NamedTuple

from .. import policy
from ..errors import (
    AccessDenied,
    Cancelled,
    IndexUnavailable,
    IntegrityError,
    MemoryEngineError,
    ValidationError,
    VaultLocked,
    WrongKey,
)
from ..host import CancellationToken, Deadline
from ..models import (
    AccessContext,
    Coverage,
    Lifecycle,
    MemoryKind,
    MemoryRecord,
    Operation,
    Query,
    ResultStatus,
    ScopeGrants,
    SearchHit,
    SearchResult,
    canonical_json,
)
from ..services import PartitionContext
from ..storage.partition import partition_bound
from ..validation import check_int, check_timestamp
from . import index as ix
from . import ranking
from .query import MAX_TERMS, ParsedQuery, check_query_text, parse_query

CANDIDATE_CAP = 500  # per ranker; RRF contributions beyond this are < 1/560
DECRYPT_CHUNK = 200  # ids per authorized() call while projecting (deadline checked between)
MAX_CACHE_ENTRIES = 8
MAX_RANK_LIMIT = 1_000
SCORE_KIND = "rrf"
_CONFLICT_LIFECYCLES = (Lifecycle.APPROVED.value, Lifecycle.STALE.value)


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return "an unknown time"


class RankResult(NamedTuple):
    """``rank()`` result: unpacks as ``(hits, coverage, status)`` and exposes the same names."""

    hits: list[SearchHit]
    coverage: Coverage
    status: ResultStatus


# --------------------------------------------------------------------------- projections
class Projection:
    """A built lexical index plus coverage facts. Reference-counted so eviction is safe."""

    def __init__(self, key: tuple, generation: int, docs: list[ix.Doc], index: ix.LexicalIndex, *,
                 total: int, nbytes: int, missing: list[str], partial_reasons: list[str],
                 interrupted: bool, bounded: bool, deletion_generation: int | None = None,
                 write_generations: dict[str, int] | None = None) -> None:
        self.key = key
        self.generation = generation
        # Reuse identity: documents are reused by a newer build only when the record's physical
        # write is the same ((id, revision) alone repeats when a forgotten id is re-created), and
        # never across a deletion (another process's forget never invalidates this cache).
        self.deletion_generation = deletion_generation
        self.write_generations = dict(write_generations or {})
        self.docs = docs
        self.index = index
        self.by_id = {doc.record.id: doc.idx for doc in docs}
        self.total = total
        self.nbytes = nbytes
        self.missing = list(missing)
        self.partial_reasons = list(partial_reasons)
        self.interrupted = interrupted
        self.bounded = bounded
        self._lock = threading.Lock()
        self._refs = 0
        self._retired = False

    @property
    def index_ready(self) -> bool:
        return not self.interrupted and not (self.total > 0 and not self.docs)

    def acquire(self) -> bool:
        with self._lock:
            if self._retired:
                return False
            self._refs += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._refs -= 1
            close = self._retired and self._refs <= 0
        if close:
            self._close()

    def retire(self) -> None:
        with self._lock:
            already = self._retired
            self._retired = True
            close = not already and self._refs <= 0
        if close:
            self._close()

    def _close(self) -> None:
        self.index.close()
        self.docs = []
        self.by_id = {}


@dataclass
class _Run:
    """Mutable per-search bookkeeping (stage interruptions and degradations)."""

    deadline: Deadline
    cancel: Any
    partial_reasons: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    cancelled: bool = False
    deadline_hit: bool = False

    @property
    def stopped(self) -> bool:
        return self.cancelled or self.deadline_hit

    def stop(self, stage: str) -> bool:
        if self.stopped:
            return True
        if self.cancel is not None and getattr(self.cancel, "cancelled", False):
            self.cancelled = True
            self.partial_reasons.append(f"cancelled:{stage}")
            return True
        if self.deadline.expired:
            self.deadline_hit = True
            self.partial_reasons.append(f"deadline_exceeded:{stage}")
            return True
        return False


# --------------------------------------------------------------------------- service
@partition_bound
class RetrievalService:
    RRF_K = ranking.RRF_K

    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx
        self.p = ctx.partition
        self.records = ctx.records
        self._cache: OrderedDict[tuple, Projection] = OrderedDict()
        self._cache_lock = threading.Lock()
        # Monotonic clock for deadlines (injectable for tests); validity uses ctx.clock().
        self.monotonic = time.monotonic

    # ------------------------------------------------------------------ public API
    def search(self, access: AccessContext, query: Query, *,
               cancel: CancellationToken | None = None) -> SearchResult:
        started = time.perf_counter()
        policy.require(access, Operation.READ)
        if not isinstance(query, Query):
            raise ValidationError("query must be a Query")
        grants = policy.narrow(access.grants, query.scope_filter)
        deadline = Deadline(query.deadline_ms, self.monotonic)
        hits, coverage, status = self._execute(
            access, query.text, grants=grants, kinds=query.kinds, lifecycles=query.lifecycles,
            limit=query.limit, since=query.since, until=query.until, at_time=query.at_time,
            include_stale=query.include_stale, deadline=deadline, cancel=cancel,
        )
        query_hash = self.p.token("retrieval-query", canonical_json(
            {k: v for k, v in query.to_dict().items() if k != "deadline_ms"}))
        elapsed = (time.perf_counter() - started) * 1000
        self.ctx.metrics.incr("retrieval.search")
        self.ctx.metrics.incr(f"retrieval.status.{status.value}")
        self.ctx.metrics.observe_ms("retrieval.search", elapsed)
        return SearchResult(hits=tuple(hits), status=status, coverage=coverage, query_hash=query_hash,
                            elapsed_ms=round(elapsed, 3))

    def rank(self, access: AccessContext, text: str, *, grants: ScopeGrants | None = None,
             kinds: Iterable[MemoryKind] = (), lifecycles: Iterable[Lifecycle] = (Lifecycle.APPROVED,),
             limit: int = 20, at_time: float | None = None, include_stale: bool = False,
             deadline: Deadline | int | float | None = None, cancel: CancellationToken | None = None,
             deadline_ms: int | None = None) -> RankResult:
        """Ranking entry point for the context compiler.

        ``grants`` (default: ``access.grants``) may only narrow the caller's grants.
        ``deadline`` is a :class:`Deadline` or milliseconds; ``deadline_ms`` is an alias
        used when ``deadline`` is not given. Returns ``RankResult(hits, coverage, status)``.
        """
        policy.require(access, Operation.READ)
        if deadline is None and deadline_ms is not None:
            deadline = deadline_ms
        grants = access.grants if grants is None else grants
        if not isinstance(grants, ScopeGrants):
            raise ValidationError("grants must be ScopeGrants")
        for dim in ScopeGrants._DIM_FIELDS:
            if not grants.values_for(dim) <= access.grants.values_for(dim):
                raise AccessDenied("the requested grants exceed the caller's grants")
        check_int(limit, "limit", lo=1, hi=MAX_RANK_LIMIT)
        at_time = check_timestamp(at_time, "at_time")
        if isinstance(deadline, Deadline):
            budget = deadline
        elif deadline is None:
            budget = Deadline(None, self.monotonic)
        else:
            if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or deadline <= 0:
                raise ValidationError("deadline must be a Deadline or a positive number of milliseconds")
            budget = Deadline(int(deadline), self.monotonic)
        hits, coverage, status = self._execute(
            access, text, grants=grants, kinds=tuple(MemoryKind.parse(k, "kind") for k in kinds),
            lifecycles=tuple(Lifecycle.parse(lc, "lifecycle") for lc in lifecycles), limit=limit,
            since=None, until=None, at_time=at_time, include_stale=bool(include_stale),
            deadline=budget, cancel=cancel,
        )
        self.ctx.metrics.incr("retrieval.rank")
        return RankResult(hits, coverage, status)

    def index_status(self, access: AccessContext) -> dict[str, Any]:
        """Index readiness for the caller's authorized namespace only."""
        policy.require(access, Operation.READ)
        backend = "fts5" if ix.fts5_usable() else "python"
        status: dict[str, Any] = {
            "ready": self.p.keyring.unlocked,
            "storage": "memory",
            "backend": backend,
            "fts5_available": ix.fts5_available(),
            "forced_fallback": bool(ix.FORCE_PYTHON_FALLBACK),
            "fusion": {"method": "rrf", "k": self.RRF_K, "score_kind": SCORE_KIND},
            "semantic": "configured" if self._semantic_fn() is not None and getattr(self.ctx.services.providers, "semantic_available", lambda _access: True)(access) else "not_configured",
            "bounds": {"max_projection_records": int(self.ctx.config.max_projection_records),
                       "max_projection_bytes": int(self.ctx.config.max_projection_bytes)},
        }
        if not self.p.keyring.unlocked:
            status["reason"] = "vault_locked"
            return status
        lifecycles = (Lifecycle.APPROVED,)
        with self.p.db.read() as conn:
            generation = self.p.generation(conn)
            authorized = self._count(conn, access.grants, lifecycles, ())
        key = self._key(generation, access.grants, lifecycles, (), backend)
        with self._cache_lock:
            projection = self._cache.get(key)
            projected = len(projection.docs) if projection is not None else 0
            bounded = projection.bounded if projection is not None else None
        status.update({
            "generation": generation,
            "authorized_records": authorized,  # approved records in the caller's namespace
            "projection_built": projection is not None,
            "records_projected": projected,
            "projection_bounded": bounded,
        })
        return status

    def purge(self, conn: Any, target_kind: str, target_token: str, forget_policy: Any) -> dict[str, int]:
        """Forgetting hook: drop every in-memory projection (decrypted copies) immediately.

        Nothing retrieval holds is persisted, so there is nothing to count; the
        generation bump that accompanies the deletion also invalidates cache keys.
        """
        self.invalidate()
        return {}

    def invalidate(self) -> None:
        with self._cache_lock:
            entries, self._cache = list(self._cache.values()), OrderedDict()
        for entry in entries:
            entry.retire()

    def close(self) -> None:
        self.invalidate()

    # ------------------------------------------------------------------ pipeline
    def _execute(self, access: AccessContext, text: str, *, grants: ScopeGrants,
                 kinds: Sequence[MemoryKind], lifecycles: Sequence[Lifecycle], limit: int,
                 since: float | None, until: float | None, at_time: float | None, include_stale: bool,
                 deadline: Deadline, cancel: Any) -> tuple[list[SearchHit], Coverage, ResultStatus]:
        pq = parse_query(check_query_text(text))
        if not self.p.keyring.unlocked:
            # Never serve decrypted copies from the cache once keys are gone.
            self.invalidate()
            raise VaultLocked("the partition is locked; the search index cannot be built")
        lifecycles = self._effective_lifecycles(lifecycles, include_stale)
        kinds = tuple(sorted(set(kinds), key=lambda k: k.value))
        now = float(self.ctx.clock())
        at = float(at_time) if at_time is not None else now
        filters = ix.Filters(at_time=at, now=now, since=since, until=until)
        run = _Run(deadline=deadline, cancel=cancel)
        if pq.truncated:
            run.partial_reasons.append(f"query_terms_truncated:max_{MAX_TERMS}")

        if run.stop("start"):
            coverage = Coverage(total=None, searched=0, index_ready=False,
                                partial_reasons=tuple(run.partial_reasons))
            return [], coverage, self._status([], coverage, run)

        projection: Projection | None = None
        try:
            with self.p.db.read() as conn:
                generation = self.p.generation(conn)
                if pq.empty or not lifecycles:
                    total = self._count(conn, grants, lifecycles, kinds) if lifecycles else 0
                    coverage = Coverage(total=total, searched=0, index_ready=True,
                                        partial_reasons=tuple(run.partial_reasons))
                    return [], coverage, self._status([], coverage, run)
                # (2) exact id lookups: authorized SQL, independent of projection bounds.
                exact_records = self._decrypt(conn, grants, lifecycles, kinds, list(pq.id_candidates))
                # (3a) projection of the authorized namespace.
                if not run.stop("projection"):
                    projection = self._projection(conn, grants, lifecycles, kinds, generation, run)
                    total: int | None = projection.total
                else:
                    total = self._count(conn, grants, lifecycles, kinds)
            cand: dict[str, ix.Doc] = {}
            lists: dict[str, list[str]] = {}
            exact_ids: list[str] = []
            for record_id in pq.id_candidates:
                record = exact_records.get(record_id)
                if record is None:
                    continue
                doc = None
                if projection is not None and record_id in projection.by_id:
                    doc = projection.docs[projection.by_id[record_id]]
                doc = doc or ix.build_doc(-1, record)
                if doc.eligible(filters):
                    exact_ids.append(record_id)
                    cand[record_id] = doc
            if exact_ids:
                lists["exact"] = list(exact_ids)
            searched = 0
            if projection is not None and not run.stopped:
                searched = self._lexical(projection, pq, filters, cand, lists, run)
            if not run.stopped and (pq.text_terms or pq.ident_terms) and self._semantic_fn() is not None:
                eligible = [d.record for d in (projection.docs if projection is not None else [])
                            if d.eligible(filters)]
                eligible += [cand[i].record for i in exact_ids if cand[i].idx < 0]
                # Hits are filtered in _finalize, but an egress embedder would receive the text of
                # every eligible record it has no vector for: drop what must not leave the store
                # (observations of now-excluded paths, read-time expired records) before that.
                eligible = self._servable(eligible)
                semantic = self._semantic(access, text, eligible, limit, run)
                if semantic:
                    lists["semantic"] = semantic
                    for record_id in semantic:
                        if record_id not in cand and projection is not None and record_id in projection.by_id:
                            cand[record_id] = projection.docs[projection.by_id[record_id]]
                run.stop("semantic")
            selected = self._select(lists, cand, exact_ids, at, limit)
            hits = self._finalize(access, grants, selected, generation, pq, run)
            if total and projection is None:
                run.missing.append(f"{total} authorized record(s) not searched (search stopped before indexing)")
            coverage = Coverage(
                total=total, searched=searched,
                index_ready=projection is not None and projection.index_ready,
                missing=tuple((projection.missing if projection is not None else []) + run.missing),
                partial_reasons=tuple((projection.partial_reasons if projection is not None else [])
                                      + run.partial_reasons),
            )
            return hits, coverage, self._status(hits, coverage, run)
        finally:
            if projection is not None:
                projection.release()

    @staticmethod
    def _effective_lifecycles(lifecycles: Iterable[Lifecycle], include_stale: bool) -> tuple[Lifecycle, ...]:
        values = {Lifecycle.parse(lc, "lifecycle") for lc in lifecycles}
        if include_stale:
            values.add(Lifecycle.STALE)
        values.discard(Lifecycle.FORGOTTEN)  # never a stored state
        return tuple(sorted(values, key=lambda lc: lc.value))

    @staticmethod
    def _status(hits: Sequence[SearchHit], coverage: Coverage, run: _Run) -> ResultStatus:
        if run.cancelled:
            return ResultStatus.CANCELLED
        if not hits and not coverage.index_ready and not run.deadline_hit and coverage.total:
            return ResultStatus.UNAVAILABLE  # records exist but none could be indexed
        if not coverage.complete:
            return ResultStatus.PARTIAL
        strong = any(ranking.WEAK_MATCH not in hit.reasons for hit in hits)
        return ResultStatus.COMPLETE if strong else ResultStatus.INSUFFICIENT_EVIDENCE

    # ------------------------------------------------------------------ lexical stage
    def _lexical(self, projection: Projection, pq: ParsedQuery, filters: ix.Filters,
                 cand: dict[str, ix.Doc], lists: dict[str, list[str]], run: _Run) -> int:
        index = projection.index
        docs = projection.docs
        searched = 0
        if run.stop("exact"):
            return searched
        # Exact ids (already in lists["exact"]) first, then docs holding a query identifier whole.
        exact_ident = index.exact_ident(pq, filters)
        ordered = sorted(exact_ident.items(), key=lambda item: (-item[1], item[0]))
        exact_list = lists.get("exact", [])
        listed = set(exact_list)
        for i, _ in ordered:
            record_id = docs[i].record.id
            cand.setdefault(record_id, docs[i])
            if record_id not in listed:
                listed.add(record_id)
                exact_list.append(record_id)
        if exact_list:
            lists["exact"] = exact_list
        stages = (
            ("text", index.text_ranker, index.text),
            ("identifier", index.ident_ranker, index.identifiers),
            ("phrase", index.phrase_ranker, index.phrase),
            ("prefix", index.prefix_ranker, index.prefix),
        )
        for stage, name, fn in stages:
            if run.stop(stage):
                break
            try:
                with self.ctx.metrics.timer(f"retrieval.{stage}"):
                    results = fn(pq, filters, CANDIDATE_CAP)
            except IndexUnavailable:
                run.partial_reasons.append(f"ranker_unavailable:{name}")
                self.ctx.metrics.incr("retrieval.ranker_failed")
                continue
            if stage == "text":
                searched = len(docs)
            if results:
                lists[name] = [docs[i].record.id for i, _ in results]
                for i, _ in results:
                    cand.setdefault(docs[i].record.id, docs[i])
        return searched

    # ------------------------------------------------------------------ semantic stage
    def _servable(self, records: list[MemoryRecord]) -> list[MemoryRecord]:
        """``records`` without those ``core.unservable`` reports (the egress predicate)."""
        core = self.ctx.services.core
        check = getattr(core, "unservable", None) if core is not None else None
        if not records or not callable(check):
            return records
        with self.p.db.read() as conn:
            hidden = check(conn, records)
        return [r for r in records if r.id not in hidden] if hidden else records

    def _semantic_fn(self):
        hub = self.ctx.services.providers
        if hub is None:
            return None
        try:
            fn = getattr(hub, "semantic_scores", None)
        except Exception:  # a hub whose attribute lookup fails is "not configured"
            return None
        return fn if callable(fn) else None

    def _semantic(self, access: AccessContext, text: str, records: list[MemoryRecord], limit: int,
                  run: _Run) -> list[str] | None:
        fn = self._semantic_fn()
        if fn is None or not records:
            return None
        remaining = run.deadline.remaining_s()
        deadline_ms = None if remaining is None else max(1, int(remaining * 1000))
        extra: dict[str, Any] = {}
        try:  # a hub that can report provider failures (instead of None) is asked to
            if "strict" in inspect.signature(fn).parameters:
                extra["strict"] = True
        except (TypeError, ValueError):
            pass
        try:
            raw = fn(access, text, list(records), deadline_ms=deadline_ms, cancel=run.cancel, **extra)
        except Cancelled:
            if run.cancel is not None and getattr(run.cancel, "cancelled", False):
                run.stop("semantic")
            else:
                run.partial_reasons.append("semantic_unavailable:cancelled")
            return None
        except Exception as exc:  # provider failure never fails the lexical path
            code = exc.code if isinstance(exc, MemoryEngineError) else "error"
            run.partial_reasons.append(f"semantic_unavailable:{code}")
            self.ctx.metrics.incr("retrieval.semantic_error")
            return None
        if raw is None:
            return None
        # A hub that declares cosine scores (in [-1, 1]): a non-positive cosine carries no
        # similarity, so it never makes a record a semantic match. Heuristic floor only; it is
        # not a calibrated relevance threshold (unrelated text can still score above zero).
        floor = 0.0 if getattr(raw, "score_kind", None) == "cosine" else None
        pairs = self._coerce_scores(raw)
        if pairs is None:
            run.partial_reasons.append("semantic_unavailable:malformed")
            return None
        allowed = {r.id: r for r in records}
        clean = [(rid, float(score)) for rid, score in pairs
                 if rid in allowed and math.isfinite(float(score)) and (floor is None or float(score) > floor)]
        # Equal cosines are common (e.g. bucketed vectors): break ties like every other ranker,
        # never by the random record id alone, so fresh stores agree on the order.
        clean.sort(key=lambda item: (-item[1], *ranking.tiebreak_key(allowed[item[0]])))
        cap = max(limit * 3, 20)
        out: list[str] = []
        for rid, _ in clean:
            if rid not in out:
                out.append(rid)
            if len(out) >= cap:
                break
        return out

    @staticmethod
    def _coerce_scores(raw: Any) -> list[tuple[str, float]] | None:
        if not isinstance(raw, Mapping) and hasattr(raw, "scores"):
            raw = raw.scores
        if isinstance(raw, Mapping):
            items: Iterable[Any] = raw.items()
        elif isinstance(raw, (list, tuple)):
            items = raw
        else:
            return None
        out = []
        for item in items:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                return None
            rid, score = item
            if not isinstance(rid, str) or isinstance(score, bool) or not isinstance(score, (int, float)):
                return None
            out.append((rid, score))
        return out

    # ------------------------------------------------------------------ fusion & selection
    def _select(self, lists: dict[str, list[str]], cand: dict[str, ix.Doc], exact_ids: list[str],
                at: float, limit: int) -> list[ranking.Candidate]:
        fused = ranking.rrf_fuse({name: ids for name, ids in lists.items() if ids}, self.RRF_K)
        exact_set = set(exact_ids)
        # Cheap pass over every fused id: validity decides the group (exact / current / historical).
        groups: dict[str, list[tuple[tuple, str, list[str], bool]]] = {"exact": [], "current": [], "historical": []}
        position = {rid: i for i, rid in enumerate(exact_ids)}
        for record_id, (score, _ranks) in fused.items():
            doc = cand.get(record_id)
            if doc is None:
                continue
            include, current, validity_reasons = ranking.assess_validity(doc.record, at)
            if not include:
                continue
            if record_id in exact_set:
                groups["exact"].append(((position[record_id],), record_id, validity_reasons, current))
            else:
                key = (-score, *ranking.tiebreak_key(doc.record))
                groups["current" if current else "historical"].append((key, record_id, validity_reasons, current))
        pool = min(max(limit * 4, 40), limit + 200)  # MMR considers this many per group
        window = 2 * pool  # headroom for duplicates collapsing inside the window

        def build(entry: tuple[tuple, str, list[str], bool]) -> ranking.Candidate:
            _, record_id, validity_reasons, current = entry
            doc = cand[record_id]
            score, ranks = fused[record_id]
            reasons: list[str] = ["exact_id"] if record_id in exact_set else []
            reasons += [f"{name}:rank={rank}" for name, rank in sorted(ranks.items(), key=lambda kv: (kv[1], kv[0]))]
            if set(ranks) == {"semantic"}:
                reasons += ["semantic_only: no lexical match", ranking.WEAK_MATCH]
            if doc.record.retention.pinned:
                reasons.append("pinned")
            if "instruction_like" in (doc.record.extra.get("flags") or ()):
                reasons.append("flagged: instruction-like text (data, not instructions)")
            reasons += validity_reasons
            return ranking.Candidate(record=doc.record, score=score, ranks=ranks, tokens=doc.token_set,
                                     exact_id=record_id in exact_set, current=current, reasons=reasons)

        ordered: list[ranking.Candidate] = []
        for name in ("exact", "current", "historical"):
            entries = sorted(groups[name], key=lambda e: e[0])
            ordered += [build(e) for e in (entries if name == "exact" else entries[:window])]
        deduped = ranking.dedupe(ordered)  # keeper preference: exact, then current, then historical
        selected = [c for c in deduped if c.exact_id][:limit]
        selected += ranking.mmr_select([c for c in deduped if not c.exact_id and c.current],
                                       limit - len(selected), pool=pool)
        selected += ranking.mmr_select([c for c in deduped if not c.exact_id and not c.current],
                                       limit - len(selected), pool=pool)
        return selected

    def _finalize(self, access: AccessContext, grants: ScopeGrants, selected: list[ranking.Candidate],
                  generation: int, pq: ParsedQuery, run: _Run) -> list[SearchHit]:
        if not selected:
            return []
        with self.p.db.read() as conn:
            if self.p.generation(conn) != generation:
                alive = self._alive(conn, grants, [c.record.id for c in selected])
                kept = [c for c in selected if alive.get(c.record.id) == c.record.revision]
                if len(kept) != len(selected):
                    run.partial_reasons.append(f"concurrent_change:{len(selected) - len(kept)}_results_dropped")
                selected = kept
            repository = self.ctx.services.repository
            if selected and repository is not None and hasattr(repository, "excluded_observations"):
                # Observations of paths excluded after ingest are never returned (current or stale).
                hidden = repository.excluded_observations(conn, [c.record for c in selected])
                selected = [c for c in selected if c.record.id not in hidden]
            conflicts = {c.record.id: self._conflicts(conn, access, c.record) for c in selected}
            presented = self._present(conn, access, [c.record for c in selected])
        terms = list(pq.all_terms)
        hits = []
        for rank, (cand, record) in enumerate(zip(selected, presented, strict=True), start=1):
            matched = tuple(name for name, _ in sorted(cand.ranks.items(), key=lambda kv: (kv[1], kv[0])))
            hits.append(SearchHit(
                record=record, rank=rank, score=cand.score, score_kind=SCORE_KIND,
                reasons=tuple(cand.reasons), matched=matched,
                snippet=ranking.snippet(cand.record.content, terms),
                conflicts=conflicts[cand.record.id], current=cand.current,
            ))
        return hits

    def _present(self, conn: Any, access: AccessContext, records: list[MemoryRecord]) -> list[MemoryRecord]:
        """Caller-facing view (core.present): no link/evidence ids outside the caller's grants."""
        core = self.ctx.services.core
        present = getattr(core, "present", None) if core is not None else None
        if callable(present):
            shown = present(conn, access, records)
            if len(shown) == len(records):
                return list(shown)
        return [self._strip_links(conn, access, r) for r in records]

    def _strip_links(self, conn: Any, access: AccessContext, record: MemoryRecord) -> MemoryRecord:
        """Fallback when core.present is unavailable: drop references the caller cannot see."""
        links = record.links
        refs = {*links.supersedes, *links.conflicts_with, *links.derived_from}
        if links.superseded_by:
            refs.add(links.superseded_by)
        refs.update(s.ref for s in record.sources if s.kind.value == "memory")
        if not refs:
            return record
        scope, scope_params = self._scope_sql(access.grants)
        ordered = sorted(refs)
        visible = {str(r[0]) for r in conn.execute(
            f"SELECT r.id FROM records r WHERE r.id IN ({','.join('?' * len(ordered))}) AND {scope}",
            [*ordered, *scope_params]).fetchall()}
        shown = dataclasses.replace(
            links, supersedes=tuple(i for i in links.supersedes if i in visible),
            superseded_by=links.superseded_by if links.superseded_by in visible else None,
            conflicts_with=tuple(i for i in links.conflicts_with if i in visible),
            derived_from=tuple(i for i in links.derived_from if i in visible))
        sources = tuple(s for s in record.sources if s.kind.value != "memory" or s.ref in visible)
        return dataclasses.replace(record, links=shown, sources=sources)

    # ------------------------------------------------------------------ SQL helpers
    def _scope_sql(self, grants: ScopeGrants) -> tuple[str, list[Any]]:
        """Same authorization predicate as ``RecordStore.authorized`` (no decryption)."""
        pairs = self.records.allowed_pairs(grants)
        if pairs:
            return ("NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id AND "
                    f"(s.dim || ':' || s.value_token) NOT IN ({','.join('?' * len(pairs))}))", list(pairs))
        return "NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id)", []

    def _namespace_sql(self, grants: ScopeGrants, lifecycles: Sequence[Lifecycle],
                       kinds: Sequence[MemoryKind]) -> tuple[str, list[Any]]:
        clauses = [f"r.lifecycle IN ({','.join('?' * len(lifecycles))})"]
        params: list[Any] = [lc.value for lc in lifecycles]
        if kinds:
            clauses.append(f"r.kind IN ({','.join('?' * len(kinds))})")
            params += [k.value for k in kinds]
        scope, scope_params = self._scope_sql(grants)
        clauses.append(scope)
        return " AND ".join(clauses), params + scope_params

    def _count(self, conn: Any, grants: ScopeGrants, lifecycles: Sequence[Lifecycle],
               kinds: Sequence[MemoryKind]) -> int:
        if not lifecycles:
            return 0
        where, params = self._namespace_sql(grants, lifecycles, kinds)
        return int(conn.execute(f"SELECT COUNT(*) FROM records r WHERE {where}", params).fetchone()[0])

    def _authorized_rows(self, conn: Any, grants: ScopeGrants, lifecycles: Sequence[Lifecycle],
                         kinds: Sequence[MemoryKind]) -> list[tuple[str, int, float, int, int]]:
        """(id, pinned, updated_at, revision, write_generation) of the authorized namespace, newest
        first. No decryption."""
        where, params = self._namespace_sql(grants, lifecycles, kinds)
        rows = conn.execute(
            f"SELECT r.id, r.pinned, r.updated_at, r.revision, r.write_generation FROM records r WHERE {where}"
            " ORDER BY r.pinned DESC, r.updated_at DESC, r.id", params,
        ).fetchall()
        return [(str(r[0]), int(r[1]), float(r[2]), int(r[3]), int(r[4])) for r in rows]

    def _decrypt(self, conn: Any, grants: ScopeGrants, lifecycles: Sequence[Lifecycle],
                 kinds: Sequence[MemoryKind], ids: list[str]) -> dict[str, MemoryRecord]:
        """Decrypt authorized records by id via ``RecordStore.authorized`` (scope re-checked in SQL).

        A record that fails authentication or whose data key is unavailable is
        skipped (and reported by the caller); a locked vault raises ``VaultLocked``.
        """
        if not ids or not lifecycles:
            return {}
        try:
            found = self.records.authorized(conn, grants, lifecycles=lifecycles, kinds=kinds or None, ids=ids)
            return {r.id: r for r in found}
        except (IntegrityError, WrongKey):
            out: dict[str, MemoryRecord] = {}
            for record_id in ids:
                try:
                    found = self.records.authorized(conn, grants, lifecycles=lifecycles, kinds=kinds or None,
                                                    ids=[record_id])
                except (IntegrityError, WrongKey):
                    self.ctx.metrics.incr("retrieval.record_unreadable")
                    continue
                out.update({r.id: r for r in found})
            return out

    def _alive(self, conn: Any, grants: ScopeGrants, ids: list[str]) -> dict[str, int]:
        scope, scope_params = self._scope_sql(grants)
        rows = conn.execute(
            f"SELECT r.id, r.revision FROM records r WHERE r.id IN ({','.join('?' * len(ids))}) AND {scope}",
            [*ids, *scope_params],
        ).fetchall()
        return {str(r[0]): int(r[1]) for r in rows}

    def _conflicts(self, conn: Any, access: AccessContext, record: MemoryRecord) -> tuple[str, ...]:
        """Live conflicting records the caller is authorized to see (others are not mentioned)."""
        core = self.ctx.services.core
        if core is not None and hasattr(core, "structured_conflicts"):
            # Live conflicts only: a stored link a later correction resolved is not a conflict.
            ids = set(core.structured_conflicts(conn, record))
        else:
            ids = set(record.links.conflicts_with)
        ids.discard(record.id)
        if not ids:
            return ()
        ordered = sorted(ids)
        scope, scope_params = self._scope_sql(access.grants)
        rows = conn.execute(
            f"SELECT r.id FROM records r WHERE r.id IN ({','.join('?' * len(ordered))})"
            f" AND r.lifecycle IN ({','.join('?' * len(_CONFLICT_LIFECYCLES))}) AND {scope} ORDER BY r.id",
            [*ordered, *_CONFLICT_LIFECYCLES, *scope_params],
        ).fetchall()
        return tuple(str(r[0]) for r in rows)

    # ------------------------------------------------------------------ projection cache
    def _key(self, generation: int, grants: ScopeGrants, lifecycles: Sequence[Lifecycle],
             kinds: Sequence[MemoryKind], backend: str) -> tuple:
        cfg = self.ctx.config
        return (generation, grants.fingerprint(), tuple(sorted(lc.value for lc in lifecycles)),
                tuple(sorted(k.value for k in kinds)), backend, int(cfg.max_projection_records),
                int(cfg.max_projection_bytes))

    def _projection(self, conn: Any, grants: ScopeGrants, lifecycles: Sequence[Lifecycle],
                    kinds: Sequence[MemoryKind], generation: int, run: _Run) -> Projection:
        backend = "fts5" if ix.fts5_usable() else "python"
        key = self._key(generation, grants, lifecycles, kinds, backend)
        stale: list[Projection] = []
        hit: Projection | None = None
        previous: Projection | None = None
        with self._cache_lock:
            for other_key in list(self._cache):
                if other_key[0] != generation:
                    old = self._cache.pop(other_key)
                    stale.append(old)
                    # Same namespace at an older generation: unchanged documents can be reused.
                    if other_key[1:] == key[1:] and previous is None and old.acquire():
                        previous = old
            entry = self._cache.get(key)
            if entry is not None and entry.acquire():
                self._cache.move_to_end(key)
                hit = entry
        try:
            if hit is not None:
                self.ctx.metrics.incr("retrieval.projection_cache_hit")
                return hit
            with self.ctx.metrics.timer("retrieval.projection_build"):
                projection = self._build(conn, key, grants, lifecycles, kinds, generation, run, previous)
        finally:
            if previous is not None:
                previous.release()
            for entry in stale:
                entry.retire()
        projection.acquire()
        self.ctx.metrics.incr("retrieval.projection_built")
        if projection.interrupted:
            projection.retire()  # closed once this search releases it; never cached
        else:
            self._cache_put(projection)
        return projection

    def _cache_put(self, projection: Projection) -> None:
        cfg = self.ctx.config
        budget = max(2 * int(cfg.max_projection_bytes), 1)
        evicted: list[Projection] = []
        with self._cache_lock:
            previous = self._cache.pop(projection.key, None)
            if previous is not None:
                evicted.append(previous)
            self._cache[projection.key] = projection
            while len(self._cache) > 1 and (
                len(self._cache) > MAX_CACHE_ENTRIES or sum(p.nbytes for p in self._cache.values()) > budget
            ):
                _, oldest = self._cache.popitem(last=False)
                evicted.append(oldest)
        for entry in evicted:
            entry.retire()

    def _build(self, conn: Any, key: tuple, grants: ScopeGrants, lifecycles: Sequence[Lifecycle],
               kinds: Sequence[MemoryKind], generation: int, run: _Run,
               previous: Projection | None = None) -> Projection:
        """Project the authorized namespace (newest/pinned first) within the configured bounds.

        Membership always comes from the authorized SQL listing of *this* snapshot.
        A document from ``previous`` (same grants/lifecycles/kinds, older generation)
        is reused only when its (id, revision) is unchanged -- every update advances
        the revision -- so nothing stale, moved out of scope or forgotten is reused.
        """
        cfg = self.ctx.config
        max_records = max(0, int(cfg.max_projection_records))
        max_bytes = max(0, int(cfg.max_projection_bytes))
        rows = self._authorized_rows(conn, grants, lifecycles, kinds)
        total = len(rows)
        docs: list[ix.Doc] = []
        nbytes = 0
        consumed = 0
        unreadable = 0
        bound: str | None = None
        interrupted = False
        candidates = rows[:max_records]
        deletion_generation = self.p.deletion_generation(conn)
        reusable: dict[str, ix.Doc] = {}
        previous_writes: dict[str, int] = {}
        if previous is not None and previous.deletion_generation == deletion_generation:
            reusable = {doc.record.id: doc for doc in previous.docs}
            previous_writes = previous.write_generations

        def reuse(row: tuple) -> ix.Doc | None:
            doc = reusable.get(row[0])
            if doc is None or doc.record.revision != row[3] or previous_writes.get(row[0]) != row[4]:
                return None
            return doc

        reused = 0
        write_generations: dict[str, int] = {}
        for start in range(0, len(candidates), DECRYPT_CHUNK):
            if run.stop("projection"):
                interrupted = True
                break
            chunk = candidates[start:start + DECRYPT_CHUNK]
            fresh = [row[0] for row in chunk if reuse(row) is None]
            decrypted = self._decrypt(conn, grants, lifecycles, kinds, fresh) if fresh else {}
            for row in chunk:
                old_doc = reuse(row)
                write_generations[row[0]] = row[4]
                if old_doc is not None:
                    doc = dataclasses.replace(old_doc, idx=len(docs))
                    reused += 1
                else:
                    record = decrypted.get(row[0])
                    if record is None:
                        unreadable += 1
                        consumed += 1
                        continue
                    doc = ix.build_doc(len(docs), record)
                if nbytes + doc.nbytes > max_bytes:
                    bound = f"max_projection_bytes={max_bytes}"
                    break
                nbytes += doc.nbytes
                docs.append(doc)
                consumed += 1
            if bound:
                break
        if bound is None and not interrupted and total > max_records:
            bound = f"max_projection_records={max_records}"
        missing: list[str] = []
        if unreadable:
            missing.append(f"{unreadable} authorized record(s) failed authentication or could not be"
                           " decrypted and were not searched")
        unsearched = rows[consumed:]
        if unsearched:
            cause = f"projection bound {bound}" if bound else (
                "search cancelled" if run.cancelled else "deadline exceeded while indexing")
            newest = max(row[2] for row in unsearched)
            pinned = sum(1 for row in unsearched if row[1])
            missing.append(
                f"{len(unsearched)} of {total} authorized record(s) not searched ({cause}); they were last"
                f" updated at or before {_iso(newest)}" + (f", including {pinned} pinned" if pinned else ""))
        if reused:
            self.ctx.metrics.incr("retrieval.projection_docs_reused", reused)
        partial: list[str] = []
        if interrupted:
            index: ix.LexicalIndex = ix.PythonIndex([])
        else:
            index, note = ix.build_index(docs)
            if note:
                partial.append(note)
        return Projection(key, generation, docs, index, total=total, nbytes=nbytes, missing=missing,
                          partial_reasons=partial, interrupted=interrupted, bounded=bound is not None,
                          deletion_generation=deletion_generation, write_generations=write_generations)
