"""Hot-context compilation: a budgeted, rendered VIEW of authorized APPROVED memory.

Hot memory is never a separate store. Every packet is compiled from the
caller's authorized ``approved`` records only - candidates, rejected, stale,
superseded, expired and forgotten records are never injected. Scope is enforced
in SQL (``RecordStore.authorized``) before anything is decrypted or ranked.

Selection
* ``ContextRequest.slices`` are caps, not fill targets. All slices compete for the
  host-owned ``token_allowance`` round-robin (one candidate per slice per round,
  slices in request order) so a small allowance is shared rather than consumed
  by the first slice.
* Membership: ``kinds`` (empty = any kind) and ``scope_dims`` (``()`` = profile-global
  records only, ``None`` = any scope, otherwise records carrying at least one of
  the listed dimensions). A record may qualify for several slices; it is
  injected at most once.
* Order: slices without relevance (or without a query) use pinned desc,
  updated_at desc, id. Relevance slices with a query use pinned records first,
  then the order returned by ``retrieval.rank``; records the ranker does not
  return are treated as not relevant. When ranking is unavailable or fails the
  slice falls back to pinned/recency order and the packet is PARTIAL.
* ``exclude_ids`` (already injected by another path) are skipped, and so is any
  record whose normalized content duplicates an excluded or selected record.
* ``max_items`` (optional) caps how many records are injected, in selection order
  (round-robin across slices); the rest are omitted with reason ``max_items``.
* Rendered order (``ContextRequest.order``): ``"slices"`` (default) renders slices in
  request order and, within a slice, in selection order. With the default slices the
  packet therefore starts with recency-ordered preferences and profile facts, so
  **packet order is not relevance order**. ``"relevance"`` renders items selected by a
  strong query match first (by relevance rank), then everything else in slice order.
  Selection (which records fit) is the same for both.
* Conflicts (``links.conflicts_with``, symmetric, among visible approved records)
  are annotated with a visible note or, with ``conflict_policy='omit'``, both
  sides are omitted.

Evidence strength (content-free, never a confidence): a relevance-slice item whose
ranker hit carries ``weak_match`` (semantic-only, no lexical/exact match) gets the
item reason ``weak_match``. The packet flag ``weak_evidence_only`` is set when a query
was given, at least one slice is query-relevant, and no injected item was selected
by a strong (lexical/exact) relevance match - i.e. everything injected is there by
pinning, recency or semantic similarity only (or nothing was injected). The packet
flag ``history_weak_only`` is set when history was searched and returned no hit
that matched every content term (``HistorySearchResult`` status
``INSUFFICIENT_EVIDENCE``). Neither flag changes coverage or status: the search was
complete, it just found no strong evidence. They are lexical signals, not proof
that the answer is absent.

History: ``include_history`` asks ``history.search`` with ``exclude_corrected=True``,
so archived messages superseded by a content correction are never offered as
history handles (the archive itself keeps them).

Budget: everything rendered is counted - wrapper, labels, ids, flags and
conflict notes. Tokenizers are not additive, so the final text is re-counted as
a whole and trimmed (latest-selected first) until it fits. No memory is ever
silently truncated; one that cannot fit is omitted with reason ``budget`` (the shared
allowance) or ``slice_cap`` (its slice's cap), with its measured token count.

Bounded selection: rendering (redaction, safety scan, neutralization) and tokenizing is the
expensive part, so a slice stops evaluating its queue after refusing ``_MAX_SLICE_MISSES``
candidates that would have fit it empty (it is crowded) or ``_MAX_SLICE_OVERSIZED`` candidates
too large for it on their own (these are not evidence that it is full). The records it did not
evaluate are omitted as ``budget`` / ``slice_cap`` only when not even the shortest possible line
fits the room left (once that holds, a slice renders nothing more); otherwise they are omitted
as ``not_evaluated`` (no token count) and the packet is PARTIAL (``R_SELECT_TRUNCATED``). That is
deterministic for a store generation and request, so such a packet is cached like a complete one.

Deadline (``deadline_ms``) and cancellation are checked cooperatively in every stage:
records are decrypted lazily in pinned/recency order and planned in chunks of
``_LOAD_CHUNK`` (the first chunk always), so an expired deadline yields a packet built from
the pinned/most recent records (PARTIAL, ``R_LOAD_DEADLINE``). Ranking and history search
are forwarded ``_UPSTREAM_DEADLINE_SHARE`` of the deadline (they spend what they are given;
the rest is kept for selection and the commit); ranking is skipped once that share is spent
(``R_RANK_DEADLINE``). Selection always completes its first round (every slice has one
turn) and evaluates at least ``_SELECT_MIN_EVALUATIONS`` candidates; after that an expired
deadline stops it (``R_SELECT_DEADLINE``). Deadline-degraded packets are never cached.

Consistency: records are read in one snapshot; ranking/history run outside any
transaction; the receipt is committed only if the partition generation is
unchanged, otherwise the compile is retried. A forget or correction that lands
mid-compile therefore never leaks into a returned packet.

Receipts hold ids, revisions, slice names, token counts, the snapshot hash, the
grants fingerprint and generations - never memory content, queries or paths.
They are scrubbed when a referenced memory is forgotten.
"""
from __future__ import annotations

import dataclasses
import hashlib
import inspect
import logging
import math
import re
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .. import policy, safety
from .. import validation as v
from ..errors import AccessDenied, Cancelled, Contention, IntegrityError, NotFound, ValidationError
from ..host import Deadline
from ..models import (
    AccessContext,
    ContextItem,
    ContextOmission,
    ContextPacket,
    ContextRequest,
    Coverage,
    Lifecycle,
    MeasureKind,
    MemoryKind,
    MemoryRecord,
    Operation,
    Query,
    Receipt,
    ResultStatus,
    ScopeDimension,
    SliceSpec,
    canonical_json,
    content_hash,
)
from ..retrieval.evidence import assess_evidence
from ..services import PartitionContext
from ..storage.partition import partition_bound
from .budget import BUDGET, SLICE_CAP, Budget, CounterFailure, TokenMeter
from .markers import CONTEXT_PREAMBLE, CONTEXT_WRAPPER_CLOSE, CONTEXT_WRAPPER_OPEN

logger = logging.getLogger("locus_memory.context")

RECEIPT_OPERATION = "context"
WRAPPER_OPEN = CONTEXT_WRAPPER_OPEN + "\n"  # public: locus_memory.context.CONTEXT_WRAPPER_OPEN
WRAPPER_PREAMBLE = CONTEXT_PREAMBLE
WRAPPER_CLOSE = CONTEXT_WRAPPER_CLOSE
MAX_ITEMS = "max_items"  # omission reason
NOT_EVALUATED = "not_evaluated"  # omission reason: queued in a slice selection stopped evaluating
WEAK_MATCH = "weak_match"  # item reason / hit reason (retrieval.ranking.WEAK_MATCH)
FLAG_WEAK_ONLY = "weak_evidence_only"
FLAG_HISTORY_WEAK_ONLY = "history_weak_only"

CONTEXT_RECEIPT_TTL_S = 30 * 86_400
CONTEXT_RECEIPT_MAX = 5_000
_PRUNE_EVERY = 32
_MAX_SLICES = 32
_MAX_EXCLUDE = 1_024
_MAX_FILES = 256
_PACKET_OMISSIONS = 1_000
_RECEIPT_OMISSIONS = 256
_CACHE_ENTRIES = 64
_REGISTRY_ENTRIES = 1_024
_COMPILE_ATTEMPTS = 3
_RANK_LIMIT = 200
# Records decrypted / planned between cooperative deadline and cancellation checks. The first
# chunk is always processed, so an expired deadline still yields the pinned/most recent records.
_LOAD_CHUNK = 256
# Candidates a slice may refuse because it is crowded (slice cap or shared budget, by a candidate
# that would fit the empty slice) before the rest of its queue is omitted without being
# rendered: rendering (redaction, safety scan, markup neutralization) and tokenizing every queued
# record of a full slice made selection O(approved records).
_MAX_SLICE_MISSES = 32
# Candidates too large for a slice on their own (more tokens than its cap, or than the whole
# allowance) a slice may refuse before it stops evaluating its queue. They are no evidence that
# the slice is full - counting them as misses retired an empty slice and omitted small records
# that fit - but rendering them is the expensive part, so they are bounded separately.
_MAX_SLICE_OVERSIZED = 64
# Candidates selection always evaluates (renders and tokenizes) before an expired deadline may
# stop it. A constant, so selection stays bounded independently of the number of approved
# records, while a deadline spent upstream (loading, ranking, history hydration) no longer
# reduces the packet to one item per slice.
_SELECT_MIN_EVALUATIONS = 64
# Share of ``deadline_ms`` the optional upstream stages (relevance ranking, history search) are
# given; the rest is kept for selection and the receipt commit. History hydration and semantic
# providers spend the whole deadline they are forwarded.
_UPSTREAM_DEADLINE_SHARE = 0.8

_DDL = (
    "CREATE TABLE IF NOT EXISTS context_receipt_items("
    " receipt_id TEXT NOT NULL, record_id TEXT NOT NULL, PRIMARY KEY(receipt_id, record_id))",
    "CREATE INDEX IF NOT EXISTS context_receipt_items_record ON context_receipt_items(record_id)",
)

# Content-free partial reasons (also persisted in receipts).
R_RANK_UNAVAILABLE = "relevance ranking unavailable; relevance slices used pinned/recency order"
R_RANK_FAILED = "relevance ranking failed; relevance slices used pinned/recency order"
R_RANK_DEADLINE = "deadline reached before relevance ranking; relevance slices used pinned/recency order"
R_RANK_PARTIAL = "relevance ranking reported partial coverage"
R_RANK_PARTIAL_TRANSIENT = ("relevance ranking was degraded by a transient condition (provider failure, deadline"
                            " or cancellation); a retry ranks again")
R_COUNTER_FAILED = "host token counter failed; counts are conservative estimates"
R_HISTORY_UNAVAILABLE = "history search unavailable"
R_HISTORY_FAILED = "history search failed"
R_HISTORY_PARTIAL = "history search reported partial coverage"
R_TRUNCATED = "more approved records than max_projection_records; only the pinned/most recent were considered"
R_LOAD_DEADLINE = ("deadline reached before every approved record was considered; the context was built from the"
                   " pinned/most recent ones")
R_SELECT_DEADLINE = "deadline reached during selection; fewer items may have been selected than would fit"
R_SELECT_TRUNCATED = ("selection stopped evaluating a slice after repeated refusals; records it did not evaluate"
                      " are omitted with reason not_evaluated and some of them might have fit")
R_FILTERED = "original request unavailable; revalidated by dropping changed items from the previous selection"
R_DISABLED = "context serving is disabled by host configuration"

_LINEBREAKS = re.compile(r"\r\n|\r| | |\x85")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")
# Partial or unterminated wrapper tags that safety.neutralize_markup (which needs a '>') misses.
_PARTIAL_TAG = re.compile(r"<(?=\s*/?\s*(?:memory|system|assistant|user|tool|instructions?)\b)", re.I)
# Stored text must not be able to impersonate an item header.
_FAKE_HEADER = re.compile(r"\[(?=\s*m\s*:)", re.I)
# The shortest line any record can render to (a one-character id, revision 1, the shortest kind
# and scope label, an empty body): a slice or budget with less room than its cost fits nothing.
_SHORTEST_LINE = "[m:x r1 {} {}] \n".format(
    min((kind.value for kind in MemoryKind), key=len),
    min(["global", *(dim.value for dim in ScopeDimension)], key=len))


# --------------------------------------------------------------------------- helpers
def snapshot_hash(pairs: Iterable[tuple[str, int]], text: str, allowance: int) -> str:
    """sha256 over the sorted (id, revision) list, the rendered text and the allowance."""
    payload = canonical_json({
        "items": sorted([str(rid), int(rev)] for rid, rev in pairs),
        "text": text, "allowance": int(allowance),
    })
    return hashlib.sha256(payload.encode()).hexdigest()


def _check_cancel(cancel: Any) -> None:
    if cancel is not None and getattr(cancel, "cancelled", False):
        raise Cancelled("context compilation was cancelled")


def _member(spec: SliceSpec, record: MemoryRecord) -> bool:
    if spec.kinds and record.kind not in spec.kinds:
        return False
    if spec.scope_dims is None:
        return True
    if not spec.scope_dims:
        return record.scope.is_global
    return any(record.scope.get(dim) is not None for dim in spec.scope_dims)


def _time_reason(record: MemoryRecord, at: float, now: float | None = None) -> str | None:
    """Why a record is not current (mirrors CoreService.expire_due), else None.

    Validity is judged at ``at`` (the request's ``at_time`` for a historical replay); retention
    at ``now`` - data whose retention has ended is gone for every replay, as after maintenance.
    """
    now = at if now is None else now
    retention = record.retention
    if (retention.expires_at is not None and retention.expires_at < now and not retention.pinned
            and retention.policy != "durable"):
        return "expired"
    validity = record.validity
    if validity.valid_until is not None and validity.valid_until < at:
        return "stale"
    if validity.valid_from is not None and validity.valid_from > at:
        return "stale"  # not yet valid
    if record.links.superseded_by:
        return "stale"
    return None


def _next_boundary(record: MemoryRecord, at: float, now: float | None = None) -> float | None:
    """Earliest future (wall-clock) time at which ``_time_reason`` could change for this record.

    For a historical replay (``at`` != ``now``) only retention moves with the clock; validity is
    judged at the fixed ``at`` and never changes.
    """
    replay = now is not None and now != at
    now = at if now is None else now
    points = []
    retention = record.retention
    if (retention.expires_at is not None and not retention.pinned and retention.policy != "durable"
            and retention.expires_at >= now):
        points.append(retention.expires_at)
    if not replay:
        validity = record.validity
        if validity.valid_until is not None and validity.valid_until >= at:
            points.append(validity.valid_until)
        if validity.valid_from is not None and validity.valid_from > at:
            points.append(validity.valid_from)
    return min(points) if points else None


# Partial reasons caused by transient conditions: a packet carrying one is never cached (a
# retry must get a fresh compile, not the degraded one) and is recompiled by revalidation.
_TRANSIENT_REASONS = frozenset({R_RANK_FAILED, R_RANK_DEADLINE, R_RANK_PARTIAL_TRANSIENT, R_COUNTER_FAILED,
                                R_HISTORY_FAILED, R_LOAD_DEADLINE, R_SELECT_DEADLINE})
# Ranker coverage reasons that are deterministic for a given store generation and request (the
# query was truncated to the term limit; the lexical index fell back to the Python ranker): a
# packet ranked under them is the same on every retry, so it may be cached. Any other reason - a
# semantic provider error or timeout (``semantic_unavailable:``), a deadline or cancellation
# inside the ranker (``deadline_exceeded:``, ``cancelled:``), an unavailable ranker stage, a
# concurrent change, or a reason this compiler does not know - is treated as transient.
_STABLE_RANK_REASON_PREFIXES = ("query_terms_truncated:", "lexical_fallback:")
_GOVERNED_STATES = frozenset({"approved", "exported"})


def _governed(record: MemoryRecord) -> bool:
    """Episode / procedure records are injected only as their own service governs them: an
    episode with its engine-managed payload; a procedure approved through ``approve_procedure``
    (legacy, ungoverned procedure-kind memories imported from Locus are ordinary memories)."""
    extra = record.extra if isinstance(record.extra, dict) else {}
    if record.kind == MemoryKind.EPISODE:
        return isinstance(extra.get("episode"), dict)
    if record.kind == MemoryKind.PROCEDURE:
        if extra.get("legacy_ungoverned_procedure"):
            return True
        payload = extra.get("procedure")
        return isinstance(payload, dict) and payload.get("state") in _GOVERNED_STATES
    return True


def _recency_key(record: MemoryRecord) -> tuple[int, float, str]:
    return (-int(record.pinned), -float(record.updated_at), record.id)


def _norm(text: str) -> str:
    return v.normalize_for_fingerprint(text)


def _inert(text: str, *, single_line: bool = False) -> tuple[str, bool]:
    """Render stored text as inert data. Returns (text, markup_was_neutralized)."""
    base = _CONTROL.sub("", _LINEBREAKS.sub("\n", text))
    if single_line:
        base = base.replace("\n", " ")
    out = safety.neutralize_markup(base)
    out = _PARTIAL_TAG.sub("‹", out)
    out = _FAKE_HEADER.sub("(", out)
    return out, out != base


def _slice_name(value: Any) -> str:
    """A slice label from a host-returned packet, or a neutral one if it is malformed."""
    try:
        return v.check_label(value, "slice name", max_chars=64)
    except ValidationError:
        return "revalidated"


def _assemble(lines: Iterable[str]) -> str:
    return WRAPPER_OPEN + WRAPPER_PREAMBLE + "".join(lines) + WRAPPER_CLOSE


def _cap_omissions(omissions: list[ContextOmission], limit: int) -> list[ContextOmission]:
    """Itemize up to ``limit`` omissions; aggregate the rest per (reason, slice) without ids."""
    if len(omissions) <= limit:
        return omissions
    head = omissions[:limit]
    groups: OrderedDict[tuple[str, str], None] = OrderedDict()
    for item in omissions[limit:]:
        groups[(item.reason, item.slice)] = None
    return head + [ContextOmission(None, reason, slice_name, None) for reason, slice_name in groups]


# ----------------------------------------------------------------- sibling-call adapter
# Sibling services (retrieval, history) are developed independently; their exact
# signatures are bound by parameter name so a signature change degrades to an
# honest "unavailable" instead of a crash.
_PARAM_ALIASES = {
    "access": "access", "access_context": "access",
    "query": "query", "text": "query", "query_text": "query",
    "records": "records", "candidates": "records", "items": "records", "memories": "records",
    "ids": "ids", "record_ids": "ids", "candidate_ids": "ids",
    "limit": "limit", "k": "limit", "top_k": "limit", "kinds": "kinds",
    "at_time": "at_time", "files": "files", "repository": "repository",
    "cancel": "cancel", "deadline_ms": "deadline_ms", "conn": "conn",
    "exclude_corrected": "exclude_corrected",
}
_CONN = object()


class _Unbindable(Exception):
    pass


def _wants_query_model(param: inspect.Parameter) -> bool:
    annotation = param.annotation
    if annotation is Query:
        return True
    return isinstance(annotation, str) and "Query" in annotation and "str" not in annotation


def _bind(func: Callable[..., Any], values: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return [values["access"], values["query"]], {}
    args: list[Any] = []
    kwargs: dict[str, Any] = {}
    for name, param in signature.parameters.items():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        key = _PARAM_ALIASES.get(name)
        if key == "conn":
            value: Any = _CONN
        elif key is not None and key in values:
            value = values[key]
            if key == "query" and _wants_query_model(param):
                value = Query(text=values["query"], limit=max(1, min(int(values.get("limit") or 8), 200)))
        elif param.default is not param.empty:
            continue
        else:
            raise _Unbindable(name)
        if param.kind is param.POSITIONAL_ONLY:
            args.append(value)
        else:
            kwargs[name] = value
    return args, kwargs


def _hit_id(hit: Any) -> str | None:
    if isinstance(hit, str):
        return hit
    if isinstance(hit, MemoryRecord):
        return hit.id
    record = getattr(hit, "record", None)
    if isinstance(record, MemoryRecord):
        return record.id
    if isinstance(hit, dict):
        value = hit.get("record_id") or hit.get("id")
        return value if isinstance(value, str) else None
    for attr in ("record_id", "id"):
        value = getattr(hit, attr, None)
        if isinstance(value, str):
            return value
    if isinstance(hit, (tuple, list)) and hit:
        return _hit_id(hit[0])
    return None


def _is_weak(hit: Any) -> bool:
    """A ranker hit that reports it has no lexical/exact evidence (``weak_match`` reason)."""
    reasons = hit.get("reasons") if isinstance(hit, dict) else getattr(hit, "reasons", None)
    return isinstance(reasons, (tuple, list)) and WEAK_MATCH in reasons


def _weak_ids(result: Any, allowed: set[str]) -> set[str]:
    """Ids among ``allowed`` whose ranker hit reports ``weak_match`` (no lexical/exact evidence)."""
    hits = getattr(result, "hits", result)
    if hits is None or isinstance(hits, (str, bytes, dict)):
        return set()
    out = set()
    for hit in hits:
        rid = _hit_id(hit)
        if isinstance(rid, str) and rid in allowed and _is_weak(hit):
            out.add(rid)
    return out


def _rank_partial_reason(result: Any) -> str | None:
    """The packet reason for a ranker result with incomplete coverage (None when complete):
    :data:`R_RANK_PARTIAL` (cacheable) only when every reported cause is deterministic, else
    :data:`R_RANK_PARTIAL_TRANSIENT` (see ``_STABLE_RANK_REASON_PREFIXES``)."""
    status = getattr(result, "status", None)
    if getattr(status, "value", status) == "cancelled":
        return R_RANK_PARTIAL_TRANSIENT
    coverage = getattr(result, "coverage", None)
    if coverage is None or getattr(coverage, "complete", True) is not False:
        return None
    reasons = getattr(coverage, "partial_reasons", ()) or ()
    if isinstance(reasons, (str, bytes)) or not isinstance(reasons, (tuple, list)):
        return R_RANK_PARTIAL_TRANSIENT  # unknown shape: never cached
    for reason in reasons:
        if not (isinstance(reason, str) and reason.startswith(_STABLE_RANK_REASON_PREFIXES)):
            return R_RANK_PARTIAL_TRANSIENT
    return R_RANK_PARTIAL


def _ranked_ids(result: Any, allowed: set[str]) -> tuple[list[str], str | None]:
    """Normalize a ranker result to ids it may legitimately order (never adds records)."""
    partial = _rank_partial_reason(result)
    hits = getattr(result, "hits", result)
    if isinstance(hits, dict):
        scored = []
        for key, score in hits.items():
            number = float(score)
            if not math.isfinite(number):
                raise ValueError("non-finite ranking score")
            scored.append((str(key), number))
        raw = [key for key, _ in sorted(scored, key=lambda kv: (-kv[1], kv[0]))]
    elif hits is None or isinstance(hits, (str, bytes)):
        raise TypeError("ranker returned an unsupported result")
    else:
        raw = [_hit_id(hit) for hit in hits]
    out: list[str] = []
    seen: set[str] = set()
    for rid in raw:
        if isinstance(rid, str) and rid in allowed and rid not in seen:
            out.append(rid)
            seen.add(rid)
    return out, partial


def _history_handles(result: Any, limit: int) -> tuple[list[str], str | None, bool]:
    """(handles, partial reason or None, weak_only).

    ``INSUFFICIENT_EVIDENCE`` is a complete search that found no strong hit: not partial,
    but ``weak_only``. Hits flagged ``superseded_by_correction`` are never offered (the
    compiler asks for ``exclude_corrected``; this also covers a search that ignores it).
    """
    partial = None
    status = getattr(result, "status", None)
    status_value = getattr(status, "value", status)
    coverage = getattr(result, "coverage", None)
    if (status is not None and status_value not in ("complete", "insufficient_evidence")) or (
            coverage is not None and getattr(coverage, "complete", True) is False):
        partial = R_HISTORY_PARTIAL
    hits = getattr(result, "hits", result)
    if hits is None or isinstance(hits, (str, bytes, dict)):
        raise TypeError("history search returned an unsupported result")
    handles: list[str] = []
    strong = False
    for hit in hits:
        handle = hit if isinstance(hit, str) else (
            hit.get("handle") if isinstance(hit, dict) else getattr(hit, "handle", None))
        flags = hit.get("flags") if isinstance(hit, dict) else getattr(hit, "flags", None)
        flags = flags if isinstance(flags, (tuple, list)) else ()
        if "superseded_by_correction" in flags:
            continue
        try:
            v.check_ref(handle, "history handle")
        except Exception:
            continue
        if handle not in handles:
            handles.append(handle)
            strong = strong or WEAK_MATCH not in flags
        if len(handles) >= limit:
            break
    weak_only = status_value == "insufficient_evidence" or not strong
    return handles, partial, weak_only and partial is None


def normalize_request(request: Any) -> ContextRequest:
    """Validate host-supplied slice specs and identifiers (bounded, typed)."""
    if not isinstance(request, ContextRequest):
        raise ValidationError("request must be a ContextRequest")
    if not isinstance(request.slices, (tuple, list)) or len(request.slices) > _MAX_SLICES:
        raise ValidationError(f"slices must be a list of at most {_MAX_SLICES} slice specs")
    names: set[str] = set()
    slices = []
    for spec in request.slices:
        if not isinstance(spec, SliceSpec):
            raise ValidationError("each slice must be a SliceSpec")
        name = v.check_label(spec.name, "slice name", max_chars=64)
        if name in names:
            raise ValidationError("slice names must be unique")
        names.add(name)
        max_tokens = v.check_int(spec.max_tokens, "slice max_tokens", lo=0, hi=1_000_000)
        if not isinstance(spec.kinds, (tuple, list)):
            raise ValidationError("slice kinds must be a list")
        kinds = tuple(MemoryKind.parse(kind, "slice kind") for kind in spec.kinds)
        if spec.scope_dims is None:
            dims = None
        elif isinstance(spec.scope_dims, (tuple, list)):
            dims = tuple(ScopeDimension.parse(dim, "slice scope dimension").value for dim in spec.scope_dims)
        else:
            raise ValidationError("slice scope_dims must be a list or null")
        if not isinstance(spec.query_relevant, bool):
            raise ValidationError("slice query_relevant must be a boolean")
        slices.append(SliceSpec(name, max_tokens, kinds, dims, spec.query_relevant))
    if not isinstance(request.exclude_ids, (tuple, list)) or len(request.exclude_ids) > _MAX_EXCLUDE:
        raise ValidationError(f"exclude_ids must be a list of at most {_MAX_EXCLUDE} ids")
    exclude = tuple(dict.fromkeys(v.check_id(item, "exclude_ids") for item in request.exclude_ids))
    if request.repository is not None:
        v.check_label(request.repository, "repository", max_chars=512)
    if not isinstance(request.files, (tuple, list)) or len(request.files) > _MAX_FILES:
        raise ValidationError(f"files must be a list of at most {_MAX_FILES} paths")
    files = tuple(v.check_text(item, "file", max_chars=1024) for item in request.files)
    v.check_timestamp(request.at_time, "at_time")
    if request.deadline_ms is not None:
        v.check_int(request.deadline_ms, "deadline_ms", lo=1, hi=600_000)
    if not isinstance(request.include_history, bool):
        raise ValidationError("include_history must be a boolean")
    if request.max_items is not None:
        v.check_int(request.max_items, "max_items", lo=0, hi=ContextRequest.MAX_ITEMS_LIMIT)
    if request.order not in ContextRequest.ORDERS:
        raise ValidationError("order must be slices or relevance")
    return dataclasses.replace(request, slices=tuple(slices), exclude_ids=exclude, files=files)


# --------------------------------------------------------------------------- internals
@dataclass
class _Candidate:
    record: MemoryRecord
    slices: tuple[str, ...]
    norm: str
    conflicts: tuple[str, ...] = ()
    sources: tuple[str, ...] | None = None  # source identities the caller may see (None: all)
    _line: str | None = None
    flags: tuple[str, ...] = ()
    redacted: bool = False
    title_dropped: bool = False
    background_context: bool = False

    def line(self) -> str:
        if self._line is None:
            self._render()
        return self._line  # type: ignore[return-value]

    def _render(self) -> None:
        record = self.record
        title, title_secrets = safety.redact_secrets(record.title or "")
        content, content_secrets = safety.redact_secrets(record.content or "")
        flags = set()
        stored_flags = record.extra.get("flags") if isinstance(record.extra, dict) else None
        if safety.scan(title + "\n" + content).injection or (
                isinstance(stored_flags, (list, tuple)) and "instruction_like" in stored_flags):
            flags.add("instruction_like")
        title, title_changed = _inert(title, single_line=True)
        content, content_changed = _inert(content)
        if title_changed or content_changed:
            flags.add("markup_neutralized")
        dims = "+".join(dim for dim, _ in record.scope.constraints) or "global"
        flag_text = (" flagged:" + ",".join(sorted(flags))) if flags else ""
        background = " background preference; not factual query evidence" if self.background_context else ""
        header = f"[m:{record.id} r{record.revision} {record.kind.value} {dims}{flag_text}{background}]"
        title = title.strip()
        # Titles auto-derived from the content (a prefix) are not repeated: they cost tokens only.
        redundant = not _norm(title) or _norm(content).startswith(_norm(title))
        # Heuristic: CoreService.correct keeps the old title, which is often the old content's
        # prefix. After a content correction a non-prefix title may restate the corrected-away
        # statement, so it is not rendered (the content is authoritative).
        self.title_dropped = not redundant and isinstance(record.extra, dict) \
            and "last_corrected_at" in record.extra
        body = content if (redundant or self.title_dropped) else f"{title}: {content}"
        first, *rest = body.split("\n")
        rendered = header + " " + first + "".join("\n    " + line for line in rest)
        if self.conflicts:
            others = ", ".join(f"m:{other}" for other in self.conflicts)
            rendered += f" (conflict: disagrees with {others}; verify before relying on either)"
        self._line = rendered + "\n"
        self.flags = tuple(sorted(flags))
        self.redacted = bool(title_secrets or content_secrets)

    def reasons(self, slice_name: str, why: str, weak: bool = False) -> tuple[str, ...]:
        self.line()
        out = [f"slice:{slice_name}", why]
        if weak:
            out.append(WEAK_MATCH)
        out += [f"flagged:{flag}" for flag in self.flags]
        if self.redacted:
            out.append("redacted:secrets")
        if self.title_dropped:
            out.append("title_omitted:possibly_stale_after_correction")
        if self.conflicts:
            out.append("conflict:annotated")
        return tuple(out)


@dataclass
class _Plan:
    candidates: dict[str, _Candidate]
    omissions: list[ContextOmission]
    conflicts: list[tuple[str, str]]
    excluded_norms: set[str]
    boundary: float | None
    considered: int
    cut_short: bool = False  # the deadline stopped planning before every loaded record was planned


@dataclass
class _Ranking:
    order: list[str] | None = None  # None = no relevance order applied
    invoked: bool = False
    reason: str | None = None
    weak: set[str] = field(default_factory=set)  # ranked ids without lexical/exact evidence


@dataclass
class _Selected:
    seq: int
    slice_index: int
    slice_name: str
    candidate: _Candidate
    tokens: int
    why: str
    rank: int | None = None  # relevance rank when selected by a strong query match


# Queue entry: (candidate, why, strong relevance rank or None, weak relevance match).
_Entry = tuple[_Candidate, str, "int | None", bool]


@dataclass
class _Compiled:
    text: str
    token_count: int
    kind: MeasureKind
    items: list[ContextItem]
    omissions: list[ContextOmission]
    usage: list[dict[str, Any]]
    partial: list[str] = field(default_factory=list)


@dataclass
class _Check:
    valid: bool
    keep: list[tuple[ContextItem, MemoryRecord]]
    dropped: list[ContextItem]
    details: dict[str, Any] | None
    at: float


@dataclass
class _CacheEntry:
    packet: ContextPacket
    valid_until: float | None


# --------------------------------------------------------------------------- service
@partition_bound
class ContextCompiler:
    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx
        self.p = ctx.partition
        self.records = ctx.records
        self._lock = threading.RLock()
        self._cache: OrderedDict[tuple[str, str, int], _CacheEntry] = OrderedDict()
        self._requests: OrderedDict[str, ContextRequest] = OrderedDict()
        self._receipt_writes = 0

    # ------------------------------------------------------------------ public API
    def build(self, access: AccessContext, request: ContextRequest, *, cancel: Any = None) -> ContextPacket:
        self._authorize(access)
        request = normalize_request(request)
        started = time.perf_counter()
        _check_cancel(cancel)
        if self.ctx.config.serving_mode == "disabled":
            return self._disabled(request, started)
        deadline = Deadline(request.deadline_ms)
        # Ranking and history are given a share of the deadline, never all of it: both spend what
        # they are forwarded (history keeps hydrating its projection until it expires), which left
        # selection a spent deadline and packets of one item per slice.
        upstream = Deadline(None if request.deadline_ms is None
                            else max(1, int(request.deadline_ms * _UPSTREAM_DEADLINE_SHARE)))
        request_key = content_hash(request)
        cacheable = not request.include_history  # history state is not covered by the generation
        for _attempt in range(_COMPILE_ATTEMPTS):
            with self.p.db.read() as conn:
                generation = self.p.generation(conn)
                now = self.ctx.clock()
                cache_key = (access.fingerprint(), request_key, generation)
                if cacheable:
                    cached = self._cache_get(cache_key, now)
                    if cached is not None:
                        self.ctx.metrics.incr("context.cache_hit")
                        return self._with_costs(cached, started, cache="hit", ranker=False, history=False)
                approved, truncated, total, load_cut = self._load(conn, access, deadline=deadline, cancel=cancel)
                shown = self._shown_sources(conn, access, approved)
                deletion_generation = self.p.deletion_generation(conn)
            at = request.at_time if request.at_time is not None else now
            plan = self._plan(request, approved, at, now=now, shown=shown, deadline=deadline, cancel=cancel)
            _check_cancel(cancel)
            ranking = self._rank(access, request, plan, upstream, cancel)
            handles, history_reason, history_invoked, history_weak = self._history(access, request, upstream,
                                                                                   cancel)
            _check_cancel(cancel)
            compiled = self._compile(request.token_allowance, self._slice_caps(request),
                                     self._queues(request, plan, ranking), plan.excluded_norms,
                                     max_items=request.max_items, order=request.order, deadline=deadline,
                                     cancel=cancel)
            flags = self._evidence_flags(request, compiled, history_weak)
            partial = list(compiled.partial)
            cut = R_LOAD_DEADLINE if load_cut or plan.cut_short else None
            for reason in (cut, ranking.reason, history_reason, R_TRUNCATED if truncated else None):
                if reason and reason not in partial:
                    partial.append(reason)
            omissions = plan.omissions + compiled.omissions
            pairs = [(item.record_id, item.revision) for item in compiled.items]
            digest = snapshot_hash(pairs, compiled.text, request.token_allowance)
            status = ResultStatus.PARTIAL if partial else ResultStatus.COMPLETE
            with self.p.db.write() as conn:
                if self.p.generation(conn) != generation:
                    # Memory changed while compiling (e.g. a forget): never return the old view.
                    self.ctx.metrics.incr("context.compile_retry")
                    continue
                receipt = self._persist(
                    conn, access, request_key, compiled, omissions, plan.conflicts, digest,
                    allowance=request.token_allowance, generation=generation,
                    deletion_generation=deletion_generation, status=status,
                    partial=partial, history_count=len(handles), conflict_policy=request.conflict_policy,
                    at_time=request.at_time, flags=flags, max_items=request.max_items, order=request.order,
                )
            ranking_needed = ranking.reason in (R_RANK_UNAVAILABLE, R_RANK_FAILED, R_RANK_DEADLINE)
            packet = ContextPacket(
                receipt_id=receipt.receipt_id, text=compiled.text, items=tuple(compiled.items),
                omissions=tuple(_cap_omissions(omissions, _PACKET_OMISSIONS)),
                conflicts=tuple(plan.conflicts), token_count=compiled.token_count,
                token_count_kind=compiled.kind, token_allowance=request.token_allowance,
                coverage=Coverage(total=total, searched=plan.considered, index_ready=not ranking_needed,
                                  partial_reasons=tuple(partial)),
                snapshot_hash=digest, generation=generation, created_at=receipt.created_at,
                status=status, history_handles=tuple(handles), costs={}, flags=flags,
            )
            packet = self._with_costs(packet, started, cache="miss", ranker=ranking.invoked,
                                      history=history_invoked)
            self._register(receipt.receipt_id, request)
            if cacheable and not _TRANSIENT_REASONS.intersection(partial):
                # A packet degraded by a transient failure (ranker, deadline, token counter) is not
                # cached: retrying the same request must compile again, not replay the degradation.
                self._cache_put(cache_key, _CacheEntry(packet, plan.boundary))
            self.ctx.metrics.incr("context.compiled")
            return packet
        raise Contention("memory kept changing while the context was compiled; retry")

    def revalidate(self, access: AccessContext, packet: ContextPacket) -> ContextPacket:
        """Check a packet right before injection; recompile if anything it relied on changed.

        Every selected (id, revision) must still exist, be approved at the same
        revision, be visible under the *current* grants, be current (not expired /
        outside validity) and not be tombstoned since compilation; the text must
        still match the snapshot hash and persisted receipt. Unchanged -> the same
        packet object. Changed -> a recompiled packet (or, when the original
        request is no longer known, the previous selection minus changed items).
        """
        self._authorize(access)
        if not isinstance(packet, ContextPacket):
            raise ValidationError("packet must be a ContextPacket")
        started = time.perf_counter()
        if self.ctx.config.serving_mode == "disabled":
            return self._disabled(ContextRequest(token_allowance=packet.token_allowance), started)
        with self.p.db.read() as conn:
            check = self._check_packet(conn, access, packet)
        degraded = isinstance(packet.coverage, Coverage) and bool(
            _TRANSIENT_REASONS.intersection(packet.coverage.partial_reasons or ()))
        if check.valid and not (degraded and self._registered(packet.receipt_id) is not None):
            return packet
        self.ctx.metrics.incr("context.revalidate_changed")
        request = self._registered(packet.receipt_id)
        if request is not None:
            return self.build(access, request)
        return self._filtered(access, packet, started)

    def explain(self, access: AccessContext, receipt_id: str) -> dict[str, Any]:
        """Explain a persisted context receipt for records this access can still see.

        Items that were deleted or are outside the caller's scope are reported only
        as counts (the two cases are indistinguishable).
        """
        self._authorize(access)
        with self.p.db.read() as conn:
            raw = self._load_receipt(conn, receipt_id, strict=True)
            if raw is None:
                raise NotFound("context receipt not found")
            details = raw["details"]
            entries = [e for e in details.get("items") or () if isinstance(e, dict)]
            omitted = [e for e in details.get("omissions") or () if isinstance(e, dict)]
            ids = sorted({str(e.get("id")) for e in entries + omitted if isinstance(e.get("id"), str)}
                         | {str(x) for pair in details.get("conflicts") or () for x in pair})
            ids = [rid for rid in ids if v.ID_PATTERN.fullmatch(rid)]
            visible = {r.id: r for r in self.records.authorized(
                conn, access.grants, lifecycles=None, ids=ids)} if ids else {}
            for rid in self._excluded(conn, list(visible.values())):
                visible.pop(rid, None)  # a now-excluded observation reads as unavailable (as in get)
            shown = self._shown_sources(conn, access, list(visible.values()))
            current_generation = self.p.generation(conn)
        items = []
        hidden_items = int(details.get("scrubbed_items") or 0)
        usage: dict[str, int] = {}
        for entry in entries:
            record = visible.get(entry.get("id"))
            if record is None:
                hidden_items += 1
                continue
            usage[entry.get("slice", "")] = usage.get(entry.get("slice", ""), 0) + int(entry.get("tokens") or 0)
            items.append({
                "record_id": record.id, "compiled_revision": entry.get("revision"),
                "current_revision": record.revision, "current_lifecycle": record.lifecycle.value,
                "changed_since": record.revision != entry.get("revision")
                or record.lifecycle != Lifecycle.APPROVED,
                "slice": entry.get("slice"), "tokens": entry.get("tokens"),
                "reasons": list(entry.get("reasons") or ()), "kind": record.kind.value,
                "scope": record.scope.as_dict(),
                # Like core.present: evidence the caller may not see is not named.
                "sources": list(shown.get(record.id, ())),
            })
        omissions = []
        for entry in omitted:
            record = visible.get(entry.get("id"))
            if record is None:
                continue
            omissions.append({"record_id": record.id, "reason": entry.get("reason"),
                              "slice": entry.get("slice"), "tokens": entry.get("tokens"),
                              "scope": record.scope.as_dict()})
        hidden_omissions = max(int(details.get("omissions_total") or 0) - len(omissions), 0)
        conflicts = []
        hidden_conflicts = int(details.get("scrubbed_conflicts") or 0)
        for pair in details.get("conflicts") or ():
            if all(member in visible for member in pair):
                conflicts.append(list(pair))
            else:
                hidden_conflicts += 1
        slices = [{"name": s.get("name"), "max_tokens": s.get("max_tokens"),
                   "used_tokens_visible": usage.get(s.get("name"), 0)}
                  for s in details.get("slices") or () if isinstance(s, dict)]
        complete_view = hidden_items == 0
        return {
            "receipt_id": raw["receipt_id"], "operation": RECEIPT_OPERATION, "status": raw.get("status"),
            "created_at": raw.get("created_at"), "generation": details.get("generation"),
            "current_generation": current_generation,
            "generation_current": details.get("generation") == current_generation,
            "deletion_generation": details.get("deletion_generation"),
            "snapshot_hash": details.get("snapshot_hash"),
            "token_allowance": details.get("token_allowance"),
            # A total that includes items this caller cannot see is withheld.
            "token_count": details.get("token_count") if complete_view else None,
            "token_count_kind": details.get("token_count_kind"),
            "grants_match": details.get("grants_fingerprint") == access.grants.fingerprint(),
            "items": items, "unavailable_items": hidden_items,
            "omissions": omissions, "unavailable_omissions": hidden_omissions,
            "conflicts": conflicts, "unavailable_conflicts": hidden_conflicts,
            "slices": slices, "history_handles": int(details.get("history_handles") or 0),
            "partial_reasons": [r for r in details.get("partial_reasons") or () if isinstance(r, str)],
            "flags": [f for f in details.get("flags") or () if isinstance(f, str)],
            "scrubbed": bool(details.get("scrubbed")),
            "note": "unavailable entries were deleted or are outside this caller's scope;"
                    " they are reported only as counts",
        }

    # ------------------------------------------------------------------ forgetting
    def purge(self, conn: Any, target_kind: str, target_token: str, forget_policy: Any) -> dict[str, int]:
        """Scrub persisted context receipts of records that no longer exist; drop cached packets.

        Works from the token alone (also replayed by ledger reconciliation): any
        receipt referencing a record id that is gone is rewritten without it.
        """
        self.clear_cache()
        self._ensure_schema(conn)
        if target_kind == "profile":
            rows = conn.execute("DELETE FROM context_receipt_items").rowcount
            return {"context_receipt_refs": rows} if rows else {}
        receipt_ids = [r[0] for r in conn.execute(
            "SELECT DISTINCT c.receipt_id FROM context_receipt_items c"
            " WHERE NOT EXISTS (SELECT 1 FROM records r WHERE r.id = c.record_id)"
            " ORDER BY c.receipt_id").fetchall()]
        scrubbed = 0
        for receipt_id in receipt_ids:
            missing = {r[0] for r in conn.execute(
                "SELECT c.record_id FROM context_receipt_items c WHERE c.receipt_id=?"
                " AND NOT EXISTS (SELECT 1 FROM records r WHERE r.id = c.record_id)", (receipt_id,))}
            try:
                raw = self.p.load_receipt(conn, receipt_id)
            except IntegrityError:
                raw = None
                conn.execute("DELETE FROM receipts WHERE id=?", (receipt_id,))
            if raw is not None:
                self.p.save_receipt(conn, _scrubbed_receipt(raw, missing))
                scrubbed += 1
            conn.executemany("DELETE FROM context_receipt_items WHERE receipt_id=? AND record_id=?",
                             [(receipt_id, rid) for rid in sorted(missing)])
        return {"context_receipts_scrubbed": scrubbed} if scrubbed else {}

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def close(self) -> None:
        with self._lock:
            self._cache.clear()
            self._requests.clear()

    # ------------------------------------------------------------------ authorization / load
    def _authorize(self, access: AccessContext) -> None:
        if not isinstance(access, AccessContext):
            raise AccessDenied("a trusted AccessContext is required")
        if access.partition.partition_id != self.p.partition_id:
            raise AccessDenied("the access context belongs to a different partition")
        policy.require(access, Operation.READ)

    def _load(self, conn: Any, access: AccessContext, *, deadline: Deadline | None = None,
              cancel: Any = None) -> tuple[list[MemoryRecord], bool, int, bool]:
        """(approved records, truncated at max_projection_records, authorized total, cut short by
        the deadline). Records are decrypted lazily in pinned/recency order with a deadline and
        cancellation check every ``_LOAD_CHUNK`` records (the first chunk is always loaded)."""
        cap = max(1, int(self.ctx.config.max_projection_records))
        approved: list[MemoryRecord] = []
        truncated = cut_short = False
        records = self.records.iter_authorized(conn, access.grants, lifecycles=(Lifecycle.APPROVED,),
                                               limit=cap + 1)
        try:
            for record in records:
                if len(approved) >= cap:
                    truncated = True
                    break
                if approved and len(approved) % _LOAD_CHUNK == 0:
                    _check_cancel(cancel)
                    if deadline is not None and deadline.expired:
                        cut_short = True
                        break
                approved.append(record)
        finally:
            records.close()
        total = self.records.count_authorized(conn, access.grants).get(Lifecycle.APPROVED.value, 0)
        # Observations of paths the host or registration now excludes are never injected.
        hidden = self._excluded(conn, approved)
        if hidden:
            approved = [r for r in approved if r.id not in hidden]
            total = max(0, total - len(hidden))
        return approved, truncated, total, cut_short

    def _excluded(self, conn: Any, records: list[MemoryRecord]) -> set[str]:
        """Ids among ``records`` that are never injected: observations of currently excluded paths
        (and what restates them), and approved procedures whose evidence episodes are gone."""
        if not records:
            return set()
        hidden: set[str] = set()
        repository = self.ctx.services.repository
        if repository is not None and hasattr(repository, "excluded_observations"):
            hidden |= set(repository.excluded_observations(conn, records))
        procedures = self.ctx.services.procedures
        if procedures is not None and hasattr(procedures, "unbacked"):
            hidden |= set(procedures.unbacked(conn, [r for r in records if r.id not in hidden]))
        return hidden

    def _shown_sources(self, conn: Any, access: AccessContext, records: Iterable[MemoryRecord]
                       ) -> dict[str, tuple[str, ...]]:
        """Per record, the source identities ``access`` may see (core.present's rule): ids of
        memories outside the grants and transcript refs of hidden sessions are not named."""
        records = list(records)
        refs = {s.ref for r in records for s in r.sources if s.kind.value == "memory"}
        visible = self.records.visible_ids(conn, access.grants, refs) if refs else set()
        archived = [s for r in records for s in r.sources if s.kind.value in ("message", "session")]
        history = self.ctx.services.history
        hidden: set[str] = set()
        if archived and history is not None and hasattr(history, "hidden_sources"):
            hidden = history.hidden_sources(conn, access.grants, archived)
        return {r.id: tuple(s.identity() for s in r.sources
                            if (s.kind.value != "memory" or s.ref in visible) and s.identity() not in hidden)
                for r in records}

    def _live_conflicts(self, current: dict[str, MemoryRecord]) -> dict[str, set[str]]:
        """Symmetric conflict partners among ``current`` computed from the records themselves
        (same subject/predicate in the same scope, different content) - never from stored links,
        which a correction can make wrong in either direction."""
        groups: dict[str, list[MemoryRecord]] = {}
        for record in current.values():
            token = self.records.subject_token(record)
            if token is not None:
                groups.setdefault(token, []).append(record)
        partners: dict[str, set[str]] = {}
        for members in groups.values():
            if len(members) < 2:
                continue
            tokens = {r.id: self.records.content_token(r.content) for r in members}
            for i, a in enumerate(members):
                for b in members[i + 1:]:
                    if tokens[a.id] != tokens[b.id]:
                        partners.setdefault(a.id, set()).add(b.id)
                        partners.setdefault(b.id, set()).add(a.id)
        return partners

    # ------------------------------------------------------------------ planning
    def _plan(self, request: ContextRequest, approved: list[MemoryRecord], at: float, *,
              now: float | None = None, shown: dict[str, tuple[str, ...]] | None = None,
              deadline: Deadline | None = None, cancel: Any = None) -> _Plan:
        now = at if now is None else now
        omissions: list[ContextOmission] = []
        current: dict[str, MemoryRecord] = {}
        members: dict[str, tuple[str, ...]] = {}
        background_ids: set[str] = set()
        boundary: float | None = None
        considered = 0
        cut_short = False
        for record in approved:
            if considered and considered % _LOAD_CHUNK == 0:
                _check_cancel(cancel)
                if deadline is not None and deadline.expired:
                    cut_short = True  # records are in pinned/recency order: the rest matter least
                    break
            considered += 1
            nxt = _next_boundary(record, at, now)
            if nxt is not None:
                boundary = nxt if boundary is None else min(boundary, nxt)
            repository = record.scope.get("repository")
            if request.repository is not None and repository is not None and repository != request.repository:
                continue  # another repository's memory is not part of this request's context
            slices = tuple(spec.name for spec in request.slices if _member(spec, record))
            reason = _time_reason(record, at, now) or (None if _governed(record) else "ungoverned")
            if reason is not None:
                if slices:
                    omissions.append(ContextOmission(record.id, reason, slices[0]))
                continue
            current[record.id] = record
            if slices and request.evidence_policy == "conservative" and request.query:
                decision = assess_evidence(request.query, record.content)
                # Only profile preferences may enter as background. They are labelled below and
                # never counted as factual evidence by the conservative packet flag.
                background = record.kind == MemoryKind.PREFERENCE and not record.scope.constraints
                if background and not decision.admitted:
                    background_ids.add(record.id)
                if not background and not decision.admitted:
                    omissions.append(ContextOmission(record.id, decision.reason, slices[0]))
                    continue
            if slices:
                members[record.id] = slices
        excluded = [rid for rid in request.exclude_ids if rid in current]
        excluded_norms = {_norm(current[rid].content) for rid in excluded}
        in_context = set(members) | set(excluded)
        pairs: set[tuple[str, str]] = set()
        for rid, others in self._live_conflicts(current).items():
            for other in others:
                if rid in in_context or other in in_context:
                    pairs.add((min(rid, other), max(rid, other)))
        conflicts = sorted(pairs)
        partners: dict[str, set[str]] = {}
        for a, b in conflicts:
            partners.setdefault(a, set()).add(b)
            partners.setdefault(b, set()).add(a)
        for rid in excluded:
            if rid in members:
                omissions.append(ContextOmission(rid, "excluded", members.pop(rid)[0]))
        if request.conflict_policy == "omit":
            for rid in sorted(partners):
                if rid in members:
                    omissions.append(ContextOmission(rid, "conflict", members.pop(rid)[0]))
        candidates = {
            rid: _Candidate(
                record=current[rid], slices=slices, norm=_norm(current[rid].content),
                background_context=rid in background_ids,
                conflicts=tuple(sorted(partners.get(rid, ()))) if request.conflict_policy == "annotate" else (),
                sources=None if shown is None else shown.get(rid, ()),
            )
            for rid, slices in members.items()
        }
        return _Plan(candidates, omissions, conflicts, excluded_norms, boundary, considered, cut_short)

    def _queues(self, request: ContextRequest, plan: _Plan, ranking: _Ranking
                ) -> list[tuple[str, list[_Entry]]]:
        fallback = sorted(plan.candidates.values(), key=lambda c: _recency_key(c.record))
        position = {rid: i for i, rid in enumerate(ranking.order)} if ranking.order is not None else None
        queues: list[tuple[str, list[_Entry]]] = []
        for spec in request.slices:
            members = [c for c in fallback if spec.name in c.slices]
            queue: list[_Entry]
            if spec.query_relevant and request.query and position is not None:
                pinned: list[_Entry] = [(c, "pinned", None, False) for c in members if c.record.pinned]
                ranked = sorted((c for c in members if not c.record.pinned and c.record.id in position),
                                key=lambda c: position[c.record.id])
                queue = pinned
                for c in ranked:
                    rank = position[c.record.id] + 1
                    weak = c.record.id in ranking.weak
                    queue.append((c, f"relevance_rank:{rank}", None if weak else rank, weak))
                # Background preferences may fill remaining space, after genuine query hits.
                if request.evidence_policy == "conservative":
                    queued = {entry[0].record.id for entry in queue}
                    # Evidence normalization covers conservative lexical paraphrases that an
                    # FTS prefix cannot (e.g. indented/indentation). These candidates passed
                    # admission independently; rank them after actual retrieval hits.
                    for c in members:
                        if c.record.id not in queued and not c.background_context:
                            rank = len(position) + len(queue) + 1
                            queue.append((c, "query_evidence", rank, False))
                    queue.extend((c, "background_context", None, False) for c in members
                                 if c.background_context and c.record.id not in queued)
            else:
                queue = [(c, "pinned" if c.record.pinned else "recency", None, False) for c in members]
            queues.append((spec.name, queue))
        return queues

    @staticmethod
    def _slice_caps(request: ContextRequest) -> dict[str, int]:
        return {spec.name: spec.max_tokens for spec in request.slices}

    # ------------------------------------------------------------------ ranking / history
    def _rank(self, access: AccessContext, request: ContextRequest, plan: _Plan, deadline: Deadline,
              cancel: Any) -> _Ranking:
        relevant = {spec.name for spec in request.slices if spec.query_relevant}
        if not request.query or not relevant:
            return _Ranking()
        pool = sorted((c.record for c in plan.candidates.values() if relevant.intersection(c.slices)),
                      key=_recency_key)
        if not pool:
            return _Ranking()
        if deadline.expired:
            return _Ranking(reason=R_RANK_DEADLINE)
        retrieval = self.ctx.services.retrieval
        rank = getattr(retrieval, "rank", None) if retrieval is not None else None
        if not callable(rank):
            return _Ranking(reason=R_RANK_UNAVAILABLE)
        allowed = {record.id for record in pool}
        remaining = deadline.remaining_s()
        values = {
            "access": access, "query": request.query, "records": pool, "ids": [r.id for r in pool],
            # A ranker that searches the whole authorized namespace (rather than the pool)
            # needs room for records outside the relevance slices (heuristic bound).
            "limit": max(1, min(plan.considered, _RANK_LIMIT)), "at_time": request.at_time,
            "files": list(request.files), "repository": request.repository, "cancel": cancel,
            "deadline_ms": None if remaining is None else max(1, int(remaining * 1000)),
        }
        relevant_specs = [spec for spec in request.slices if spec.query_relevant]
        if all(spec.kinds for spec in relevant_specs):
            values["kinds"] = tuple(sorted({k for spec in relevant_specs for k in spec.kinds}, key=str))
        try:
            args, kwargs = _bind(rank, values)
        except _Unbindable:
            return _Ranking(reason=R_RANK_UNAVAILABLE)
        try:
            order, partial, weak = self._invoke(
                rank, args, kwargs, lambda result: (*_ranked_ids(result, allowed), _weak_ids(result, allowed)))
        except Cancelled:
            raise
        except Exception as exc:  # sibling failure must degrade, not break context
            logger.warning("context: relevance ranking failed (%s)", type(exc).__name__)
            self.ctx.metrics.incr("context.rank_failed")
            return _Ranking(invoked=True, reason=R_RANK_FAILED)
        return _Ranking(order=order, invoked=True, reason=partial, weak=weak)

    def _history(self, access: AccessContext, request: ContextRequest, deadline: Deadline,
                 cancel: Any) -> tuple[list[str], str | None, bool, bool]:
        """(handles, partial reason, invoked, weak_only)."""
        if not request.include_history or request.history_limit <= 0 or not request.query:
            return [], None, False, False
        history = self.ctx.services.history
        search = getattr(history, "search", None) if history is not None else None
        if not callable(search):
            return [], R_HISTORY_UNAVAILABLE, False, False
        remaining = deadline.remaining_s()
        values = {
            "access": access, "query": request.query, "limit": request.history_limit, "cancel": cancel,
            "deadline_ms": None if remaining is None else max(1, int(remaining * 1000)),
            # Messages superseded by a content correction are not offered as evidence.
            "exclude_corrected": True,
        }
        try:
            args, kwargs = _bind(search, values)
        except _Unbindable:
            return [], R_HISTORY_UNAVAILABLE, False, False
        try:
            handles, partial, weak_only = self._invoke(
                search, args, kwargs, lambda result: _history_handles(result, request.history_limit))
        except Cancelled:
            raise
        except Exception as exc:
            logger.warning("context: history search failed (%s)", type(exc).__name__)
            self.ctx.metrics.incr("context.history_failed")
            return [], R_HISTORY_FAILED, True, False
        return handles, partial, True, weak_only

    @staticmethod
    def _evidence_flags(request: ContextRequest, compiled: _Compiled, history_weak: bool) -> tuple[str, ...]:
        """Content-free evidence-strength flags (see the module docstring)."""
        flags = []
        relevant = {spec.name for spec in request.slices if spec.query_relevant}
        if request.query and relevant:
            strong = any(item.slice in relevant and WEAK_MATCH not in item.reasons
                         and any(r.startswith("relevance_rank:") for r in item.reasons) for item in compiled.items)
            if not strong:
                flags.append(FLAG_WEAK_ONLY)
        if request.evidence_policy == "conservative" and request.query:
            evidence = [item for item in compiled.items if "background_context" not in item.reasons]
            if not evidence:
                flags.append("no_query_evidence")
            if any("background_context" in item.reasons for item in compiled.items):
                flags.append("background_preferences")
        if history_weak:
            flags.append(FLAG_HISTORY_WEAK_ONLY)
        return tuple(flags)

    def _invoke(self, func: Callable[..., Any], args: list[Any], kwargs: dict[str, Any],
                normalize: Callable[[Any], Any]) -> Any:
        if any(a is _CONN for a in args) or any(value is _CONN for value in kwargs.values()):
            with self.p.db.read() as conn:
                args = [conn if a is _CONN else a for a in args]
                kwargs = {k: conn if value is _CONN else value for k, value in kwargs.items()}
                return normalize(func(*args, **kwargs))
        return normalize(func(*args, **kwargs))

    # ------------------------------------------------------------------ selection
    def _meter(self) -> TokenMeter:
        return TokenMeter(self.ctx.host.token_counter, chars_per_token=self.ctx.config.estimate_chars_per_token,
                          margin=self.ctx.config.estimate_margin)

    def _compile(self, allowance: int, caps: dict[str, int], queues: list[tuple[str, list[_Entry]]],
                 excluded_norms: set[str], *, max_items: int | None = None, order: str = "slices",
                 deadline: Deadline | None = None, cancel: Any = None) -> _Compiled:
        meter = self._meter()
        try:
            return self._select(allowance, caps, queues, excluded_norms, meter, max_items=max_items, order=order,
                                deadline=deadline, cancel=cancel)
        except CounterFailure:
            logger.warning("context: host token counter failed; using the conservative estimate")
            self.ctx.metrics.incr("context.token_counter_failed")
            compiled = self._select(allowance, caps, queues, excluded_norms, meter.estimator(),
                                    max_items=max_items, order=order, deadline=deadline, cancel=cancel)
            compiled.partial.append(R_COUNTER_FAILED)
            return compiled

    def _select(self, allowance: int, caps: dict[str, int], queues: list[tuple[str, list[_Entry]]],
                excluded_norms: set[str], meter: TokenMeter, *, max_items: int | None = None,
                order: str = "slices", deadline: Deadline | None = None, cancel: Any = None) -> _Compiled:
        """Round-robin selection (see the module docstring).

        Work is bounded independently of the number of approved records. A slice stops
        evaluating its queue once it has refused ``_MAX_SLICE_MISSES`` candidates that would have
        fit it empty (it is crowded) or ``_MAX_SLICE_OVERSIZED`` candidates too large for it on
        their own; the records it did not evaluate are omitted as ``slice_cap`` / ``budget`` only
        when not even the shortest possible line fits the room left, otherwise as
        ``not_evaluated`` and the packet is PARTIAL (``R_SELECT_TRUNCATED``). An expired deadline
        stops selection only after the first round (every slice had one turn) and after
        ``_SELECT_MIN_EVALUATIONS`` candidates were evaluated (PARTIAL, ``R_SELECT_DEADLINE``).
        """
        overhead = meter.count(_assemble(()))
        budget = Budget(allowance, overhead, caps)
        pending_queues = {name: deque(queue) for name, queue in queues}
        slice_index = {name: i for i, (name, _) in enumerate(queues)}
        seen_norms = set(excluded_norms)
        resolved: set[str] = set()
        refused: OrderedDict[str, ContextOmission] = OrderedDict()
        token_cost: dict[str, int] = {}
        selected: list[_Selected] = []
        weak_ids: set[str] = set()
        misses = {name: 0 for name, _ in queues}  # refusals because the slice/budget is crowded
        oversized = {name: 0 for name, _ in queues}  # refusals of records no state of the slice fits
        shortest = meter.count(_SHORTEST_LINE)  # no record renders to a cheaper line
        evaluated = 0
        partial: list[str] = []
        active = [name for name, queue in queues if queue]
        rounds = 0

        def retire(name: str, queue: deque) -> None:
            """Omit the rest of ``queue`` unrendered, with an honest reason."""
            if budget.remaining < shortest:
                reason = BUDGET  # nothing fits the shared total any more
            elif caps[name] - budget.used[name] < shortest:
                reason = SLICE_CAP  # nothing fits this slice any more
            else:
                reason = NOT_EVALUATED  # a later, smaller record might still have fit
            for other, *_ in queue:
                rid = other.record.id
                if rid not in resolved:
                    if reason == BUDGET:
                        resolved.add(rid)
                    # A record still queued in another slice may be selected there (its omission
                    # is then dropped).
                    refused.setdefault(rid, ContextOmission(rid, reason, name, token_cost.get(rid)))
            queue.clear()

        while active:
            _check_cancel(cancel)
            if (rounds and deadline is not None and deadline.expired
                    and evaluated >= _SELECT_MIN_EVALUATIONS):
                partial.append(R_SELECT_DEADLINE)  # every slice had one turn; stop here
                break
            rounds += 1
            still_active = []
            for name in active:
                queue = pending_queues[name]
                entry = None
                while queue:
                    candidate, why, rank, weak = queue.popleft()
                    if candidate.record.id not in resolved:
                        entry = (candidate, why, rank, weak)
                        break
                if entry is not None:
                    candidate, why, rank, weak = entry
                    rid = candidate.record.id
                    if candidate.norm in seen_norms:
                        resolved.add(rid)
                        refused[rid] = ContextOmission(rid, "duplicate", name)
                    elif max_items is not None and len(selected) >= max_items:
                        resolved.add(rid)  # the item cap is reached; nothing more is injected
                        refused[rid] = ContextOmission(rid, MAX_ITEMS, name, token_cost.get(rid))
                    elif budget.exhausted:
                        resolved.add(rid)  # nothing more can fit; skip tokenizer calls
                        refused[rid] = ContextOmission(rid, BUDGET, name, token_cost.get(rid))
                    elif rid not in token_cost and min(budget.remaining, caps[name] - budget.used[name]) < shortest:
                        # Not even the shortest possible line fits: nothing queued here can, so
                        # nothing more is rendered for this slice (exact budget / slice_cap reasons).
                        queue.appendleft(entry)
                        retire(name, queue)
                    else:
                        if rid not in token_cost:
                            token_cost[rid] = meter.count(candidate.line())
                            evaluated += 1
                        tokens = token_cost[rid]
                        refusal = budget.refusal(name, tokens)
                        if refusal is None:
                            budget.take(name, tokens)
                            selected.append(_Selected(len(selected), slice_index[name], name, candidate,
                                                      tokens, why, rank))
                            if weak:
                                weak_ids.add(rid)
                            resolved.add(rid)
                            seen_norms.add(candidate.norm)
                            refused.pop(rid, None)
                        else:
                            refused[rid] = ContextOmission(rid, refusal, name, tokens)
                            if refusal == BUDGET:
                                resolved.add(rid)  # the shared total only shrinks
                            if tokens > caps[name] or tokens > budget.allowance - budget.overhead:
                                oversized[name] += 1  # fits no state of this slice: not crowding
                            else:
                                misses[name] += 1
                            if misses[name] >= _MAX_SLICE_MISSES or oversized[name] >= _MAX_SLICE_OVERSIZED:
                                retire(name, queue)
                if queue:
                    still_active.append(name)
            active = still_active
        def render_key(s: _Selected) -> tuple:
            if order == "relevance":  # strong query matches first, by relevance rank
                return (0, s.rank, s.slice_index, s.seq) if s.rank is not None else (1, 0, s.slice_index, s.seq)
            return (s.slice_index, s.seq)

        # Tokenizers are not additive: count the whole text and trim until it fits.
        text, total = "", 0
        while selected:
            ordered = sorted(selected, key=render_key)
            text = _assemble(s.candidate.line() for s in ordered)
            total = meter.count(text)
            if total <= allowance:
                break
            victim = max(selected, key=lambda s: s.seq)
            selected.remove(victim)
            budget.release(victim.slice_name, victim.tokens)
            refused[victim.candidate.record.id] = ContextOmission(
                victim.candidate.record.id, BUDGET, victim.slice_name, victim.tokens)
        if not selected:
            text, total = "", 0
        items = [
            ContextItem(
                record_id=s.candidate.record.id, revision=s.candidate.record.revision, slice=s.slice_name,
                kind=s.candidate.record.kind, scope=s.candidate.record.scope, tokens=s.tokens,
                reasons=s.candidate.reasons(s.slice_name, s.why, s.candidate.record.id in weak_ids)
                    + (("background_context",) if s.candidate.background_context else ()) ,
                sources=s.candidate.sources if s.candidate.sources is not None
                else tuple(src.identity() for src in s.candidate.record.sources),
                conflict_note=("disagrees with " + ", ".join(f"m:{c}" for c in s.candidate.conflicts))
                if s.candidate.conflicts else "",
            )
            for s in sorted(selected, key=render_key)
        ]
        if any(omission.reason == NOT_EVALUATED for omission in refused.values()):
            partial.append(R_SELECT_TRUNCATED)
        return _Compiled(text=text, token_count=total, kind=meter.kind, items=items,
                         omissions=list(refused.values()), usage=budget.slice_usage(caps), partial=partial)

    # ------------------------------------------------------------------ revalidation
    def _check_packet(self, conn: Any, access: AccessContext, packet: ContextPacket) -> _Check:
        # Packets come back from the host: anything malformed simply counts as "changed".
        raw_items = list(packet.items) if isinstance(packet.items, (tuple, list)) else []
        items = [i for i in raw_items if isinstance(i, ContextItem) and isinstance(i.record_id, str)
                 and isinstance(i.revision, int) and not isinstance(i.revision, bool)]
        well_formed = len(items) == len(raw_items) and isinstance(packet.text, str)
        now = self.ctx.clock()
        try:
            intact = well_formed and snapshot_hash([(i.record_id, i.revision) for i in items], packet.text,
                                                   packet.token_allowance) == packet.snapshot_hash
        except (TypeError, ValueError):
            intact = False
        raw = self._load_receipt(conn, packet.receipt_id, strict=False)
        details = raw["details"] if raw is not None else None
        receipt_ok = details is not None and details.get("snapshot_hash") == packet.snapshot_hash
        observed = details.get("deletion_generation") if details else 0
        observed = observed if isinstance(observed, int) and not isinstance(observed, bool) else 0
        at_time = details.get("at_time") if details else None
        at = float(at_time) if isinstance(at_time, (int, float)) and not isinstance(at_time, bool) else now
        conflicts = packet.conflicts if isinstance(packet.conflicts, (tuple, list)) else ()
        partners = {x for pair in conflicts if isinstance(pair, (tuple, list)) for x in pair
                    if isinstance(x, str)}
        ids = sorted({i.record_id for i in items} | partners)
        ids = [rid for rid in ids if v.ID_PATTERN.fullmatch(rid)]
        current = {r.id: r for r in self.records.authorized(
            conn, access.grants, lifecycles=None, ids=ids)} if ids else {}
        # Observations of paths the *current* exclusion set covers (an exclusion added after the
        # packet was compiled, e.g. by a host restarted with new patterns) count as gone, exactly
        # as build_context/get/list hide them: such an item never passes this pre-injection check.
        for rid in self._excluded(conn, list(current.values())):
            current.pop(rid, None)
        tombstoned = self._tombstoned_since(conn, list(current.values()), observed)
        # A conflict partner that vanished makes an annotation stale (or, with 'omit',
        # may now allow the other side in): treat it as a change.
        partners_ok = all(
            rid in current and current[rid].lifecycle == Lifecycle.APPROVED and rid not in tombstoned
            and _time_reason(current[rid], at, now) is None for rid in partners)
        keep: list[tuple[ContextItem, MemoryRecord]] = []
        dropped: list[ContextItem] = []
        for item in items:
            record = current.get(item.record_id)
            if (record is not None and record.lifecycle == Lifecycle.APPROVED
                    and record.revision == item.revision and _time_reason(record, at, now) is None
                    and _governed(record) and record.id not in tombstoned):
                keep.append((item, record))
            else:
                dropped.append(item)
        valid = intact and receipt_ok and partners_ok and not dropped
        compiled_generation = details.get("generation") if details else None
        if valid and keep and compiled_generation != self.p.generation(conn):
            # Something changed since compilation. A newly approved record that conflicts with an
            # injected one does not touch the injected record's revision, so look for conflicts
            # the packet does not account for (the conflict policy must be applied to them).
            known = {(min(a, b), max(a, b)) for pair in conflicts if isinstance(pair, (tuple, list))
                     and len(pair) == 2 for a, b in [pair] if isinstance(a, str) and isinstance(b, str)}
            approved, _truncated, _total, _cut = self._load(conn, access)
            live = {r.id: r for r in approved if _time_reason(r, at, now) is None and _governed(r)}
            partners_now = self._live_conflicts(live)
            for item, _record in keep:
                for other in partners_now.get(item.record_id, ()):
                    if (min(item.record_id, other), max(item.record_id, other)) not in known:
                        valid = False
        return _Check(valid, keep, dropped, details, at)

    def _tombstoned_since(self, conn: Any, records: list[MemoryRecord], observed: int) -> set[str]:
        if not records:
            return set()
        rows = conn.execute(
            "SELECT target_kind, target_token FROM tombstones WHERE generation > ?"
            " AND target_kind IN ('memory', 'source')", (observed,)).fetchall()
        if not rows:
            return set()
        memories = {r[1] for r in rows if r[0] == "memory"}
        sources = {r[1] for r in rows if r[0] == "source"}
        out = set()
        for record in records:
            if record.id in memories or any(
                    self.records.source_token(s.identity()) in sources for s in record.sources):
                out.add(record.id)
        return out

    def _filtered(self, access: AccessContext, packet: ContextPacket, started: float) -> ContextPacket:
        """Revalidate without the original request: keep only still-valid items, re-render, re-count."""
        for _attempt in range(_COMPILE_ATTEMPTS):
            with self.p.db.read() as conn:
                generation = self.p.generation(conn)
                check = self._check_packet(conn, access, packet)
                approved, _truncated, total, _cut = self._load(conn, access)
                shown = self._shown_sources(conn, access, [record for _, record in check.keep])
                deletion_generation = self.p.deletion_generation(conn)
            details = check.details or {}
            conflict_policy = details.get("conflict_policy") if details.get("conflict_policy") in (
                "annotate", "omit") else "annotate"
            now = self.ctx.clock()
            current = {r.id: r for r in approved if _time_reason(r, check.at, now) is None and _governed(r)}
            keep_ids = {record.id for _, record in check.keep}
            partners: dict[str, set[str]] = {}
            for rid, others in self._live_conflicts(current).items():
                for other in others:
                    if rid in keep_ids or other in keep_ids:
                        partners.setdefault(rid, set()).add(other)
                        partners.setdefault(other, set()).add(rid)
            omissions = [ContextOmission(None, "stale", _slice_name(item.slice)) for item in check.dropped]
            queues: OrderedDict[str, list[_Entry]] = OrderedDict()
            for item, record in check.keep:
                name = _slice_name(item.slice)
                conflicts = tuple(sorted(partners.get(record.id, ())))
                if conflicts and conflict_policy == "omit":
                    omissions.append(ContextOmission(record.id, "conflict", name))
                    continue
                candidate = _Candidate(record=record, slices=(name,), norm=_norm(record.content),
                                       conflicts=conflicts, sources=shown.get(record.id, ()),
                                       background_context="background_context" in item.reasons)
                queues.setdefault(name, []).append((candidate, "revalidated", None, False))
            stored_caps = {s.get("name"): s.get("max_tokens") for s in details.get("slices") or ()
                           if isinstance(s, dict)}
            caps = {}
            for name in queues:
                cap = stored_caps.get(name)
                valid_cap = isinstance(cap, int) and not isinstance(cap, bool) and cap >= 0
                caps[name] = cap if valid_cap else packet.token_allowance
            compiled = self._compile(packet.token_allowance, caps, list(queues.items()), set())
            partial = [R_FILTERED] + [r for r in compiled.partial if r != R_FILTERED]
            omissions += compiled.omissions
            pairs = [(item.record_id, item.revision) for item in compiled.items]
            selected_ids = {item.record_id for item in compiled.items}
            conflicts = sorted({(min(a, b), max(a, b)) for a, others in partners.items() for b in others
                                if a in selected_ids or b in selected_ids})
            digest = snapshot_hash(pairs, compiled.text, packet.token_allowance)
            with self.p.db.write() as conn:
                if self.p.generation(conn) != generation:
                    continue
                receipt = self._persist(
                    conn, access, "", compiled, omissions, conflicts, digest,
                    allowance=packet.token_allowance, generation=generation,
                    deletion_generation=deletion_generation, status=ResultStatus.PARTIAL, partial=partial,
                    history_count=0, conflict_policy=conflict_policy,
                    at_time=details.get("at_time") if isinstance(details.get("at_time"), (int, float)) else None,
                )
            result = ContextPacket(
                receipt_id=receipt.receipt_id, text=compiled.text, items=tuple(compiled.items),
                omissions=tuple(_cap_omissions(omissions, _PACKET_OMISSIONS)), conflicts=tuple(conflicts),
                token_count=compiled.token_count, token_count_kind=compiled.kind,
                token_allowance=packet.token_allowance,
                coverage=Coverage(total=total, searched=len(packet.items), index_ready=True,
                                  partial_reasons=tuple(partial)),
                snapshot_hash=digest, generation=generation, created_at=receipt.created_at,
                status=ResultStatus.PARTIAL, history_handles=(), costs={},
            )
            return self._with_costs(result, started, cache="miss", ranker=False, history=False)
        raise Contention("memory kept changing while the context was revalidated; retry")

    # ------------------------------------------------------------------ receipts
    def _ensure_schema(self, conn: Any) -> None:
        # Stores created before this table existed get it lazily (inside the caller's write tx).
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='context_receipt_items'").fetchone()
        if not exists:
            for statement in _DDL:
                conn.execute(statement)

    def _persist(self, conn: Any, access: AccessContext, request_key: str, compiled: _Compiled,
                 omissions: list[ContextOmission], conflicts: list[tuple[str, str]], digest: str, *,
                 allowance: int, generation: int, deletion_generation: int, status: ResultStatus,
                 partial: list[str],
                 history_count: int, conflict_policy: str, at_time: float | None,
                 flags: tuple[str, ...] = (), max_items: int | None = None, order: str = "slices") -> Receipt:
        self._ensure_schema(conn)
        itemized = [o for o in omissions if o.record_id]
        details = {
            "format": 1, "snapshot_hash": digest, "generation": generation,
            "deletion_generation": deletion_generation,
            "grants_fingerprint": access.grants.fingerprint(), "access_fingerprint": access.fingerprint(),
            "request_token": self.p.token("context-request", request_key) if request_key else None,
            "token_allowance": allowance, "token_count": compiled.token_count,
            "token_count_kind": compiled.kind.value, "slices": compiled.usage,
            "items": [{"id": i.record_id, "revision": i.revision, "slice": i.slice, "tokens": i.tokens,
                       "reasons": list(i.reasons)} for i in compiled.items],
            "omissions": [{"id": o.record_id, "reason": o.reason, "slice": o.slice, "tokens": o.tokens}
                          for o in itemized[:_RECEIPT_OMISSIONS]],
            "omissions_total": len(omissions),
            "conflicts": [list(pair) for pair in conflicts], "conflict_policy": conflict_policy,
            "at_time": at_time, "history_handles": history_count, "partial_reasons": list(partial),
            "flags": list(flags), "max_items": max_items, "order": order,
        }
        receipt = self.p.make_receipt(
            conn, RECEIPT_OPERATION, "partial" if status != ResultStatus.COMPLETE else "ok",
            record_ids=tuple(i.record_id for i in compiled.items),
            revisions=tuple(i.revision for i in compiled.items), details=details,
            limitations=("context receipts store ids, revisions and token counts only - no memory content",),
        )
        refs = sorted({i.record_id for i in compiled.items}
                      | {o.record_id for o in itemized[:_RECEIPT_OMISSIONS] if o.record_id}
                      | {x for pair in conflicts for x in pair})
        conn.executemany("INSERT OR IGNORE INTO context_receipt_items(receipt_id, record_id) VALUES(?, ?)",
                         [(receipt.receipt_id, rid) for rid in refs])
        self._prune(conn)
        return receipt

    def _prune(self, conn: Any) -> None:
        with self._lock:
            self._receipt_writes += 1
            due = (self._receipt_writes - 1) % max(1, _PRUNE_EVERY) == 0
        if not due:
            return
        now = self.ctx.clock()
        conn.execute("DELETE FROM receipts WHERE operation=? AND created_at < ?",
                     (RECEIPT_OPERATION, now - CONTEXT_RECEIPT_TTL_S))
        conn.execute(
            "DELETE FROM receipts WHERE id IN (SELECT id FROM receipts WHERE operation=?"
            " ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?)", (RECEIPT_OPERATION, CONTEXT_RECEIPT_MAX))
        conn.execute("DELETE FROM context_receipt_items WHERE NOT EXISTS"
                     " (SELECT 1 FROM receipts r WHERE r.id = context_receipt_items.receipt_id)")

    def _load_receipt(self, conn: Any, receipt_id: Any, *, strict: bool) -> dict[str, Any] | None:
        if not isinstance(receipt_id, str) or not v.ID_PATTERN.fullmatch(receipt_id):
            return None
        try:
            raw = self.p.load_receipt(conn, receipt_id)
        except IntegrityError:
            if strict:
                raise
            return None
        if not isinstance(raw, dict) or raw.get("operation") != RECEIPT_OPERATION \
                or not isinstance(raw.get("details"), dict):
            return None
        return raw

    # ------------------------------------------------------------------ cache / registry
    def _cache_get(self, key: tuple[str, str, int], now: float) -> ContextPacket | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.valid_until is not None and now >= entry.valid_until:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return entry.packet

    def _cache_put(self, key: tuple[str, str, int], entry: _CacheEntry) -> None:
        with self._lock:
            self._cache[key] = entry
            self._cache.move_to_end(key)
            while len(self._cache) > _CACHE_ENTRIES:
                self._cache.popitem(last=False)

    def _register(self, receipt_id: str, request: ContextRequest) -> None:
        with self._lock:
            self._requests[receipt_id] = request
            self._requests.move_to_end(receipt_id)
            while len(self._requests) > _REGISTRY_ENTRIES:
                self._requests.popitem(last=False)

    def _registered(self, receipt_id: str) -> ContextRequest | None:
        with self._lock:
            return self._requests.get(receipt_id)

    # ------------------------------------------------------------------ packets
    def _with_costs(self, packet: ContextPacket, started: float, *, cache: str, ranker: bool,
                    history: bool) -> ContextPacket:
        external = ranker or history
        costs = {
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3), "elapsed_kind": "measured",
            "cache": cache, "ranker_invoked": ranker, "history_invoked": history,
            # Sibling services may call external providers; their cost is not reported to us.
            "provider_cost_kind": "unknown" if external else "zero",
            "provider_cost_micros": None if external else 0,
        }
        if cache == "hit" and packet.costs:
            costs["compiled_elapsed_ms"] = packet.costs.get("elapsed_ms")
        return dataclasses.replace(packet, costs=costs)

    def _disabled(self, request: ContextRequest, started: float) -> ContextPacket:
        with self.p.db.read() as conn:
            generation = self.p.generation(conn)
        packet = ContextPacket(
            receipt_id="", text="", items=(), omissions=(), conflicts=(), token_count=0,
            token_count_kind=self._meter().kind, token_allowance=request.token_allowance,
            coverage=Coverage(total=None, searched=0, index_ready=False, partial_reasons=(R_DISABLED,)),
            snapshot_hash=snapshot_hash((), "", request.token_allowance), generation=generation,
            created_at=self.ctx.clock(), status=ResultStatus.UNAVAILABLE,
        )
        return self._with_costs(packet, started, cache="miss", ranker=False, history=False)


def _scrubbed_receipt(raw: dict[str, Any], missing: set[str]) -> Receipt:
    details = dict(raw.get("details") or {})
    items = [e for e in details.get("items") or () if isinstance(e, dict)]
    kept = [e for e in items if e.get("id") not in missing]
    details["items"] = kept
    details["scrubbed_items"] = int(details.get("scrubbed_items") or 0) + len(items) - len(kept)
    omissions = [e for e in details.get("omissions") or () if isinstance(e, dict)]
    kept_omissions = [e for e in omissions if e.get("id") not in missing]
    details["omissions"] = kept_omissions
    details["scrubbed_omissions"] = int(details.get("scrubbed_omissions") or 0) + len(omissions) - len(kept_omissions)
    conflicts = [list(pair) for pair in details.get("conflicts") or ()]
    kept_conflicts = [pair for pair in conflicts if not missing.intersection(pair)]
    details["conflicts"] = kept_conflicts
    details["scrubbed_conflicts"] = int(details.get("scrubbed_conflicts") or 0) + len(conflicts) - len(kept_conflicts)
    if len(kept) != len(items):
        # The hash covered the forgotten record's rendered text; it is dropped, so any
        # packet that still carries that text fails revalidation.
        details["snapshot_hash"] = None
    details["scrubbed"] = True
    # Not strict: scrubbing must never make a forget fail on a malformed receipt.
    pairs = [(rid, rev) for rid, rev in zip(raw.get("record_ids") or (), raw.get("revisions") or (),
                                             strict=False)
             if rid not in missing]
    return Receipt(
        receipt_id=raw["receipt_id"], operation=raw["operation"], status=raw.get("status") or "ok",
        created_at=float(raw.get("created_at") or 0.0), partition_id=raw.get("partition_id") or "",
        record_ids=tuple(rid for rid, _ in pairs), revisions=tuple(int(rev) for _, rev in pairs),
        generation=int(raw.get("generation") or 0), idempotent_replay=bool(raw.get("idempotent_replay")),
        details=details, limitations=tuple(raw.get("limitations") or ()),
    )
