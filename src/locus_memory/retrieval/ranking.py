"""Rank fusion, validity, de-duplication, diversity and snippets.

Fusion is Reciprocal Rank Fusion (Cormack, Clarke & Buettcher, 2009)::

    rrf(d) = sum over rankers r that returned d of  1 / (RRF_K + rank_r(d)),  RRF_K = 60

with 1-based ranks. Only *ranks* are fused -- raw BM25 values (lower is better in
FTS5, higher is better in the Python fallback) and cosine similarities live on
incomparable scales and are never added together. The fused value is a
rank-fusion score (``score_kind="rrf"``), not a probability and not a confidence.
Ties are broken deterministically (pinned first, then most recently updated, then
content, then id) so identical inputs always produce identical orderings -- also
across fresh stores, where record ids differ (they are random) but content and
timestamps do not.

After fusion (see ``service.py`` for the order of stages):

* validity: ``valid_from`` after the evaluation time excludes a record;
  ``valid_until`` at/before it marks the hit historical (``current=False``) and
  demotes it below every current hit; stale/superseded/expired lifecycles are
  historical too;
* de-duplication by normalized content: copies (an archive copy, a summary that
  restates a memory, an approved duplicate) collapse into the best-ranked one
  and are *not* counted as independent confirmations;
* diversity: Maximal Marginal Relevance over the fused score with token Jaccard
  similarity (``MMR_LAMBDA`` relevance weight). Heuristic.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .. import safety
from ..models import Lifecycle, MemoryRecord
from ..validation import normalize_for_fingerprint
from .query import fold

RRF_K = 60
MMR_LAMBDA = 0.7
WEAK_MATCH = "weak_match"  # hit reason: no lexical/exact evidence (e.g. semantic-only)
SNIPPET_BEFORE = 60
SNIPPET_AFTER = 160

_HISTORICAL_LIFECYCLES = {
    Lifecycle.STALE: "stale: needs re-confirmation",
    Lifecycle.SUPERSEDED: "superseded by a newer memory",
    Lifecycle.EXPIRED: "expired",
    Lifecycle.REJECTED: "rejected in review",
}


def rrf_fuse(lists: dict[str, Sequence[str]], k: int = RRF_K) -> dict[str, tuple[float, dict[str, int]]]:
    """Fuse ranked id lists. Returns id -> (rrf score, {ranker: 1-based rank})."""
    fused: dict[str, tuple[float, dict[str, int]]] = {}
    for name in sorted(lists):  # sorted: float summation order is deterministic
        seen: set[str] = set()
        rank = 0
        for item in lists[name]:
            if item in seen:
                continue
            seen.add(item)
            rank += 1
            score, ranks = fused.get(item, (0.0, {}))
            ranks = {**ranks, name: rank}
            fused[item] = (score + 1.0 / (k + rank), ranks)
    return fused


def tiebreak_key(record: MemoryRecord) -> tuple:
    """Deterministic tie order: pinned, most recently updated, content, then the (random) id.

    Content precedes the id so that records written at the same instant (e.g. the
    observations of one repository snapshot) order the same way in every store.
    """
    return (0 if record.retention.pinned else 1, -float(record.updated_at or 0.0), record.content or "",
            record.id)


@dataclass
class Candidate:
    record: MemoryRecord
    score: float
    ranks: dict[str, int]
    tokens: frozenset[str]
    exact_id: bool = False
    current: bool = True
    reasons: list[str] = field(default_factory=list)
    duplicates: int = 0

    def order_key(self) -> tuple:
        return (-self.score, *tiebreak_key(self.record))


def assess_validity(record: MemoryRecord, at_time: float) -> tuple[bool, bool, list[str]]:
    """Return (include, current, reasons) for a record evaluated at ``at_time``."""
    reasons: list[str] = []
    validity = record.validity
    if validity.valid_from is not None and validity.valid_from > at_time:
        return False, False, ["not yet valid"]
    current = True
    if record.lifecycle in _HISTORICAL_LIFECYCLES:
        current = False
        reasons.append(_HISTORICAL_LIFECYCLES[record.lifecycle])
    elif record.lifecycle == Lifecycle.CANDIDATE:
        reasons.append("unapproved candidate")
    if validity.valid_until is not None and validity.valid_until <= at_time:
        current = False
        reasons.append("historical: valid_until has passed")
    if not current:
        reasons.append("demoted below current results")
    return True, current, reasons


def dedupe(candidates: Sequence[Candidate]) -> list[Candidate]:
    """Collapse identical normalized content; keep the first (callers pass best-first)."""
    kept: dict[str, Candidate] = {}
    out: list[Candidate] = []
    for cand in candidates:
        key = normalize_for_fingerprint(cand.record.content)
        first = kept.get(key)
        if first is None:
            kept[key] = cand
            out.append(cand)
        else:
            first.duplicates += 1
    for cand in out:
        if cand.duplicates:
            cand.reasons.append(
                f"collapsed {cand.duplicates} duplicate(s) with identical content (not independent confirmation)")
    return out


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 1.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def mmr_select(candidates: Sequence[Candidate], limit: int, *, lam: float = MMR_LAMBDA,
               pool: int | None = None) -> list[Candidate]:
    """Greedy Maximal Marginal Relevance selection (deterministic).

    Each remaining candidate's maximum similarity to the selected set is updated
    incrementally against the newest pick, so the cost is O(limit x pool) Jaccard
    computations rather than O(limit^2 x pool).
    """
    if limit <= 0 or not candidates:
        return []
    ordered = sorted(candidates, key=Candidate.order_key)
    if pool is not None:
        ordered = ordered[: max(pool, limit)]
    top = ordered[0].score or 1.0
    remaining = list(ordered)
    redundancy = [0.0] * len(remaining)
    selected: list[Candidate] = []
    while remaining and len(selected) < limit:
        best_i = 0
        best_value = None
        for i, cand in enumerate(remaining):
            value = lam * (cand.score / top) - (1 - lam) * redundancy[i]
            if best_value is None or value > best_value + 1e-12:
                best_i, best_value = i, value
        pick = remaining.pop(best_i)
        redundancy.pop(best_i)
        selected.append(pick)
        for i, cand in enumerate(remaining):
            similarity = jaccard(cand.tokens, pick.tokens)
            if similarity > redundancy[i]:
                redundancy[i] = similarity
    return selected


# --------------------------------------------------------------------------- snippets
def _fold_with_map(text: str) -> tuple[str, list[int]]:
    chars: list[str] = []
    positions: list[int] = []
    for i, ch in enumerate(text):
        folded = fold(ch) if not ch.isascii() else ch.lower()
        for out in folded:
            chars.append(out)
            positions.append(i)
    return "".join(chars), positions


def snippet(content: str, terms: Iterable[str], *, before: int = SNIPPET_BEFORE,
            after: int = SNIPPET_AFTER) -> str:
    """A short window around the first matched term, markup-neutralized and secret-redacted."""
    if not content:
        return ""
    folded, positions = _fold_with_map(content)
    first = None
    for term in terms:
        if not term:
            continue
        pos = folded.find(term)
        if pos >= 0 and (first is None or pos < first):
            first = pos
    if first is None:
        start, end = 0, min(len(content), before + after)
    else:
        origin = positions[first]
        start = max(0, origin - before)
        end = min(len(content), origin + after)
        if start > 0:
            space = content.rfind(" ", 0, start + 1)
            start = space + 1 if space >= 0 and origin - space <= before + 20 else start
    if end < len(content):
        space = content.find(" ", end)
        end = space if 0 <= space <= end + 20 else end
    window = " ".join(content[start:end].split())
    window = ("…" if start > 0 else "") + window + ("…" if end < len(content) else "")
    redacted, _ = safety.redact_secrets(window)
    return safety.neutralize_markup(redacted)
