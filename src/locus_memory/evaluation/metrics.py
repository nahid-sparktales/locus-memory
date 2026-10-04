"""Deterministic metrics (no model, no LLM judge) and repetition statistics.

Evidence list. Each arm hands the model an ordered list of units: context-packet
items in packet order interleaved round-robin with history hits in rank order
(see ``arms.interleave``). Ranking metrics are computed over that list:

* ``recall@k``    fraction of the question's requirements satisfied by the first k
                  units (a requirement lists alternative keys; any one satisfies it)
* ``precision@k`` units among the first k that carry a gold key, divided by k
                  (standard definition: short lists are not rescaled)
* ``MRR``         1 / rank of the first unit carrying a gold key (0 when none)

Ranking metrics are computed on answerable questions only. Retrieval-level
abstention (missing-evidence questions): the arm *abstains* when none of its units
carries a candidate answer for the question (gold, forbidden or distractor key).
This is a property of what was retrieved, not of a model's answer.

Repetition statistics use the two-sided 95% Student-t interval of the mean over
repetitions (one value per repetition and arm). Scores are rates and counts, never
probabilities of correctness.
"""
from __future__ import annotations

import math
import re
import statistics
from collections.abc import Iterable, Sequence
from typing import Any

from ..models import Scope
from .arms import Unit, question_grants
from .corpus import KeyInfo, Question

# Two-sided 95% critical values t_{0.975, df} for df = 1..30 (standard tables).
_T975 = (
    12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
    2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
    2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042,
)
_Z975 = 1.959963984540054


def t_critical_975(df: int) -> float:
    """Two-sided 95% Student-t critical value (table for df <= 30, Cornish-Fisher beyond)."""
    if df < 1:
        raise ValueError("degrees of freedom must be >= 1")
    if df <= len(_T975):
        return _T975[df - 1]
    z = _Z975
    return z + (z ** 3 + z) / (4 * df) + (5 * z ** 5 + 16 * z ** 3 + 3 * z) / (96 * df ** 2)


def summarize(values: Iterable[float | int | None]) -> dict[str, Any]:
    """Mean, sample stdev and a 95% t-interval of the mean. ``None`` values are excluded."""
    data = [float(x) for x in values if x is not None]
    n = len(data)
    if n == 0:
        return {"n": 0, "mean": None, "stdev": None, "ci95_low": None, "ci95_high": None, "min": None, "max": None}
    mean = statistics.fmean(data)
    if n == 1:
        return {"n": 1, "mean": mean, "stdev": None, "ci95_low": None, "ci95_high": None,
                "min": data[0], "max": data[0]}
    stdev = statistics.stdev(data)
    half = t_critical_975(n - 1) * stdev / math.sqrt(n)
    return {"n": n, "mean": mean, "stdev": stdev, "ci95_low": mean - half, "ci95_high": mean + half,
            "min": min(data), "max": max(data)}


def percentile(values: Sequence[float], q: float) -> float | None:
    """Nearest-rank percentile (q in [0, 100])."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(q / 100.0 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def mean_or_none(values: Iterable[float | int | bool | None]) -> float | None:
    data = [float(x) for x in values if x is not None]
    return statistics.fmean(data) if data else None


# --------------------------------------------------------------------------- ranking metrics
def _relevant(requirements: Sequence[Iterable[str]]) -> frozenset[str]:
    return frozenset(k for req in requirements for k in req)


def recall_at_k(keys: Sequence[str | None], requirements: Sequence[Iterable[str]], k: int | None) -> float:
    reqs = [frozenset(r) for r in requirements]
    if not reqs:
        raise ValueError("recall needs at least one requirement")
    window = set(keys if k is None else keys[:k])
    return sum(1 for r in reqs if r & window) / len(reqs)


def precision_at_k(keys: Sequence[str | None], requirements: Sequence[Iterable[str]], k: int) -> float:
    if k < 1:
        raise ValueError("k must be >= 1")
    relevant = _relevant(requirements)
    return sum(1 for key in keys[:k] if key in relevant) / k


def reciprocal_rank(keys: Sequence[str | None], requirements: Sequence[Iterable[str]]) -> float:
    relevant = _relevant(requirements)
    for i, key in enumerate(keys, start=1):
        if key in relevant:
            return 1.0 / i
    return 0.0


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


# --------------------------------------------------------------------------- per-unit classification
def unit_flags(unit: Unit, question: Question, keys: dict[str, KeyInfo]) -> set[str]:
    """Ground-truth flags of one unit at the question's time.

    ``leak``: the unit's origin (from the arm's ledger) or its engine-reported scope is
    outside the question's trusted scope. ``deleted`` / ``superseded`` / ``stale``: the
    unit's statement was forgotten / corrected / outdated before the question.
    """
    flags: set[str] = set()
    t = question.asked_at
    origin = unit.origin
    grants = question_grants(question.project)
    try:
        reported_ok = grants.allows(Scope.from_dict(unit.reported_scope or {}))
    except Exception:  # an unparseable reported scope is treated as out of scope
        reported_ok = False
    if not reported_ok:
        flags.add("leak")
    if origin is None:
        flags.add("unattributed")
    elif origin.profile != question.profile or origin.project not in (None, question.project):
        flags.add("leak")
    if origin is not None and origin.time >= t:
        flags.add("future")
    if unit.reported_time is not None and unit.reported_time >= t:
        flags.add("future")
    key = unit.key
    if key is None:
        return flags
    if key in _relevant(question.gold):
        flags.add("gold")
    if key in question.distractors:
        flags.add("distractor")
    if key in question.forbidden:
        flags.add("forbidden")
    info = keys.get(key)
    if info is not None:
        if info.deleted_at is not None and info.deleted_at < t:
            flags.add("deleted")
        if info.superseded_at is not None and info.superseded_at < t:
            flags.add("superseded")
        if info.stale_at is not None and info.stale_at < t:
            flags.add("stale")
    return flags


DISTRACTING_FLAGS = frozenset({"distractor", "forbidden", "deleted", "superseded", "stale"})


def score_question(question: Question, units: Sequence[Unit], keys: dict[str, KeyInfo],
                   source_keys: dict[str, str | None], evidence_text: str) -> dict[str, Any]:
    """Quality metrics for one question (tokens and latency are added by the runner)."""
    unit_keys = [u.key for u in units]
    flags = [unit_flags(u, question, keys) for u in units]
    gold = question.gold
    candidates = _relevant(gold) | set(question.forbidden) | set(question.distractors)
    abstained = not any(k in candidates for k in unit_keys if k is not None)
    out: dict[str, Any] = {
        "qid": question.qid, "category": question.category, "profile": question.profile,
        "project": question.project, "day": question.day, "asked_at": question.asked_at,
        "expect_abstain": question.expect_abstain, "requirements": len(gold),
        "units": len(units), "context_units": sum(1 for u in units if u.channel == "context"),
        "history_units": sum(1 for u in units if u.channel == "history"),
        "abstained": abstained,
    }
    if gold:
        complete = recall_at_k(unit_keys, gold, None) == 1.0
        text = normalize_text(evidence_text)
        out.update({
            "recall@5": recall_at_k(unit_keys, gold, 5), "recall@10": recall_at_k(unit_keys, gold, 10),
            "recall_all": recall_at_k(unit_keys, gold, None), "precision@5": precision_at_k(unit_keys, gold, 5),
            "mrr": reciprocal_rank(unit_keys, gold), "complete": complete,
            "proxy_verbatim": all(any(normalize_text(keys[k].answer) in text for k in req) for req in gold),
            "abstain_correct": None,
        })
    else:
        out.update({"recall@5": None, "recall@10": None, "recall_all": None, "precision@5": None, "mrr": None,
                    "complete": None, "proxy_verbatim": None, "abstain_correct": abstained})
    counts = {name: 0 for name in ("gold", "distractor", "forbidden", "deleted", "superseded", "stale", "leak",
                                   "unattributed", "future", "distracting")}
    superseded_by_channel = {"context": 0, "history": 0}
    gold_memory = attributed = 0
    for unit, f in zip(units, flags, strict=True):
        for name in f:
            if name in counts:
                counts[name] += 1
        if f & DISTRACTING_FLAGS and "gold" not in f:
            counts["distracting"] += 1
        if "superseded" in f:
            superseded_by_channel[unit.channel] += 1
        if "gold" in f and unit.channel == "context":
            gold_memory += 1
            if any(source_keys.get(s) == unit.key for s in unit.sources):
                attributed += 1
    out.update({f"{name}_units": value for name, value in counts.items()})
    out["superseded_context_units"] = superseded_by_channel["context"]
    out["superseded_history_units"] = superseded_by_channel["history"]
    out["gold_memory_units"] = gold_memory
    out["attributed_gold_memory_units"] = attributed
    out["leaked_unit_ids"] = [u.unit_id for u, f in zip(units, flags, strict=True) if "leak" in f]
    return out


# --------------------------------------------------------------------------- run aggregation
def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def aggregate_run(scores: list[dict[str, Any]]) -> dict[str, Any]:
    """One arm x one repetition -> scalar metrics (means over questions, pooled unit rates)."""
    answerable = [s for s in scores if not s["expect_abstain"]]
    abstain = [s for s in scores if s["expect_abstain"]]
    total_units = sum(s["units"] for s in scores)

    def total(name: str, rows: list[dict[str, Any]] = scores) -> int:
        return int(sum(s.get(name) or 0 for s in rows))

    deletion_q = [s for s in scores if s["category"] == "deletion"]
    correction_q = [s for s in scores if s["category"] == "correction"]
    packets = [s for s in scores if s.get("packet_tokens") is not None]
    out: dict[str, Any] = {
        "questions": len(scores), "answerable_questions": len(answerable), "abstention_questions": len(abstain),
        "recall@5": mean_or_none(s["recall@5"] for s in answerable),
        "recall@10": mean_or_none(s["recall@10"] for s in answerable),
        "recall_all": mean_or_none(s["recall_all"] for s in answerable),
        "precision@5": mean_or_none(s["precision@5"] for s in answerable),
        "mrr": mean_or_none(s["mrr"] for s in answerable),
        "multi_session_complete": mean_or_none(s["complete"] for s in answerable if s["requirements"] > 1),
        "extractive_proxy": mean_or_none(s["proxy_verbatim"] for s in answerable),
        "abstention_accuracy": mean_or_none(s["abstain_correct"] for s in abstain),
        "false_abstention_rate": mean_or_none(s["abstained"] for s in answerable),
        "engine_no_evidence_rate": mean_or_none(s.get("engine_no_evidence") for s in abstain),
        "units_total": total_units,
        "distracting_rate": _rate(total("distracting_units"), total_units),
        "distractor_rate": _rate(total("distractor_units"), total_units),
        "stale_rate": _rate(total("stale_units") + total("superseded_units"), total_units),
        "scope_leakage_count": total("leak_units"),
        "future_units": total("future_units"),
        "unattributed_units": total("unattributed_units"),
        "deletion_failures": total("deleted_units"),
        "deletion_probe_pass_rate": mean_or_none(s["deleted_units"] == 0 and s["forbidden_units"] == 0
                                                 for s in deletion_q),
        "correction_failures_context": total("superseded_context_units"),
        "correction_failures_history": total("superseded_history_units"),
        "correction_probe_pass_rate": mean_or_none(s["superseded_units"] == 0 for s in correction_q),
        "attribution_correct_rate": _rate(total("attributed_gold_memory_units"), total("gold_memory_units")),
        "gold_memory_units": total("gold_memory_units"),
        "budget_compliance": mean_or_none(s["budget_ok"] for s in packets) if packets else None,
        "packet_tokens_mean": mean_or_none(s["packet_tokens"] for s in packets) if packets else 0.0,
        "overhead_tokens_mean": mean_or_none(s["overhead_tokens"] for s in scores),
        "overhead_tokens_max": max((s["overhead_tokens"] for s in scores), default=0),
        "warm_inconsistencies": sum(1 for s in scores if s.get("warm_consistent") is False),
    }
    by_category: dict[str, list[float]] = {}
    for s in scores:
        value = s["abstain_correct"] if s["expect_abstain"] else s["recall_all"]
        by_category.setdefault(s["category"], []).append(float(value))
    out["by_category"] = {k: statistics.fmean(v) for k, v in sorted(by_category.items())}
    for name in ("context_ms", "history_ms", "context_warm_ms", "history_warm_ms"):
        values = [s[name] for s in scores if s.get(name) is not None]
        out[f"{name}_mean"] = mean_or_none(values)
        out[f"{name}_p50"] = percentile(values, 50)
        out[f"{name}_p95"] = percentile(values, 95)
        out[f"{name}_max"] = max(values) if values else None
    return out
