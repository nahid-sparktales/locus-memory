"""Chronological benchmark runner.

For every repetition a corpus is generated from its own seed; every arm replays the
same corpus (paired design) in a fresh temporary root. The timeline merges events
and questions in time order; at equal timestamps questions come first, so an event
at time t is never visible to a question asked at t.

Leakage self-check (:class:`ChronologyGuard`), enforced on every question:

1. events are applied in non-decreasing time order;
2. before a question at t, *exactly* the events with time < t have been applied (no
   future event ingested early, no past event skipped);
3. every returned unit traces (through the arm's ledger) to an event before t, and
   engine-reported message times are before t.

Any violation raises :class:`ChronologyViolation` and aborts the run. Scope leakage
(a unit outside the question's trusted scope) does not abort; it is counted and
fails the run and the benchmark.
"""
from __future__ import annotations

import bisect
import importlib.metadata
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import tempfile
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .arms import (
    ARM_DESCRIPTIONS,
    ARMS,
    F_NOT_EXECUTED,
    FAKE_EMBEDDING_LABEL,
    Arm,
    ArmConfig,
    StageTimer,
    Unit,
)
from .corpus import DAY_END, Corpus, Event, Question, corpus_hash, generate_corpus
from .metrics import aggregate_run, percentile, score_question, summarize

RESULT_FORMAT = "locus-memory-eval-results/1"
DEFAULT_SEED = 20261004
SAFETY_GATES = ("C1", "C2", "C3", "C4", "C6", "C7")
C8_MIN_ABSTENTION = 0.75
C11_MARGIN = 0.01


class ChronologyViolation(RuntimeError):
    """The runner made (or would have made) a future event visible to a question."""


class ChronologyGuard:
    def __init__(self, corpus: Corpus) -> None:
        self._times = sorted(e.time for e in corpus.events)
        self.applied = 0
        self.last_time = float("-inf")

    def on_event(self, event: Event) -> None:
        if event.time < self.last_time:
            raise ChronologyViolation(f"event {event.eid} applied out of time order")
        self.last_time = event.time
        self.applied += 1

    def before_question(self, question: Question) -> None:
        if self.last_time >= question.asked_at:
            raise ChronologyViolation(f"{question.qid}: an event at or after the question time was ingested")
        expected = bisect.bisect_left(self._times, question.asked_at)
        if self.applied != expected:
            raise ChronologyViolation(
                f"{question.qid}: {self.applied} events applied, {expected} happened before the question")

    @staticmethod
    def check_units(units: Iterable[Unit], question: Question) -> None:
        for unit in units:
            if unit.origin is not None and unit.origin.time >= question.asked_at:
                raise ChronologyViolation(f"{question.qid}: unit {unit.unit_id} comes from a future event")
            if unit.reported_time is not None and unit.reported_time >= question.asked_at:
                raise ChronologyViolation(f"{question.qid}: unit {unit.unit_id} has a future timestamp")


def iterate_timeline(corpus: Corpus) -> Iterator[Event | Question]:
    """Events and questions in time order; a question precedes an event with the same timestamp."""
    items: list[tuple[float, int, int, Event | Question]] = [
        (e.time, 1, i, e) for i, e in enumerate(corpus.events)]
    items += [(q.asked_at, 0, i, q) for i, q in enumerate(corpus.questions)]
    for _t, _order, _i, item in sorted(items, key=lambda x: x[:3]):
        yield item


@dataclass(frozen=True)
class BenchmarkConfig:
    repetitions: int = 5
    seed: int = DEFAULT_SEED
    arms: tuple[str, ...] = ("A", "B", "C", "D", "E")
    size: str = "full"
    token_allowance: int = 800
    history_k: int = 5
    embedding_dimensions: int = 64

    def seeds(self) -> list[int]:
        return [self.seed + i for i in range(self.repetitions)]


# --------------------------------------------------------------------------- one arm x one repetition
def _stats(values: Sequence[float]) -> dict[str, Any]:
    return {"count": len(values), "total_ms": round(sum(values), 3),
            "mean_ms": round(sum(values) / len(values), 3) if values else None,
            "p50_ms": percentile(values, 50), "p95_ms": percentile(values, 95),
            "max_ms": max(values) if values else None}


def run_arm(corpus: Corpus, arm_cls: type[Arm], workdir: Path, config: BenchmarkConfig) -> dict[str, Any]:
    """Replay ``corpus`` through one arm; returns the raw run record (metrics + per-question rows)."""
    timer = StageTimer()
    arm = arm_cls(corpus, workdir, ArmConfig(config.token_allowance, config.history_k,
                                             config.embedding_dimensions), timer)
    guard = ChronologyGuard(corpus)
    scores: list[dict[str, Any]] = []
    days: list[dict[str, Any]] = []
    engine_timings: dict[str, Any] = {}
    started = time.perf_counter()
    arm.open()
    try:
        for item in iterate_timeline(corpus):
            if isinstance(item, Question):
                guard.before_question(item)
                evidence = arm.retrieve(item)
                guard.check_units(evidence.units, item)
                score = score_question(item, evidence.units, corpus.keys, arm.ledger.sources, evidence.text)
                packet = evidence.packet
                history_tokens = arm.estimate(evidence.history_text)
                if packet is not None:
                    independent = arm.estimate(packet.text)
                    score.update({
                        "packet_tokens": packet.token_count, "packet_token_kind": packet.token_count_kind.value,
                        "packet_tokens_reestimated": independent, "token_allowance": packet.token_allowance,
                        "budget_ok": packet.token_count <= packet.token_allowance
                        and independent <= packet.token_allowance,
                        "packet_status": packet.status.value,
                    })
                else:
                    score.update({"packet_tokens": None, "budget_ok": None})
                score.update({
                    "history_tokens": history_tokens,
                    "overhead_tokens": (packet.token_count if packet is not None else 0) + history_tokens,
                    "warm_consistent": evidence.warm_consistent if arm.memory else None,
                    "engine_no_evidence": arm.engine_signalled_no_evidence(evidence),
                    "unit_keys": [u.key for u in evidence.units],
                    **{k: round(v, 3) for k, v in evidence.timings.items()},
                })
                scores.append(score)
            else:
                guard.on_event(item)
                arm.apply(item)
                if item.type == DAY_END:
                    days.append({
                        "day": item.data["day"], "storage_bytes": arm.storage_bytes(),
                        "storage_bytes_main": arm.storage_bytes(include_journals=False),
                        "cumulative_cost_ms": round(_cost(timer), 3),
                        "ingest_ms": round(timer.total("ingest"), 3),
                    })
        if arm.engine is not None:
            engine_timings = arm.engine.metrics.snapshot().get("timings", {})
        probes = _last_question_per_profile(corpus)
        cold_open = arm.cold_open_probe(probes)
    finally:
        arm.close()
    wall_ms = (time.perf_counter() - started) * 1000.0
    needles = sorted({info.answer for info in corpus.keys.values()})
    plaintext = arm.plaintext_hits(needles) if arm.memory else 0
    final_bytes = arm.storage_bytes()  # after close: the WAL has been checkpointed
    metrics = aggregate_run(scores)
    metrics.update({
        "plaintext_hits": plaintext,
        "deletion_self_check_failures": int(arm.notes["deletion_self_check_failures"]),
        "storage_bytes_final": final_bytes,
        "storage_bytes_per_event": final_bytes / len(corpus.events) if corpus.events else None,
        "ingest_ms_total": round(timer.total("ingest"), 3),
        "maintenance_ms_total": round(timer.total("maintenance"), 3),
        "cumulative_cost_ms": round(_cost(timer), 3),
        "amortized_cost_ms_per_question": round(_cost(timer) / len(scores), 3) if scores else None,
        "engine_construct_ms": cold_open.get("open_ms"),
        "cold_open_first_context_ms": cold_open.get("context_cold_ms"),
        "cold_open_first_history_ms": cold_open.get("history_cold_ms"),
        "cold_open_warm_context_ms": cold_open.get("context_warm_ms"),
        "cold_open_warm_history_ms": cold_open.get("history_warm_ms"),
        "projection_build_p95_ms": _engine_p95(engine_timings, "retrieval.projection_build"),
        "history_search_engine_p95_ms": _engine_p95(engine_timings, "history.search"),
        "wall_ms": round(wall_ms, 3),
    })
    failures = _hard_failures(metrics, arm)
    return {
        "arm": arm.name, "seed": corpus.seed, "corpus_hash": corpus_hash(corpus), "passed": not failures,
        "failures": failures, "metrics": metrics,
        "stages": {
            "ingest": {op.split(".", 1)[1]: _stats(v) for op, v in sorted(timer.by_op.items())
                       if op.startswith("ingest.")},
            "world_git_ms": _stats(timer.samples.get("world", [])),
            "maintenance": _stats(timer.samples.get("maintenance", [])),
            "context_build_cold": _stats(timer.by_op.get("context_build.cold", [])),
            "context_build_warm": _stats(timer.by_op.get("context_build.warm", [])),
            "retrieval_cold": _stats(timer.by_op.get("retrieval.cold", [])),
            "retrieval_warm": _stats(timer.by_op.get("retrieval.warm", [])),
            "hydration_engine_timers": {k: v for k, v in engine_timings.items()
                                        if k in ("retrieval.projection_build", "history.search", "history.ingest")},
            "cold_open": cold_open,
        },
        "days": days,
        "notes": {**{k: v for k, v in arm.notes.items()}, "provider_usage": arm.provider_usage()},
        "questions": scores,
    }


def _cost(timer: StageTimer) -> float:
    """Serving cost: ingestion + maintenance + cold context builds + cold history searches."""
    return (timer.total("ingest") + timer.total("maintenance") + sum(timer.by_op.get("context_build.cold", ()))
            + sum(timer.by_op.get("retrieval.cold", ())))


def _engine_p95(timings: dict[str, Any], name: str) -> float | None:
    """p95 of an engine-internal timer (the engine keeps its last 1000 samples)."""
    entry = timings.get(name) or {}
    return entry.get("p95_ms") if entry.get("kind") == "measured" else None


def _last_question_per_profile(corpus: Corpus) -> list[Question]:
    last: dict[str, Question] = {}
    for question in corpus.questions:
        last[question.profile] = question
    return [last[p] for p in sorted(last)]


def _hard_failures(metrics: dict[str, Any], arm: Arm) -> list[str]:
    failures = []
    if metrics["scope_leakage_count"]:
        failures.append(f"scope leakage: {metrics['scope_leakage_count']} unit(s) outside the trusted scope")
    if metrics["future_units"]:
        failures.append(f"chronology: {metrics['future_units']} future unit(s)")
    if metrics["deletion_failures"] or metrics["deletion_self_check_failures"]:
        failures.append("deletion propagation: forgotten statements were retrievable")
    if metrics["correction_failures_context"]:
        failures.append("correction propagation: a corrected-away memory value was injected")
    if metrics["budget_compliance"] is not None and metrics["budget_compliance"] < 1.0:
        failures.append("context budget exceeded")
    if metrics["plaintext_hits"]:
        failures.append(f"plaintext on disk: {metrics['plaintext_hits']} hit(s)")
    if arm.memory and metrics["unattributed_units"]:
        failures.append(f"{metrics['unattributed_units']} returned unit(s) could not be attributed to the corpus")
    return failures


# --------------------------------------------------------------------------- environment
def environment() -> dict[str, Any]:
    from .. import __version__
    from ..storage.db import fts5_available

    git = shutil.which("git")
    git_version = None
    if git:
        try:
            git_version = subprocess.run([git, "--version"], capture_output=True, text=True, timeout=10,
                                         check=False).stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            git_version = None
    try:
        crypto = importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError:
        crypto = None
    return {
        "versions": {
            "locus_memory": __version__, "python": platform.python_version(),
            "python_implementation": platform.python_implementation(), "sqlite": sqlite3.sqlite_version,
            "cryptography": crypto, "git": git_version, "fts5_available": fts5_available(),
        },
        "hardware": {
            "platform": platform.platform(), "system": platform.system(), "release": platform.release(),
            "machine": platform.machine(), "processor": platform.processor() or None, "cpu_count": os.cpu_count(),
        },
    }


# --------------------------------------------------------------------------- criteria
CRITERIA: tuple[dict[str, str], ...] = (
    {"id": "C1", "arms": "A-E", "text": "Scope leakage = 0 in every run (any leaked unit fails the run)"},
    {"id": "C2", "arms": "A-E", "text": "Chronology: 0 units from events at/after the question time"},
    {"id": "C3", "arms": "B-E", "text": "Deletion propagation: 0 forgotten statements retrieved after the forget"},
    {"id": "C4", "arms": "B-E", "text": "Correction propagation (curated memory): 0 corrected-away values in context"},
    {"id": "C5", "arms": "B-E",
     "text": "Correction propagation (strict, memory + raw history): 0 superseded statements in any channel"},
    {"id": "C6", "arms": "B-E", "text": "Context budget compliance: 100% of packets within the token allowance"},
    {"id": "C7", "arms": "B-E", "text": "Nothing plaintext on disk: 0 answer phrases found in store files"},
    {"id": "C8", "arms": "B-E", "text": "Retrieval-level abstention accuracy >= 0.75 on missing-evidence questions"},
    {"id": "C9", "arms": "C,D vs B", "text": "Mean recall@5 of C and of D >= B (mean paired difference >= 0)"},
    {"id": "C10", "arms": "D vs C",
     "text": "D improves recall_all over C on repository, stale_repository and episode questions"},
    {"id": "C11", "arms": "D vs C",
     "text": "D's distracting/stale unit rate is not worse than C's by more than 0.01 (mean paired difference)"},
    {"id": "C12", "arms": "B-E", "text": "Source attribution: 100% of gold memory items cite a source of that statement"},
    {"id": "C13", "arms": "E", "text": "E (fake hash embeddings) passes safety gates C1-C4, C6, C7; quality not interpreted"},
)
_DEPENDENT = ("repository", "stale_repository", "episode")


def _arm_runs(runs: list[dict[str, Any]], arm: str) -> list[dict[str, Any]]:
    return [r for r in runs if r["arm"] == arm]


def _values(runs: list[dict[str, Any]], arm: str, metric: str) -> list[Any]:
    return [r["metrics"].get(metric) for r in _arm_runs(runs, arm)]


def evaluate_criteria(runs: list[dict[str, Any]], arms: Sequence[str]) -> list[dict[str, Any]]:
    present = [a for a in arms if any(r["arm"] == a for r in runs)]
    memory_arms = [a for a in present if a != "A"]
    out = []

    def row(cid: str, observed: dict[str, Any], met: bool | None, note: str = "") -> None:
        spec = next(c for c in CRITERIA if c["id"] == cid)
        out.append({**spec, "observed": observed, "met": met, "note": note})

    def all_zero(arm_list: list[str], *metrics: str) -> tuple[dict[str, Any], bool]:
        observed = {a: max(sum(int(r["metrics"].get(m) or 0) for m in metrics) for r in _arm_runs(runs, a))
                    for a in arm_list}
        return observed, all(v == 0 for v in observed.values())

    obs, ok = all_zero(present, "scope_leakage_count")
    row("C1", obs, ok, "max over runs")
    obs, ok = all_zero(present, "future_units")
    row("C2", obs, ok, "max over runs; the runner also aborts on any chronology violation")
    obs, ok = all_zero(memory_arms, "deletion_failures", "deletion_self_check_failures")
    row("C3", obs, ok if memory_arms else None, "max over runs")
    obs, ok = all_zero(memory_arms, "correction_failures_context")
    row("C4", obs, ok if memory_arms else None, "max over runs")
    obs, ok = all_zero(memory_arms, "correction_failures_context", "correction_failures_history")
    row("C5", obs, ok if memory_arms else None, "max over runs; history = archived transcripts")
    observed = {a: min(v for v in _values(runs, a, "budget_compliance") if v is not None) for a in memory_arms}
    row("C6", observed, all(v >= 1.0 for v in observed.values()) if memory_arms else None, "min over runs")
    obs, ok = all_zero(memory_arms, "plaintext_hits")
    row("C7", obs, ok if memory_arms else None, "max over runs")
    observed = {a: summarize(_values(runs, a, "abstention_accuracy"))["mean"] for a in memory_arms}
    row("C8", observed, all(v is not None and v >= C8_MIN_ABSTENTION for v in observed.values()) if memory_arms
        else None,
        "mean over runs; A abstains trivially and is not gated")
    paired = paired_differences(runs, present)
    if "B" in present and ("C" in present or "D" in present):
        observed = {f"{a}-B": paired.get(f"{a}-B", {}).get("recall@5", {}).get("mean")
                    for a in ("C", "D") if a in present}
        row("C9", observed, all(v is not None and v >= 0 for v in observed.values()))
    else:
        row("C9", {}, None, "requires arms B and C/D")
    if "C" in present and "D" in present:
        observed = {a: _dependent_recall(runs, a) for a in ("C", "D")}
        row("C10", observed, observed["D"] is not None and observed["C"] is not None
            and observed["D"] > observed["C"], "mean recall_all over those categories and runs")
        diff = paired.get("D-C", {}).get("distracting_rate", {}).get("mean")
        observed = {a: summarize(_values(runs, a, "distracting_rate"))["mean"] for a in ("C", "D")}
        observed["D-C"] = diff
        row("C11", observed, diff is not None and diff <= C11_MARGIN, f"non-inferiority margin {C11_MARGIN}")
    else:
        row("C10", {}, None, "requires arms C and D")
        row("C11", {}, None, "requires arms C and D")
    observed = {a: min((v for v in _values(runs, a, "attribution_correct_rate") if v is not None), default=None)
                for a in memory_arms}
    row("C12", observed, all(v is not None and v >= 1.0 for v in observed.values()) if memory_arms else None,
        "min over runs")
    if "E" in present:
        gates = {c["id"]: c for c in out if c["id"] in SAFETY_GATES}
        observed = {cid: gates[cid]["observed"].get("E") for cid in SAFETY_GATES if cid in gates}
        met = all(v in (0, None) for k, v in observed.items() if k != "C6") and (observed.get("C6") in (None, 1.0))
        row("C13", observed, met, FAKE_EMBEDDING_LABEL)
    else:
        row("C13", {}, None, "arm E not run")
    return out


def _dependent_recall(runs: list[dict[str, Any]], arm: str) -> float | None:
    values = [q["recall_all"] for r in _arm_runs(runs, arm) for q in r["questions"]
              if q["category"] in _DEPENDENT and q["recall_all"] is not None]
    return sum(values) / len(values) if values else None


def paired_differences(runs: list[dict[str, Any]], arms: Sequence[str]) -> dict[str, dict[str, Any]]:
    """Per-seed differences between arms on the same corpus, summarized with a t-interval."""
    pairs = [("C", "B"), ("D", "B"), ("D", "C"), ("E", "D")]
    by = {(r["arm"], r["seed"]): r["metrics"] for r in runs}
    seeds = sorted({r["seed"] for r in runs})
    out: dict[str, dict[str, Any]] = {}
    for a, b in pairs:
        if a not in arms or b not in arms:
            continue
        entry = {}
        for metric in ("recall@5", "recall_all", "mrr", "abstention_accuracy", "distracting_rate"):
            diffs = [by[(a, s)][metric] - by[(b, s)][metric] for s in seeds
                     if (a, s) in by and (b, s) in by and by[(a, s)].get(metric) is not None
                     and by[(b, s)].get(metric) is not None]
            entry[metric] = summarize(diffs)
        out[f"{a}-{b}"] = entry
    return out


# --------------------------------------------------------------------------- benchmark
AGGREGATE_METRICS = (
    "recall@5", "recall@10", "recall_all", "precision@5", "mrr", "multi_session_complete", "extractive_proxy",
    "abstention_accuracy", "false_abstention_rate", "engine_no_evidence_rate", "distracting_rate",
    "distractor_rate", "stale_rate", "scope_leakage_count", "future_units", "unattributed_units",
    "deletion_failures", "deletion_probe_pass_rate", "correction_failures_context", "correction_failures_history",
    "correction_probe_pass_rate", "attribution_correct_rate", "budget_compliance", "packet_tokens_mean",
    "overhead_tokens_mean", "overhead_tokens_max", "warm_inconsistencies", "plaintext_hits",
    "deletion_self_check_failures", "storage_bytes_final", "storage_bytes_per_event", "ingest_ms_total",
    "maintenance_ms_total", "cumulative_cost_ms", "amortized_cost_ms_per_question", "context_ms_mean",
    "context_ms_p50", "context_ms_p95", "context_warm_ms_mean", "context_warm_ms_p50", "context_warm_ms_p95",
    "history_ms_mean", "history_ms_p50", "history_ms_p95", "history_warm_ms_mean", "history_warm_ms_p50",
    "history_warm_ms_p95", "engine_construct_ms", "cold_open_first_context_ms", "cold_open_first_history_ms",
    "cold_open_warm_context_ms", "cold_open_warm_history_ms", "projection_build_p95_ms",
    "history_search_engine_p95_ms", "wall_ms",
)


def _growth(arm_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mean storage bytes and cumulative serving cost at each simulated day end."""
    per_day: dict[int, list[dict[str, Any]]] = {}
    for run in arm_runs:
        for sample in run["days"]:
            per_day.setdefault(sample["day"], []).append(sample)
    return [{"day": day,
             "storage_bytes": summarize(s["storage_bytes"] for s in samples)["mean"],
             "storage_bytes_main": summarize(s["storage_bytes_main"] for s in samples)["mean"],
             "cumulative_cost_ms": summarize(s["cumulative_cost_ms"] for s in samples)["mean"]}
            for day, samples in sorted(per_day.items())]


def _resolve_arms(arms: Iterable[str | type[Arm]]) -> list[tuple[str, type[Arm]]]:
    out = []
    for arm in arms:
        if isinstance(arm, str):
            if arm == "F":
                continue  # reported as not executed
            if arm not in ARMS:
                raise ValueError(f"unknown arm {arm!r}")
            out.append((arm, ARMS[arm]))
        elif isinstance(arm, type) and issubclass(arm, Arm):
            out.append((arm.name, arm))
        else:
            raise ValueError("arms must be arm names or Arm subclasses")
    return out


def run_benchmark(out_dir: Path | str, *, repetitions: int = 5, seed: int = DEFAULT_SEED,
                  arms: Sequence[str | type[Arm]] = ("A", "B", "C", "D", "E"), size: str = "full",
                  token_allowance: int = 800, history_k: int = 5, workdir: Path | str | None = None,
                  write: bool = True) -> dict[str, Any]:
    """Run every arm on ``repetitions`` seeded corpora; write manifest, per-question rows and a report.

    Returns the manifest dict (``passed`` is False when any run violated a hard invariant).
    """
    if repetitions < 1:
        raise ValueError("repetitions must be >= 1")
    resolved = _resolve_arms(arms)
    names = [name for name, _ in resolved]
    config = BenchmarkConfig(repetitions=repetitions, seed=seed, arms=tuple(names), size=size,
                             token_allowance=token_allowance, history_k=history_k)
    started = time.perf_counter()
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    corpora: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    base = Path(workdir) if workdir is not None else None
    if base is not None:
        base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="locus-eval-", dir=base) as tmp:
        for rep, rep_seed in enumerate(config.seeds()):
            corpus = generate_corpus(rep_seed, size=size)
            corpora.append(corpus.summary())
            for name, arm_cls in resolved:
                workdir_arm = Path(tmp) / f"rep{rep}-{name}"
                record = run_arm(corpus, arm_cls, workdir_arm, config)
                record["repetition"] = rep
                runs.append(record)
                shutil.rmtree(workdir_arm, ignore_errors=True)
    aggregate = {name: {m: summarize(_values(runs, name, m)) for m in AGGREGATE_METRICS} for name in names}
    categories = sorted({c for r in runs for c in r["metrics"]["by_category"]})
    by_category = {name: {c: summarize(r["metrics"]["by_category"].get(c) for r in _arm_runs(runs, name))
                          for c in categories} for name in names}
    criteria = evaluate_criteria(runs, names)
    growth = {name: _growth(_arm_runs(runs, name)) for name in names}
    failures = [f"{r['arm']} seed {r['seed']}: {f}" for r in runs for f in r["failures"]]
    manifest: dict[str, Any] = {
        "format": RESULT_FORMAT, "created_at": created, **environment(),
        "config": asdict(config), "seeds": config.seeds(),
        "corpora": corpora,
        "arms": {name: ARM_DESCRIPTIONS.get(name, getattr(cls, "__doc__", "") or name) for name, cls in resolved},
        "arms_not_executed": {"F": ARM_DESCRIPTIONS["F"]},
        "labels": {"E": FAKE_EMBEDDING_LABEL, "F": F_NOT_EXECUTED,
                   "scores": "rates and counts over synthetic questions; never probabilities"},
        "not_measured": {
            "evidence_backed_task_correctness": (
                "not measured: it needs a model that answers from the context and a verifier of the answer"
                " against task evidence; this benchmark runs no model. extractive_proxy (gold answer phrase"
                " present verbatim in the context packet or history hits) is a proxy, not task correctness."),
            "F": F_NOT_EXECUTED,
        },
        "passed": not failures, "failures": failures,
        "criteria": criteria,
        "aggregate": aggregate, "by_category": by_category, "paired": paired_differences(runs, names),
        "growth_by_day": growth,
        "runs": [{k: v for k, v in r.items() if k != "questions"} for r in runs],
        "runtime_s": round(time.perf_counter() - started, 3),
    }
    if write:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True, default=str) + "\n")
        with (out / "questions.jsonl").open("w") as fh:
            for r in runs:
                for q in r["questions"]:
                    fh.write(json.dumps({"arm": r["arm"], "seed": r["seed"], "repetition": r["repetition"], **q},
                                        sort_keys=True, default=str) + "\n")
        from .report import render_report

        (out / "report.md").write_text(render_report(manifest))
    return manifest
