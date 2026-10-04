"""Offline evaluation benchmark: corpus invariants, metric math, chronology and scope-leak detection.

Everything runs on the synthetic corpus in pytest temp dirs; no network, no model, no real data.
"""
from __future__ import annotations

import dataclasses
import json
import math
import shutil
from pathlib import Path

import pytest

from locus_memory.evaluation import ChronologyViolation, generate_corpus, run_benchmark
from locus_memory.evaluation import runner as runner_mod
from locus_memory.evaluation.arms import (
    ARMS,
    F_NOT_EXECUTED,
    FAKE_EMBEDDING_LABEL,
    ArmB,
    ArmC,
    Origin,
    Unit,
    interleave,
    write_access,
)
from locus_memory.evaluation.corpus import (
    ABSTAIN_CATEGORIES,
    CorpusError,
    Event,
    Question,
    blob_sha1,
    corpus_hash,
    validate_corpus,
)
from locus_memory.evaluation.metrics import (
    aggregate_run,
    percentile,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
    score_question,
    summarize,
    t_critical_975,
    unit_flags,
)
from locus_memory.evaluation.runner import (
    BenchmarkConfig,
    ChronologyGuard,
    iterate_timeline,
    run_arm,
)
from locus_memory.models import AccessContext, Actor, Operation

QUALITY_METRICS = (
    "recall@5", "recall@10", "recall_all", "precision@5", "mrr", "multi_session_complete", "extractive_proxy",
    "abstention_accuracy", "false_abstention_rate", "distracting_rate", "stale_rate", "scope_leakage_count",
    "deletion_failures", "correction_failures_context", "correction_failures_history", "attribution_correct_rate",
    "budget_compliance", "packet_tokens_mean", "overhead_tokens_mean", "plaintext_hits", "by_category",
)


# --------------------------------------------------------------------------- corpus
def test_corpus_is_deterministic_and_seed_dependent():
    a, b, c = generate_corpus(7), generate_corpus(7), generate_corpus(8)
    assert corpus_hash(a) == corpus_hash(b)
    assert corpus_hash(a) != corpus_hash(c)
    assert a.to_dict() == b.to_dict()
    summary = a.summary()
    assert summary["questions"] == len(a.questions) and summary["abstention_questions"] >= 8
    assert set(summary["questions_by_category"]) >= {"correction", "deletion", "cross_scope", "cross_profile",
                                                      "missing_evidence", "multi_session", "stale_repository",
                                                      "episode", "distractor"}


def test_corpus_invariants_hold_for_many_seeds():
    for seed in range(12):
        for size in ("full", "small"):
            corpus = generate_corpus(seed, size=size)
            times = [e.time for e in corpus.events] + [q.asked_at for q in corpus.questions]
            assert len(times) == len(set(times))
            for q in corpus.questions:
                assert q.expect_abstain == (q.category in ABSTAIN_CATEGORIES)
                assert bool(q.gold) != q.expect_abstain
                for requirement in q.gold:
                    for key in requirement:
                        assert corpus.keys[key].introduced_at < q.asked_at


def test_corpus_validation_rejects_gold_from_the_future():
    corpus = generate_corpus(1, size="small")
    target = next(q for q in corpus.questions if q.gold)
    key = target.gold[0][0]
    too_early = corpus.keys[key].introduced_at - 1.0
    moved = dataclasses.replace(target, asked_at=too_early)
    broken = dataclasses.replace(corpus, questions=tuple(moved if q is target else q for q in corpus.questions))
    with pytest.raises(CorpusError):
        validate_corpus(broken)


def test_blob_sha1_matches_git_object_ids():
    assert blob_sha1(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    assert blob_sha1(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


# --------------------------------------------------------------------------- metric math
def test_ranking_metrics():
    keys = [None, "x", "a", None, "b", "a"]
    requirements = [("a",), ("b", "c")]
    assert recall_at_k(keys, requirements, 2) == 0.0
    assert recall_at_k(keys, requirements, 3) == 0.5
    assert recall_at_k(keys, requirements, 5) == 1.0
    assert recall_at_k(keys, requirements, None) == 1.0
    assert precision_at_k(keys, requirements, 5) == pytest.approx(2 / 5)
    assert precision_at_k(keys[:1], requirements, 5) == 0.0  # short lists are not rescaled
    assert reciprocal_rank(keys, requirements) == pytest.approx(1 / 3)
    assert reciprocal_rank([None, "z"], requirements) == 0.0
    with pytest.raises(ValueError):
        recall_at_k(keys, [], 5)
    with pytest.raises(ValueError):
        precision_at_k(keys, requirements, 0)


def test_t_interval_and_summaries():
    assert t_critical_975(1) == 12.706
    assert t_critical_975(4) == 2.776
    assert t_critical_975(30) == 2.042
    assert t_critical_975(120) == pytest.approx(1.980, abs=2e-3)  # Cornish-Fisher beyond the table
    assert t_critical_975(10_000) == pytest.approx(1.960, abs=1e-3)
    s = summarize([1.0, 2.0, 3.0, 4.0, 5.0])
    assert s["n"] == 5 and s["mean"] == 3.0 and s["stdev"] == pytest.approx(math.sqrt(2.5))
    half = 2.776 * math.sqrt(2.5) / math.sqrt(5)
    assert s["ci95_low"] == pytest.approx(3.0 - half) and s["ci95_high"] == pytest.approx(3.0 + half)
    flat = summarize([0, 0, 0])
    assert flat["mean"] == 0 and flat["ci95_low"] == 0 and flat["ci95_high"] == 0
    assert summarize([None, 2.0])["n"] == 1 and summarize([None, 2.0])["ci95_low"] is None
    assert summarize([])["mean"] is None
    assert percentile([5, 1, 3, 2, 4], 50) == 3 and percentile([5, 1, 3, 2, 4], 95) == 5
    assert percentile([], 50) is None


def test_interleave_is_round_robin():
    def u(name: str, channel: str) -> Unit:
        return Unit(channel, name, None, {}, (), None)

    ctx = [u("c1", "context"), u("c2", "context"), u("c3", "context")]
    hist = [u("h1", "history")]
    assert [x.unit_id for x in interleave(ctx, hist)] == ["c1", "h1", "c2", "c3"]


def _unit(key: str | None, *, project: str | None = "atlas", profile: str = "alpha", time: float = 0.0,
          channel: str = "context", reported: dict | None = None, sources: tuple[str, ...] = ()) -> Unit:
    origin = Origin("ev1", time, profile, project, key)
    scope = reported if reported is not None else ({"project": project} if project else {})
    return Unit(channel, f"id-{key}-{project}-{channel}", 1, scope, sources, origin)


def test_unit_flags_and_question_scoring():
    corpus = generate_corpus(2, size="small")
    q = next(x for x in corpus.questions if x.category == "correction" and x.project == "atlas")
    keys = corpus.keys
    t = q.asked_at - 1.0
    gold, = q.gold[0]
    old = "atlas.deploy@v1"
    assert old in q.forbidden
    units = [
        _unit(None, time=t),
        _unit(gold, time=t, sources=("message:m-gold",)),
        _unit(old, time=t, channel="history"),
        _unit("borealis.db", project="borealis", time=t),  # other scope: a leak
    ]
    flags = [unit_flags(x, q, keys) for x in units]
    assert flags[1] >= {"gold"} and "leak" not in flags[1]
    assert {"superseded", "forbidden"} <= flags[2]
    assert "leak" in flags[3]
    score = score_question(q, units, keys, {"message:m-gold": gold}, evidence_text=keys[gold].answer.upper())
    assert score["recall@5"] == 1.0 and score["mrr"] == 0.5 and score["precision@5"] == pytest.approx(0.2)
    assert score["leak_units"] == 1 and score["superseded_history_units"] == 1
    assert score["attributed_gold_memory_units"] == 1 and score["proxy_verbatim"] is True
    assert score["abstained"] is False and score["abstain_correct"] is None
    # A unit whose engine-reported scope is outside the trusted scope leaks even if attributed in-scope.
    sneaky = _unit(gold, time=t, reported={"project": "borealis"})
    assert "leak" in unit_flags(sneaky, q, keys)
    # A unit from another profile leaks.
    assert "leak" in unit_flags(_unit("cobalt.db", project="cobalt", profile="beta", time=t), q, keys)


def test_abstention_is_retrieval_level():
    corpus = generate_corpus(2, size="small")
    q = next(x for x in corpus.questions if x.category == "deletion" and x.project is None)
    keys = corpus.keys
    t = q.asked_at - 1.0
    clean = score_question(q, [_unit(None, project=None, time=t)], keys, {}, "")
    assert clean["abstained"] is True and clean["abstain_correct"] is True
    deleted = q.forbidden[0]
    leaked = score_question(q, [_unit(deleted, project=None, time=t, channel="history")], keys, {}, "")
    assert leaked["abstain_correct"] is False and leaked["deleted_units"] == 1
    rows = [dict(clean, budget_ok=True, packet_tokens=10, overhead_tokens=10),
            dict(leaked, budget_ok=True, packet_tokens=10, overhead_tokens=12)]
    agg = aggregate_run(rows)
    assert agg["abstention_accuracy"] == 0.5 and agg["deletion_failures"] == 1
    assert agg["deletion_probe_pass_rate"] == 0.5 and agg["overhead_tokens_max"] == 12


# --------------------------------------------------------------------------- chronology
def test_chronology_guard_unit_checks():
    corpus = generate_corpus(4, size="small")
    guard = ChronologyGuard(corpus)
    first_q = corpus.questions[0]
    before = [e for e in corpus.events if e.time < first_q.asked_at]
    for event in before:
        guard.on_event(event)
    guard.before_question(first_q)  # exactly the past has been applied
    guard.check_units([_unit("x", time=first_q.asked_at - 1)], first_q)
    with pytest.raises(ChronologyViolation):
        guard.check_units([_unit("x", time=first_q.asked_at)], first_q)
    future = Unit("history", "h1", None, {}, (), None, reported_time=first_q.asked_at + 5)
    with pytest.raises(ChronologyViolation):
        guard.check_units([future], first_q)
    with pytest.raises(ChronologyViolation):
        guard.on_event(dataclasses.replace(before[0], time=before[0].time - 1))
    # Skipping a past event is also caught.
    lagging = ChronologyGuard(corpus)
    for event in before[:-1]:
        lagging.on_event(event)
    with pytest.raises(ChronologyViolation):
        lagging.before_question(first_q)


def test_timeline_orders_questions_before_simultaneous_events():
    corpus = generate_corpus(5, size="small")
    q = corpus.questions[0]
    clash = Event("ev-clash", q.asked_at, q.profile, "day_end", {"day": 0})
    events = tuple(sorted((*corpus.events, clash), key=lambda e: e.time))
    items = list(iterate_timeline(dataclasses.replace(corpus, events=events)))
    assert items.index(q) < items.index(clash)


@pytest.mark.slow
def test_leakage_self_check_catches_an_injected_future_event(monkeypatch, tmp_path):
    corpus = generate_corpus(3, size="small")
    original = runner_mod.iterate_timeline

    def leaky_feeder(c):
        items = list(original(c))
        q_index = next(i for i, item in enumerate(items) if isinstance(item, Question) and item.day >= 2)
        future = next(item for item in items[q_index + 1:] if isinstance(item, Event) and item.type == "message")
        items.remove(future)
        items.insert(q_index, future)  # a future message becomes visible to the question
        return iter(items)

    monkeypatch.setattr(runner_mod, "iterate_timeline", leaky_feeder)
    with pytest.raises(ChronologyViolation):
        run_arm(corpus, ArmC, tmp_path / "work", BenchmarkConfig(repetitions=1, size="small"))


# --------------------------------------------------------------------------- scope leakage detector
class LeakyArm(ArmC):
    """Deliberately wrong: retrieves with the whole profile's grants instead of the question's scope."""

    name = "LEAKY"

    def retrieval_access(self, question):
        wide = write_access(question.profile)
        return AccessContext(principal=wide.principal, partition=wide.partition, actor=Actor.AGENT,
                             grants=wide.grants, operations=frozenset({Operation.READ}))


@pytest.mark.slow
def test_scope_leak_detector_fails_a_leaky_arm(tmp_path):
    manifest = run_benchmark(tmp_path / "out", repetitions=1, seed=11, arms=("C", LeakyArm), size="small",
                             workdir=tmp_path / "work", write=False)
    runs = {r["arm"]: r for r in manifest["runs"]}
    assert runs["C"]["metrics"]["scope_leakage_count"] == 0 and runs["C"]["passed"]
    assert runs["LEAKY"]["metrics"]["scope_leakage_count"] > 0
    assert not runs["LEAKY"]["passed"] and any("scope leakage" in f for f in runs["LEAKY"]["failures"])
    assert manifest["passed"] is False
    c1 = next(c for c in manifest["criteria"] if c["id"] == "C1")
    assert c1["met"] is False and c1["observed"]["LEAKY"] > 0


# --------------------------------------------------------------------------- end to end
@pytest.mark.slow
def test_small_corpus_benchmark_completes_and_writes_outputs(tmp_path):
    arms = ("A", "B", "C", "D", "E", "F") if shutil.which("git") else ("A", "B", "C", "E", "F")
    out = tmp_path / "out"
    manifest = run_benchmark(out, repetitions=1, seed=5, arms=arms, size="small", workdir=tmp_path / "work")
    assert manifest["passed"], manifest["failures"]
    assert (out / "manifest.json").exists() and (out / "report.md").exists()
    rows = [json.loads(line) for line in (out / "questions.jsonl").read_text().splitlines()]
    executed = [a for a in arms if a != "F"]
    assert {r["arm"] for r in rows} == set(executed)
    on_disk = json.loads((out / "manifest.json").read_text())
    assert on_disk["config"]["arms"] == list(executed) and "F" in on_disk["arms_not_executed"]
    assert on_disk["versions"]["sqlite"] and on_disk["hardware"]["machine"] is not None
    assert on_disk["corpora"][0]["hash"] == corpus_hash(generate_corpus(5, size="small"))
    report = (out / "report.md").read_text()
    assert FAKE_EMBEDDING_LABEL in report and F_NOT_EXECUTED in report
    assert "not proof of production gains" in report
    agg = manifest["aggregate"]
    assert agg["A"]["recall_all"]["mean"] == 0.0 and agg["A"]["abstention_accuracy"]["mean"] == 1.0
    for arm in executed:
        assert agg[arm]["scope_leakage_count"]["mean"] == 0
        assert agg[arm]["deletion_failures"]["mean"] == 0
    for arm in [a for a in executed if a != "A"]:
        assert agg[arm]["budget_compliance"]["mean"] == 1.0
        assert agg[arm]["plaintext_hits"]["mean"] == 0
        assert agg[arm]["correction_failures_context"]["mean"] == 0
    e_run = next(r for r in manifest["runs"] if r["arm"] == "E")
    assert e_run["notes"]["provider_usage"]["label"] == FAKE_EMBEDDING_LABEL
    assert e_run["notes"]["provider_usage"]["embed_calls"] > 0
    if "D" in executed:
        d_run = next(r for r in manifest["runs"] if r["arm"] == "D")
        assert d_run["notes"]["repository_available"] and d_run["notes"]["unmapped_observations"] == 0
        assert manifest["by_category"]["D"]["stale_repository"]["mean"] == 1.0


@pytest.mark.slow
def test_runs_are_deterministic_for_a_fixed_seed(tmp_path):
    # Arm E is excluded from exact comparison: FakeEmbeddingProvider vectors are integer bucket counts,
    # so exact cosine ties are common and retrieval breaks them by (random) record id; see
    # docs/evaluation.md. Its safety invariants are still compared.
    arms = ("B", "C", "D", "E") if shutil.which("git") else ("B", "C", "E")
    assert corpus_hash(generate_corpus(21, size="small")) == corpus_hash(generate_corpus(21, size="small"))
    corpus = generate_corpus(21, size="small")
    config = BenchmarkConfig(repetitions=1, size="small")
    for arm in arms:
        r1 = run_arm(corpus, ARMS[arm], tmp_path / f"{arm}-1", config)
        r2 = run_arm(corpus, ARMS[arm], tmp_path / f"{arm}-2", config)
        if arm != "E":
            assert [q["unit_keys"] for q in r1["questions"]] == [q["unit_keys"] for q in r2["questions"]], arm
            for metric in QUALITY_METRICS:
                assert r1["metrics"][metric] == r2["metrics"][metric], (arm, metric)
        for metric in ("scope_leakage_count", "deletion_failures", "correction_failures_context",
                       "plaintext_hits", "budget_compliance"):
            assert r1["metrics"][metric] == r2["metrics"][metric], (arm, metric)


def test_arm_f_is_reported_not_executed_and_unknown_arms_are_refused(tmp_path):
    manifest = run_benchmark(tmp_path / "out", repetitions=1, arms=("A", "F"), size="small", write=False)
    assert [r["arm"] for r in manifest["runs"]] == ["A"]
    assert manifest["arms_not_executed"]["F"].endswith(F_NOT_EXECUTED)
    with pytest.raises(ValueError):
        run_benchmark(tmp_path / "x", repetitions=1, arms=("Z",), write=False)
    with pytest.raises(ValueError):
        run_benchmark(tmp_path / "x", repetitions=0, write=False)


def test_memory_arm_state_is_isolated_per_run(tmp_path):
    corpus = generate_corpus(9, size="small")
    config = BenchmarkConfig(repetitions=1, size="small")
    first = run_arm(corpus, ArmB, tmp_path / "one", config)
    second = run_arm(corpus, ArmB, tmp_path / "two", config)
    assert first["metrics"]["recall_all"] == second["metrics"]["recall_all"]
    assert first["metrics"]["storage_bytes_final"] > 0
    assert Path(tmp_path / "one" / "store").exists() and Path(tmp_path / "two" / "store").exists()
