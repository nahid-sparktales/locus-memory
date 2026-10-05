"""Evaluate the production policy without changing preregistered arms or results.

Run: python -m locus_memory.evaluation.production --out /tmp/production.json
The corpus, chronology guard, attribution and metrics are the original benchmark's.
Background preferences stay rendered but do not count as factual query evidence.
"""
from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from ..models import ContextRequest
from ..runtime import _SLICES
from .arms import ArmD, Evidence, interleave
from .corpus import generate_corpus
from .runner import BenchmarkConfig, run_arm


class ProductionArm(ArmD):
    name = "production"

    def context_request(self, question):
        return ContextRequest(token_allowance=self.config.token_allowance, query=question.text,
                              slices=_SLICES, order="relevance", evidence_policy="conservative")

    def retrieve(self, question):
        self.clock.set(question.asked_at)
        access = self.retrieval_access(question)
        start = time.perf_counter()
        packet = self.engine.build_context(access, self.context_request(question))
        context_ms = (time.perf_counter() - start) * 1000
        start = time.perf_counter()
        history = self.engine.search_history_for_context(access, question.text, limit=self.config.history_k)
        history_ms = (time.perf_counter() - start) * 1000
        evidence = Evidence(packet=packet, history=history, history_text=self.render_history(history),
                            timings={"context_ms": context_ms, "history_ms": history_ms})
        context = [unit for unit in self._context_units(packet) if "background_context" not in unit.reasons]
        evidence.units = interleave(context, self._history_units(history))
        return evidence

    def engine_signalled_no_evidence(self, evidence):
        return "no_query_evidence" in evidence.packet.flags and not evidence.history.hits


def evaluate(*, seed=20261004, repetitions=3, size="full"):
    runs = []
    with tempfile.TemporaryDirectory(prefix="locus-production-eval-") as directory:
        for index in range(repetitions):
            corpus = generate_corpus(seed + index, size=size)
            runs.append(run_arm(corpus, ProductionArm, Path(directory) / str(index), BenchmarkConfig()))
    return {"format": "locus-memory-production-evaluation/1", "baseline_modified": False,
            "policy": "conservative-v2", "runs": runs}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261004)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--size", choices=("full", "small"), default="full")
    args = parser.parse_args()
    report = evaluate(seed=args.seed, repetitions=args.repetitions, size=args.size)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps([{"seed": r["seed"], "passed": r["passed"], "metrics": r["metrics"]}
                      for r in report["runs"]], indent=2))
