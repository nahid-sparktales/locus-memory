"""``python -m locus_memory.evaluation --out DIR`` runs the benchmark and prints a one-line summary."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .runner import DEFAULT_SEED, run_benchmark


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m locus_memory.evaluation", description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="directory for manifest.json, report.md, ...")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--arms", default="A,B,C,D,E", help="comma-separated subset of A,B,C,D,E (F is never run)")
    parser.add_argument("--size", choices=("full", "small"), default="full")
    parser.add_argument("--token-allowance", type=int, default=800)
    parser.add_argument("--history-k", type=int, default=5)
    args = parser.parse_args(argv)
    manifest = run_benchmark(args.out, repetitions=args.repetitions, seed=args.seed,
                             arms=tuple(a.strip() for a in args.arms.split(",") if a.strip()), size=args.size,
                             token_allowance=args.token_allowance, history_k=args.history_k)
    met = sum(1 for c in manifest["criteria"] if c["met"] is True)
    print(f"passed={manifest['passed']} criteria_met={met}/{len(manifest['criteria'])}"
          f" runtime_s={manifest['runtime_s']} out={args.out}")
    return 0 if manifest["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
