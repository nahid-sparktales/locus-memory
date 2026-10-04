"""Write one synthetic benchmark corpus as JSON (for inspection; the benchmark generates its own).

    python evals/generate_corpus.py --seed 20261004 --out /tmp/corpus.json [--size small]

The corpus is synthetic and deterministic for a seed; it contains no real user data.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from locus_memory.evaluation.corpus import generate_corpus


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=20261004)
    parser.add_argument("--size", choices=("full", "small"), default="full")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    corpus = generate_corpus(args.seed, size=args.size)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(corpus.to_dict(), indent=1, sort_keys=True) + "\n")
    print(json.dumps(corpus.summary(), indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
