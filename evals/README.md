# evals

An offline, chronological benchmark of cumulative memory usefulness, run over a **synthetic** corpus.
The code is in `src/locus_memory/evaluation/`. Design, metric definitions, rollout criteria and the
measured results are in [`docs/evaluation.md`](../docs/evaluation.md).

* No network, no model, no LLM judge, no real user data. Every value comes from a seeded generator.
* Arm E uses `FakeEmbeddingProvider`: fake hash embeddings, contract check only, NOT semantic quality.
* Arm F (evaluated procedures) is not executed: it requires a host evaluation runner and task execution.
* Small synthetic fixtures are not proof of production gains.

## Run

```bash
# full benchmark: 5 repetitions x arms A-E (about one minute on an Apple-silicon laptop)
python -m locus_memory.evaluation --out evals/results/<name> --repetitions 5 --seed 20261004

# quick smoke run
python -m locus_memory.evaluation --out /tmp/eval-smoke --repetitions 1 --size small

# inspect one generated corpus
python evals/generate_corpus.py --seed 20261004 --out /tmp/corpus.json
```

Arms D and E need `git` on `PATH` to build the synthetic repositories. Without it, they run without
repository facts, and the manifest records `repository_available: false`.

## Outputs (one directory per run)

| file | content |
|---|---|
| `manifest.json` | versions (package, Python, SQLite, cryptography, git); platform and hardware; config; seeds; corpus size and hash per seed; per-run raw metrics, stage latencies and per-day growth; aggregates (mean, stdev, 95% t-interval); paired differences; rollout criteria results |
| `questions.jsonl` | one row per arm, repetition and question: retrieval metrics, flags, evidence keys, tokens, latency |
| `report.md` | the human-readable summary of the manifest |

The exit status of `python -m locus_memory.evaluation` is non-zero when any hard invariant failed (for
example scope leakage, a forgotten statement retrieved, or the context budget exceeded).

## Results in this directory

`results/2026-10-04-r5-seed20261004/` holds the reported run summarised in `docs/evaluation.md`.
