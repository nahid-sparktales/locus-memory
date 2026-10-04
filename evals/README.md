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

Options of `python -m locus_memory.evaluation` (`locus_memory.evaluation.__main__.main`):

| option | meaning | default |
|---|---|---|
| `--out` | output directory; required | none |
| `--repetitions` | number of repetitions | 5 |
| `--seed` | base seed; repetition i uses seed + i | 20261004 |
| `--arms` | comma-separated subset of A-E; F is never run | A,B,C,D,E |
| `--size` | `full` or `small` | `full` |
| `--token-allowance` | context token allowance | 800 |
| `--history-k` | history hits per question | 5 |

Arms D and E need `git` on `PATH` to build the synthetic repositories. Without it, they run without
repository facts, and the manifest records `repository_available: false`.

## Outputs (one directory per run)

| file | content |
|---|---|
| `manifest.json` | `format`, `created_at`; versions (package, Python, SQLite, cryptography, git, FTS5) and hardware; `config`; `seeds`; `corpora` (summary and hash per seed); `arms`, `arms_not_executed` (F), `labels`, `not_measured`; `passed` and `failures`; rollout `criteria`; exploratory `supplementary` checks (S5a, S5b, S8); `aggregate` (mean, stdev, 95% t-interval per arm and metric); `by_category`; `paired` differences; `growth_by_day`; `runs` (per run: raw metrics, stage latencies, per-day samples, `passed`/`failures`, and `notes`: provider usage, repository availability, snapshot count and states, deletion self-check failures, unmapped observations); `runtime_s`. No source commit is recorded |
| `questions.jsonl` | one row per arm, repetition and question: retrieval metrics, unit keys and flag counts, packet flags, history status, exploratory `excl_*` and `relorder_*` variants, tokens, latencies |
| `report.md` | the human-readable summary of the manifest; pre-registered criteria first, exploratory checks and measurements in separate, labelled tables |

The exit status of `python -m locus_memory.evaluation` is non-zero when a run failed
(`runner._hard_failures`). That happens on:
* scope leakage;
* a future unit (in practice the chronology guard aborts the benchmark first);
* a forgotten statement retrieved, or a failed deletion self-check;
* a corrected-away value in a context packet;
* the context budget exceeded;
* an answer phrase in plaintext on disk;
* in a memory arm, a returned unit that cannot be attributed to the corpus.

Criterion C12 (source attribution) is reported as met or not met, but it does not change the exit
status. A chronology violation (`ChronologyViolation`) aborts the benchmark with a traceback and writes
no outputs.

## Results in this directory

* `results/2026-10-04-r5-seed20261004/`: the first reported run (`docs/evaluation.md`, section 9).
* `results/2026-10-04-r5-seed20261004-f3/`: the re-run on the same seeds after the F3 engine changes
  (code as of commit 967136e, before the four adversarial review rounds; `docs/evaluation.md`, section
  11), with the exploratory checks S5a, S5b and S8 reported separately from the pre-registered criteria.
* `results/2026-10-04-r5-seed20261004-final/`: the final run on the same seeds after four adversarial
  review rounds (commit f02541e; `docs/evaluation.md`, section 12).
  * Criteria: 11 of 13 met (C5 and C8 not met), and all hard invariants held.
  * Every question row is identical to the f3 run except the latencies.
  * Cost and storage differ from the f3 run.

The manifests record no source commit. Which code each run measured is inferred from timestamps
(`docs/evaluation.md`, section 12.1).
