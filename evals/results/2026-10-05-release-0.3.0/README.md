# 0.3.0 release held-out verification

The exact 0.3.0 wheel ran the conservative-v2 production policy on five synthetic
corpora with seeds 20303030–20303034. The policy was frozen before this run;
`frozen-policy.json` records source SHA-256 values and acceptance thresholds.
The recorded hashes match the files in the release wheel. No source change or
parameter tuning followed this held-out run.

All five hard gates passed. Recall@5 ranges from 0.9737 to 1.0, abstention accuracy
is 1.0, and false abstention is 0.0. All scope, future-evidence, deletion,
corrected-history and plaintext-leak counters are zero. `heldout.json` includes
every question and the remaining metrics. Historical benchmark outputs remain unchanged.

These are retrieval and privacy measurements on synthetic data. There were no
model calls, real user records or provider charges. They do not demonstrate
improved real agent task quality or semantic embedding quality. The initial live
campaign still has 2/6 success in both memory arms.

```sh
.venv/bin/python -m locus_memory.evaluation.production --seed 20303030 \
  --repetitions 5 --out evals/results/2026-10-05-release-0.3.0/heldout.json
```
