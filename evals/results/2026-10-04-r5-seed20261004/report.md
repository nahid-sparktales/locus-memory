# locus-memory cumulative-usefulness benchmark (synthetic, offline)

Run created 2026-10-04T07:05:39Z; 5 repetitions (seeds 20261004, 20261005, 20261006, 20261007, 20261008); corpus size `full`; arms A, B, C, D, E; runtime 65.354 s.

**Small synthetic fixtures are not proof of production gains.** Every number below comes from a generated corpus of two fictional profiles and three fictional projects; it checks behaviour and invariants of this engine on that corpus, nothing more.

Overall: **all hard invariants held**

## Setup

* Corpus per repetition: 858 events, 48 questions (10 expect abstention), 101 ground-truth statements, 14 simulated days. Hashes: `20261004:a952a0bac02d`, `20261005:75fe3d03ea57`, `20261006:727ecce5ff93`, `20261007:417b3405f379`, `20261008:497c99e4a60a`.
* Context: token allowance 800 (engine estimator, no host tokenizer); history hits per question k=5; fake embedding dimensions 64.
* Versions: locus_memory 0.1.0, Python 3.14.6 (CPython), SQLite 3.53.3, cryptography 50.0.0, git version 2.50.1 (Apple Git-155), FTS5 True.
* Hardware: macOS-26.4.1-arm64-arm-64bit-Mach-O; machine arm64; CPUs 12.

## Arms

| arm | configuration |
|---|---|
| A | no memory (empty context) |
| B | approved hot memory only (build_context with query='') |
| C | hot memory + lexical session-history retrieval (build_context(query) + search_history) |
| D | C + task episodes (fake host receipts) + repository observations (synthetic git repository) |
| E | D + semantic retrieval with FakeEmbeddingProvider - fake hash embeddings: contract check only, NOT semantic quality |
| F | D + evaluated procedures in an explicitly enabled host harness - not executed (requires host evaluation runner and task execution) |

Arm E uses `FakeEmbeddingProvider`: **fake hash embeddings: contract check only, NOT semantic quality**. Its numbers only show that the semantic path runs inside the same safety gates.

## Rollout criteria (defined before the run in docs/evaluation.md)

| id | arms | criterion | observed | result |
|---|---|---|---|---|
| C1 | A-E | Scope leakage = 0 in every run (any leaked unit fails the run) | A: 0; B: 0; C: 0; D: 0; E: 0 | met |
| C2 | A-E | Chronology: 0 units from events at/after the question time | A: 0; B: 0; C: 0; D: 0; E: 0 | met |
| C3 | B-E | Deletion propagation: 0 forgotten statements retrieved after the forget | B: 0; C: 0; D: 0; E: 0 | met |
| C4 | B-E | Correction propagation (curated memory): 0 corrected-away values in context | B: 0; C: 0; D: 0; E: 0 | met |
| C5 | B-E | Correction propagation (strict, memory + raw history): 0 superseded statements in any channel | B: 0; C: 13; D: 13; E: 13 | **NOT met** |
| C6 | B-E | Context budget compliance: 100% of packets within the token allowance | B: 1.000; C: 1.000; D: 1.000; E: 1.000 | met |
| C7 | B-E | Nothing plaintext on disk: 0 answer phrases found in store files | B: 0; C: 0; D: 0; E: 0 | met |
| C8 | B-E | Retrieval-level abstention accuracy >= 0.75 on missing-evidence questions | B: 0.800; C: 0.700; D: 0.700; E: 0.700 | **NOT met** |
| C9 | C,D vs B | Mean recall@5 of C and of D >= B (mean paired difference >= 0) | C-B: 0.579; D-B: 0.579 | met |
| C10 | D vs C | D improves recall_all over C on repository, stale_repository and episode questions | C: 0.083; D: 1.000 | met |
| C11 | D vs C | D's distracting/stale unit rate is not worse than C's by more than 0.01 (mean paired difference) | C: 0.025; D: 0.028; D-C: 0.003 | met |
| C12 | B-E | Source attribution: 100% of gold memory items cite a source of that statement | B: 1.000; C: 1.000; D: 1.000; E: 1.000 | met |
| C13 | E | E (fake hash embeddings) passes safety gates C1-C4, C6, C7; quality not interpreted | C1: 0; C2: 0; C3: 0; C4: 0; C6: 1.000; C7: 0 | met |

## Retrieval quality (mean [95% t-interval] over repetitions)

| metric | A | B | C | D | E |
|---|---|---|---|---|---|
| recall@5 | 0.000 [0.000, 0.000] | 0.053 [0.053, 0.053] | 0.632 [0.606, 0.657] | 0.632 [0.606, 0.657] | 0.632 [0.606, 0.657] |
| recall@10 | 0.000 [0.000, 0.000] | 0.158 [0.158, 0.158] | 0.684 [0.661, 0.707] | 0.684 [0.661, 0.707] | 0.684 [0.661, 0.707] |
| recall (all units) | 0.000 [0.000, 0.000] | 0.439 [0.412, 0.467] | 0.711 [0.711, 0.711] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| precision@5 | 0.000 [0.000, 0.000] | 0.011 [0.011, 0.011] | 0.164 [0.159, 0.170] | 0.164 [0.159, 0.170] | 0.164 [0.159, 0.170] |
| MRR | 0.000 [0.000, 0.000] | 0.068 [0.067, 0.070] | 0.335 [0.322, 0.349] | 0.351 [0.338, 0.365] | 0.351 [0.338, 0.365] |
| multi-session complete | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| abstention accuracy | 1.000 [1.000, 1.000] | 0.800 [0.800, 0.800] | 0.700 [0.700, 0.700] | 0.700 [0.700, 0.700] | 0.700 [0.700, 0.700] |
| false abstention | 1.000 [1.000, 1.000] | 0.521 [0.494, 0.548] | 0.184 [0.184, 0.184] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| distracting/stale unit rate | n/a | 0.003 [0.003, 0.003] | 0.025 [0.024, 0.026] | 0.028 [0.027, 0.029] | 0.028 [0.027, 0.029] |
| stale+superseded unit rate | n/a | 0.000 [0.000, 0.000] | 0.012 [0.011, 0.013] | 0.013 [0.012, 0.014] | 0.013 [0.012, 0.014] |
| extractive proxy (verbatim answer present) | 0.000 [0.000, 0.000] | 0.400 [0.373, 0.427] | 0.711 [0.711, 0.711] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |

Evidence list = context-packet items (packet order) interleaved round-robin with history hits (rank order). Ranking metrics use answerable questions; abstention uses missing-evidence, deleted, cross-scope and cross-profile questions (retrieval-level: no candidate answer surfaced).

## Safety and invariants (totals per run; mean [CI] over repetitions)

| check | A | B | C | D | E |
|---|---|---|---|---|---|
| scope leakage units | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| future units | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| forgotten units retrieved | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| deletion probes passed | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| superseded units in context | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| superseded units in history hits | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 12.200 [11.161, 13.239] | 12.200 [11.161, 13.239] | 12.200 [11.161, 13.239] |
| correction probes passed | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| budget compliance | n/a | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| plaintext hits on disk | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| source attribution correct | n/a | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| unattributed units | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| warm/cold result mismatches | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |

## By question category (recall_all, or abstention accuracy for abstention categories; mean over runs)

| category | A | B | C | D | E |
|---|---|---|---|---|---|
| correction | 0.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| cross_profile | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| cross_scope | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| deletion | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| deletion_before | 0.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| distractor | 0.000 | 0.000 | 1.000 | 1.000 | 1.000 |
| episode | 0.000 | 0.000 | 0.000 | 1.000 | 1.000 |
| long_horizon | 0.000 | 0.371 | 1.000 | 1.000 | 1.000 |
| missing_evidence | 1.000 | 0.600 | 0.400 | 0.400 | 0.400 |
| multi_session | 0.000 | 0.375 | 1.000 | 1.000 | 1.000 |
| preference | 0.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| project_decision | 0.000 | 0.767 | 1.000 | 1.000 | 1.000 |
| repository | 0.000 | 0.000 | 0.200 | 1.000 | 1.000 |
| stale_repository | 0.000 | 0.000 | 0.000 | 1.000 | 1.000 |

## Paired differences (same corpus per seed; mean [95% t-interval])

| pair | recall@5 | recall_all | mrr | abstention_accuracy | distracting_rate |
|---|---|---|---|---|---|
| C-B | 0.579 [0.553, 0.605] | 0.271 [0.244, 0.298] | 0.267 [0.254, 0.280] | -0.100 [-0.100, -0.100] | 0.022 [0.021, 0.023] |
| D-B | 0.579 [0.553, 0.605] | 0.561 [0.533, 0.588] | 0.283 [0.270, 0.296] | -0.100 [-0.100, -0.100] | 0.025 [0.024, 0.026] |
| D-C | 0.000 [0.000, 0.000] | 0.289 [0.289, 0.289] | 0.016 [0.016, 0.016] | 0.000 [0.000, 0.000] | 0.003 [0.003, 0.003] |
| E-D | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | -0.000 [-0.000, 0.000] | 0.000 [0.000, 0.000] | -0.000 [-0.001, -0.000] |

## Cost, latency and storage (wall clock on the machine above; mean [CI] over repetitions)

| measure | A | B | C | D | E |
|---|---|---|---|---|---|
| context build p50 ms (cold) | n/a | 1.8 [1.5, 2.1] | 5.4 [5.0, 5.7] | 7.0 [5.6, 8.4] | 9.6 [6.8, 12.4] |
| context build p95 ms (cold) | n/a | 5.5 [3.3, 7.6] | 8.7 [7.4, 10.0] | 17.4 [0.8, 34.0] | 18.4 [9.5, 27.2] |
| context build p50 ms (warm repeat) | n/a | 0.2 [0.1, 0.2] | 0.2 [0.1, 0.2] | 0.2 [0.2, 0.2] | 0.2 [0.2, 0.2] |
| history search p50 ms (cold) | n/a | n/a | 4.7 [4.3, 5.1] | 5.0 [4.5, 5.6] | 5.5 [3.8, 7.2] |
| history search p95 ms (cold) | n/a | n/a | 11.9 [11.0, 12.8] | 15.3 [3.9, 26.7] | 16.7 [4.8, 28.5] |
| history search p50 ms (warm repeat) | n/a | n/a | 0.4 [0.4, 0.4] | 0.4 [0.4, 0.5] | 0.4 [0.4, 0.5] |
| ingestion total ms (cold, all events) | 0.0 [0.0, 0.0] | 218.0 [101.4, 334.7] | 504.8 [400.4, 609.2] | 3752.3 [3141.5, 4363.1] | 4286.1 [2430.2, 6142.1] |
| maintenance total ms | 0.0 [0.0, 0.0] | 31.2 [-2.8, 65.2] | 14.0 [12.9, 15.2] | 19.0 [12.7, 25.4] | 26.8 [7.0, 46.7] |
| engine construction ms (partitions open lazily) | n/a | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.1] | 0.0 [0.0, 0.1] |
| first context after reopen ms (open + unlock + index warming; sum of one probe per profile) | n/a | 8.5 [7.3, 9.7] | 9.5 [7.9, 11.0] | 11.2 [6.4, 16.1] | 11.0 [6.8, 15.3] |
| first history search after reopen ms (archive hydration; sum of one probe per profile) | n/a | n/a | 11.9 [11.3, 12.5] | 13.0 [10.3, 15.7] | 14.2 [9.9, 18.5] |
| second context after reopen ms (warm; sum of one probe per profile) | n/a | 0.4 [0.3, 0.4] | 0.3 [0.3, 0.4] | 0.4 [0.2, 0.6] | 0.4 [0.3, 0.4] |
| memory projection build p95 ms (engine timer) | n/a | n/a | 2.9 [2.2, 3.5] | 5.0 [1.1, 8.9] | 4.1 [2.0, 6.2] |
| history search incl. hydration p95 ms (engine timer) | n/a | n/a | 11.2 [10.4, 12.1] | 12.5 [7.6, 17.3] | 13.2 [8.8, 17.6] |
| cumulative serving cost ms | 0.0 [0.0, 0.0] | 358.5 [158.2, 558.7] | 1030.2 [881.7, 1178.7] | 4474.5 [3529.3, 5419.8] | 5113.5 [2993.4, 7233.6] |
| amortized cost ms / question | 0.0 [0.0, 0.0] | 7.5 [3.3, 11.6] | 21.5 [18.4, 24.6] | 93.2 [73.5, 112.9] | 106.5 [62.4, 150.7] |
| context packet tokens (mean) | 0.0 [0.0, 0.0] | 697.9 [695.6, 700.2] | 673.9 [670.3, 677.6] | 681.5 [679.7, 683.3] | 704.6 [703.4, 705.8] |
| context overhead tokens (mean, packet + history) | 0.0 [0.0, 0.0] | 697.9 [695.6, 700.2] | 844.0 [837.3, 850.6] | 851.5 [847.0, 856.0] | 874.6 [871.7, 877.6] |
| context overhead tokens (max) | 0.0 [0.0, 0.0] | 787.0 [785.0, 789.0] | 980.8 [966.5, 995.1] | 980.6 [976.3, 984.9] | 984.4 [978.6, 990.2] |
| bytes on disk (final, after close) | 0.0 [0.0, 0.0] | 1460633.6 [1456085.4, 1465181.8] | 2728755.2 [2716093.6, 2741416.8] | 2899148.8 [2887008.4, 2911289.2] | 2984345.6 [2959278.9, 3009412.3] |
| bytes per corpus event | 0.0 [0.0, 0.0] | 1722.6 [1698.9, 1746.3] | 3218.1 [3181.5, 3254.7] | 3419.0 [3386.8, 3451.2] | 3519.4 [3490.5, 3548.3] |

Growth over simulated days (mean over runs; database + deletion-ledger bytes excluding the SQLite -wal/-shm journals, which the open engine has not yet checkpointed / cumulative serving cost ms):

| arm | end of day 0 | end of day 7 | end of day 13 |
|---|---|---|---|
| A | 0 B / 0.0 ms | 0 B / 0.0 ms | 0 B / 0.0 ms |
| B | 16384 B / 75.0 ms | 695501 B / 262.5 ms | 781517 B / 358.5 ms |
| C | 539853 B / 76.7 ms | 1827635 B / 559.3 ms | 2537882 B / 1030.2 ms |
| D | 539853 B / 1130.1 ms | 1997210 B / 3530.6 ms | 2695168 B / 4474.5 ms |
| E | 539853 B / 1361.4 ms | 2047181 B / 4066.6 ms | 2788557 B / 5113.5 ms |

Cumulative serving cost = ingestion + maintenance + cold context builds + cold history searches (warm repeats excluded). Token counts are the engine's conservative estimate (characters / 3.5 x 1.15), not a model tokenizer. Provider cost is zero: no external provider is called; arm E's embeddings are local fakes.

## Not measured

* Evidence-backed task correctness: not measured: it needs a model that answers from the context and a verifier of the answer against task evidence; this benchmark runs no model. extractive_proxy (gold answer phrase present verbatim in the context packet or history hits) is a proxy, not task correctness.
* Arm F: not executed (requires host evaluation runner and task execution).

Raw per-run metrics are in `manifest.json`; per-question rows in `questions.jsonl`.
