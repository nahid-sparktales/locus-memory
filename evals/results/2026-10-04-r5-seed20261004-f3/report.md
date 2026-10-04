# locus-memory cumulative-usefulness benchmark (synthetic, offline)

Run created 2026-10-04T08:01:08Z; 5 repetitions (seeds 20261004, 20261005, 20261006, 20261007, 20261008); corpus size `full`; arms A, B, C, D, E; runtime 55.638 s.

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
| C5 | B-E | Correction propagation (strict, memory + raw history): 0 superseded statements in any channel | B: 0; C: 9; D: 9; E: 9 | **NOT met** |
| C6 | B-E | Context budget compliance: 100% of packets within the token allowance | B: 1.000; C: 1.000; D: 1.000; E: 1.000 | met |
| C7 | B-E | Nothing plaintext on disk: 0 answer phrases found in store files | B: 0; C: 0; D: 0; E: 0 | met |
| C8 | B-E | Retrieval-level abstention accuracy >= 0.75 on missing-evidence questions | B: 0.800; C: 0.700; D: 0.700; E: 0.700 | **NOT met** |
| C9 | C,D vs B | Mean recall@5 of C and of D >= B (mean paired difference >= 0) | C-B: 0.579; D-B: 0.579 | met |
| C10 | D vs C | D improves recall_all over C on repository, stale_repository and episode questions | C: 0.083; D: 1.000 | met |
| C11 | D vs C | D's distracting/stale unit rate is not worse than C's by more than 0.01 (mean paired difference) | C: 0.022; D: 0.025; D-C: 0.003 | met |
| C12 | B-E | Source attribution: 100% of gold memory items cite a source of that statement | B: 1.000; C: 1.000; D: 1.000; E: 1.000 | met |
| C13 | E | E (fake hash embeddings) passes safety gates C1-C4, C6, C7; quality not interpreted | C1: 0; C2: 0; C3: 0; C4: 0; C6: 1.000; C7: 0 | met |

## Supplementary checks (exploratory, NOT pre-registered; they do not replace C5 or C8)

| id | next to | arms | check | observed | holds |
|---|---|---|---|---|---|
| S5a | C5 | C-E | Every superseded statement in history hits carries the engine flag superseded_by_correction | C: 0; D: 0; E: 0 | yes |
| S5b | C5 | C-E | C5 with history searched using the opt-in filter exclude_corrected=True | C: 0; D: 0; E: 0 | yes |
| S8 | C8 | C-E | Abstention accuracy >= 0.75 when the arm also abstains on the engine's no-evidence signal | C: 0.700; C false abstention: 0.368; D: 0.700; D false abstention: 0.174; E: 0.700; E false abstention: 0.174 | no |

## Retrieval quality (mean [95% t-interval] over repetitions)

| metric | A | B | C | D | E |
|---|---|---|---|---|---|
| recall@5 | 0.000 [0.000, 0.000] | 0.053 [0.053, 0.053] | 0.632 [0.606, 0.657] | 0.632 [0.606, 0.657] | 0.632 [0.606, 0.657] |
| recall@10 | 0.000 [0.000, 0.000] | 0.158 [0.158, 0.158] | 0.689 [0.675, 0.704] | 0.689 [0.675, 0.704] | 0.689 [0.675, 0.704] |
| recall (all units) | 0.000 [0.000, 0.000] | 0.439 [0.412, 0.467] | 0.711 [0.711, 0.711] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| precision@5 | 0.000 [0.000, 0.000] | 0.011 [0.011, 0.011] | 0.160 [0.154, 0.166] | 0.160 [0.154, 0.166] | 0.160 [0.154, 0.166] |
| MRR | 0.000 [0.000, 0.000] | 0.068 [0.067, 0.070] | 0.336 [0.320, 0.351] | 0.352 [0.336, 0.367] | 0.352 [0.336, 0.368] |
| multi-session complete | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| abstention accuracy | 1.000 [1.000, 1.000] | 0.800 [0.800, 0.800] | 0.700 [0.700, 0.700] | 0.700 [0.700, 0.700] | 0.700 [0.700, 0.700] |
| false abstention | 1.000 [1.000, 1.000] | 0.521 [0.494, 0.548] | 0.184 [0.184, 0.184] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| distracting/stale unit rate | n/a | 0.003 [0.003, 0.003] | 0.022 [0.021, 0.023] | 0.025 [0.023, 0.026] | 0.024 [0.023, 0.026] |
| stale+superseded unit rate | n/a | 0.000 [0.000, 0.000] | 0.008 [0.007, 0.009] | 0.009 [0.008, 0.010] | 0.009 [0.007, 0.010] |
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
| superseded units in history hits | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 7.400 [6.290, 8.510] | 7.400 [6.290, 8.510] | 7.400 [6.290, 8.510] |
| correction probes passed | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.267 [0.082, 0.452] | 0.267 [0.082, 0.452] | 0.267 [0.082, 0.452] |
| budget compliance | n/a | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| plaintext hits on disk | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| source attribution correct | n/a | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| unattributed units | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| warm/cold result mismatches | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |

## Exploratory measurements (not pre-registered; mean [CI] over repetitions)

| measure | A | B | C | D | E |
|---|---|---|---|---|---|
| superseded history units flagged superseded_by_correction | n/a | n/a | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| superseded history units without the flag | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| superseded history units with exclude_corrected=True | n/a | n/a | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| correction probes passed with exclude_corrected=True | n/a | n/a | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| recall@5 with exclude_corrected=True | n/a | n/a | 0.650 [0.631, 0.669] | 0.650 [0.631, 0.669] | 0.650 [0.631, 0.669] |
| recall (all units) with exclude_corrected=True | n/a | n/a | 0.711 [0.711, 0.711] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| abstention accuracy with exclude_corrected=True | n/a | n/a | 0.700 [0.700, 0.700] | 0.700 [0.700, 0.700] | 0.700 [0.700, 0.700] |
| history units flagged weak_match | n/a | n/a | 0.976 [0.964, 0.988] | 0.976 [0.964, 0.988] | 0.976 [0.964, 0.988] |
| engine no-evidence signal on abstention questions | n/a | n/a | 0.300 [0.300, 0.300] | 0.300 [0.300, 0.300] | 0.300 [0.300, 0.300] |
| engine no-evidence signal on answerable questions | n/a | n/a | 0.184 [0.184, 0.184] | 0.174 [0.156, 0.192] | 0.174 [0.156, 0.192] |
| abstention accuracy, abstaining on the signal | n/a | n/a | 0.700 [0.700, 0.700] | 0.700 [0.700, 0.700] | 0.700 [0.700, 0.700] |
| false abstention, abstaining on the signal | n/a | n/a | 0.368 [0.368, 0.368] | 0.174 [0.156, 0.192] | 0.174 [0.156, 0.192] |
| recall@5 with relevance-first packet order | n/a | 0.053 [0.053, 0.053] | 0.655 [0.637, 0.673] | 0.945 [0.927, 0.963] | 0.942 [0.917, 0.967] |
| MRR with relevance-first packet order | n/a | 0.068 [0.067, 0.070] | 0.593 [0.573, 0.612] | 0.888 [0.869, 0.907] | 0.846 [0.819, 0.874] |

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
| C-B | 0.579 [0.553, 0.605] | 0.271 [0.244, 0.298] | 0.267 [0.252, 0.283] | -0.100 [-0.100, -0.100] | 0.019 [0.018, 0.020] |
| D-B | 0.579 [0.553, 0.605] | 0.561 [0.533, 0.588] | 0.284 [0.268, 0.299] | -0.100 [-0.100, -0.100] | 0.022 [0.020, 0.023] |
| D-C | 0.000 [0.000, 0.000] | 0.289 [0.289, 0.289] | 0.016 [0.016, 0.016] | 0.000 [0.000, 0.000] | 0.003 [0.002, 0.003] |
| E-D | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | -0.000 [-0.000, 0.000] | 0.000 [0.000, 0.000] | -0.000 [-0.000, -0.000] |

## Cost, latency and storage (wall clock on the machine above; mean [CI] over repetitions)

| measure | A | B | C | D | E |
|---|---|---|---|---|---|
| context build p50 ms (cold) | n/a | 1.6 [1.5, 1.7] | 5.0 [4.9, 5.1] | 6.0 [5.8, 6.2] | 7.6 [7.5, 7.8] |
| context build p95 ms (cold) | n/a | 4.2 [4.0, 4.4] | 8.0 [6.8, 9.2] | 9.4 [8.8, 9.9] | 11.8 [10.5, 13.1] |
| context build p50 ms (warm repeat) | n/a | 0.1 [0.1, 0.1] | 0.2 [0.1, 0.2] | 0.2 [0.2, 0.2] | 0.2 [0.2, 0.2] |
| history search p50 ms (cold) | n/a | n/a | 4.5 [4.3, 4.7] | 4.5 [4.3, 4.8] | 4.6 [4.2, 4.9] |
| history search p95 ms (cold) | n/a | n/a | 10.8 [10.5, 11.1] | 10.9 [10.0, 11.8] | 10.5 [10.0, 11.0] |
| history search p50 ms (warm repeat) | n/a | n/a | 0.5 [0.4, 0.5] | 0.5 [0.4, 0.5] | 0.5 [0.4, 0.5] |
| ingestion total ms (cold, all events) | 0.0 [0.0, 0.0] | 172.4 [105.1, 239.8] | 451.2 [398.5, 503.8] | 3409.7 [3170.9, 3648.5] | 3503.0 [3391.9, 3614.0] |
| maintenance total ms | 0.0 [0.0, 0.0] | 15.5 [15.2, 15.8] | 17.5 [9.1, 25.9] | 14.8 [14.0, 15.5] | 14.6 [14.2, 15.1] |
| engine construction ms (partitions open lazily) | n/a | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.1] |
| first context after reopen ms (open + unlock + index warming; sum of one probe per profile) | n/a | 7.7 [7.2, 8.3] | 8.6 [7.9, 9.3] | 8.6 [8.0, 9.1] | 8.1 [7.8, 8.4] |
| first history search after reopen ms (archive hydration; sum of one probe per profile) | n/a | n/a | 12.0 [10.8, 13.2] | 11.8 [11.5, 12.2] | 11.9 [11.2, 12.6] |
| second context after reopen ms (warm; sum of one probe per profile) | n/a | 0.4 [0.3, 0.4] | 0.3 [0.3, 0.3] | 0.3 [0.3, 0.3] | 0.3 [0.3, 0.3] |
| memory projection build p95 ms (engine timer) | n/a | n/a | 2.4 [2.2, 2.5] | 2.9 [2.8, 3.1] | 2.9 [2.7, 3.1] |
| history search incl. hydration p95 ms (engine timer) | n/a | n/a | 9.4 [8.9, 9.9] | 9.4 [8.7, 10.1] | 9.4 [9.0, 9.7] |
| cumulative serving cost ms | 0.0 [0.0, 0.0] | 269.6 [201.3, 337.9] | 953.6 [885.4, 1021.8] | 3943.9 [3687.5, 4200.3] | 4117.7 [3989.5, 4245.9] |
| amortized cost ms / question | 0.0 [0.0, 0.0] | 5.6 [4.2, 7.0] | 19.9 [18.4, 21.3] | 82.2 [76.8, 87.5] | 85.8 [83.1, 88.5] |
| context packet tokens (mean) | 0.0 [0.0, 0.0] | 697.9 [695.6, 700.2] | 673.9 [670.3, 677.6] | 681.5 [679.7, 683.3] | 704.5 [703.8, 705.2] |
| context overhead tokens (mean, packet + history) | 0.0 [0.0, 0.0] | 697.9 [695.6, 700.2] | 814.1 [808.6, 819.6] | 821.6 [819.3, 824.0] | 844.7 [842.9, 846.4] |
| context overhead tokens (max) | 0.0 [0.0, 0.0] | 787.0 [785.0, 789.0] | 983.4 [969.9, 996.9] | 976.8 [969.2, 984.4] | 984.0 [972.4, 995.6] |
| bytes on disk (final, after close) | 0.0 [0.0, 0.0] | 1501593.6 [1498808.4, 1504378.8] | 2765619.2 [2758076.9, 2773161.5] | 2946662.4 [2926449.8, 2966875.0] | 3030220.8 [3013587.2, 3046854.4] |
| bytes per corpus event | 0.0 [0.0, 0.0] | 1770.9 [1747.0, 1794.8] | 3261.6 [3225.7, 3297.4] | 3475.1 [3433.8, 3516.4] | 3573.5 [3546.2, 3600.9] |

Growth over simulated days (mean over runs; database + deletion-ledger bytes excluding the SQLite -wal/-shm journals, which the open engine has not yet checkpointed / cumulative serving cost ms):

| arm | end of day 0 | end of day 7 | end of day 13 |
|---|---|---|---|
| A | 0 B / 0.0 ms | 0 B / 0.0 ms | 0 B / 0.0 ms |
| B | 16384 B / 55.8 ms | 715981 B / 206.3 ms | 801997 B / 269.6 ms |
| C | 560333 B / 59.2 ms | 1869414 B / 499.8 ms | 2574746 B / 953.6 ms |
| D | 560333 B / 1116.1 ms | 2031616 B / 3246.0 ms | 2747597 B / 3943.9 ms |
| E | 560333 B / 1170.8 ms | 2082406 B / 3394.1 ms | 2836890 B / 4117.7 ms |

Cumulative serving cost = ingestion + maintenance + cold context builds + cold history searches (warm repeats excluded). Token counts are the engine's conservative estimate (characters / 3.5 x 1.15), not a model tokenizer. Provider cost is zero: no external provider is called; arm E's embeddings are local fakes.

## Not measured

* Evidence-backed task correctness: not measured: it needs a model that answers from the context and a verifier of the answer against task evidence; this benchmark runs no model. extractive_proxy (gold answer phrase present verbatim in the context packet or history hits) is a proxy, not task correctness.
* Arm F: not executed (requires host evaluation runner and task execution).

Raw per-run metrics are in `manifest.json`; per-question rows in `questions.jsonl`.
