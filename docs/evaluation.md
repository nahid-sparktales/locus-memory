# Evaluation: offline chronological benchmark of cumulative usefulness

This document describes the benchmark in `src/locus_memory/evaluation/`, fixes the rollout criteria, and
then reports one measured run. The design and the criteria (sections 1 to 8) were written before the
reported run (section 9).

**Small synthetic fixtures are not proof of production gains.** The benchmark runs a generated corpus
through the real engine. It can show that invariants hold, that a configuration retrieves what the corpus
says it should, and what that costs on one machine. It cannot show that real users get better answers.

## 1. What the benchmark answers

The benchmark asks whether memory that accumulates over simulated days helps or hurts later questions, for
each engine configuration ("arm"). It answers with deterministic retrieval measurements. No model or LLM
judge is involved:

* **Usefulness:** does the evidence handed to the model contain what is needed (recall@k, precision@k,
  MRR, multi-session coverage)? Does it stay silent when nothing applies (retrieval-level abstention)?
* **Harm:** does it surface distractors, stale or superseded statements, forgotten statements, or anything
  outside the trusted scope?
* **Cost:** ingestion, hydration, retrieval, context build and maintenance latency; context overhead
  tokens; bytes on disk; cumulative and amortized cost, with cold and warm paths reported separately.

### Not measured

* **Evidence-backed task correctness.** Measuring it needs a model that answers from the context and a
  verifier that checks the answer against task evidence, and this benchmark runs no model. As a clearly
  labelled proxy, `extractive_proxy` reports whether every required answer phrase appears verbatim in the
  context packet or history hits. That shows the answer was available, not that a model would use it
  correctly.
* **Arm F** (D + evaluated procedures in an explicitly enabled host harness): not executed (requires host
  evaluation runner and task execution).
* **Semantic retrieval quality.** Arm E uses `providers.fake.FakeEmbeddingProvider`, labelled everywhere
  as *fake hash embeddings: contract check only, NOT semantic quality*. Its vectors hash words into
  buckets (lexical overlap, not meaning). E shows only that the semantic path runs inside the same safety
  gates.
* No Hermes, paper or other external numbers are used or compared.

## 2. Corpus (synthetic, deterministic)

The corpus is built by `corpus.generate_corpus(seed, size="full"|"small")`. Everything in it is invented:
two profiles (`alpha` with projects `atlas` and `borealis`, `beta` with project `cobalt`), fictional
values and fictional company names, over 14 simulated days. The structure is fixed: which kind of
statement happens on which day, which question is asked when, and which keys are gold or forbidden. The
seed varies the values, wording, filler chatter, background facts, minute-level timing and question
paraphrases.

| element | what the corpus contains |
|---|---|
| sessions | per day: one general and one per project for each profile, inside fixed hour slots; filler chatter in each |
| user preferences | indentation, commit style, test runner, answer style, editor, background preferences (profile-global) |
| project decisions / constraints | production DB, deploy target, latency SLO, licence, job queue, CI, API style, retention, plus 14 background tool decisions per project (budget competitors) |
| corrections | test runner (day 6), atlas deploy target (day 6), borealis frontend (day 8), applied with `engine.correct` |
| multi-session dependencies | four questions that need two statements made in different sessions |
| distractors | same-scope similar wording (staging vs production DB, deploy target vs staging deploy), an unverified assistant claim ("done and all tests pass") |
| stale repository facts | synthetic git repositories; `atlas/cache.py` changes on day 7 and `borealis/export.py` on day 9; a chat statement about the old cache becomes stale too |
| failed / interrupted attempts | episodes with fake host receipts: atlas rate limiting fails (claimed success, failed required check) then is verified; the borealis toolchain upgrade is interrupted; the cobalt fix is partial and later verified |
| deletions | the user's weather city (day 5) and the borealis pilot customer (day 9) are forgotten; later questions must not retrieve them |
| missing evidence | questions whose correct answer is "insufficient evidence"; some have in-scope look-alikes |
| cross-scope / cross-profile probes | atlas questions about borealis, profile-global questions about a project, beta asking about alpha's project |

Per seed (`size="full"`): 858 events (about 730 messages, 82 remembered statements, 3 corrections,
2 forgets, 5 episodes, 11 repository commits and snapshots, 14 day ends), 48 questions (10 expect
abstention) and about 100 ground-truth statement keys. The `small` size keeps the structure and drops most
filler and background (used by the tests).

Each question carries: `asked_at` (time t), the trusted scope (profile plus project, or profile-global),
gold requirements (each requirement lists alternative keys, any of which satisfies it), forbidden keys
(deleted, other scope, superseded, stale), distractor keys, and an expected-abstention flag.
`validate_corpus` checks that every timestamp is unique, that cited events come earlier, that every gold
key exists before t and is not entirely outdated at t, and that the abstention flag matches the category.

## 3. Ground truth: statement keys, not text

Each statement has a key such as `atlas.deploy@v2`. When an arm writes something, it records which engine
identifier carries which key, using identifiers the engine returned:

* archived message: the message id from `ingest_event`
* memory record: (record id, revision) from `remember` / `correct`
* episode: the record revision from `record_episode`
* repository observation: the git blob id of the file version (computed from the committed bytes and
  matched to the observation's `blob_range` source)

Every unit an arm returns resolves through this ledger to its key, origin event, time, profile and
project. Metrics compare keys, never free text. The one exception is the labelled extractive proxy.

## 4. Arms

| arm | ingests | retrieval handed to the model |
|---|---|---|
| A | nothing | nothing (empty context) |
| B | `remember` / `correct` / `forget` of explicit statements (sources: host-attested user actions) | `build_context(query='')`: approved hot memory, recency order, no history |
| C | B + every message (`ingest_event`); memories cite their source messages; forgetting also deletes the archived messages (`delete_source_archive=True`) | `build_context(query=q)` + `search_history(q, limit=5)` |
| D | C + `record_episode` (fake `VerificationAuthority` that resolves a receipt only once it has been issued) + `register_repository` / `snapshot_repository` against synthetic git repositories committed at simulated times | as C (episodes and observations reach the packet through their slices) |
| E | D + `FakeEmbeddingProvider` (local, 64 dimensions) registered as a provider. **Fake hash embeddings: contract check only, NOT semantic quality.** | as D, with the cosine list fused into retrieval |
| F | D + evaluated procedures in a host harness | **not executed (requires host evaluation runner and task execution)** |

State is isolated per arm and per repetition: each run has its own temporary root, its own random master
key and its own world repositories. State persists across all sessions within a run. All arms in one
repetition replay the same corpus (paired design).

Every question is answered with a trusted `AccessContext` that the runner builds from the question's
scope: the question's profile partition, grants for its project and that project's repository only, and
the READ operation. Nothing in the corpus can widen it.

## 5. Protocol and chronology

1. Events and questions are merged into one timeline sorted by time. At equal timestamps a question comes
   before an event, so an event at time t is never visible to a question at t. The engine's host clock is
   the simulated clock, which can only move forward.
2. **Leakage self-check** (`ChronologyGuard`, checked on every question). It verifies that events were
   applied in order, and that before a question at t exactly the events with time < t have been applied:
   no future event early, no past event skipped. It also checks that every returned unit traces to an
   event before t, and that engine-reported message times are before t. Any violation raises
   `ChronologyViolation` and aborts the run. A test injects a future message before a question and asserts
   the abort.
3. Per question, the arm retrieves once ("cold": the state has usually just changed, so projections and
   caches must be rebuilt). It then immediately repeats the same retrieval ("warm": caches and projections
   reused). Only the cold result is scored. A cold/warm mismatch is counted.
4. At each simulated day end, memory arms run `maintain()` per profile and record bytes on disk and the
   cumulative serving cost.
5. After the timeline, the engine is closed and reopened on the same store. The first and second retrieval
   of the last question per profile are timed (cold open, index warming, archive hydration). The store
   files are then scanned for every answer phrase in plaintext.

## 6. Metrics

**Evidence list.** Context-packet items in packet order are interleaved round-robin with history hits in
rank order. Scores from different channels are not comparable, the same reason the compiler round-robins
its slices. Over that list:

* `recall@k`: fraction of the question's requirements satisfied within the first k units (k = 5, 10,
  all).
* `precision@5`: units among the first 5 carrying a gold key, divided by 5 (standard, not rescaled for
  short lists).
* `MRR`: 1 / rank of the first gold unit.
* `multi_session_complete`: share of multi-requirement questions with every requirement covered.

These are computed on answerable questions only.

**Abstention (retrieval-level).** On missing-evidence, deletion, cross-scope and cross-profile questions,
the arm *abstains* when none of its units carries a candidate answer (gold, forbidden or distractor key).
`abstention_accuracy` is the share of those questions where it abstains. Arm A abstains trivially and is
not gated. `false_abstention_rate` is the share of answerable questions with no gold unit.
`engine_no_evidence_rate` is informational: how often the engine itself reports no relevant evidence.

**Harm.**

* `distracting_rate`: share of all returned units that carry a distractor, forbidden, deleted, superseded
  or stale key (excluding gold).
* `stale_rate`: superseded plus stale units only.
* `scope_leakage_count`: units whose origin (ledger) or engine-reported scope lies outside the question's
  trusted scope. This must be 0, and any leaked unit fails the run.
* `deletion_failures`: units carrying a statement forgotten before t.
* `correction_failures_context` and `correction_failures_history`: units carrying a statement superseded
  by a correction before t, in the context packet or in history hits.
* `correction_probe_pass_rate` and `deletion_probe_pass_rate`: the same, per probe question.

**Attribution.** For every gold unit in the context packet, the unit must cite a source that carries the
same statement: the source message, the correction message, the episode's attempt or receipt, or the
file version's blob.

**Budget and overhead.**

* `budget_compliance`: packet `token_count` <= allowance, and an independent re-estimate of the packet text
  with the engine's estimator is also <= allowance. The allowance is 800 tokens. No host tokenizer is
  configured, so counts are the conservative estimate (characters / 3.5 x 1.15).
* Overhead tokens: packet tokens plus the estimated tokens of the rendered history hits.

**Cost.** All stage latencies are wall clock (`time.perf_counter`):

* ingestion, per operation
* hydration: engine-internal projection and archive timers, plus the first retrieval after a reopen
* history retrieval and context build (cold and warm)
* maintenance

Cumulative serving cost = ingestion + maintenance + cold context builds + cold history searches. Amortized
cost = cumulative cost / questions. Git commits that change the synthetic world are timed separately and
excluded. Storage is the bytes of every file under the arm's store, sampled at each day end. Provider
cost is zero: no external provider is called.

Scores are rates and counts over synthetic questions. They are never probabilities of correctness.

## 7. Statistics

Each repetition uses its own seed (base seed + i) and produces one value per metric per arm. The report
gives the mean, sample standard deviation and a two-sided 95% Student-t interval of the mean (t table for
df <= 30, stdlib only). Pairwise arm differences (C-B, D-B, D-C, E-D) are computed per seed on the same
corpus and summarized the same way.

## 8. Rollout criteria (fixed before the reported run)

These criteria were fixed after a single harness debug run on one seed, used to find harness bugs, and
before the reported 5-repetition run. Changes made after that debug run:

* the "observed equal" check of C11 was given an explicit non-inferiority margin, because a strict `<=`
  on two rates that differ in the fifth decimal is noise;
* two more missing-evidence questions with in-scope look-alikes were added, which makes C8 harder to meet.

| id | arms | criterion | gate |
|---|---|---|---|
| C1 | A-E | Scope leakage = 0 in every run (any leaked unit fails the run) | hard |
| C2 | A-E | Chronology: 0 units from events at or after the question time | hard |
| C3 | B-E | Deletion propagation: 0 forgotten statements retrieved after the forget, and the forgotten record is gone for its own writer | hard |
| C4 | B-E | Correction propagation in curated memory: 0 corrected-away values in any context packet | hard |
| C5 | B-E | Correction propagation, strict (memory + raw history): 0 superseded statements in any channel | rollout gate for enabling history retrieval by default |
| C6 | B-E | Context budget compliance: 100% of packets within the allowance | hard |
| C7 | B-E | Nothing plaintext on disk: 0 answer phrases in store files | hard |
| C8 | B-E | Retrieval-level abstention accuracy >= 0.75 (mean over runs) | rollout |
| C9 | C, D vs B | Mean paired recall@5 difference >= 0 for C-B and for D-B | rollout |
| C10 | D vs C | D's recall (all units) on repository, stale-repository and episode questions > C's | rollout |
| C11 | D vs C | D's distracting/stale unit rate is not worse than C's by more than 0.01 (mean paired difference) | rollout |
| C12 | B-E | Source attribution: 100% of gold memory items cite a source of that statement | hard |
| C13 | E | E passes C1-C4, C6 and C7; E's quality numbers are not interpreted (fake embeddings) | contract |

"hard" criteria are invariants. Their failure fails the run, and the benchmark returns `passed=false`.
C5 encodes the literal requirement that after a correction only the corrected value is retrieved. Raw
history hits are archived transcripts, so a superseded statement can reappear there even though curated
memory is correct (C4). If C5 is not met for an arm, that arm should not ship history retrieval by
default until history hits are marked as superseded or dated evidence.

## 9. Results (measured run)

Run directory: `evals/results/2026-10-04-r5-seed20261004/` (`manifest.json`, `questions.jsonl`,
`report.md`).

* **Config:** 5 repetitions, seeds 20261004-20261008 (corpus hashes `a952a0bac02d`, `75fe3d03ea57`,
  `727ecce5ff93`, `417b3405f379`, `497c99e4a60a`), corpus size `full` (858 events, 48 questions of which
  10 expect abstention, 101 statement keys, 14 simulated days), arms A-E, token allowance 800, history
  k = 5, fake embedding dimensions 64. Total runtime 65 s.
* **Software:** locus_memory 0.1.0, CPython 3.14.6, SQLite 3.53.3 (FTS5), cryptography 50.0.0, git 2.50.1.
  The test suite also passes on CPython 3.10.22.
* **Hardware:** macOS 26.4.1 arm64, 12 CPUs. Other processes shared the machine during the run, so
  latency numbers are noisy.

### 9.1 Rollout criteria: 11 of 13 met; all hard invariants held

| id | result | observed |
|---|---|---|
| C1 scope leakage = 0 | met | 0 leaked units in every run of every arm |
| C2 chronology | met | 0 future units; the guard never fired |
| C3 deletion propagation | met | 0 forgotten statements retrieved; every forgotten record is gone for its writer |
| C4 correction propagation (curated memory) | met | 0 corrected-away values in any context packet |
| C5 correction propagation (strict, + raw history) | **not met** (C, D, E) | 13 superseded history hits in the worst run (mean 12.2 per run); B: 0 |
| C6 budget compliance | met | 100% of packets within 800 tokens (engine count and an independent re-estimate) |
| C7 nothing plaintext on disk | met | 0 answer phrases in any store file |
| C8 abstention accuracy >= 0.75 | **not met** (C, D, E: 0.70; B: 0.80) | see 9.3 |
| C9 recall@5 of C and D >= B | met | paired C-B = D-B = +0.579 [0.553, 0.605] |
| C10 D > C on repository/episode questions | met | recall (all units) 1.000 vs 0.083 |
| C11 D distracting rate not worse than C by > 0.01 | met | D-C = +0.003 [0.003, 0.003] |
| C12 source attribution 100% | met | 1.000 for B-E in every run |
| C13 E passes the safety gates | met | fake hash embeddings: contract check only, NOT semantic quality |

The scope-leak detector itself is tested. `tests/test_evaluation.py` runs a deliberately leaky arm that
retrieves with the whole profile's grants instead of the question's scope. The detector counts its leaked
units, fails that run, and marks C1 as not met. A second test injects a future message before a question;
the chronology guard aborts the run.

### 9.2 Usefulness (mean [95% t-interval] over 5 repetitions)

| metric | A | B | C | D | E (fake embeddings) |
|---|---|---|---|---|---|
| recall@5 | 0.000 | 0.053 [0.053, 0.053] | 0.632 [0.606, 0.657] | 0.632 [0.606, 0.657] | 0.632 [0.606, 0.657] |
| recall@10 | 0.000 | 0.158 [0.158, 0.158] | 0.684 [0.661, 0.707] | 0.684 [0.661, 0.707] | 0.684 [0.661, 0.707] |
| recall (all units) | 0.000 | 0.439 [0.412, 0.467] | 0.711 [0.711, 0.711] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| precision@5 | 0.000 | 0.011 | 0.164 [0.159, 0.170] | 0.164 [0.159, 0.170] | 0.164 [0.159, 0.170] |
| MRR | 0.000 | 0.068 [0.067, 0.070] | 0.335 [0.322, 0.349] | 0.351 [0.338, 0.365] | 0.351 [0.338, 0.365] |
| multi-session complete | 0.000 | 0.000 | 1.000 | 1.000 | 1.000 |
| false abstention (answerable, no gold unit) | 1.000 | 0.521 [0.494, 0.548] | 0.184 | 0.000 | 0.000 |
| extractive proxy (NOT task correctness) | 0.000 | 0.400 [0.373, 0.427] | 0.711 | 1.000 | 1.000 |

Recall (all units) by category, mean over runs:

| category | B | C | D |
|---|---|---|---|
| long-horizon (early background facts asked on days 11-13) | 0.371 | 1.000 | 1.000 |
| multi-session | 0.375 | 1.000 | 1.000 |
| project decision | 0.767 | 1.000 | 1.000 |
| repository / stale repository | 0.000 / 0.000 | 0.200 / 0.000 | 1.000 / 1.000 |
| episode (failed, interrupted, verified attempts) | 0.000 | 0.000 | 1.000 |

What this shows, on this corpus:

* **Hot memory alone (B) runs out of budget.** Roughly 30 approved records are visible to a project
  question (profile-global plus project-scoped), and the recency-ordered packet holds about 21 of them
  within 800 tokens. Old background facts
  and second facts of multi-session questions fall out of the packet.
* **Query-relevant context plus history retrieval (C)** recovers every statement that was ever said in
  chat (multi-session coverage 1.0). It cannot know repository state or verified task outcomes: the only
  repository answer it finds is an old chat remark.
* **D** adds the only sources of current repository facts (the observation of the changed file) and of
  host-verified task outcomes. Recall over all units reaches 1.0.
* **D's gain does not appear in recall@5/10.** The context compiler orders its slices with
  recency-ordered user preferences and profile facts first and the query-relevant project, repository and
  episode slices after them. The first gold unit for repository questions sits at median rank 15, and for
  episode questions at rank ~24. This is a property of packet order combined with the benchmark's
  round-robin evidence list. It matters to a host only if the host truncates the packet.
* **E** equals D on every quality metric at the reported precision. With fake hash embeddings this means
  nothing about semantic quality. E's deeper unit order also varies between fresh stores (see 10).

### 9.3 Harm

| metric | B | C | D | E |
|---|---|---|---|---|
| distracting/stale unit rate (of all units) | 0.003 | 0.025 [0.024, 0.026] | 0.028 [0.027, 0.029] | 0.028 |
| superseded statements in history hits (per run) | 0 | 12.2 [11.2, 13.2] | 12.2 | 12.2 |
| correction probes with no superseded unit | 1.000 | 0.000 | 0.000 | 0.000 |
| abstention accuracy (retrieval-level) | 0.800 | 0.700 | 0.700 | 0.700 |

* **Raw history re-surfaces corrected-away statements (C5).** `correct()` fixes the curated record (C4
  holds), but the archived message that stated the old value stays in the archive and matches later
  queries. In every run of C, D and E, all three correction probes also retrieved the superseded
  statement. Superseded messages also appear in unrelated questions that share words. The same mechanism
  surfaces the stale chat remark about the old atlas cache backend (0.5 stale units per stale-repository
  question in C and D).
* **Look-alikes defeat retrieval-level abstention (C8).** Every abstention failure comes from the three
  missing-evidence questions that have in-scope look-alikes: "atlas staging deploy target" surfaces the
  production deploy target, "borealis staging database" the production database, "cobalt staging deploy
  target" the production one. Every deletion, cross-scope and cross-profile probe abstained in every run
  of every arm. Lexical channels have no abstention threshold. The engine never reported
  INSUFFICIENT_EVIDENCE on an abstention question (rate 0.0), because history search falls back to
  any-term matching and packets always carry recency items. B scores higher only because one look-alike
  had fallen out of its recency packet.
* **Unverified claims stay retrievable.** The assistant's "rate limiting is done and all tests pass" chat
  claim was retrieved on both rate-limiting questions in every run of C and D. Only D also shows the
  episode whose outcome the engine derived from the host receipt: `failure` on day 4, `verified_success`
  after the second attempt.

### 9.4 Cost (wall clock; noisy shared machine; mean over runs)

| measure | B | C | D | E |
|---|---|---|---|---|
| context build p50 / p95 ms (cold) | 1.8 / 5.5 | 5.4 / 8.7 | 7.0 / 17.4 | 9.6 / 18.4 |
| context build p50 ms (warm repeat, cache hit) | 0.2 | 0.2 | 0.2 | 0.2 |
| history search p50 / p95 ms (cold) | - | 4.7 / 11.9 | 5.0 / 15.3 | 5.5 / 16.7 |
| history search p50 ms (warm repeat) | - | 0.4 | 0.4 | 0.4 |
| first context / first history search after reopen, ms (2 profiles) | 8.5 / - | 9.5 / 11.9 | 11.2 / 13.0 | 11.0 / 14.2 |
| ingestion total ms (cold, 14 days) | 218 | 505 | 3752 | 4286 |
| cumulative serving cost ms (ingest + maintenance + cold retrieval) | 359 | 1030 | 4475 | 5114 |
| amortized cost ms / question | 7.5 | 21.5 | 93.2 | 106.5 |
| context overhead tokens mean (max): packet + history hits | 698 (787) | 844 (981) | 852 (981) | 875 (984) |
| bytes on disk after close | 1.46 MB | 2.73 MB | 2.90 MB | 2.98 MB |
| bytes per corpus event | 1723 | 3218 | 3419 | 3519 |

Per-operation means (ms):

* `ingest_event` 0.5-0.6
* `remember` 1.8-2.5
* `correct` 0.9-1.4
* forget memory 4-9
* forget source message 1.5-2.4
* `record_episode` 1.6
* `register_repository` 140-165
* `snapshot_repository` 245-290

Repository snapshots run bounded git subprocesses, and they account for most of D's and E's cost, even
on these tiny repositories. Git commits that change the synthetic world (about 57 ms each) are excluded.
History hits add about 170 tokens on top of the 800-token packet. The engine does not budget them, so
a host must. Provider cost is zero: E's 40 embedding calls (138 texts) were local fakes.

### 9.5 Reading for rollout

* **The safety invariants hold for every arm on this corpus:** scope, chronology, deletion, curated
  correction, budget, encryption at rest and attribution (C1-C4, C6, C7, C12).
* **B** meets every criterion that applies to it, but under a realistic budget it misses about half of
  the answerable requirements.
* **C/D** are much more useful (paired recall@5 +0.58 over B), but they do not meet C5 or C8. Do not
  enable history retrieval by default until:
  * history hits whose message was superseded by a correction are suppressed or annotated (requested
    engine change below);
  * hosts present history hits as dated transcript evidence, not facts;
  * an abstention signal exists for look-alike questions.
* **D's repository observations and episodes** are the only correct source for current repository state
  and verified task outcomes here (C10). They do not raise the distracting rate beyond the margin (C11).
  Their cost is dominated by repository snapshots.
* **E** passes the safety gates; no quality claim is made.
* **F** was not executed.

## 10. Limitations

* **Synthetic and small.** Two fictional profiles, three projects, 14 days, 48 questions per seed. The
  structure is fixed and only values, wording, filler and timing vary with the seed, so between-seed
  variance is small and the t-intervals are narrow. Several have zero width because the metric does not
  depend on seeded values. These intervals understate real-world variance. Small synthetic fixtures are
  not proof of production gains.
* **Lexical-friendly wording.** Questions share key terms with the statements they target. Paraphrase
  robustness is not tested, and the fake embeddings are lexical by construction.
* **No model in the loop.** All metrics are retrieval-level. Abstention means "no candidate answer
  surfaced", not a model saying "insufficient evidence". Task correctness is not measured; the extractive
  proxy only shows the answer phrase was present.
* **Ordering convention.** recall@k, precision@k and MRR depend on the evidence-list convention (packet
  order, round-robin with history). Recall over all units does not.
* **Token counts** are the engine's conservative estimate, not a tokenizer.
* **Latency** is wall clock on one shared laptop with 5 samples. t-intervals on skewed latency data can
  be wide, and in a few cases extend below zero in the manifest. Treat them as indicative.
* **Repositories are tiny.** Snapshot cost here is mostly fixed git overhead, and says nothing about large
  repositories.
* **E is not reproducible unit by unit.** `FakeEmbeddingProvider` vectors are integer bucket counts, so
  exact cosine ties are common: in one probe, 39 positive cosines had only 20 distinct values. Retrieval
  breaks semantic ties by record id, which is random per store. E's deeper unit order therefore varies
  between fresh stores. Its aggregate metrics matched across reruns here, but that is not guaranteed.
  Arms A-D are reproducible unit by unit (tested).
* **Single reported configuration.** One machine and one Python version for the reported run; the tests
  pass on CPython 3.10 and 3.14.

## How to run

```bash
python -m locus_memory.evaluation --out evals/results/<name> --repetitions 5 --seed 20261004
python evals/generate_corpus.py --seed 20261004 --out /tmp/corpus.json   # inspect one corpus
pytest tests/test_evaluation.py
```
