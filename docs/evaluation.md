# Evaluation: offline chronological benchmark of cumulative usefulness

This document describes the benchmark in `src/locus_memory/evaluation/`, fixes the rollout criteria, and
then reports three measured runs on the same seeds: the first run (section 9, kept as written at the time
apart from marked corrections of factual slips), a re-run after the F3 engine changes (section 11, code
as of commit 967136e), and a final run on commit f02541e after four adversarial review rounds (section
12, the current code). The design and the criteria (sections 1 to 8) were written before the first run.
No criterion and no metric has been changed since. A few descriptions in sections 5, 6 and 8 were later
corrected to match what the code does; each correction is marked *corrected*. Measurements added after
the first run are labelled *exploratory* and never replace a criterion.

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
3. Per question, the arm retrieves once ("cold"). The state has usually just changed. For C-E the query
   changes with every question, so the context cache misses. The memory projection is rebuilt when a
   memory write has moved the partition generation, and the rebuild reuses every decrypted document
   whose id and revision are unchanged (`retrieval.service` module docstring). The history projection is
   topped up with the messages archived since the last search; it is discarded only when the deletion
   generation changes, which in this benchmark means after a forget (`history.archive` module
   docstring). There is one history projection per grant set and at most four per partition; no profile
   here asks from more than three scopes, so none is evicted. Arm B sends an empty query, so its request
   repeats. When no memory write has happened since the previous question with the same scope, B's
   "cold" build can be answered from the context cache, which is keyed on access, request and generation
   (`context.compiler.ContextCompiler.build`).
   In the final run, 115 of B's 240 cold builds took under 0.6 ms, as fast as a warm repeat, which is
   consistent with a cache hit. The arm then immediately repeats the same retrieval ("warm": caches and
   projections reused). Only the cold result is scored. A cold/warm mismatch is counted.
   *Corrected:* this item first said that on the cold path "projections and caches must be rebuilt".
   For the history projection, that was true only up to commit 967136e. Since review round 1 (commit
   5383d30), appends no longer discard it.
4. At each simulated day end, memory arms run `maintain()` per profile and record bytes on disk and the
   cumulative serving cost.
5. After the timeline, the engine is closed and reopened on the same store. The first and second retrieval
   of the last question per profile are timed (cold open, index warming, archive hydration). After the
   final close, the store files are scanned for every answer phrase of at least 8 bytes in plaintext
   (`arms.Arm.plaintext_hits` skips shorter phrases). In the reported seeds, every one of the 88-92
   distinct answer phrases per seed is 13 characters or longer, so none was skipped.

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
not gated. `false_abstention_rate` is the share of answerable questions on which the arm abstains, that
is, on which no returned unit carries a gold, forbidden or distractor key (`metrics.aggregate_run`).
*Corrected:* this sentence first said "answerable questions with no gold unit". That is a different
and larger share, because a question that surfaces only a distractor or a stale unit does not count as
an abstention. In arm C, 11 of the 38 answerable questions per run have no gold unit (0.289), while
the reported false-abstention rate is 0.184 (7 of 38), in all three runs. In arms B, D and E the two
shares are equal. `engine_no_evidence_rate` is informational: how often, on abstention questions, the
engine itself reports no relevant evidence. It exists for history arms only, because
`arms.Arm.engine_signalled_no_evidence` returns None for an arm without a query channel.

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

"hard" criteria are invariants. A failure of C1-C4, C6 or C7 fails the run (`runner._hard_failures`),
so the benchmark returns `passed=false` and `python -m locus_memory.evaluation` exits with a non-zero
status. In a memory arm, a returned unit that the ledger cannot attribute to the corpus also fails the
run. A chronology violation aborts the whole benchmark before any output is written
(`ChronologyViolation`). C12 is checked by `runner.evaluate_criteria` and reported as met or not met,
but it does not change `passed`. *Corrected:* this paragraph first said that the failure of any "hard"
criterion fails the run. That was not true of C12. The criterion itself is unchanged.

C5 encodes the literal requirement that after a correction only the corrected value is retrieved. Raw
history hits are archived transcripts, so a superseded statement can reappear there even though curated
memory is correct (C4). If C5 is not met for an arm, that arm should not ship history retrieval by
default until history hits are marked as superseded or dated evidence.

## 9. Results (first measured run, before the F3 changes)

This section reports the first run as it was written at the time. Section 11 reports the F3 re-run
(code as of 967136e). Section 12 reports the final run on the current code (f02541e). Its quality,
harm and criteria results are identical to section 11 question by question; only latency and storage
differ.

*Corrected later:* factual slips in this section have been fixed in place without changing any
measured value:
* the recency packet holds about 23 items, not 21 (9.2);
* the false-abstention row label (9.2; see section 6);
* the days of the rate-limiting episode (9.3);
* B's and E's cumulative serving cost are 358 and 5113 ms, not 359 and 5114 (9.4, rounding);
* the sentence on history-hit tokens (9.4);
* a dangling reference (9.5).

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
| false abstention (answerable, no candidate-answer unit) | 1.000 | 0.521 [0.494, 0.548] | 0.184 | 0.000 | 0.000 |
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
  question (profile-global plus project-scoped), and the recency-ordered packet holds about 23 of them
  within 800 tokens (16-24 items per project question, mean 23.0). Old background facts
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
  episode whose outcome the engine derived from the host receipt: `failure` after the day-3 attempt
  (seen by the day-4 question), and `verified_success` after the second attempt on day 7.

### 9.4 Cost (wall clock; noisy shared machine; mean over runs)

| measure | B | C | D | E |
|---|---|---|---|---|
| context build p50 / p95 ms (cold) | 1.8 / 5.5 | 5.4 / 8.7 | 7.0 / 17.4 | 9.6 / 18.4 |
| context build p50 ms (warm repeat, cache hit) | 0.2 | 0.2 | 0.2 | 0.2 |
| history search p50 / p95 ms (cold) | - | 4.7 / 11.9 | 5.0 / 15.3 | 5.5 / 16.7 |
| history search p50 ms (warm repeat) | - | 0.4 | 0.4 | 0.4 |
| first context / first history search after reopen, ms (2 profiles) | 8.5 / - | 9.5 / 11.9 | 11.2 / 13.0 | 11.0 / 14.2 |
| ingestion total ms (cold, 14 days) | 218 | 505 | 3752 | 4286 |
| cumulative serving cost ms (ingest + maintenance + cold retrieval) | 358 | 1030 | 4475 | 5113 |
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
History hits add about 170 tokens on top of the packet (the allowance is 800 tokens; C's packets average
about 674). The engine does not budget them, so a host must. Provider cost is zero: E's 40 embedding
calls (138 texts) were local fakes.

### 9.5 Reading for rollout

* **The safety invariants hold for every arm on this corpus:** scope, chronology, deletion, curated
  correction, budget, encryption at rest and attribution (C1-C4, C6, C7, C12).
* **B** meets every criterion that applies to it, but under a realistic budget it misses about half of
  the answerable requirements.
* **C/D** are much more useful (paired recall@5 +0.58 over B), but they do not meet C5 or C8. Do not
  enable history retrieval by default until:
  * history hits whose message was superseded by a correction are suppressed or annotated (a requested
    engine change, since implemented: see section 11.1 item 3);
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
* **E was not reproducible unit by unit in the first run (fixed in F3).** `FakeEmbeddingProvider` vectors
  are integer bucket counts, so exact cosine ties are common: in one probe, 39 positive cosines had only 20
  distinct values. In the first run, retrieval broke semantic ties by record id, which is random per store,
  so E's deeper unit order varied between fresh stores. Since F3, ties are broken by
  `ranking.tiebreak_key` (pinned, most recently updated, content, id), and all arms A-E are reproducible
  unit by unit (tested, including E).
* **The weak-match signals are lexical** (sections 11.1 and 11.2). A history hit counts as strong only
  when it contains every content term of the question; natural-language questions rarely share every
  content word with the statement that answers them, so on this corpus 97.6% of history hits are weak
  and history reports `INSUFFICIENT_EVIDENCE` on 92% of questions, answerable ones included. Look-alike
  statements are strong lexical matches. Neither signal is a calibrated relevance or abstention
  decision.
* **Single reported configuration.** One machine and one Python version per reported run; the tests
  pass on CPython 3.10 and 3.14.
* **Shared working tree for the re-run.** The F3 re-run used the working tree as it was, which also held
  other in-progress changes outside retrieval, history and context. Arm B's evidence and arms C/D's
  context packets were identical unit by unit to the first run, so the quality differences in section 11
  are attributable to the history-search change; cost and storage differences are not attributable.
* **Code provenance is inferred, not recorded.** The manifests record the package version (0.1.0) but no
  source commit. Which code each run measured is inferred from timestamps (section 12.1).
* **One final run.** The cost differences between the F3 and final runs (section 12.3) come from one
  run of each on a shared laptop, and several final-run intervals are wide. The run does not attribute
  any of them to a code change.

## 11. Re-run after the F3 engine changes (same seeds)

Run directory: `evals/results/2026-10-04-r5-seed20261004-f3/` (`manifest.json`, `questions.jsonl`,
`report.md`). The first run's directory is kept unchanged. This run measured the code as of commit
967136e. That predates the four adversarial review rounds, so section 11 no longer describes the
current engine's cost and storage. Its quality, harm, abstention and exploratory numbers are still the
current ones, because the final run reproduces every question row (section 12).

* **Config:** identical to section 9: 5 repetitions, seeds 20261004-20261008, the same five corpus hashes,
  corpus size `full`, arms A-E, token allowance 800, history k = 5, fake embedding dimensions 64. Runtime
  56 s. Same software versions and machine (CPython 3.14.6, SQLite 3.53.3, cryptography 50.0.0, git
  2.50.1); the test suite passes on CPython 3.10.22 and 3.14.6.
* **Unchanged:** the rollout criteria (section 8), the arms, the evidence list (section 6) and every
  metric used by a criterion. C5 and C8 are reported against their original definitions.
* **Added after the first run (exploratory, labelled as such in the report):** checks S5a, S5b and S8
  next to C5 and C8, and supplementary metrics (11.2, 11.5). History arms run one extra
  `search_history(..., exclude_corrected=True)` per question after the timed calls; it is excluded from
  the serving cost and writes nothing. The relevance-first order is derived from the same packet's item
  reasons (selection is identical; a test checks it against the engine's `order="relevance"`).
* **Changed implementation of an informational metric:** `engine_no_evidence_rate` keeps its meaning
  ("the engine itself reports no relevant evidence") but now reads the engine's new signals: the packet
  flag `weak_evidence_only` and history status `INSUFFICIENT_EVIDENCE` (before: no relevance-ranked
  packet item and no history hit). It is not used by any criterion.

### 11.1 What changed in the engine

1. **Semantic ties.** Equal cosine similarities are ordered by `ranking.tiebreak_key` (pinned, most
   recently updated, content, id) instead of the random record id. E's context packets differ from the
   first run in 122 of 240 question-runs (tie order only). E now equals D on recall@5, recall@10,
   recall over all units, precision@5, multi-session coverage, abstention, false abstention and the
   extractive proxy. MRR agrees to three decimals (0.352). E's distracting rate is 0.0003 lower (paired
   E-D -0.0003 [-0.0005, -0.0002]), and its relevance-first order differs (11.5).
2. **History match strength.** A strong hit must contain every *content* term of the query (stopwords
   such as "what", "is", "the" are no longer required; before, a message had to contain them), and the
   any-term stage matches content terms only (before, a shared "the" or "is" could rank a message). Strong
   hits come first; any-term hits fill the remaining slots and carry the flag `weak_match`. A search with
   no hit or only weak hits reports `INSUFFICIENT_EVIDENCE` and still returns the hits. On this corpus
   the history hits changed in 180 of 240 question-runs of each history arm; context packets of B, C and D
   did not change at all.
3. **Correction propagation in raw history.** `CoreService.correct` records, when content changes, the
   MESSAGE/SESSION sources of the corrected-away revision in the new table `history_corrections` (keyed
   source/session tokens and the record id; nothing plaintext). History hits from those messages carry
   `superseded_by_correction` when the caller may see the corrected memory; nothing is removed from the
   archive. `search_history(..., exclude_corrected=True)` is an opt-in filter. The context compiler's
   history inclusion always uses the filter. Rows go with the memory and are purged by forgetting of the
   source, session, scope or profile.
4. **Weak evidence.** Semantic-only retrieval hits carry `weak_match`; `SearchResult` is
   `INSUFFICIENT_EVIDENCE` when every hit is weak. Packets carry `flags`: `weak_evidence_only` (a query was
   given, but no item was selected by a lexical/exact match in a query-relevant slice) and
   `history_weak_only`. Coverage and status are not changed by these flags.
5. **Host API.** `ContextRequest.max_items` (cap in selection order), `ContextRequest.order="relevance"`,
   and `locus_memory.context.is_context_block` / `CONTEXT_WRAPPER_OPEN`. The pre-registered arms use the
   defaults, so these do not affect the criteria.

### 11.2 Criteria before and after: 11 of 13 met in both runs; all hard invariants held

| id | first run (section 9) | re-run (F3) | result |
|---|---|---|---|
| C1-C4, C6, C7, C12, C13 | met | met (unchanged observations) | met |
| C5 correction propagation, strict | C/D/E: 13 superseded history hits in the worst run (mean 12.2) | C/D/E: 9 in the worst run (mean 7.4 [6.3, 8.5]) | **not met** |
| C8 abstention accuracy >= 0.75 | B 0.80; C/D/E 0.70 | B 0.80; C/D/E 0.70 | **not met** |
| C9 recall@5 C, D >= B | paired +0.579 | paired +0.579 [0.553, 0.605] | met |
| C10 D > C on repository/episode | 1.000 vs 0.083 | 1.000 vs 0.083 | met |
| C11 D-C distracting rate <= 0.01 | +0.003 | +0.003 [0.002, 0.003] | met |

**Why C5 is still not met.** The pre-registered arms call `search_history` with its defaults, and the
engine, by design, annotates superseded messages instead of removing them (they are the user's
transcript; the filter is opt-in). The drop from 12.2 to 7.4 superseded hits per run comes from change 2,
not from the annotation: before, superseded messages also matched unrelated questions through shared
stopwords. Over the five runs of C the superseded hits fell from cross-scope 4, deletion 2,
stale-repository 2 and long-horizon 5 to 0 each, from missing-evidence 15 to 11, correction 20 to 16 and
multi-session 13 to 10. Correction probes without a superseded unit rose from 0.000 to 0.267
[0.082, 0.452] for the same reason.

What the annotation and filter do (exploratory, not pre-registered):

| check | C | D | E |
|---|---|---|---|
| S5a superseded history hits carrying `superseded_by_correction` | 100% (7.4 of 7.4 per run) | 100% | 100% |
| S5b superseded units with `exclude_corrected=True` (context + history, worst run) | 0 | 0 | 0 |
| correction probes passed with the filter | 1.000 | 1.000 | 1.000 |
| recall@5 with the filter (without: 0.632) | 0.650 [0.631, 0.669] | 0.650 | 0.650 |
| recall (all units) with the filter | 0.711 (unchanged) | 1.000 (unchanged) | 1.000 (unchanged) |
| distracting/stale unit rate with the filter (without: 0.022 / 0.025 / 0.024) | 0.016 | 0.018 | 0.018 |
| abstention accuracy with the filter | 0.700 | 0.700 | 0.700 |

Whether C5 was mis-specified: as written, C5 counts every superseded statement that is retrieved, whether
or not the engine marks it, so only filtering can meet it. Section 8 itself named marking ("until history
hits are marked as superseded or dated evidence") as the condition for shipping history retrieval by
default, which suggests the gate was meant to accept marked hits. We still report against the original
definition: **not met**. S5a shows the marking condition of section 8 holds on this corpus; S5b shows
that a host that opts into the filter meets the strict C5 here, at no recall cost.

**Why C8 is still not met.** The three failing questions are the same look-alikes as in section 9.3
("atlas staging deploy target" surfaces the production deploy target, and so on). Those are strong lexical
matches by the engine's definitions: they contain most query terms, and only history's all-content-terms
rule marks them weak, together with nearly every other history hit. The new signals do not change
which units are retrieved, and C8 is defined on retrieved units. C8 is not mis-specified: a signal can
only move it if the host acts on it, and S8 shows what happens when it does.

| signal (exploratory) | C | D | E |
|---|---|---|---|
| engine no-evidence signal on abstention questions (first run: 0.000) | 0.300 | 0.300 | 0.300 |
| engine no-evidence signal on answerable questions (false alarms) | 0.184 | 0.174 [0.156, 0.192] | 0.174 |
| S8 abstention accuracy when the arm also abstains on the signal | 0.700 | 0.700 | 0.700 |
| false abstention when the arm also abstains on the signal (without: 0.184 / 0.000 / 0.000) | 0.368 | 0.174 | 0.174 |
| history hits flagged `weak_match` | 97.6% | 97.6% | 97.6% |
| history searches reporting `INSUFFICIENT_EVIDENCE` | 92% (221 of 240) | 92% | 92% |

The signal fires on the same 3 of the 10 abstention questions in every run (the profile-global
cross-scope and deletion probes, and the atlas-scoped question about the borealis frontend), all of which
already abstained. It also fires on 7 of the 38 answerable questions in C (6-7 in D and E): profile-global
questions about preferences, commit style, the editor, the corrected test runner and the weather city,
whose answers the packet carries in its recency-ordered, non-query slices. As an abstention gate it costs
answerable questions and gains nothing here: **it is not a usable abstention signal on this corpus.** It is
an honest "no lexical evidence" label, not a relevance decision.

### 11.3 Usefulness and harm before and after (mean [95% t-interval] over 5 repetitions)

| metric | C before | C after | D before | D after | E before | E after |
|---|---|---|---|---|---|---|
| recall@5 | 0.632 | 0.632 [0.606, 0.657] | 0.632 | 0.632 | 0.632 | 0.632 |
| recall@10 | 0.684 | 0.689 [0.675, 0.704] | 0.684 | 0.689 | 0.684 | 0.689 |
| recall (all units) | 0.711 | 0.711 | 1.000 | 1.000 | 1.000 | 1.000 |
| precision@5 | 0.164 | 0.160 [0.154, 0.166] | 0.164 | 0.160 | 0.164 | 0.160 |
| MRR | 0.335 | 0.336 [0.320, 0.351] | 0.351 | 0.352 | 0.351 | 0.352 |
| abstention accuracy | 0.700 | 0.700 | 0.700 | 0.700 | 0.700 | 0.700 |
| false abstention | 0.184 | 0.184 | 0.000 | 0.000 | 0.000 | 0.000 |
| distracting/stale unit rate | 0.025 | 0.022 [0.021, 0.023] | 0.028 | 0.025 | 0.028 | 0.024 |
| stale + superseded unit rate | 0.012 | 0.008 [0.007, 0.009] | 0.013 | 0.009 | 0.013 | 0.009 |
| superseded statements in history hits per run | 12.2 | 7.4 [6.3, 8.5] | 12.2 | 7.4 | 12.2 | 7.4 |

B is unchanged unit by unit (recall@5 0.053, recall (all units) 0.439, abstention 0.800). The history
change is roughly neutral for usefulness (recall@5 equal, recall@10 +0.005, precision@5 -0.004) and
reduces harm (distracting rate -0.003, superseded history hits -40%).

### 11.4 Cost before and after (code as of 967136e; wall clock; noisy shared machine; mean over runs)

"After" here is the cost at commit 967136e. For the current engine's cost and storage, see section 12.3.

| measure | C before | C after | D before | D after | E before | E after |
|---|---|---|---|---|---|---|
| context build p50 / p95 ms (cold) | 5.4 / 8.7 | 5.0 / 8.0 | 7.0 / 17.4 | 6.0 / 9.4 | 9.6 / 18.4 | 7.6 / 11.8 |
| history search p50 / p95 ms (cold) | 4.7 / 11.9 | 4.5 / 10.8 | 5.0 / 15.3 | 4.5 / 10.9 | 5.5 / 16.7 | 4.6 / 10.5 |
| `correct` mean ms | 1.07 | 0.99 | 1.35 | 1.17 | 1.11 | 1.10 |
| cumulative serving cost ms | 1030 | 954 | 4475 | 3944 | 5113 | 4118 |
| context overhead tokens mean (max) | 844 (981) | 814 (983) | 852 (981) | 822 (977) | 875 (984) | 845 (984) |
| bytes on disk after close | 2.73 MB | 2.77 MB | 2.90 MB | 2.95 MB | 2.98 MB | 3.03 MB |

No latency regression is visible; the differences are within the noise of a shared laptop (the first run
had wider intervals). History hits cost about 30 fewer tokens per question because fewer filler messages
match. Every store grew by about 40 KB, B included (1.46 MB to 1.50 MB). 16 KB of that are the empty pages
of the new table and its indexes (4 pages of 4 KiB). The rest is not attributable from this run (see
section 10, shared working tree). The correction hook writes one row per cited message or session.

### 11.5 Packet order (exploratory)

By default, **packet order is not relevance order**: slices are rendered in request order, and the default
slices put recency-ordered preferences and profile facts first. With `order="relevance"` (same
selection, strong query matches first by relevance rank), the evidence list changes as follows:

| metric | C | D | E |
|---|---|---|---|
| recall@5, default order | 0.632 | 0.632 | 0.632 |
| recall@5, relevance-first order | 0.655 [0.637, 0.673] | 0.945 [0.927, 0.963] | 0.942 [0.917, 0.967] |
| MRR, default order | 0.336 | 0.352 | 0.352 |
| MRR, relevance-first order | 0.593 [0.573, 0.612] | 0.888 [0.869, 0.907] | 0.846 [0.819, 0.874] |

This confirms section 9.2: D's repository and episode gains were hidden by packet order, not missing
from the packet. It matters to a host that truncates the packet or reads it top-down. Recall over all
units does not change.

### 11.6 Reading for rollout (F3 code; conclusions re-confirmed by the final run, section 12)

* The safety invariants still hold for every arm (C1-C4, C6, C7, C12); E is now reproducible unit by unit.
* **C5 and C8 remain not met** under the pre-registered protocol.
* History retrieval can be enabled by default only if the host either passes `exclude_corrected=True`
  (strict C5 holds on this corpus, S5b) or presents `superseded_by_correction` hits as outdated, dated
  transcript evidence (the marking condition of section 8 holds, S5a). The context compiler already
  filters.
* There is still no usable abstention signal for look-alike questions. `weak_match`,
  `INSUFFICIENT_EVIDENCE` and `weak_evidence_only` say "no lexical evidence"; they fire on many
  answerable questions and miss look-alikes. Hosts must not treat them as "the answer is absent". A
  calibrated relevance model or real semantic embeddings, evaluated against C8, are the next step; they
  were not tried here.
* Hosts that inject the packet top-down, or cap it (`max_items`), should consider `order="relevance"`
  (11.5).

## 12. Final run on the current code (commit f02541e, same seeds)

Run directory: `evals/results/2026-10-04-r5-seed20261004-final/` (`manifest.json`, `questions.jsonl`,
`report.md`). The two earlier run directories are kept unchanged.

* **Config:** identical to sections 9 and 11:
  * 5 repetitions, seeds 20261004-20261008, the same five corpus hashes, corpus size `full`;
  * arms A-E, token allowance 800, history k = 5, fake embedding dimensions 64.

  Runtime 59.4 s; `passed=true`.
* **Software and machine:** the same as sections 9 and 11:
  * locus_memory 0.1.0, CPython 3.14.6, SQLite 3.53.3 (FTS5), cryptography 50.0.0, git 2.50.1;
  * macOS 26.4.1 arm64, 12 CPUs, shared with other processes.

  At f02541e, the package test suite has 1495 tests and passes on CPython 3.14.6 and 3.10.22
  (`python -m pytest -o addopts="" -q`).
* **Unchanged:** the rollout criteria, the arms, the evidence list, every metric and the exploratory
  checks. The benchmark code (`src/locus_memory/evaluation/`) is identical at 967136e and f02541e.

### 12.1 Which code each run measured

The manifests record the package version (0.1.0) but no source commit. The code is inferred from
timestamps:

| run | created (UTC) | code |
|---|---|---|
| first (section 9) | 2026-10-04 07:05:39 | working tree 26 min before commit 3383b40 (07:31:19), which added the benchmark and this run |
| F3 (section 11) | 2026-10-04 08:01:08 | working tree 43 min before commit 967136e (08:43:55), which committed the F3 changes and this run; whether the tree changed in between is not recorded |
| final (this section) | 2026-10-04 21:27:15 | commit f02541e (21:26:32), committed 43 s before the run |

The four adversarial review rounds are commits 5383d30, a1706f3, 219fd15 and f02541e. All of them
come after the F3 run. When this section was written, no file under `src/` or `tests/` differed from
f02541e. The next commit, 1eb14e6, added this run's directory and changed no source or test file.

### 12.2 Quality, harm and criteria: identical to the F3 run, question by question

All 1200 rows of the final run's `questions.jsonl` (5 arms x 5 seeds x 48 questions) are identical to
the F3 run in every field except the four latencies (`context_ms`, `context_warm_ms`, `history_ms`,
`history_warm_ms`). That includes unit keys, unit flags, packet flags, history status, packet tokens and
all scores. Every quality, harm, abstention and exploratory number in sections 11.2, 11.3 and 11.5 is
therefore also the current number. On this corpus, the review-round fixes changed no retrieved unit.

Most of the paths the review rounds fixed are not exercised here. The arms call no migration,
rollback, export or interchange API (`evaluation.arms`), and the corpus contains two forgets per seed
and no tampering. Those fixes are covered by the regression tests, not by this benchmark.

| id | result | observed in the final run |
|---|---|---|
| C1-C4, C6, C7, C12, C13 | met | the same observations as in 9.1 and 11.2: 0 leaked, future, forgotten or corrected-away units; 100% budget compliance; 0 plaintext hits; attribution 1.000 for B-E |
| C5 correction propagation, strict | **not met** | C/D/E: 9 superseded history hits in the worst run (mean 7.4 [6.29, 8.51]); B: 0 |
| C8 abstention accuracy >= 0.75 | **not met** | B 0.80; C/D/E 0.70 |
| C9 recall@5 C, D >= B | met | paired C-B = D-B = +0.579 [0.553, 0.605] |
| C10 D > C on repository/episode | met | recall (all units) 1.000 vs 0.083 |
| C11 D-C distracting rate <= 0.01 | met | +0.003 [0.002, 0.003] |

Rollout criteria: 11 of 13 met, and every hard invariant held.

Supplementary checks (exploratory, not pre-registered):
* S5a holds.
* S5b holds.
* S8 does not hold: abstention is 0.700 for C, D and E, and false abstention when the arm also abstains
  on the signal is 0.368 / 0.174 / 0.174.

### 12.3 Cost and storage: first run, F3 run, final run

All values are wall-clock means over runs on a noisy, shared machine. Each cell reads
first run → F3 run → final run.

| measure | B | C | D | E |
|---|---|---|---|---|
| context build p50 / p95 ms (cold) | 1.8/5.5 → 1.6/4.2 → 1.7/4.9 | 5.4/8.7 → 5.0/8.0 → 5.5/8.3 | 7.0/17.4 → 6.0/9.4 → 6.7/10.6 | 9.6/18.4 → 7.6/11.8 → 8.9/17.8 |
| history search p50 / p95 ms (cold) | - | 4.7/11.9 → 4.5/10.8 → 1.7/7.9 | 5.0/15.3 → 4.5/10.9 → 1.7/7.9 | 5.5/16.7 → 4.6/10.5 → 1.7/8.6 |
| history search p50 ms (warm repeat) | - | 0.4 → 0.5 → 0.6 | 0.4 → 0.5 → 0.6 | 0.4 → 0.5 → 0.6 |
| history search p95 ms, engine timer (incl. hydration) | - | 11.2 → 9.4 → 3.8 | 12.5 → 9.4 → 4.1 | 13.2 → 9.4 → 4.8 |
| memory projection build p95 ms, engine timer | - | 2.9 → 2.4 → 2.9 | 5.0 → 2.9 → 5.4 | 4.1 → 2.9 → 5.2 |
| ingestion total ms | 218 → 172 → 203 | 505 → 451 → 525 | 3752 → 3410 → 3716 | 4286 → 3503 → 3726 |
| maintenance total ms | 31.2 → 15.5 → 25.5 | 14.0 → 17.5 → 29.5 | 19.0 → 14.8 → 36.8 | 26.8 → 14.6 → 36.0 |
| first context after reopen ms | 8.5 → 7.7 → 9.5 | 9.5 → 8.6 → 10.6 | 11.2 → 8.6 → 13.4 | 11.0 → 8.1 → 12.1 |
| first history search after reopen ms | - | 11.9 → 12.0 → 12.2 | 13.0 → 11.8 → 13.2 | 14.2 → 11.9 → 13.8 |
| cumulative serving cost ms | 358 → 270 → 323 | 1030 → 954 → 927 | 4475 → 3944 → 4191 | 5113 → 4118 → 4339 |
| amortized cost ms / question | 7.5 → 5.6 → 6.7 | 21.5 → 19.9 → 19.3 | 93.2 → 82.2 → 87.3 | 106.5 → 85.8 → 90.4 |
| context overhead tokens mean (max) | 698 (787), unchanged | 844 (981) → 814 (983) → 814 (983) | 852 (981) → 822 (977) → 822 (977) | 875 (984) → 845 (984) → 845 (984) |
| bytes on disk after close | 1.46 → 1.50 → 1.72 MB | 2.73 → 2.77 → 2.98 MB | 2.90 → 2.95 → 3.15 MB | 2.98 → 3.03 → 3.24 MB |
| bytes per corpus event | 1723 → 1771 → 2033 | 3218 → 3262 → 3509 | 3419 → 3475 → 3710 | 3519 → 3574 → 3821 |

Per-operation means, F3 run → final run (ms):

| operation | F3 run | final run |
|---|---|---|
| `ingest_event` | 0.39-0.41 | 0.49-0.52 |
| `remember` | 1.6-2.0 | 1.5-2.3 |
| `correct` | 0.93-1.17 | 1.07-1.42 (C 1.42, D 1.23, E 1.19) |
| forget memory | 4.0-6.3 | 7.7-10.5 |
| forget source message | 1.4-1.5 | 4.0-4.4 |
| `record_episode` | 1.3 | E 1.6; D 4.7, of which one run averaged 15.2 ms and the other four 1.5-3.4 ms |
| `register_repository` | 139-145 | 147 |
| `snapshot_repository` | 232-238 | 248 |

Repository registration and snapshots still dominate D's and E's cost: in the final run they take
about 3.2 s of D's 4.2 s and of E's 4.3 s cumulative serving cost. Overhead tokens and packet tokens
are unchanged since F3, as 12.2 implies.

**The run is noisy.** Several final-run intervals are wide:
* E's cold context p95 is 17.8 [3.9, 31.7] ms;
* D's projection-build p95 is 5.4 [0.4, 10.4] ms;
* D's maintenance total is 36.8 [15.9, 57.7] ms.

The git commits that change the synthetic world are excluded from the serving cost and run no engine
code. They also took longer than in the F3 run: 51-54 ms per commit, against 46-48 ms. That points to
a slower machine state during the final run, but it does not prove one.

**Storage split.** The per-day growth table in `report.md` counts database files without their -wal
and -shm journals, and that split is not comparable between the runs. At the end of day 0, B's main
files hold 1.07 MB in the final run, against 16 KB in the F3 run. With journals, the totals are 3.48 MB
and 3.23 MB. So in the final run, more of the data leaves the WAL during the run. The cause is not
measured.

### 12.4 What the cost differences can and cannot be attributed to

The run attributes none of the cost or storage changes to a code change. Where a verified code change
between 967136e and f02541e is consistent with a difference, it is named below, but none was measured
as a cause:

* **History search is faster.** Cold p50 is about 1.7 ms against 4.5 ms, and the engine-timer p95 is
  3.8-4.8 ms against 9.4 ms. Since review round 1 (5383d30), appends no longer discard a history
  projection. Messages archived after a build are topped up incrementally, and a projection is
  discarded only when the deletion generation changes (`history.archive` module docstring). At
  967136e, a projection was "discarded whenever the partition generation changes". The warm repeat
  became slightly slower (p50 0.5 → 0.6 ms); this run does not explain why.
* **Stores are about 0.2 MB larger per arm** (B +0.22 MB, C +0.21 MB, D +0.20 MB, E +0.21 MB). Between
  967136e and f02541e, `storage/schema.py` gained 8 tables and 2 indexes:
  * tables `forget_outcomes`, `tombstone_aliases`, `idempotency_records`, `migration_forgets`,
    `migration_cutover_ids`, `migration_recovery_ids`, `migration_scope_covered` and `repo_derived`;
  * indexes `idempotency_records_record` and `repo_derived_path`.

  How much of the growth these account for is not measured; the rest is unattributed.
* **Forgets are slower.** `forgetting` changed in all four review rounds, and `storage.partition` and
  `storage.db` changed with it. The changes include:
  * cascades and tombstones;
  * the post-purge checkpoint. It now covers the deletion ledger's WAL as well as the main database,
    and it retries a busy checkpoint, recording `pending_purge_checkpoint` when it cannot complete
    (`storage.partition.Partition.flush_purged`). At 967136e, `forgetting` checkpointed only the main
    database (`Database.checkpoint`).

  The cause of the slowdown is not measured.
* **Maintenance is slower:** 15-17 ms per run in F3, 25-37 ms in the final run. The totals are small
  and have wide intervals, and this run does not attribute the change.

### 12.5 Reading for rollout (current code)

* Every conclusion of 11.6 holds unchanged for the current code, because every retrieved unit is the
  same:
  * the safety invariants hold for every arm (C1-C4, C6, C7, C12);
  * C5 and C8 are not met under the pre-registered protocol;
  * history retrieval can be enabled by default only if the host either filters with
    `exclude_corrected=True` or presents `superseded_by_correction` hits as outdated, dated transcript
    evidence;
  * there is no usable abstention signal for look-alike questions;
  * hosts that read the packet top-down or cap it should consider `order="relevance"`.
* Cost moved in both directions:
  * Cold history search is cheaper.
  * Forgets, maintenance and storage are more expensive.
  * Against the F3 run, cumulative serving cost changed by -3% in C, +6% in D, +5% in E and +20% in B
    (270 → 323 ms).
  * On this corpus, none of these changes affects the rollout reading.
* E passes the safety gates; no quality claim is made. F was not executed.

## How to run

```bash
python -m locus_memory.evaluation --out evals/results/<name> --repetitions 5 --seed 20261004
python evals/generate_corpus.py --seed 20261004 --out /tmp/corpus.json   # inspect one corpus
pytest tests/test_evaluation.py
```

Options of `python -m locus_memory.evaluation` (`locus_memory.evaluation.__main__.main`):

| option | meaning | default |
|---|---|---|
| `--out` | output directory; required | none |
| `--repetitions` | number of repetitions | 5 |
| `--seed` | base seed | 20261004 |
| `--arms` | comma-separated subset of A-E; F is never run | A,B,C,D,E |
| `--size` | `full` or `small` | `full` |
| `--token-allowance` | context token allowance | 800 |
| `--history-k` | history hits per question | 5 |

The exit status is non-zero when a run failed (section 8). A chronology violation aborts with a
traceback and writes no outputs.

`report.md` lists the pre-registered criteria first, then the exploratory checks (S5a, S5b, S8) and the
exploratory measurements in separate, labelled tables. The C8 row of `report.md` (text from
`runner.CRITERIA`) says "on missing-evidence questions". The metric actually covers all 10 abstention
questions per seed (5 missing-evidence, 2 cross-scope, 2 deletion, 1 cross-profile), as section 6
defines it.
