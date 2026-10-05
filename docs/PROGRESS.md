# Progress

Current release evidence is recorded in [0.3.0 validation](release-0.3.0.md).
The user authorized release verification on 2026-10-05, superseding the earlier
pause for RAM usage. Existing canonical cutovers were not repeated.

## Historical 0.1.0 implementation record

This is the state of the work on 2026-10-04, written so that a later session can pick it up
without this session's context. The governing specification is restated as numbered
requirements in [requirements.md](requirements.md). Section 25 of the specification sets the
milestones and Gate A (R25.1), and R25.2 asks for progress and test evidence to be kept in the
repository for later sessions; this file is that record.

**Nothing was published, pushed, migrated for real, or enabled in the real Locus checkout.**
Package version `0.1.0` exists only in this local repository. The host integration exists as
patch files in [`handoff/locus/`](../handoff/locus/README.md), and those patches were applied
and tested only in disposable copies of the Locus tree.

**State at package commit `f02541e` (2026-10-04, 17:26).** Four adversarial review rounds found
and fixed 63 + 29 + 21 + 20 = 133 reproduced defects, each with regression tests (section 2.4):

* round 1 (`5383d30`) in `tests/test_review_group1.py`-`test_review_group3.py` and
  `tests/test_db_close.py`;
* round 2 (`a1706f3`) in `tests/test_review_round2_batch1.py`-`batch4.py`;
* round 3 (`219fd15`) in `tests/test_review_round3_batch1.py`-`batch3.py`;
* round 4 (`f02541e`) in `tests/test_review_round4_batch1.py`-`batch3.py`.

The package suite has 1495 tests. `python -m pytest -o addopts="" -q` passed all 1495 on CPython
3.14.6 and 3.10.22, and `ruff check src tests` is clean. The next commit, `1eb14e6` (17:46), added
the final evaluation run and the final host evidence in the handoff README; it changed no file
under `src/` or `tests/`. Run `git log --oneline` for anything later, and see section 4 for the
commands.

## 1. Inspected repositories and runtimes

| What | Where | Revision | Access |
|---|---|---|---|
| Locus (host) | `<locus-checkout>` | `b332e4554e72956f949506207ffa034749360d79` | read-only; never modified |
| Agent Dispatcher (`agent-skills`) | `<agent-dispatcher-checkout>` | `d68446fe33c4e2162c1eb4d4d15bb663a3040888`, plus 2 uncommitted user edits | read-only |
| langgraph-workflow | `<langgraph-workflow-checkout>` | `52799242a53d80ed067797d0cbb6e1c83363214e` | read-only |

* **Bundled Locus runtime:** `/Applications/Locus.app/Contents/Resources/AgentRuntime`. It is
  CPython 3.14.6 with SQLite 3.53.1 (FTS5 available) and `cryptography` 50.0.0 in its
  `site-packages`. It does not include pytest. The package's own environments use other SQLite
  builds: `.venv` (Homebrew CPython 3.14.6) has SQLite 3.53.3 and `.venv310` (CPython 3.10.22)
  has 3.53.1. The package suite and every evaluation run used these environments; the evaluation
  ran on `.venv` (SQLite 3.53.3), not on the bundled runtime. The bundled runtime was used only
  for the host-copy tests (section 2.3) and the `pip --target` checks (section 2.2).
* **Package:** `requires-python = ">=3.10"`. Its only runtime dependency is `cryptography>=42`,
  which the Locus lock pin `cryptography==50.0.0` satisfies. It is tested on CPython 3.10.22 and
  3.14.6 only. CPython 3.11, 3.12 and 3.13 are allowed by `requires-python` but have not been
  tested (R24.3 asks to test declared Python support; this is an open gap).
* **Audit outputs:** [locus-compatibility.md](locus-compatibility.md) (formats, call sites and
  defects D1-D61) and [ownership-and-extraction.md](ownership-and-extraction.md) (ownership
  matrix, with the current extraction status at the top).
* **Status and evidence documents:** [requirements-checklist.md](requirements-checklist.md)
  (each requirement with its status and evidence) and [feature-matrix.md](feature-matrix.md)
  (the implemented, experimental, contract-only and deferred classification that R24.5 asks
  for).
* **Design and integration documents:** [architecture.md](architecture.md),
  [storage-and-encryption.md](storage-and-encryption.md),
  [security-and-privacy.md](security-and-privacy.md),
  [migrations-and-rollback.md](migrations-and-rollback.md),
  [integration-locus.md](integration-locus.md),
  [integration-workflows.md](integration-workflows.md) and
  [repository-interchange.md](repository-interchange.md).

## 2. Milestones and Gate A

R25.1 names milestones 1-5 for the package and refers to later (host) milestones without
numbering them in this repository. Gate A requires a tested standalone offline path. Without
authorized host writes, R25.1 says to stop at Gate A with a full handoff and to report the later
milestones as not executed. This repository does not contain the specification's milestone
titles, so the tables below do not assign individual work items to individual milestone numbers.

| Milestone | Status |
|---|---|
| Milestones 1-5 (package) | **Executed in the package**, in this repository (section 2.1). |
| Gate A (standalone offline path tested) | **Met** (section 2.2). |
| Later (host) milestones | **Not executed** (no authorized host writes, R25.1). A handoff was prepared instead: two patches, applied and tested only in disposable `git archive` copies of Locus `b332e455` (section 2.3). |

### 2.1 What milestones 1-5 delivered (package)

| Area | Main modules | Test evidence |
|---|---|---|
| Typed, versioned models; access context; validation; typed errors. Boolean fields accept only real booleans (`validation.check_bool`: `"false"` is refused, never coerced), mapping nesting is bounded (`validation.MAX_MAPPING_DEPTH` = 32), and a forget policy that is not a `ForgetPolicy` is refused before anything is recorded (`forgetting._check_request`) | `models`, `validation`, `errors`, `policy` | `tests/test_models.py`, `tests/test_core.py::test_scoped_records_are_visible_only_with_every_grant`, `tests/test_review_round3_batch3.py::test_api2_boolean_fields_accept_only_real_booleans`, `tests/test_review_round2_batch4.py::test_rob4_a_too_deep_mapping_is_a_validation_error`, `tests/test_review_round3_batch1.py::test_api1_a_non_policy_is_refused_before_anything_is_recorded` |
| Envelope encryption: host key provider, per-partition data keys, wrong or missing key fails closed | `crypto.PartitionKeyring`, `crypto.FileKeyProvider`, `crypto.StaticKeyProvider` | `tests/test_crypto.py`, `tests/test_storage.py::test_wrong_key_is_refused_and_never_replaced` |
| Encrypted partition storage, schema migrations, deletion ledger. Plaintext metadata that disagrees with the authenticated payload (lifecycle, kind, revision, scope token, the `expires_at`/`valid_from`/`valid_until`/`pinned` columns, the scope-index rows) fails closed with `IntegrityError` (`storage.records.RecordStore._decode`, `RecordStore.authorized`). `Database.close` never closes another live thread's connection under it: that thread's next access raises (`storage.db.Database.close`) | `storage.partition.Partition`, `storage.schema`, `storage.ledger.DeletionLedger`, `storage.records.RecordStore`, `storage.db.Database` | `tests/test_storage.py`, `tests/test_concurrency.py`, `tests/test_db_close.py`, `tests/test_review_round4_batch3.py::test_tamper6_relabelled_time_columns_are_never_served`, `tests/test_review_round4_batch1.py::test_tamper2_a_stripped_scope_index_fails_closed_instead_of_serving` |
| Lifecycle (remember, propose, approve, reject, correct, supersede, expire). Correcting or superseding a record, or the end of its validity or retention, invalidates the records derived from it at every level | `core.CoreService` | `tests/test_core.py::test_candidates_are_never_served_or_silently_approved`, `tests/test_review_round4_batch2.py::test_eg4_correction_invalidates_every_level`, `::test_eg4_supersede_invalidates_every_level` |
| Forgetting with tombstones, derived-state purge, and ledger replay after a crash or after a restore of the main database (a joint restore of database and ledger needs a host `storage.ledger.LedgerMirror`; section 5.3). Since review rounds 3 and 4: which ledger entries are replayed is decided by an authenticated checkpoint (`meta.deletion_checkpoint`, read by `storage.partition.Partition.deletion_generation`), not by the plaintext counter; tombstones, suppressions and source aliases are rebuilt from the ledger's MACed outcomes on every reconcile (`storage.ledger` docstring, `Partition.reconcile`); cascades follow derivations and citations to any depth, and every record a cascade removes gets a tombstone; victims are found even when plaintext index rows were stripped; a project, repository, agent, source or session target that covers records outside the caller's grants needs an `ADMIN` context; after a cutover, forgets reach the migration's rollback copies (`forgetting.ForgettingService.propagate_to_migration_copies`, `migrations.cutover.propagate_forgets_to_legacy`) | `forgetting.ForgettingService` | `tests/test_forgetting.py::test_restoring_an_old_database_cannot_resurrect_forgotten_memories`, `::test_restoring_database_and_ledger_against_a_newer_mirror`, `::test_broad_forget_counts_only_what_the_caller_may_see`; `tests/test_review_round4_batch1.py::test_tamper1_restored_old_database_with_an_edited_counter_still_replays`, `::test_tamper1_deleted_tombstone_rows_are_restored_from_the_ledger`, `::test_tamper2_scope_forget_finds_a_record_whose_scope_index_was_stripped`; `tests/test_review_round3_batch1.py::test_mf2_a_citation_chain_of_any_depth_is_followed`, `::test_mf2_a_citer_of_a_cascade_removed_record_is_removed`; `tests/test_review_round2_batch1.py::test_rob1_forgetting_a_chain_deeper_than_the_interpreter_stack` |
| Scoped retrieval (in-memory FTS5 projection, Python BM25 fallback, RRF, validity, dedup, MMR) | `retrieval.service.RetrievalService`, `retrieval.index`, `retrieval.query`, `retrieval.ranking` | `tests/test_retrieval.py`, `tests/test_retrieval_query.py` |
| Hot-context compilation with budget, receipts and revalidation | `context.compiler.ContextCompiler`, `context.budget`, `context.markers` | `tests/test_context.py::test_forget_racing_a_compile_never_leaks` |
| Encrypted session-history archive | `history.archive.HistoryArchive` | `tests/test_history.py` |
| Repository memory (hardened read-only git, path safety, observations, interchange v1) | `repository.service.RepositoryService`, `repository.git.Git`, `repository.scanner`, `repository.interchange` | `tests/test_repository.py::test_repository_config_hooks_and_filters_never_execute` (the whole module is skipped when `git` is not on `PATH`) |
| Episodes, governed procedures, bounded consolidation | `learning.episodes.EpisodeService`, `learning.procedures.ProcedureService`, `learning.consolidation.ConsolidationService` | `tests/test_learning.py` |
| Optional providers: consent, guarded calls, encrypted versioned vectors, external-deletion outbox (contracts plus deterministic fakes only). Egress consent covers provider, scope and data class (`providers.base.DATA_CLASSES`: `memory_text`, `transcripts`, `repository_source`), and replicas of records that are forgotten or no longer current are withdrawn (`providers.hub._WITHDRAW_LIFECYCLES`) | `providers.hub.ProviderHub`, `providers.base`, `providers.embeddings`, `providers.fake` | `tests/test_providers.py`, `tests/test_integration.py`, `tests/test_review_round4_batch2.py::test_eg3_observation_evidence_needs_repository_source_consent` |
| Key administration (master-key re-wrap, progressive data-key rotation) | `admin.rotate_master_key`, `admin.rotate_data_key` | `tests/test_storage.py::test_data_key_rotation_is_progressive_and_keeps_old_data_readable` |
| Format-compatible extraction of the Locus vault and continuity store | `compat.legacy_vault.LegacyMemoryVault`, `compat.legacy_vault.LegacyContinuityStore` | `tests/test_compat_legacy.py::test_bidirectional_parity_with_real_locus_code` (runs only when a Locus checkout is readable; see 4.2) |
| Migration tooling: inventory, snapshot, resumable import, verify, ownership state machine, cutover, rollback. The importer runs only while legacy is authoritative (`migrations.legacy.IMPORT_STATES`; otherwise `OwnershipFenced`); a migration that cannot validate can be aborted back to legacy; a rollback refuses records of agents the mapping does not know (unless `allow_partial=True`, which keeps them in the package); migration snapshots are recorded and removed, including those of a failed or crashed `prepare_shadow` | `migrations.legacy.LegacyImporter`, `migrations.state.OwnershipControl`, `migrations.cutover.Migrator` | `tests/test_migrations.py::test_crash_during_cutover_resumes_without_losing_writes`, `tests/test_review_round4_batch1.py::test_mf1_a_migration_that_cannot_validate_can_be_aborted_back_to_legacy`, `::test_mf2_rollback_refuses_records_of_an_agent_the_mapping_does_not_know`, `tests/test_review_round4_batch2.py::test_mf3_a_crashed_prepare_shadow_leaves_no_snapshot_after_cutover` |
| Diagnostic CLI | `cli` | `tests/test_cli.py` |
| Offline chronological benchmark (synthetic) | `evaluation` | `tests/test_evaluation.py`, [evaluation.md](evaluation.md) |
| Packaging: side-effect-free import, offline quickstart, clean-venv wheel check | `examples/quickstart.py`, `scripts/verify_wheel.sh` | `tests/test_packaging_imports.py` (import hygiene). The quickstart and the clean-venv wheel check are verified by running `scripts/verify_wheel.sh` by hand (section 2.2), not by the pytest suite. |

### 2.2 Gate A evidence

* The package suite has 1495 tests at `f02541e` (`pytest --collect-only`). The final runs of
  `python -m pytest -o addopts="" -q`, twice in `.venv` (CPython 3.14.6) and twice in `.venv310`
  (CPython 3.10.22), each reported `1495 passed` (about 2 min 41 s on 3.14 and 2 min 46-49 s on
  3.10, as pytest reported them). No file under `src/` or `tests/` was modified after 17:09, before
  the first of these runs started (about 17:15), and those files are identical to `f02541e`.
  Commands are in section 4. No other interpreter version has been tested.
* The wheel was built and then installed offline into clean 3.10 and 3.14 virtualenvs outside the
  checkout with `scripts/verify_wheel.sh`. In a fresh temporary directory outside the checkout
  (which holds a copy of `examples/quickstart.py`), the script checks that `locus_memory` is
  imported from the installed wheel and pulls in no host packages. It then runs
  `examples/quickstart.py` (persist, restart, retrieve, correct, build context, forget, plaintext
  scan) and a CLI smoke test.
  * **First run:** 2026-10-04 at about 03:32, before commits `967136e` and `5383d30`. Both
    interpreters passed.
  * **Re-run on `5383d30` (before review rounds 2-4):** 2026-10-04 at about 07:10, on a scratch
    copy of commit `5383d30` (the working tree had no uncommitted source changes), with the same
    wheelhouse. CPython 3.14.6 and 3.10.22 both printed `quickstart OK` and `cli search ok`.
  * **Latest re-run, on `f02541e`:** 2026-10-04 at about 17:27. The wheel (SHA-256
    `d8cd6a724c61fbdf29c2d4c82d7da74f091ef38ce004bdcacfa9eb69749ab15e` for that build) was
    installed offline into clean CPython 3.10.22 and 3.14.6 venvs with `scripts/verify_wheel.sh`.
    The wheel's `locus_memory/` tree, and the tree installed in each venv, are file-for-file
    identical to `src/locus_memory` at `f02541e`, and the run directories the script created are
    dated 17:27. At about 17:53, the quickstart and the CLI smoke test were run again in those two
    venvs, from new directories outside the checkout, and both printed `quickstart OK` and
    `cli search ok`.
  * **Bundled Locus runtime (`pip --target`):** the same wheel was also installed with
    `pip --target` (17:27) and imported by the bundled runtime (CPython 3.14.6, SQLite 3.53.1,
    `cryptography` 50.0.0 from its `site-packages`); `locus_memory` loads from the target
    directory. At about 17:53, `examples/quickstart.py` was also run there (from a temporary
    directory outside the checkout) and printed `quickstart OK`. The CLI smoke test was not run on
    the bundled runtime.
  * The script is run by hand. No pytest test runs it or the quickstart. Its preconditions are
    in section 4.3.
* Importing creates no files and loads no network client or host package
  (`tests/test_packaging_imports.py::test_import_is_side_effect_free_and_pulls_in_no_host_or_network_stack`).
  The test runs the import in an isolated `HOME`, working directory and `TMPDIR` under
  `-W error`, and checks that no files appear, nothing is written to stderr, and no host or
  network-client module is loaded. Importing still reads files, such as module sources.

### 2.3 Host handoff (later milestones not executed)

The later (host) milestones were not executed, because there were no authorized host writes
(R25.1). A handoff was prepared instead: two patches, applied and tested only in disposable
`git archive` copies of Locus `b332e455`. Nothing was applied to the real Locus checkout.

**The authoritative host evidence is [handoff/locus/README.md](../handoff/locus/README.md),
section 7.** The numbers below are copied from it (final run, 2026-10-04, against package commit
`f02541e`, recorded in commit `1eb14e6`). If the two disagree, section 7 wins.

| Patch | Stage | Tested where | Result (handoff README section 7) |
|---|---|---|---|
| `handoff/locus/0001-stage1-delegate-memory-vault-to-locus-memory.patch` | 1: `memory.py` and `continuity.py` become facades over `locus_memory.compat.legacy_vault`. Locus keeps key custody. | `git archive` copy of Locus `b332e455` on the bundled runtime, with `PYTHONPATH=<locus-memory>/src` | Memory-related host tests: 768 passed, 6 failed (recorded there as "earlier runs"). Whole host suite: 2729 passed, 108 failed, 42 errors. |
| `handoff/locus/0002-stage2-memory-adapter.patch` (applies on top of 0001) | 2: `memory_adapter.MemoryAdapter` behind `LOCUS_MEMORY_ENGINE_MODE` (`disabled` by default). The canonical store stays the legacy vault. | Same | Memory-related host tests: 793 passed, 7 failed (767 + 26 new; the 7th is a timing failure). Whole host suite: 2755 passed, 108 failed, 42 errors. `agent/tests/test_memory_adapter.py`: 26 passed. |

* **The failures are environmental (handoff README section 7).** The failing and erroring test ids
  of the two whole-suite runs were diffed and are identical. Six are staged-server tests in
  `agent/tests/test_product_backend.py`, whose subprocesses do not get the `PYTHONPATH` packages.
  The seventh memory-related failure,
  `agent/tests/test_document_library.py::test_timeout_kills_helper_and_does_not_publish_fake_success`,
  failed in the final runs of both columns and, per section 7, also fails on an unmodified Locus
  copy with no `locus_memory` on the path.
* **The current 0002 adapter test file** (`agent/tests/test_memory_adapter.py` in the patch) has
  25 test functions, one parametrized over two modes: 26 tests, which matches "26 passed" above.
  The patch changed after the documentation commit `2921bd6`:
  * in `a1706f3` the single-layer check stopped failing turns (`MemoryAdapter._single_layer` logs,
    counts `adapter.layer_violation` and serves no engine memory), and 2 adapter tests were added;
  * in `219fd15` the adapter stopped importing from the legacy vault once ownership leaves the
    legacy-authoritative states, and
    `test_after_cutover_the_adapter_stops_importing_from_the_legacy_vault` was added.
* **Earlier host runs (historical).**
  * The first runs (memory-related sets and whole suite, both stages) were on 2026-10-04 between
    about 04:22 and 04:28, before commits `967136e` (04:43) and `5383d30` (06:36).
  * **Re-run against `5383d30` with the pre-round-2 0002 patch (23 adapter tests):** on
    2026-10-04 at about 07:10-07:12, in fresh disposable `git archive` copies made with the
    procedure in section 4.4 (run under bash). The memory-related sets gave Stage 1 768 passed,
    6 failed and Stage 2 791 passed, 6 failed (the same 6 `test_product_backend.py` tests), and
    `agent/tests/test_memory_adapter.py` in the Stage-2 copy gave 23 passed. The whole host suite
    was not re-run then.
* **Not executed, even in a copy:**
  * bundling the wheel through Locus's hashed lock (handoff README section 3);
  * the Stage-3 canonical cutover (the host wiring is not written, and no cutover was run);
  * moving the routes and tools to the adapter;
  * legacy retirement.

  `migrations.cutover.Migrator` (cutover and rollback) has been tested only on disposable package
  fixtures.

### 2.4 Adversarial review rounds (regression evidence)

After the package milestones, four adversarial review rounds looked for defects. Each defect was
reproduced before it was fixed, and each fix landed with regression tests. Test counts are
`pytest --collect-only` counts at `f02541e` (later rounds also edited some earlier test files).

| Round | Commit | Defects | Finding ids in the tests | Regression-test files (collected tests) |
|---|---|---|---|---|
| 1 | `5383d30` | 63 | (none; grouped by area: scope, crypto residue, forgetting cascades, migration and rollback resurrection, lifecycle and context, injection and repository) | `tests/test_review_group1.py` (93), `test_review_group2.py` (7), `test_review_group3.py` (23): 123 tests; plus `tests/test_db_close.py` (3 tests at `f02541e`; round 3 extended it for the close race) |
| 2 | `a1706f3` | 29 | R2-CD-1..5, R2-FG-1..7, R2-HC-1..2, R2-ROB-1..8, R2-SL-1..7 | `tests/test_review_round2_batch1.py`-`batch4.py` (33 + 26 + 32 + 35 = 126) |
| 3 | `219fd15` | 21 | R3-API-1..3, R3-EG-1..6, R3-MF-1..8, R3-RG-1..4 | `tests/test_review_round3_batch1.py`-`batch3.py` (45 + 38 + 72 = 155) |
| 4 | `f02541e` | 20 | R4-TAMPER-1..9, R4-MF-1..3, R4-EG-1..5, R4-RG-1..2, R4-PERF-1 | `tests/test_review_round4_batch1.py`-`batch3.py` (37 + 39 + 25 = 101) |
| **Total** | | **133** | | 505 tests in the round files plus `tests/test_db_close.py` |

* **Round 2 count.** The subject of commit `a1706f3` says 28 defects, but the round has 29
  distinct finding ids in its tests (listed above). 29 is the count used here.
* The commit summaries in section 3 say what each round changed. Finding ids name the defect in
  the test file's module docstring or section comments (for example R4-TAMPER-1 in
  `tests/test_review_round4_batch1.py`).

## 3. Commit history

These are paraphrased summaries of `git log --oneline` at the time of writing, newest first.
Run `git log --oneline` for the exact subjects. The documentation set was committed in `2921bd6`;
review rounds 2-4 then updated several docs and the handoff patch. Documentation edits made after
`1eb14e6`, including this revision of this file, were not committed when it was written (run
`git status`).

| Commit | Summary |
|---|---|
| `1eb14e6` | Final host evidence in `handoff/locus/README.md` (section 7, against package commit `f02541e`) and a note on the adapter's ownership-gated sync; the final evaluation run `evals/results/2026-10-04-r5-seed20261004-final/`. No change under `src/` or `tests/`, and the patches are unchanged. |
| `f02541e` | Review round 4, 20 defects (R4-TAMPER-1..9, R4-MF-1..3, R4-EG-1..5, R4-RG-1..2, R4-PERF-1): ledger replay anchored to an authenticated deletion checkpoint (critical); tamper-resistant forget victim discovery and procedure evidence; derived-scope reconciliation; multi-level derived invalidation; rollback agent mapping; migration-snapshot residue tracking. |
| `219fd15` | Review round 3, 21 defects: cascade through citations, with tombstones for cascade-removed records; rollback and re-migration edge cases; egress data-class and lifecycle checks; interchange observation exclusion; derived invalidation; strict boolean model validation; secret and sensitive gates on every stored field; `ForgetPolicy` robustness; `Database.close` race. In the 0002 patch, the adapter stops importing after cutover. |
| `a1706f3` | Review round 2, 29 defects (the commit subject says 28; section 2.4): migration round-trip and forget interplay; egress of excluded or expired content; partition binding; cached partial packets; typed storage errors (CLI exit code 4); robustness bounds. In the 0002 patch, the single-layer check never fails a turn. |
| `2921bd6` | Documentation set: architecture, security and privacy, storage and encryption, Locus and workflow integration, repository interchange, migrations and rollback, feature matrix, requirements and the requirements-to-tests checklist, and this file. |
| `5383d30` | Adversarial review (round 1), 63 defects (scope, crypto residue, forgetting cascades, migration and rollback resurrection, lifecycle and context, injection and repository), each with a regression test; thread-safe `Database.close`. |
| `967136e` | Fix round: importer fingerprint deltas and scoped deletion propagation; consolidation liveness; deterministic semantic ties; correction and weak-evidence flags; `ContextRequest.max_items` and context markers; open-existing partitions; engine export; side-effect-free fenced compat reads. Adapter bridges removed from 0002; evaluation re-run. |
| `70543a0` | Packaging: offline quickstart example and the clean-venv wheel verification script. |
| `3383b40` | CLI, chronological evaluation benchmark and results, provider summarizer, Stage-2 handoff patch, README. |
| `350dde8` | Models: normalize `IngestionEvent` timestamp, scope and tool name. |
| `6ecfe1d` | Lead fixes: idempotent schema re-apply, uncited-source forget authorization, correction sensitive-content gate, ownership fencing of canonical writes, engine wrappers, host repository settings. |
| `f2f7a3a` | Modules: retrieval, context compiler, history archive, repository memory, episodes, procedures and consolidation, providers, admin key rotation. |
| `93118d6` | Docs: Locus compatibility audit and ownership matrix; compat fixes for D1, D23, D24 and D25. |
| `c43324e` | Compat: lazy fail-closed key verification; Stage-1 delegation patch verified in a disposable host copy. |
| `0d6cb15` | Compat: format-compatible vault and continuity extraction; migrations: inventory, snapshot, resumable import, verify, ownership state machine, cutover and rollback. |
| `9de4e1e` | Foundation: models, crypto envelope, encrypted partition storage, deletion ledger, lifecycle core, forgetting. |

## 4. How a later session continues

Rules that still apply:

* Never modify anything under `~/Documents`.
* Do not publish, push, migrate real data or enable anything in the real Locus checkout without
  separate authorization (R0.3).
* Host work happens only in disposable copies.

### 4.1 Interpreters

Two editable development environments exist in the checkout. Both are git-ignored.

* `.venv`: CPython 3.14.6 (Homebrew `python@3.14`, SQLite 3.53.3), with pytest and ruff. The
  evaluation runs used this environment.
* `.venv310`: CPython 3.10.22 (SQLite 3.53.1), created by `uv` with its interpreter under
  `.toolchains/`, with pytest. It has no ruff, pip or setuptools, so it was not created with
  `'.[dev]'`. Lint with `.venv/bin/ruff`.

To recreate either environment, create a venv with the interpreter, then run
`<venv>/bin/python -m pip install -e '.[dev]'`. That install needs these from an index or a local
wheelhouse:

* setuptools>=77 (the build uses the PEP 639 `license` and `license-files` fields);
* `cryptography` and its dependencies (`cffi`, `pycparser`, and `typing-extensions` on 3.10);
* pytest and ruff.

`scripts/verify_wheel.sh` builds with `.venv/bin/python`, so `.venv` also needs pip and
setuptools>=77 (it has setuptools 84.0.0 now).

### 4.2 Package tests, lint and benchmark smoke

```bash
cd <locus-memory-checkout>
.venv/bin/python -m pytest -o addopts="" -q            # CPython 3.14.6 (the evidence command)
.venv310/bin/python -m pytest -o addopts="" -q         # CPython 3.10.22
.venv/bin/python -m pytest -m "not slow"              # skip the tests marked slow (benchmark runs)
.venv/bin/python -m pytest -o addopts="" --collect-only -q | tail -1   # 1495 tests at f02541e
.venv/bin/ruff check src tests                        # ruff 0.16.10; config in pyproject.toml
.venv/bin/python -m locus_memory.evaluation --out /tmp/eval-smoke --repetitions 1 --size small
```

At `f02541e`, the evidence command reported `1495 passed` twice on each interpreter, in about
2 min 41 s on 3.14 and 2 min 46-49 s on 3.10 (section 2.2). `-o addopts=""` clears the
`addopts = "-q"` of `pyproject.toml`, so the explicit `-q` gives the same output either way;
`-p no:cacheprovider` (used in earlier runs) only avoids writing `.pytest_cache`.

One test runs against real Locus code:
`tests/test_compat_legacy.py::test_bidirectional_parity_with_real_locus_code` (through the
`locus_modules` fixture). It runs only when `LOCUS_SOURCE_DIR` names a Locus checkout (use an
unmodified `git archive` of `b332e455`), and is skipped otherwise. It copies `memory.py` and
`continuity.py` to a temporary directory first, so the checkout is never written. The other tests
in that file run against the committed fixture under `tests/fixtures/locus_legacy/`, which was
produced by the real Locus code at `b332e455` (`make_fixture.py`).

Tests that need `git`:

* `tests/test_repository.py` is skipped as a whole when `git` is not on `PATH` (a module-level
  `pytestmark`).
* Git-dependent tests in 12 other files are skipped individually without `git` (a
  `skipif(GIT is None)` marker, a `needs_git` marker or a `pytest.skip` in the fixture or test):
  `test_cli.py`, `test_integration.py`, `test_review_group1.py`, `test_review_group3.py`,
  `test_review_round2_batch1.py`, `test_review_round2_batch2.py`, `test_review_round2_batch3.py`,
  `test_review_round3_batch1.py`, `test_review_round3_batch2.py`, `test_review_round3_batch3.py`,
  `test_review_round4_batch1.py` and `test_review_round4_batch2.py`.
* `tests/test_evaluation.py` drops arm D (episodes and repository observations) from its benchmark
  runs without `git`.

The repository-memory evidence therefore depends on git being installed. The final suite runs at
`f02541e` reported `1495 passed` with nothing skipped, so git (and the Locus checkout for the
parity test) were available there.

The legacy fixture changed once after it was created: commit `219fd15` changed
`tests/fixtures/locus_legacy/memory.sqlite3` (header bytes 19-20, 1-based, now mark it as a WAL-mode
file, and the file change counter and version-valid-for number moved) and committed its
`memory.sqlite3-shm` and `memory.sqlite3-wal` files. Its logical content is unchanged (the `.dump`
of the `0d6cb15` and `219fd15` versions is identical), so something opened the committed fixture in
place rather than a copy. Which test did so is not identified (low priority).

### 4.3 Wheel verification (clean venvs outside the checkout, offline)

Preconditions:

* The script always builds with the checkout's `.venv/bin/python`, which needs pip and
  setuptools>=77 (section 4.1).
* `<work-dir>/wheelhouse` must already hold wheels for `cryptography` and its dependencies for
  every interpreter: `cffi`, `pycparser`, and `typing-extensions` for Python 3.10. A directory
  with only a `cryptography` wheel cannot satisfy the offline install. The wheelhouse used on
  2026-10-04 held `cryptography` 50.0.0, `cffi` 2.1.1, `pycparser` 3.0 and `typing_extensions`
  4.16.0.
* `pip download` resolves `cffi` and `pycparser` on its own. It evaluates dependency markers
  against the interpreter that runs pip, not the `--python-version` target (pip 26.2.1,
  `pip._internal.metadata.importlib._dists.Distribution.iter_dependencies`). When `python3` is
  3.11 or later, the 3.10 download therefore skips `typing-extensions`
  (`python_full_version < '3.11'`), so the third command below fetches it explicitly.

```bash
# once, with network: fill a wheelhouse with cryptography and its dependencies per interpreter
python3 -m pip download --only-binary=:all: cryptography -d /tmp/lm-wheel/wheelhouse --python-version 3.10
python3 -m pip download --only-binary=:all: cryptography -d /tmp/lm-wheel/wheelhouse --python-version 3.14
python3 -m pip download --only-binary=:all: 'typing-extensions>=4.13.2' -d /tmp/lm-wheel/wheelhouse --python-version 3.10
# build, install offline, run the quickstart and the CLI smoke test for each interpreter
scripts/verify_wheel.sh /tmp/lm-wheel \
  /opt/homebrew/opt/python@3.14/bin/python3.14 \
  <python3.10>
```

The script prints the wheel's SHA-256, which is the value a Locus lock entry would pin. A local
wheel is not a release.

### 4.4 Host-copy testing (git archive plus the bundled runtime)

The helper scripts used in this session were in a temporary scratch directory and are not in
the repository. The commands below are the complete procedure. `git archive` reads only the
object store, so the Locus checkout is not touched.

**Run these commands under bash** (for example, save them to a file and run `bash <file>`). The
user's login shell is zsh, and zsh does not split the unquoted `$FILES` in step 3 into words, so
pytest receives one newline-joined path and stops with "file or directory not found". In zsh,
use `${=FILES}` instead.

```bash
LOCUS=<locus-checkout>                 # read-only
REV=b332e4554e72956f949506207ffa034749360d79
LM=<locus-memory-checkout>
RT=/Applications/Locus.app/Contents/Resources/AgentRuntime
WORK=$(mktemp -d)                                  # disposable

# 1. Disposable copies of the audited tree, Stage 1, then Stage 2
mkdir "$WORK/stage1"
git -C "$LOCUS" archive --format=tar "$REV" agent Tools Config ProtocolFixtures Docs LICENSE pytest.ini \
  | tar -x -C "$WORK/stage1"
(cd "$WORK/stage1" && patch -p1 < "$LM/handoff/locus/0001-stage1-delegate-memory-vault-to-locus-memory.patch")
cp -R "$WORK/stage1" "$WORK/stage2"
(cd "$WORK/stage2" && patch -p1 < "$LM/handoff/locus/0002-stage2-memory-adapter.patch")

# 2. pytest for CPython 3.14, kept outside the runtime (the runtime ships none)
python3.14 -m pip install --target "$WORK/pydeps" pytest

# 3. Memory-related host tests on the bundled runtime (repeat in stage1 for the baseline)
cd "$WORK/stage2"
FILES=$(grep -lE "MemoryVault|memory_vault|ContinuityStore|/api/memory|propose_memory|search_memory|context-snapshots|skill-observations|KnowledgeStore|_automatic_memory_context|memory_context" agent/tests/*.py)
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$LM/src:$WORK/pydeps:$RT/site-packages" \
  "$RT/python/bin/python3.14" -m pytest $FILES -q -p no:cacheprovider

# 4. Whole host suite (compare the FAILED/ERROR set between stage1 and stage2)
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$LM/src:$WORK/pydeps:$RT/site-packages" \
  "$RT/python/bin/python3.14" -m pytest agent/tests -q -p no:cacheprovider
```

The six `test_product_backend.py` staged-server failures are expected in this setup (section
2.3). The latest host runs, against package commit `f02541e`, are recorded in
[handoff/locus/README.md](../handoff/locus/README.md) section 7 (summarized in section 2.3): the
memory-related set, the whole host suite in both stages, `agent/tests/test_memory_adapter.py` and
`ruff`, on the bundled runtime with `PYTHONPATH=<locus-memory>/src`. Section 7 also records that
0001 then 0002 apply cleanly to a fresh `git archive` of Locus HEAD and give a tree byte-identical
to the tested one. The earlier re-run against `5383d30` (steps 1 and 3 and the adapter test file,
under bash, with an existing pytest target directory instead of step 2) is historical.

To regenerate 0002 after changing the Stage-2 tree, produce a `diff -ruN` of the Stage-2
`agent/` tree against the Stage-1 `agent/` tree, run from a directory that holds them as `a/agent`
and `b/agent`. Exclude `__pycache__`, `.ruff_cache`, `.pytest_cache` and `*.pyc`. Then re-check it
with `patch --dry-run -p1` on a fresh Stage-1 copy.

### 4.5 Next host-side step

The next host step is the remaining work in [handoff/locus/README.md](../handoff/locus/README.md),
sections 3 and 9. In order:

1. Pin the wheel in Locus's hashed lock (handoff section 9, step 1).
2. Wire `OwnershipControl.writer_guard` into the legacy vault (step 2).
3. Run `Migrator.prepare_shadow`, then `validate`, then `cutover`, with a host `quiesce` hook
   (step 2).
4. Move the `/api/memory*` routes and the model tools to the adapter (step 3).

The list continues with handoff section 9, steps 4-7, which section 5.2 also describes:

5. Make the context-snapshot and skill-observation families package-owned, with D11 and D12
   fixed (step 4).
6. Give the adapter to the parallel writer, helper and evaluation cores, or decide against it,
   and revalidate each team member's packet before that member's call (step 5).
7. Decide key custody and add a canary for the legacy key (step 6).
8. Deliver memory to native providers per turn and ephemerally (D4, D44) (step 7).

Each step needs explicit authorization before it touches a real Locus checkout or real data.

## 5. Open issues

### 5.1 Evaluation: rollout criteria not met ([evaluation.md](evaluation.md), sections 11 and 12)

* **Final run on `f02541e`:** `evals/results/2026-10-04-r5-seed20261004-final/` (created
  2026-10-04 21:27:15Z, 43 s after the `f02541e` commit; committed in `1eb14e6`). It used 5
  repetitions (seeds 20261004-20261008) on CPython 3.14.6 in `.venv` with SQLite 3.53.3. 11 of 13
  pre-registered criteria were met; C5 and C8 were not met, with the same values as the F3 run;
  all hard invariants held. Its quality and safety numbers are identical to the F3 run (every
  question row matches except the latencies; evaluation.md section 12.2). Only cost, latency and
  storage differ: for example, arm C's cold history search p50 went from 4.5 to 1.7 ms and its
  bytes on disk rose from 2.77 MB to 2.98 MB (section 12.3).
* **C5 (strict correction propagation, including raw history): not met for arms C, D and E.**
  After the F3 changes there were 7.4 superseded history hits per run on average (worst run 9), and
  the same in the final run. The archive annotates superseded messages (`superseded_by_correction`)
  and does not remove them. `search_history(..., exclude_corrected=True)` is an opt-in filter. The
  context compiler always applies it.
* **C8 (retrieval-level abstention accuracy >= 0.75): not met** (B scores 0.80; C, D and E score
  0.70, in the F3 and final runs). Look-alike questions defeat abstention. `weak_match`,
  `INSUFFICIENT_EVIDENCE` and `weak_evidence_only` are lexical signals, not a usable abstention
  signal on this corpus.
* **Arm F (evaluated procedures in a host harness) was not executed.** It needs a host evaluation
  runner and task execution.
* **Not measured:**
  * semantic retrieval quality (arm E uses fake hash embeddings, a contract check only);
  * evidence-backed task correctness (no model in the loop).
* **The results come from a small synthetic corpus on one machine.** They are not proof of
  production gains.
* **Default packet order is not relevance order.** `ContextRequest.order="relevance"` exists.
* **The engine does not budget history hits.** They add tokens on top of the packet: about 140
  per question in the F3 and final runs (arm C: 814.1 packet-plus-history tokens against 673.9
  packet tokens) and about 170 in the first run (section 9.4). A host must budget them.

### 5.2 Host integration remaining ([handoff/locus/README.md](../handoff/locus/README.md), sections 3, 8 and 9)

**Not shipped.**

* The wheel is not in Locus's hashed lock or bundle (`--find-links`, the `requirements-runtime`
  lock, `agent/pyproject.toml`).
* The patches were tested with `PYTHONPATH`, not through the lock.

**Still on the legacy vault.**

* The model tools (`search_memory`, `propose_memory`) and the `/api/memory*` routes still use the
  legacy vault. Id-addressed route operations are not target-checked: `enforce_target` exists in
  the package but Stage 1 does not enable it (D2). Server-side approval (D3) is unchanged.
* Parallel team writer cores, collaboration helpers and evaluation cores have no adapter.
* Team-member packets are not revalidated before each member's call.
* The per-request plaintext-note migration still runs on every `/api/memory*` route (D28). It has
  no marker and no physical purge (D5).

**Limits of the derived copy.**

* Agent records stay scoped as `legacy_target`.
* A damaged derived-copy row keeps the sync incomplete. The recovery is deleting
  `APP_DIR/memory-engine/`.
* Legacy `helpful`/`ignored` feedback, `use_count` and `last_used_at` are not imported as
  deltas.
* The legacy recall query is still the decorated prompt. D42 is fixed only for the engine query.

**Rollout costs.**

* Shadow mode adds synchronous engine latency to each turn.
* The first sync in each process decrypts every legacy row once.

**Stage 3 host work, not started.** The package tooling for the cutover exists and is tested on
disposable fixtures. The host side still needs:

* The canonical cutover.
* Package ownership of context snapshots and skill observations, with D11 and D12 fixed.
* A decision on key custody (Keychain via the stdin bootstrap) and a canary for the legacy key.
* Per-turn, ephemeral delivery of memory to native providers (D4, D44).
* Deleting the `memory.py` facade.

### 5.3 Known package limitations (from module docstrings and receipts)

**Encryption and keys**

* **Metadata outside the ciphertext.** Plaintext columns include, among others: ids, kinds,
  lifecycle, revisions, timestamps, pinned flags and keyed tokens; history message roles,
  sequence numbers and redacted flags; episode outcomes; procedure states and versions;
  repository snapshot states; data-key ids; provider names, operations, usage units and cost;
  and content-free event codes (`storage.schema`, `status`). Row counts and ciphertext lengths
  are also visible. The full list is in
  [security-and-privacy.md](security-and-privacy.md), section 5 (the "File-level metadata" row).
* **What encryption covers.** It protects app-managed data at rest. It does not protect against
  a compromised running process, swap or a stolen key (`status`).
* **Key rotation** (`admin` module docstring):
  * Both rotations checkpoint after committing and report `flushed` (in the `rotate_master_key`
    receipt details and in the report of a completed `rotate_data_key`). If a reader blocked the
    checkpoint (`flushed: False`), treat the replaced key as able to open the vault until
    `admin.flush_key_material` returns True (`admin.UNFLUSHED_LIMITATION`).
  * Backups or copies taken before the rotation still open with the old key
    (`admin.PRE_ROTATION_COPIES_LIMITATION`).
* **The HMAC key** is not rotated in place (`crypto`).

**Forgetting and the deletion ledger**

* Without a host-held high-water mark (`storage.ledger.LedgerMirror`, passed as
  `HostCapabilities.ledger_mirror`, default `None`), two things are not protected
  (`storage.ledger` docstring):
  * truncating the tail of the deletion ledger is undetectable;
  * restoring the database and the ledger together from an older copy brings forgotten data
    back. With a mirror, the engine refuses to serve (`ReconciliationRequired`) until the newer
    ledger is restored or an operator acknowledges the gap
    (`tests/test_forgetting.py::test_restoring_database_and_ledger_against_a_newer_mirror`).

  Stage 2 does not supply a mirror, so restoring an older copy of `APP_DIR/memory-engine/` as a
  whole would bring forgotten derived-copy rows back, undetected. The next import sync forgets
  again only the legacy-origin memory records (imported, or written back by a rollback) whose
  legacy row is gone (`migrations.legacy.LegacyImporter._propagate_deletions`,
  `migrations.legacy._orphaned_legacy_records`).
* Forgetting cannot recall content already sent to a provider and does not reach copies outside
  the application. Suppression does not match paraphrases (`forgetting`).
* **Forget receipts state where data may remain** (`forgetting` receipt limitations). The
  legacy, migration and purge ones are added by `ForgettingService._finish_result` to every receipt
  handed to a caller, whether live, an idempotent replay or one recorded by a reconcile:
  * `_LEGACY_AUTHORITY`: while the legacy store is authoritative (before a cutover, or after a
    rollback), a package forget applies to the package store only. The legacy store keeps serving
    its copy until it is forgotten there or the next cutover applies the deletion.
  * `_CUTOVER_PENDING` and `_ROLLBACK_PENDING`: a cutover or a rollback is in progress, and the
    legacy store still holds its copy until that operation completes (or, for a cutover, aborts
    with the partition context).
  * `_MIGRATION_RESIDUE`: after a cutover, a copy the migration keeps for rollback (the legacy
    vault or a migration snapshot) could not be updated yet, for example because the legacy file
    was busy. It is retried after later forgets and on open.
  * `_PURGE_PENDING`: a concurrent reader blocked the WAL checkpoint, so deleted pages may stay on
    disk until it completes.
  * `_APPLIED_ELSEWHERE` (added when the forget finds its own entry already applied): the deletion
    was applied by a concurrent reconciliation that recorded no receipt, so counts are unavailable.
* **Broad forget targets need `ADMIN`.** Forgetting a project, repository, agent, source or session
  that also covers records outside the caller's grants requires an `ADMIN` access context, and a
  profile forget always does. Receipts given to non-admin callers count only items the caller may
  see (`forgetting` module docstring, `ForgettingService._authorize`;
  `tests/test_forgetting.py::test_broad_forget_counts_only_what_the_caller_may_see`).

**Lifecycle**

* `remember`'s `possible_conflicts` compares only the `core.CONFLICT_SCAN_LIMIT` (200) most
  recently updated approved memories of the scope. When the scope holds more, the receipt carries
  `core.CONFLICT_SCAN_LIMITATION`.

**Retrieval and history**

* The stopword list is English only.
* Identifier detection and MMR diversity are heuristics (`retrieval.query`, `retrieval.ranking`).
* Weak-match and `INSUFFICIENT_EVIDENCE` are lexical labels, not relevance decisions
  (`history.archive`, `retrieval.service`).
* Token counts are estimates unless the host supplies a tokenizer (`context.budget`).

**Repository memory** (`repository.service.LIMITATIONS`)

* JavaScript and TypeScript imports are found with a heuristic.
* Rename detection is a heuristic.
* Languages other than Python, JavaScript and TypeScript are inventoried only.
* Untracked files are not inventoried.

**Providers and the Agent Dispatcher contract**

* **Providers are contract-only.** Only the deterministic fakes in `providers.fake` ship. No
  production embedding, rerank, extraction or summarization provider is included.
* **No real Agent Dispatcher exporter integration exists.** `repository.interchange.SyntheticRepositoryProducer`
  is a test stand-in.

**Learning**

* Consolidation detects exact duplicates only (`learning.consolidation`).
* Episode narrative fields are agent-reported. Only the outcome is derived from host receipts
  (`learning.episodes`).
* The procedure safety screen is heuristic. `procedure evaluate` is unsupported in the
  standalone CLI because it needs a host `EvaluationRunner` (`learning.procedures`, `cli`).

### 5.4 Documentation and tracking gaps

Two documents that other files refer to were missing in an earlier draft of this file. Both
now exist: [requirements-checklist.md](requirements-checklist.md) (the requirements-to-tests
checklist, R3.5) and [storage-and-encryption.md](storage-and-encryption.md). The link from
[feature-matrix.md](feature-matrix.md) to the checklist therefore resolves.

Stale source docstrings and packaging metadata (source changes, not made in this documentation
round):

* The docstring of `migrations.state` refers to `migrations.rollback`. Rollback is implemented
  in `migrations.cutover.Migrator.rollback`.
* The `crypto` module docstring says Locus backs the `KeyProvider` with the macOS Keychain.
  Locus uses `master.key` file custody, and the Keychain is an open decision
  ([ownership-and-extraction.md, section 8](ownership-and-extraction.md#8-ownership-decisions-still-open),
  decision 2).
* The `compat.legacy_vault` module docstring calls `enforce_target=True` the "adapter default".
  The `LegacyMemoryVault` constructor default is `False`, and neither handoff patch passes
  `enforce_target`.
* The `cli` module docstring and the argparse epilog (`cli.build_parser`) both say
  "Exit codes: 0 ok, 1 error, 2 preview only (nothing changed), 3 capability unavailable".
  `cli.EXIT_STORAGE` = 4
  also exists, for `StorageUnavailable` and its subclasses `StorageFull` and `StorageReadOnly`, as
  the exit-code table in [README.md](../README.md) documents.
* Resolved: `pyproject.toml` now declares `[build-system] requires = ["setuptools>=77"]`, which the
  PEP 639 `license` string and `license-files` fields need.
* The header comment of `scripts/verify_wheel.sh` says the wheelhouse needs "the cryptography
  wheel" and that the checks run "from an empty working directory". The offline install also
  needs the dependency wheels (section 4.3), and the run directory holds a copy of
  `examples/quickstart.py`.

Other gaps:

* CPython 3.11, 3.12 and 3.13 are declared by `requires-python` but untested (section 1).
* The committed legacy fixture was opened in place before commit `219fd15` recorded the change
  (section 4.2); the test that did so is not identified.
* The ownership decisions in
  [ownership-and-extraction.md, section 8](ownership-and-extraction.md#8-ownership-decisions-still-open)
  are still open on the host side.

### 5.5 External repositories

The audit found issues in the reference repositories. These are not package defects:

* **langgraph-workflow:** `WorkflowHost` has no memory port. Job outputs can echo recalled
  memory into a plaintext checkpoint sidecar (the plugin passes no cipher) and into
  `agent-host.sqlite3`, which has no encryption option.
* **Agent Dispatcher:** no versioned memory exporter, and redaction gaps.

They are recorded in [locus-compatibility.md](locus-compatibility.md), sections 15, 16 and 19.5.
Nothing in those repositories was changed.
