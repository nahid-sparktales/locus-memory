# Progress

This is the state of the work on 2026-10-04, written so that a later session can pick it up
without this session's context. The governing specification is restated as numbered
requirements in [requirements.md](requirements.md). Section 25 of the specification sets the
milestones and Gate A (R25.1), and R25.2 asks for progress and test evidence to be kept in the
repository for later sessions; this file is that record.

**Nothing was published, pushed, migrated for real, or enabled in the real Locus checkout.**
Package version `0.1.0` exists only in this local repository. The host integration exists as
patch files in [`handoff/locus/`](../handoff/locus/README.md), and those patches were applied
and tested only in disposable copies of the Locus tree.

A second review round may still be adding fixes after this file was written. Run
`git log --oneline` for the current history, and see section 4 for the test commands. This file
deliberately quotes no package test counts.

## 1. Inspected repositories and runtimes

| What | Where | Revision | Access |
|---|---|---|---|
| Locus (host) | `/Users/nahid/Documents/locus` | `b332e4554e72956f949506207ffa034749360d79` | read-only; never modified |
| Agent Dispatcher (`agent-skills`) | `/Users/nahid/Documents/agent-skills` | `d68446fe33c4e2162c1eb4d4d15bb663a3040888`, plus 2 uncommitted user edits | read-only |
| langgraph-workflow | `/Users/nahid/Documents/langgraph-workflow` | `52799242a53d80ed067797d0cbb6e1c83363214e` | read-only |

* **Bundled Locus runtime:** `/Applications/Locus.app/Contents/Resources/AgentRuntime`. It is
  CPython 3.14.6 with SQLite 3.53.1 (FTS5 available) and `cryptography` 50.0.0 in its
  `site-packages`. It does not include pytest.
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
| Typed, versioned models; access context; validation; typed errors | `models`, `validation`, `errors`, `policy` | `tests/test_models.py`, `tests/test_core.py::test_scoped_records_are_visible_only_with_every_grant` |
| Envelope encryption: host key provider, per-partition data keys, wrong or missing key fails closed | `crypto.PartitionKeyring`, `crypto.FileKeyProvider`, `crypto.StaticKeyProvider` | `tests/test_crypto.py`, `tests/test_storage.py::test_wrong_key_is_refused_and_never_replaced` |
| Encrypted partition storage, schema migrations, deletion ledger | `storage.partition.Partition`, `storage.schema`, `storage.ledger.DeletionLedger`, `storage.records.RecordStore` | `tests/test_storage.py`, `tests/test_concurrency.py` |
| Lifecycle (remember, propose, approve, reject, correct, supersede, expire) | `core.CoreService` | `tests/test_core.py::test_candidates_are_never_served_or_silently_approved` |
| Forgetting with tombstones, derived-state purge, and ledger replay after a crash or after a restore of the main database (a joint restore of database and ledger needs a host `storage.ledger.LedgerMirror`; section 5.3) | `forgetting.ForgettingService` | `tests/test_forgetting.py::test_restoring_an_old_database_cannot_resurrect_forgotten_memories`, `::test_restoring_database_and_ledger_against_a_newer_mirror` |
| Scoped retrieval (in-memory FTS5 projection, Python BM25 fallback, RRF, validity, dedup, MMR) | `retrieval.service.RetrievalService`, `retrieval.index`, `retrieval.query`, `retrieval.ranking` | `tests/test_retrieval.py`, `tests/test_retrieval_query.py` |
| Hot-context compilation with budget, receipts and revalidation | `context.compiler.ContextCompiler`, `context.budget`, `context.markers` | `tests/test_context.py::test_forget_racing_a_compile_never_leaks` |
| Encrypted session-history archive | `history.archive.HistoryArchive` | `tests/test_history.py` |
| Repository memory (hardened read-only git, path safety, observations, interchange v1) | `repository.service.RepositoryService`, `repository.git.Git`, `repository.scanner`, `repository.interchange` | `tests/test_repository.py::test_repository_config_hooks_and_filters_never_execute` (the whole module is skipped when `git` is not on `PATH`) |
| Episodes, governed procedures, bounded consolidation | `learning.episodes.EpisodeService`, `learning.procedures.ProcedureService`, `learning.consolidation.ConsolidationService` | `tests/test_learning.py` |
| Optional providers: consent, guarded calls, encrypted versioned vectors, external-deletion outbox (contracts plus deterministic fakes only) | `providers.hub.ProviderHub`, `providers.base`, `providers.embeddings`, `providers.fake` | `tests/test_providers.py`, `tests/test_integration.py` |
| Key administration (master-key re-wrap, progressive data-key rotation) | `admin.rotate_master_key`, `admin.rotate_data_key` | `tests/test_storage.py::test_data_key_rotation_is_progressive_and_keeps_old_data_readable` |
| Format-compatible extraction of the Locus vault and continuity store | `compat.legacy_vault.LegacyMemoryVault`, `compat.legacy_vault.LegacyContinuityStore` | `tests/test_compat_legacy.py::test_bidirectional_parity_with_real_locus_code` (runs only when a Locus checkout is readable; see 4.2) |
| Migration tooling: inventory, snapshot, resumable import, verify, ownership state machine, cutover, rollback | `migrations.legacy.LegacyImporter`, `migrations.state.OwnershipControl`, `migrations.cutover.Migrator` | `tests/test_migrations.py::test_crash_during_cutover_resumes_without_losing_writes` |
| Diagnostic CLI | `cli` | `tests/test_cli.py` |
| Offline chronological benchmark (synthetic) | `evaluation` | `tests/test_evaluation.py`, [evaluation.md](evaluation.md) |
| Packaging: side-effect-free import, offline quickstart, clean-venv wheel check | `examples/quickstart.py`, `scripts/verify_wheel.sh` | `tests/test_packaging_imports.py` (import hygiene). The quickstart and the clean-venv wheel check are verified by running `scripts/verify_wheel.sh` by hand (section 2.2), not by the pytest suite. |

### 2.2 Gate A evidence

* The package suite passes on CPython 3.10.22 and 3.14.6. Commands are in section 4. No other
  interpreter version has been tested.
* The wheel was built and then installed offline into clean 3.10 and 3.14 virtualenvs outside the
  checkout with `scripts/verify_wheel.sh`. In a fresh temporary directory outside the checkout
  (which holds a copy of `examples/quickstart.py`), the script checks that `locus_memory` is
  imported from the installed wheel and pulls in no host packages. It then runs
  `examples/quickstart.py` (persist, restart, retrieve, correct, build context, forget, plaintext
  scan) and a CLI smoke test.
  * **First run:** 2026-10-04 at about 03:32, before commits `967136e` and `5383d30`. Both
    interpreters passed.
  * **Re-run on the current source:** 2026-10-04 at about 07:10, on a scratch copy of commit
    `5383d30` (the working tree had no uncommitted source changes), with the same wheelhouse.
    CPython 3.14.6 and 3.10.22 both printed `quickstart OK` and `cli search ok`.
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

| Patch | Stage | Tested where | Result |
|---|---|---|---|
| `handoff/locus/0001-stage1-delegate-memory-vault-to-locus-memory.patch` | 1: `memory.py` and `continuity.py` become facades over `locus_memory.compat.legacy_vault`. Locus keeps key custody. | `git archive` copy of Locus `b332e455` on the bundled runtime, with `PYTHONPATH=<locus-memory>/src` | Memory-related host tests: 768 passed, 6 failed |
| `handoff/locus/0002-stage2-memory-adapter.patch` (applies on top of 0001) | 2: `memory_adapter.MemoryAdapter` behind `LOCUS_MEMORY_ENGINE_MODE` (`disabled` by default). The canonical store stays the legacy vault. | Same | Memory-related host tests: 791 passed, 6 failed. The new adapter test file passes. |

* **The 6 failures are environmental.** They are the same 6 in both columns: staged-server tests in
  `agent/tests/test_product_backend.py`, whose subprocesses do not get the `PYTHONPATH`
  packages. The whole host suite had identical failure sets for Stage 1 and Stage 2. The handoff
  README section 7 lists the tests and the whole-suite numbers.
* **Which package state produced these results.**
  * The first runs (memory-related sets and whole suite, both stages) were on 2026-10-04 between
    about 04:22 and 04:28. That was before commits `967136e` (04:43) and `5383d30` (06:36),
    and before any later second-round fixes.
  * **Re-run on the current source:** on 2026-10-04 at about 07:10-07:12, in fresh disposable
    `git archive` copies made with the procedure in section 4.4 (run under bash), against
    package commit `5383d30` with no uncommitted source changes. The memory-related sets gave
    the same results: Stage 1 768 passed, 6 failed; Stage 2 791 passed, 6 failed (the same 6
    `test_product_backend.py` tests). `agent/tests/test_memory_adapter.py` in the Stage-2 copy:
    23 passed.
  * The whole host suite was not re-run against `5383d30`. Its result is the 04:27 run only.
* **Not executed, even in a copy:**
  * bundling the wheel through Locus's hashed lock (handoff README section 3);
  * the Stage-3 canonical cutover (the host wiring is not written, and no cutover was run);
  * moving the routes and tools to the adapter;
  * legacy retirement.

  `migrations.cutover.Migrator` (cutover and rollback) has been tested only on disposable package
  fixtures.

## 3. Commit history

These are paraphrased summaries of `git log --oneline` at the time of writing, newest first.
Run `git log --oneline` for the exact subjects. The documents of the final
documentation round, including this file and `docs/requirements.md`, were not yet committed.

| Commit | Summary |
|---|---|
| `5383d30` | Adversarial review: fixes for reproduced defects (scope, crypto residue, forgetting cascades, migration and rollback resurrection, lifecycle and context, injection and repository), each with a regression test; thread-safe `Database.close`. |
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

* Never modify anything under `/Users/nahid/Documents`.
* Do not publish, push, migrate real data or enable anything in the real Locus checkout without
  separate authorization (R0.3).
* Host work happens only in disposable copies.

### 4.1 Interpreters

Two editable development environments exist in the checkout. Both are git-ignored.

* `.venv`: CPython 3.14.6 (Homebrew `python@3.14`), with pytest and ruff.
* `.venv310`: CPython 3.10.22, created by `uv` with its interpreter under `.toolchains/`, with
  pytest. It has no ruff, pip or setuptools, so it was not created with `'.[dev]'`. Lint with
  `.venv/bin/ruff`.

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
cd /Users/nahid/locus-memory
.venv/bin/python -m pytest -p no:cacheprovider        # CPython 3.14.6
.venv310/bin/python -m pytest -p no:cacheprovider     # CPython 3.10.22
.venv/bin/python -m pytest -m "not slow"              # skip the tests marked slow (benchmark runs)
.venv/bin/ruff check src tests                        # ruff 0.16.10; config in pyproject.toml
.venv/bin/python -m locus_memory.evaluation --out /tmp/eval-smoke --repetitions 1 --size small
```

One test runs against real Locus code:
`tests/test_compat_legacy.py::test_bidirectional_parity_with_real_locus_code` (through the
`locus_modules` fixture). It runs only when a checkout is readable at `LOCUS_SOURCE_DIR` (default
`/Users/nahid/Documents/locus`), and is skipped otherwise. It copies `memory.py` and
`continuity.py` to a temporary directory first, so the checkout is never written. The other tests
in that file run against the committed fixture under `tests/fixtures/locus_legacy/`, which was
produced by the real Locus code at `b332e455` (`make_fixture.py`).

`tests/test_repository.py` is skipped as a whole when `git` is not on `PATH` (a module-level
`pytestmark`). The repository-memory evidence therefore depends on git being installed.

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
  /Users/nahid/locus-memory/.toolchains/cpython-3.10.22-macos-aarch64-none/bin/python3.10
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
LOCUS=/Users/nahid/Documents/locus                 # read-only
REV=b332e4554e72956f949506207ffa034749360d79
LM=/Users/nahid/locus-memory
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
2.3). Steps 1 and 3 (both stages) and `agent/tests/test_memory_adapter.py` in the Stage-2 copy
were re-run under bash against package commit `5383d30`; the results are in section 2.3. That
run used an existing pytest target directory instead of step 2. Step 4 (the whole suite) was not
re-run against `5383d30`.

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

### 5.1 Evaluation: rollout criteria not met ([evaluation.md](evaluation.md), section 11)

* **C5 (strict correction propagation, including raw history): not met for arms C, D and E.**
  After the F3 changes there were 7.4 superseded history hits per run on average (worst run 9).
  The archive annotates superseded messages (`superseded_by_correction`) and does not remove
  them. `search_history(..., exclude_corrected=True)` is an opt-in filter. The context compiler
  always applies it.
* **C8 (retrieval-level abstention accuracy >= 0.75): not met** (C, D and E score 0.70). Look-alike
  questions defeat abstention. `weak_match`, `INSUFFICIENT_EVIDENCE` and `weak_evidence_only` are
  lexical signals, not a usable abstention signal on this corpus.
* **Arm F (evaluated procedures in a host harness) was not executed.** It needs a host evaluation
  runner and task execution.
* **Not measured:**
  * semantic retrieval quality (arm E uses fake hash embeddings, a contract check only);
  * evidence-backed task correctness (no model in the loop).
* **The results come from a small synthetic corpus on one machine.** They are not proof of
  production gains.
* **Default packet order is not relevance order.** `ContextRequest.order="relevance"` exists.
* **The engine does not budget history hits.** They add tokens on top of the packet (about 170
  per question in the first run, section 9.4), so a host must budget them.

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
* **Master-key rotation** (`admin`):
  * It does not reach backups or copies taken before the rotation.
  * The replaced key can still open the vault until the WAL checkpoint flushes
    (`admin.flush_key_material`).
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
  again only the imported memory records whose legacy row is gone
  (`migrations.legacy.LegacyImporter._propagate_deletions`).
* Forgetting cannot recall content already sent to a provider and does not reach copies outside
  the application. Suppression does not match paraphrases (`forgetting`).

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
* `pyproject.toml` declares `[build-system] requires = ["setuptools>=68"]`, but the PEP 639
  `license` string and `license-files` fields need setuptools 77 or later.
* The header comment of `scripts/verify_wheel.sh` says the wheelhouse needs "the cryptography
  wheel" and that the checks run "from an empty working directory". The offline install also
  needs the dependency wheels (section 4.3), and the run directory holds a copy of
  `examples/quickstart.py`.

Other gaps:

* CPython 3.11, 3.12 and 3.13 are declared by `requires-python` but untested (section 1).
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
