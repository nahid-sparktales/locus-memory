# locus-memory

A local-first, encrypted, scope-enforcing memory engine, extracted from Locus. It is an
in-process Python library (Python >= 3.10) with a diagnostic command line. Its only runtime
dependency is `cryptography`. It runs no daemon, opens no port and needs no cloud account.

## Status

* **Version 0.1.0, local only.** Nothing has been published to a package index, released or
  pushed.
* **Package milestones are implemented and tested.** The standalone offline path (Gate A) is
  tested on CPython 3.10.22 and 3.14.6, including a wheel installed into clean virtualenvs
  outside the checkout. `requires-python` is `>=3.10`, but CPython 3.11, 3.12 and 3.13 have not
  been tested.
* **Host integration is delivered only as patches.** The patches in
  [`handoff/locus/`](handoff/locus/README.md) are a Stage-1 facade and a Stage-2 adapter behind a
  switch that is off by default. They were tested only in disposable copies of Locus `b332e455`.
  They have not been applied to a real Locus checkout, bundled through Locus's lock, or used to
  migrate real data.
* **Evaluation is synthetic only.** Two rollout criteria are not met
  ([docs/evaluation.md](docs/evaluation.md)). No production-readiness claim is made.
* Milestones, the commit history, how to continue and the open issues are in
  [docs/PROGRESS.md](docs/PROGRESS.md).

## Install from a local wheel

```bash
python -m pip wheel --no-deps --no-build-isolation -w dist .   # needs setuptools>=77 installed
python -m pip install dist/locus_memory-0.1.0-py3-none-any.whl
# offline: add  --no-index --find-links <dir containing wheels for cryptography and its
#          dependencies (cffi, pycparser; typing-extensions on Python 3.10)>
```

The build needs setuptools 77 or later, because `pyproject.toml` uses the PEP 639 fields
`license = "Apache-2.0"` and `license-files`. Older setuptools rejects them. The wheel was built
with setuptools 84.0.0. The `[build-system]` floor in `pyproject.toml` (`setuptools>=68`) is
too low; this is an open issue.

`scripts/verify_wheel.sh <work-dir> <python> [<python> ...]` checks the wheel. It has two
preconditions:

* It always builds with the checkout's own `.venv/bin/python`, which needs pip and
  setuptools>=77.
* `<work-dir>/wheelhouse` must already hold wheels for `cryptography` and its dependencies
  (`cffi`, `pycparser`, and `typing-extensions` for Python 3.10) for every interpreter.
  [docs/PROGRESS.md](docs/PROGRESS.md) section 4.3 has the download commands.

The script builds the wheel and prints its SHA-256. For each interpreter, it then installs the
wheel offline into a clean venv outside the checkout. From a fresh temporary directory outside
the checkout (which holds a copy of `examples/quickstart.py`), it checks the import, then runs the
quickstart and a CLI smoke test.

For development, use `pip install -e '.[dev]'`, which adds pytest and ruff. With build
isolation, that install also needs setuptools>=77, `cryptography` and its dependencies, pytest
and ruff from an index or a local wheelhouse.

## Quickstart

```bash
python examples/quickstart.py /tmp/locus-memory-demo
```

The example works only inside the given directory. It does the following:

1. Creates a demo file key.
2. Remembers a preference and a project decision.
3. Restarts the engine and searches.
4. Corrects the decision with a revision check.
5. Builds a context packet within a 300-token allowance.
6. Forgets the preference and restarts again.
7. Scans the store for the plaintext canary.

A host application supplies its own `KeyProvider` instead of a file key.

## Library use

```python
import secrets
from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.models import (AccessContext, Operation, PartitionRef, RememberRequest, Scope,
                                 ScopeGrants)

keys = StaticKeyProvider({"k1": secrets.token_bytes(32)})  # the host holds the master key
access = AccessContext(principal="user-1", partition=PartitionRef("standalone", "default"),
                       grants=ScopeGrants(projects=frozenset({"proj-a"})),
                       operations=frozenset({Operation.READ, Operation.WRITE}))
with MemoryEngine("/path/to/store", keys) as engine:
    engine.remember(access, RememberRequest(content="Use tabs in Makefiles",
                                            scope=Scope.of(project="proj-a")))
    result = engine.search(access, "makefiles")
```

`MemoryEngine` (`src/locus_memory/engine.py`) is the public entry point. Every data operation
takes a trusted `AccessContext`, which the host builds from its own authenticated state. (The
lifecycle methods `open`, `close`, the context-manager methods and `partition_context(ref)` do
not take one.) Its operations cover:

* memory records and review: `remember`, `propose`, `approve`, `reject`, `correct`, `supersede`,
  `forget`;
* ranked `search`;
* context packets: `build_context`, `revalidate_context`, `explain_context`;
* the session history archive: `ingest_event`, `search_history`;
* episodes and governed procedures;
* repository observations;
* maintenance and consolidation;
* plaintext `export`;
* key rotation.

## Command line

`locus-memory` (or `python -m locus_memory.cli`) is a diagnostic CLI for one local profile. It
uses a file key under `--root` (default `$LOCUS_MEMORY_HOME`, else `~/.locus-memory`).

```bash
locus-memory --root ./store init
locus-memory --root ./store --project p1 remember "Use tabs in Makefiles" --scope-project p1
locus-memory --root ./store --project p1 search makefiles
locus-memory --root ./store --project p1 forget --project p1        # preview only (exit 2)
locus-memory --help
```

The CLI acts as the host. It builds the access context from its own flags (`--project`,
`--repository`, `--agent`, ...), so nothing read from the store or from input files can widen it.

| Area | Commands |
|---|---|
| Setup | `init` (never over an existing key or vault), `status` |
| Records | `list`, `search`, `show`, `explain`, `remember`, `propose`, `approve`, `reject`, `correct`, `pin`, `unpin`, `forget` |
| Context | `context preview`, `context explain` |
| History | `history ingest`, `history search`, `history scroll`, `history browse` |
| Episodes and procedures | `episode record/show/list`; `procedure list/show/nominate/evaluate/approve/reject/export` (`evaluate` needs a host runner and is unsupported standalone) |
| Repository | `repo register`, `repo snapshot`, `repo status`, `repo observations` |
| Maintenance | `maintain`, `consolidate` |
| Locus vault migration | `migrate inventory/snapshot/import/verify/state/cutover/abort/rollback` |
| Export and keys | `export` (plaintext), `keys rotate-master`, `keys rotate-data` |
| Benchmark | `eval run` |

`forget`, `export`, and `migrate cutover`, `migrate abort` and `migrate rollback` only preview
unless you pass `--yes`. `--json` prints exactly one JSON document.

| Exit code | Meaning |
|---|---|
| 0 | ok |
| 1 | error |
| 2 | preview only (nothing changed) |
| 3 | capability unavailable |

## Testing

```bash
.venv/bin/python -m pytest          # CPython 3.14
.venv310/bin/python -m pytest       # CPython 3.10
.venv/bin/ruff check src tests
python -m locus_memory.evaluation --out /tmp/eval-smoke --repetitions 1 --size small
```

* **Parity test.** One test,
  `tests/test_compat_legacy.py::test_bidirectional_parity_with_real_locus_code`, runs against
  real Locus code. It runs only when a Locus checkout is readable at `LOCUS_SOURCE_DIR` (default
  `/Users/nahid/Documents/locus`) and is skipped otherwise. It copies `memory.py` and
  `continuity.py` to a temporary directory first, so the checkout is never written. The other
  tests in that file run against the committed fixture in `tests/fixtures/locus_legacy/`.
* **Repository tests need git.** `tests/test_repository.py` is skipped as a whole when `git` is
  not on `PATH`, so the repository-memory evidence depends on git being installed.
* **Python versions.** The suite has been run on CPython 3.10.22 and 3.14.6 only. 3.11, 3.12 and
  3.13 are allowed by `requires-python` but untested.
* **Host-copy tests.** [docs/PROGRESS.md](docs/PROGRESS.md) section 4 has the procedure for
  testing the handoff patches in a disposable Locus copy with the bundled runtime, and the
  wheel verification commands. Run the host-copy commands under bash, not zsh.

## Guarantees and limitations

**What the package enforces:**

* **Authorization comes from the host.** Scope, operation and actor are checked against the
  trusted `AccessContext`. Scope filtering runs in SQL before anything is decrypted, ranked or
  counted. Model output and stored text never grant access, change budgets or approve memory.
* **Encrypted at rest.**
  * Records, history, vectors, episodes and repository observations are sealed with AES-256-GCM.
  * The data keys are per partition and wrapped under host-supplied master keys.
  * The associated data binds each row's identity and security metadata.
  * The package never reads a keychain. It never generates a new key over an existing vault: a
    missing key raises `VaultLocked`, and a wrong key raises `WrongKey`.
* **No plaintext search index on disk.** FTS5 projections exist only in memory. Without FTS5,
  memory search falls back to a pure-Python BM25 and history search to substring matching.
* **Forgetting has receipts and a write-ahead deletion ledger.** Deletions are written ahead to
  a separate ledger file. They are replayed after a crash, or after the main database is restored
  from an older copy (`tests/test_forgetting.py::test_restoring_an_old_database_cannot_resurrect_forgotten_memories`).
  A forget purges the target and the state derived from it, such as revisions, vectors, derived
  summaries and context receipts. Restoring the database and the ledger together is covered only
  with a host ledger mirror; see the limits below.
* **Lifecycle.** Candidates are never injected into context. Retrieval never writes. Every score
  carries a `score_kind` label and is never a probability: `rrf` (rank fusion) for memory
  search; `bm25`, `bm25_any_term`, `substring_recency` or `recency` for history search; `cosine`
  or `provider_relevance` for provider signals.
* **No files created on import and no network by default.** Importing the package creates no
  files and loads no network client or host package
  (`tests/test_packaging_imports.py::test_import_is_side_effect_free_and_pulls_in_no_host_or_network_stack`).
  Providers must be registered by the host, and any provider that sends data off the device
  needs a host consent policy.
* **Repository memory is read-only.** Git runs hardened and bounded. Repository code is never
  executed. Excluded secret files are never read or named.

**Limits:**

* **Metadata is stored in the clear.** This includes, among others: ids, kinds, lifecycle
  states, revisions, timestamps, pinned flags and keyed tokens; history message roles, sequence
  numbers and redacted flags; episode outcomes; procedure states and versions; repository
  snapshot states; data-key ids; provider names, operations, usage units and cost; and
  content-free event stage and outcome codes (`storage.schema`). Row counts and ciphertext
  lengths are also visible. The full list is in
  [docs/security-and-privacy.md](docs/security-and-privacy.md), section 5 (the "File-level
  metadata" row), with details in [docs/storage-and-encryption.md](docs/storage-and-encryption.md),
  section 2.
* Encryption does not protect against a compromised running process, swap, a stolen key, or
  backups made before a key rotation.
* **The deletion ledger needs a host mirror for full restore protection.** If the database and
  the ledger are restored together from an older copy, forgotten data comes back unless the host
  supplies a `LedgerMirror` (`storage.ledger.LedgerMirror`, passed as
  `HostCapabilities.ledger_mirror`, which defaults to `None`). With a mirror, the engine refuses
  to serve (`ReconciliationRequired`) until the newer ledger is restored or an operator
  acknowledges the gap
  (`tests/test_forgetting.py::test_restoring_database_and_ledger_against_a_newer_mirror`).
  Without a mirror, truncating the ledger's tail is also undetectable. The Stage-2 Locus adapter
  supplies no mirror.
* Forgetting cannot recall content already sent to a model provider.
* Weak-match and insufficient-evidence signals are lexical, not calibrated relevance.
* Several extractors are heuristic: stopwords, identifier detection, JS/TS imports and rename
  detection.
* Only deterministic fake providers ship, so semantic retrieval quality is not evaluated.

The full list of known limitations is in [docs/PROGRESS.md](docs/PROGRESS.md), section 5.

## Documentation

* [docs/PROGRESS.md](docs/PROGRESS.md): milestone status, commit history, how to continue, open
  issues.
* [docs/requirements.md](docs/requirements.md): the governing specification as numbered
  requirements.
* [docs/requirements-checklist.md](docs/requirements-checklist.md): each requirement with its
  status and evidence.
* [docs/feature-matrix.md](docs/feature-matrix.md): each feature area classified as implemented,
  experimental, contract-only or deferred, with evidence.
* [docs/architecture.md](docs/architecture.md): module map, storage layout, authorization model,
  data flows and rollout dimensions.
* [docs/storage-and-encryption.md](docs/storage-and-encryption.md): files on disk, what is
  plaintext, keyed or sealed, the key hierarchy, rotation and the deletion-ledger protocol.
* [docs/security-and-privacy.md](docs/security-and-privacy.md): threat model, untrusted-data
  handling, provider egress and consent, forgetting guarantees and non-guarantees.
* [docs/migrations-and-rollback.md](docs/migrations-and-rollback.md): ownership state machine,
  legacy migration, cutover and rollback.
* [docs/integration-locus.md](docs/integration-locus.md): host contract and staged extraction plan
  for Locus.
* [docs/integration-workflows.md](docs/integration-workflows.md): langgraph-workflow and Agent
  Dispatcher as optional consumers and producers (no integration exists).
* [docs/repository-interchange.md](docs/repository-interchange.md): the repository interchange
  format v1, its validation and safety rules, and a proposed mapping from Agent Dispatcher
  stores.
* [docs/locus-compatibility.md](docs/locus-compatibility.md): audit of Locus's memory behaviour,
  formats and defects (D1-D61).
* [docs/ownership-and-extraction.md](docs/ownership-and-extraction.md): current extraction
  status, the ownership matrix and the extraction plan.
* [docs/evaluation.md](docs/evaluation.md) and [evals/README.md](evals/README.md): benchmark design,
  rollout criteria and measured results.
* [handoff/locus/README.md](handoff/locus/README.md): the Locus patches, the bundling steps, rollout
  controls, rollback and test evidence.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
