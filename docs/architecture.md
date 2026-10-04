# Architecture

This document describes how `locus-memory` is built and how it is meant to sit inside a host such
as Locus. It covers:

* the end-state dependency direction and where the extraction stands now (§1);
* what runs inside the package and what stays in the host (§2);
* the package module map (§3) and the on-disk layout (§4);
* the partition and `AccessContext` authorization model (§5);
* the main data flows (§6): remember, propose, approve, search, build_context, ingest, forget
  (ledger-first), repository snapshot, episodes, procedures, providers and maintenance;
* the two rollout dimensions, serving mode and canonical backend (§7);
* the extension points a host fills in (§8);
* limits the architecture does not remove (§9), and how to check the claims here (§10).

It describes the code in this tree. Code is cited by module and symbol, for example
`forgetting.ForgettingService.apply_tombstone`, never by line number. Evidence is cited by test id,
for example `tests/test_forgetting.py::test_crash_between_ledger_and_apply_is_repaired_before_serving`.
Requirement ids (`R1.1`, ...) refer to [requirements.md](requirements.md). Locus defect ids (`D1`, ...)
refer to §19 of [locus-compatibility.md](locus-compatibility.md).

This document summarises; the detail is in the topic documents:
[storage-and-encryption.md](storage-and-encryption.md) (files, sealing, ledger and reconcile; §4 and
§6.7 here), [security-and-privacy.md](security-and-privacy.md) (authorization, egress, forgetting
guarantees and limits; §§5, 6.7 and 6.12), [migrations-and-rollback.md](migrations-and-rollback.md)
(the full migration, cutover and rollback protocol; §7.2),
[repository-interchange.md](repository-interchange.md) (repository observation and the interchange
format; §6.8) and [integration-locus.md](integration-locus.md) (the Locus host contract and staged
extraction; §§1.2, 7 and 8).

### Status words used below

| Word | Meaning |
|---|---|
| **implemented** | Code in this repository, exercised by tests in `tests/`. |
| **handoff** | A Locus-side patch in `handoff/locus/`. It was applied and tested in a disposable `git archive` copy of Locus `b332e4554e72956f949506207ffa034749360d79` with the bundled runtime. It has **not** been applied to the real Locus checkout. |
| **contract-only** | A protocol or document format exists, with test doubles. No production implementation exists. |
| **not executed** | Designed (and possibly partly built) but never run end to end. |

Nothing described here has been published, pushed, enabled in the real Locus checkout, or run on
real user data. The benchmark in [evaluation.md](evaluation.md) uses synthetic fixtures only and
makes no claim about production quality.

---

## 1. End-state architecture

### 1.1 Dependency direction

Arrows point from caller to callee. Nothing points back up.

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Locus (host application)                                                 │
│   Swift UI, REST routes, chat turns, model tools, Task Capsules,         │
│   verification, provider accounts, consent, key custody, scheduling      │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ in-process Python calls
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Thin Locus adapter   agent/ollama_code/memory_adapter.py  (handoff 0002) │
│   builds AccessContext from host state, supplies KeyProvider and         │
│   HostCapabilities, chooses the rollout mode, routes calls, renders      │
│   the packet into the existing "## Approved memory" prompt layer         │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ public API: locus_memory.MemoryEngine
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ locus_memory   (this package; in-process library + diagnostic CLI)       │
│   lifecycle, retrieval, context compilation, history archive, episodes,  │
│   procedures, repository observations, forgetting, crypto format,        │
│   migration tooling, legacy codec, evaluation benchmark                  │
└──────────────┬───────────────────────────────────────┬───────────────────┘
               ▼                                       ▼
   local encrypted persistence              optional capabilities injected
   <root>/<partition_id>/memory.sqlite3     through HostCapabilities:
   <root>/<partition_id>/deletion-ledger…   providers + ConsentPolicy,
   <root>/control.sqlite3 (migrations)      VerificationAuthority,
                                            EvaluationRunner, LedgerMirror,
                                            OwnershipControl, TokenCounter,
                                            clock, repository roots

Optional peers (same direction, never required to install or run the engine):

  langgraph-workflow ──WorkflowHost port (implemented by Locus)──▶ Locus adapter ──▶ locus_memory
  Agent Dispatcher   ──interchange document (RepositoryIntelligenceProvider)─────▶ locus_memory
```

Rules the code holds to:

* **One way (R1.1, R1.3).** The package imports nothing from Locus (`ollama_code`), langgraph,
  Agent Dispatcher, web frameworks, HTTP clients or provider SDKs. Its only third-party runtime
  dependency is `cryptography`. Tests: `tests/test_packaging_imports.py::test_import_is_side_effect_free_and_pulls_in_no_host_or_network_stack`
  and `::test_importing_every_submodule_stays_local`. `scripts/verify_wheel.sh` installs the built
  wheel offline into fresh virtual environments under the given work directory and runs a narrower
  import check there: `locus_memory` is not loaded from the checkout's `src`, and none of
  `ollama_code`, `langgraph`, `langgraph_workflow`, `fastapi`, `requests` or `httpx` is loaded after
  importing `locus_memory.cli`. It has no third-party allow-list and no network-client or
  `agent_dispatcher` check; those are covered only by the tests above. Its prerequisites are in §10.
* **In-process only (R1.2).** No daemon, server, port, scheduler or background worker. Importing
  does no I/O, and constructing an engine creates nothing on disk
  (`tests/test_packaging_imports.py::test_constructing_and_closing_an_engine_creates_nothing`,
  `tests/test_storage.py::test_constructing_an_engine_touches_nothing`). The only threads the package
  starts are the short-lived output pumps (and a stdin feeder when input is passed) inside one
  bounded git invocation (`repository.git`).
* **Host integration code lives in the host (R1.4).** The package carries the portable contracts:
  the typed models (`models`), the host protocols (`host`, `crypto.KeyProvider`,
  `storage.ledger.LedgerMirror`, `providers.base`), the repository interchange format
  (`repository.interchange`), the public context markers (`context.markers`), the ownership state
  machine (`migrations.state`) and the format-compatible legacy codec (`compat.legacy_vault`).
* **Peers are optional (R1.5).** langgraph-workflow and Agent Dispatcher are not dependencies.

### 1.2 Where the extraction stands

| Layer | End state | State now |
|---|---|---|
| Legacy vault code in Locus (`agent/ollama_code/memory.py`, `continuity.py`) | Removed, or reduced to a re-export with no SQL or crypto | **Handoff** (patch 0001): both become facades over `compat.legacy_vault.LegacyMemoryVault` and `LegacyContinuityStore`. Same tables, AAD strings, payloads and ids. Locus keeps key custody. |
| Locus adapter | One narrow adapter for every memory call site | **Handoff** (patch 0002): `MemoryAdapter` handles automatic recall, pre-call revalidation, an opt-in history archive, maintenance and scope-change hooks behind `LOCUS_MEMORY_ENGINE_MODE` (default `disabled`). The `/api/memory*` routes and the model tools still use the legacy vault. |
| Canonical memory store | A package partition | Still the legacy vault `APP_DIR/memory/memory.sqlite3`. In patch 0002's shadow and enabled modes the engine holds an encrypted **derived copy** built by `migrations.legacy.LegacyImporter`, and package canonical writes are fenced (§7.2). |
| Cutover and rollback | `migrations.cutover.Migrator`, run once per partition at a time the host chooses | **Implemented**, tested on disposable fixtures (`tests/test_migrations.py`). **Not executed** against any real store. Listed as Stage 3 in [handoff/locus/README.md](../handoff/locus/README.md) §9. |
| Context snapshots and skill observations | Package episodes and procedural candidates | Still legacy-owned; patch 0002 does not import them. |
| langgraph-workflow memory | Recall and candidate proposal through the same Locus adapter | **Not started.** The audit found that its `WorkflowHost` port has no memory method and that it defers memory to the host ([ownership-and-extraction.md](ownership-and-extraction.md) §3.8). |
| Agent Dispatcher repository intelligence | Optional producer of interchange documents | **Contract-only.** No versioned exporter exists. `repository.interchange.SyntheticRepositoryProducer` is a deterministic test stand-in. |

Host-side test evidence for the two patches (memory-related host tests and the whole host suite,
Stage 1 and Stage 2) is in [handoff/locus/README.md](../handoff/locus/README.md) §7. This document
does not quote the counts (§10).

---

## 2. What runs in the package and what stays in the host

| Concern | Package (in-process) | Host |
|---|---|---|
| Identity and authorization | Enforces the `AccessContext` it is given on every call (§5). | Authenticates the user, resolves workspace and agent ids, and builds the `AccessContext`. Model-supplied ids grant nothing. |
| Key custody | Wraps per-partition data keys under host master keys (`crypto.PartitionKeyring`). Never reads a keychain and never generates a new key over an existing vault. | Holds master keys and supplies them through a `KeyProvider`. In handoff 0002, `LocusKeyProvider` derives the engine key from the legacy `master.key` with `crypto.derive_subkey`. The Keychain decision is open ([ownership-and-extraction.md](ownership-and-extraction.md) §8, item 2). |
| Record lifecycle, ranking, context compilation | All of it (`core`, `retrieval`, `context`). | Decides *when* to recall and with what query; composes the prompt; injects the packet text. Has no second ranker (R2.4). |
| Prompt delivery | Returns a bounded `ContextPacket` with a receipt; `revalidate_context` re-checks it. | Places the text in the prompt, calls `revalidate_context` right before the model call, and keeps injected blocks out of the archive (`context.contains_context_block`). |
| Conversation records | Keeps a searchable encrypted archive of events the host sends (`history.archive`). | Owns the live session, transcript files and session lifecycle (R2.3, R10.3). Sends committed messages; never lets the engine scrape app-data directories. |
| Task outcome | Derives an episode's outcome from receipts (`learning.episodes.derive_outcome`). | Owns verification and attests receipts through a `VerificationAuthority`. |
| Procedures | Nomination, evidence counting, safety screen, state machine, versioned export. Never executes a step. | Runs evaluation through an `EvaluationRunner`, reviews, and decides activation and rollback. |
| Model providers | Capability negotiation, consent checks, guarded calls, validation of output, encrypted vector storage, external-deletion outbox (`providers`). | Registers provider objects, records consent, owns accounts, egress and cost. |
| Maintenance | Bounded, resumable units: `maintain`, `consolidate`, `process_provider_outbox`, `rotate_data_key`. | Schedules them (R16.6). Handoff 0002 runs `maintain` on a session boundary, at most once every 6 hours per adapter. |
| Repository observation | Registration, bounded snapshots, parsing without execution, hardened read-only git (`repository`). | Decides which roots are allowed (`HostCapabilities.allowed_repository_roots`) and when to snapshot. |
| Migration | Inventory, encrypted snapshot, idempotent import, verify, cutover, rollback (`migrations`). | Chooses the time, supplies the legacy key and a `quiesce` hook that drains host writes, and wires `OwnershipControl.writer_guard` into its legacy writer. |
| Deletion state across restores | Ledger, tombstones and reconciliation (`storage.ledger`, `storage.partition`). | Optionally stores a high-water mark through a `LedgerMirror`. |
| UI, routes, CLI | A diagnostic CLI for one local profile (`cli`). | All product surfaces. |

---

## 3. Package module map

All paths are under `src/locus_memory/`.

### 3.1 Top level

| Module | Owns | Key symbols |
|---|---|---|
| `__init__` | Public names; no side effects on import. | `MemoryEngine`, `KeyProvider`, `StaticKeyProvider`, `FileKeyProvider`, `HostCapabilities`, `EngineConfig`, `CancellationToken` |
| `engine` | The single public entry point. Opens one `PartitionContext` per partition lazily, reconciles deletions before serving, applies the ownership fence, and builds the plaintext export document (returned, never written). | `MemoryEngine`, `MemoryEngine._fence`, `MemoryEngine.partition_context`, `MemoryEngine.export` |
| `host` | Host-supplied capabilities and engine configuration; host protocols. | `HostCapabilities`, `EngineConfig`, `TokenCounter`, `VerificationAuthority`, `EvaluationRunner`, `CancellationToken`, `Deadline` |
| `models` | Typed, validated, versioned public models (`API_VERSION = "1.0"`). Partition, scope, kind, storage role and lifecycle are independent dimensions. The boolean input flags that change what is stored or served (`allow_sensitive` of `RememberRequest` and `Correction`, `Retention.pinned`, `Confidence.calibrated`, `SourceRef.available`, `Query.include_stale`, `IngestionEvent.is_memory_injection` / `is_generated_summary`, and every `ForgetPolicy` flag) accept only real bools, so `"false"` is no longer true (`tests/test_review_round3_batch3.py::test_api2_boolean_fields_accept_only_real_booleans`). A forget refuses a target or policy of the wrong type before anything reaches the ledger (`forgetting._check_request`; `tests/test_review_round3_batch1.py::test_api1_a_non_policy_is_refused_before_anything_is_recorded`). | `PartitionRef`, `Scope`, `ScopeGrants`, `AccessContext`, `MemoryRecord`, `RememberRequest`, `CandidateProposal`, `Correction`, `Query`, `SearchResult`, `ContextRequest`, `ContextPacket`, `IngestionEvent`, `EpisodeReport`, `ProcedureDraft`, `ForgetTarget`, `ForgetPolicy`, `ForgetReceipt`, `Receipt`, `EngineStatus` |
| `policy` | Authorization checks, applied before content is read. | `require`, `require_scope`, `require_author`, `require_reviewer`, `require_visible`, `narrow` |
| `services` | Per-partition service wiring and the `purge` / `reencrypt` hook conventions that forgetting and key rotation rely on. | `PartitionContext`, `Services`, `build_services` |
| `core` | Canonical memory lifecycle and its transition table; the write-time secret and sensitive gate; the "servable now" predicate of every egress path. | `CoreService` (`remember`, `propose`, `approve`, `reject`, `correct`, `set_pinned`, `supersede`, `expire_due`, `explain`, `unservable`), `ALLOWED`, `check_transition`, `gate_scan` |
| `forgetting` | Ledger-first forgetting, derived-state cascade, suppression, commit guards, propagation of deletions to migration copies. | `ForgettingService` (`forget`, `preview`, `apply_tombstone`, `commit_guard`, `blocked_reason`, `propagate_to_migration_copies`) |
| `crypto` | Envelope encryption for one partition, key providers, keyed tokens. | `KeyProvider`, `StaticKeyProvider`, `FileKeyProvider`, `PartitionKeyring`, `derive_subkey` |
| `admin` | Master-key re-wrap and progressive data-key rotation; flushing old key material. | `rotate_master_key`, `rotate_data_key`, `data_key_rotation_status`, `flush_key_material`, `reencrypt_table` |
| `status` | Status scoped to the caller's authorized namespace. | `build_status` |
| `safety` | Defense-in-depth content checks: secret detection and redaction, instruction-like flagging, sensitive-category detection. | `scan`, `redact_secrets` |
| `validation` | Bounds for identifiers, text, numbers, timestamps, lists, booleans and mapping nesting depth. | `check_id`, `check_text`, `check_int`, `check_timestamp`, `check_bool`, `check_depth` (`MAX_MAPPING_DEPTH = 32`) |
| `errors` | Typed errors. | `AccessDenied`, `NotFound`, `VaultLocked`, `WrongKey`, `RevisionConflict`, `IntegrityError`, `Contention`, `StorageUnavailable` (`StorageFull`, `StorageReadOnly`: disk full, read-only files and I/O errors, never reported as `Contention`), `UnsupportedCapability`, `ConsentRequired`, `SensitiveContent`, `ReconciliationRequired`, `OwnershipFenced`, ... |
| `observability` | In-process, content-free counters, timings and gauges. | `Metrics` |
| `cli` | The `locus-memory` diagnostic CLI for one local profile. It acts as its own host: file key, local user, grants from flags. | `main` |

### 3.2 Subpackages

| Subpackage | Owns | Key symbols |
|---|---|---|
| `storage/` | SQLite connections and pragmas (`db`), schema and migrations (`schema`), one partition's database, keyring, receipts, idempotency and reconciliation (`partition`), sealed records with authorization in SQL (`records`), and the deletion ledger (`ledger`). | `Database`, `memory_connection`, `fts5_available`, `schema.migrate`, `Partition`, `Partition.reconcile`, `partition_bound`, `RecordStore`, `RecordStore.authorized`, `DeletionLedger`, `LedgerMirror`, `MemoryLedgerMirror` |
| `retrieval/` | Query parsing and FTS escaping (`query`), in-memory lexical indexes (`index`), rank fusion, validity, de-duplication, diversity and snippets (`ranking`), the search pipeline (`service`). | `parse_query`, `Fts5Index`, `PythonIndex`, `rrf_fuse`, `mmr_select`, `RetrievalService` |
| `context/` | Hot-context compilation and revalidation (`compiler`), token metering and budgets (`budget`), public markers of a rendered block (`markers`). | `ContextCompiler`, `TokenMeter`, `Budget`, `CONTEXT_WRAPPER_OPEN`, `is_context_block`, `contains_context_block` |
| `history/` | The encrypted session-history archive: idempotent ingestion, cursors, gaps, authorized search, scroll and browse, correction flags. | `HistoryArchive` |
| `learning/` | Task episodes with derived outcomes (`episodes`), governed procedural candidates (`procedures`), bounded maintenance and consolidation jobs (`consolidation`). | `EpisodeService`, `derive_outcome`, `ProcedureService`, `screen_draft`, `ConsolidationService` |
| `repository/` | Registration and bounded snapshots (`service`), path safety and exclusions (`scanner`), hardened read-only git (`git`), parsing facts without execution (`observations`), the versioned interchange format (`interchange`). | `RepositoryService`, `Git`, `check_root`, `validate_document`, `RepositoryIntelligenceProvider`, `SyntheticRepositoryProducer` |
| `providers/` | Provider contracts, consent and guarded calls (`base`), per-partition orchestration (`hub`), encrypted versioned vectors (`embeddings`), deterministic test doubles (`fake`). | `EmbeddingProvider`, `Reranker`, `Extractor`, `Summarizer`, `ExternalMemoryService`, `ProviderDescriptor`, `ConsentPolicy`, `ConsentGrant`, `StaticConsentPolicy`, `GuardedCall`, `ProviderHub` |
| `migrations/` | The canonical-ownership state machine with writer fencing (`state`), legacy inventory, snapshot, import and verify (`legacy`), cutover and rollback orchestration (`cutover`). | `OwnershipControl`, `LegacyMapping`, `LegacyImporter`, `inventory`, `snapshot`, `verify`, `Migrator`, `abort_cutover` |
| `compat/` | Format-compatible code extracted from Locus `memory.py` and `continuity.py`, with the safety fixes listed in its module docstring (wrong-key detection, no re-targeting, D1, D23, D24, D25, `write_guard`). Two more are not in that list: every connection to a legacy file sets `secure_delete` (`compat.legacy_vault._connect_legacy`), and `LegacyContinuityStore` also verifies its key and raises `LegacyWrongKey` (`tests/test_review_group1.py::test_continuity_store_fails_closed_on_a_wrong_key`). | `LegacyMemoryVault`, `LegacyContinuityStore`, `legacy_workspace_hash`, `legacy_agent_hash` |
| `evaluation/` | The offline chronological benchmark ([evaluation.md](evaluation.md)). Not used by the engine at runtime. | `generate_corpus`, `ARMS`, the runner in `evaluation.runner` |
| `testing/` | Empty package. No test helpers ship in it yet. | none |

Services are constructed once per partition by `services.build_services` and reach each other late
through `PartitionContext.services`. A service that stores data derived from forgettable inputs
implements `purge(conn, target_kind, target_token, policy)`, which the forgetting service calls inside
the deletion transaction. A service that owns sealed tables implements `reencrypt(...)` so a data-key
rotation can finish (`admin.rotate_data_key` stays blocked while any sealed table still references a
retiring key).

---

## 4. Storage layout

```
<root>/                                     MemoryEngine(root, keys, ...)
  control.sqlite3                           OwnershipControl; created only by a host or CLI that migrates
  <partition_id>/                           one directory per PartitionRef, mode 0700
    memory.sqlite3  (+ -wal, -shm)          everything the partition stores (WAL mode)
    deletion-ledger.sqlite3                 append-only, MAC-chained deletion ledger, its MACed
                                            per-entry outcomes (ledger_outcomes), plus the
                                            sealed, mutable forget_requests table (see below)
<key directory>/                            FileKeyProvider only (CLI default: <root>/keys)
```

`<partition_id>` is `PartitionRef.partition_id`: `"p"` plus 31 hex characters of a SHA-256 over the
edition and profile labels. The main database holds the sealed records and their revisions, the scope
and source index (keyed tokens), tombstones, receipts, idempotency rows, key wraps, the history
archive, repository registrations and observations, episode and procedure indexes, encrypted vectors,
the provider outbox and usage log, consolidation jobs, and the migration bookkeeping tables
`migration_cutover_ids`, `migration_recovery_ids`, `migration_scope_covered` and the legacy
`migration_forgets` (`storage.schema`). Its `meta` table carries, next to the plaintext
`deletion_generation` counter, an authenticated deletion checkpoint (`DELETION_CHECKPOINT_KEY`: the
generation plus a keyed tag; `Partition._checkpoint`, written with the counter by
`Partition._set_deletion_generation`). Ledger replay trusts the checkpoint, never the plaintext
counter (`Partition._applied_generation`; §6.7).

The deletion-ledger file holds more than the ledger table. After an entry is applied, its outcome
(the ids of every record it removed, the suppression keys and the source aliases it recorded; keyed
tokens and opaque ids only) is kept there, MACed and bound to its entry, in `ledger_outcomes`
(`storage.ledger.DeletionLedger.record_outcome` / `.outcomes`, through `Partition.record_outcome`).
Reconciliation rebuilds the main database's deletion state from it (§6.7).
`storage.partition.Partition` also keeps
a `forget_requests` table there (`Partition._requests_conn`). Unlike the ledger it is mutable. A
forget writes one row (`Partition.record_forget_request`) **before** its write-ahead ledger append
and binds it to the appended generation. The row's sealed payload holds the caller's access context,
the target's kind (never its ref) and the policy. Its clear columns hold the target kind, keyed target token, policy and
keyed idempotency token. Whoever applies that ledger entry (the forget itself, a later forget, or
reconciliation in any process) uses the row to apply it with the original caller's access and to
record the caller's receipt. Rows are deleted once their entry is applied, and unbound rows older
than ten minutes are deleted too (`Partition.drop_forget_requests`); the ledger file's WAL is then
checkpointed with the main database's (`Partition.flush_purged` → `Partition._checkpoint_all`).

Encryption at rest (`crypto`):

* Each partition has random 256-bit data-encryption keys and one HMAC key. They are wrapped with
  AES-256-GCM under host master keys and stored in `key_wraps`.
* Every sealed row uses AES-256-GCM with a random 96-bit nonce. The associated data binds the
  partition, table, row id and the security metadata kept in clear columns (revision, lifecycle,
  kind, scope hash, data-key id), so moving or relabelling a row makes decryption fail
  (`tests/test_storage.py::test_relabelled_metadata_is_never_served`,
  `::test_ciphertext_moved_between_rows_fails`).
* Clear columns hold ids, kinds, lifecycle, revisions, timestamps and keyed HMAC tokens (scope values,
  sources, content fingerprints). `status.build_status` reports this as a limitation.
* A missing or locked key raises `VaultLocked`, and a key that fails to authenticate raises `WrongKey`.
  Neither ever causes a new key to be generated for an existing vault
  (`tests/test_storage.py::test_wrong_key_is_refused_and_never_replaced`,
  `::test_missing_or_locked_key_is_vault_locked_and_never_replaced`). With
  `MemoryEngine(..., create_partitions=False)` a missing vault raises `NotFound` and nothing is created
  (`tests/test_storage.py::test_open_existing_only_engine_refuses_a_missing_vault_and_creates_nothing`).
  A deletion ledger without its main database is refused
  (`tests/test_review_group1.py::test_missing_database_next_to_a_ledger_is_refused_without_new_keys`).

Every connection to an on-disk database (store, ledger, control file) sets `secure_delete=ON`,
`temp_store=MEMORY`, `trusted_schema=OFF`, `synchronous=FULL` and `foreign_keys=ON`
(`storage.db.Database`). Search projections live only in
`:memory:` connections (`storage.db.memory_connection`); there is no plaintext search file on disk
(R8.4; `tests/test_retrieval.py::test_fts_projection_is_memory_only`). A canary test scans every
file under the engine root (database, WAL, ledger) and the log and error output for plaintext
(`tests/test_storage.py::test_canary_never_reaches_disk_logs_or_errors`). A search test checks that
nothing spills into a redirected temp directory (`TMPDIR` and `SQLITE_TMPDIR`); it covers the search
path only (`tests/test_retrieval.py::test_search_never_writes_plaintext_to_disk`).

Concurrency: one `Database` per file, per-thread connections, `BEGIN IMMEDIATE` writes and a bounded
busy timeout. Writers in several processes on one store are tested
(`tests/test_concurrency.py::test_multiprocess_writers_never_corrupt_the_store`), and contention
beyond the bound surfaces as the typed `Contention` error
(`tests/test_concurrency.py::test_bounded_contention_surfaces_as_contention`). A full disk, an I/O
error or a read-only file is never reported as contention: `storage.db` classifies SQLite failures by
result code and raises `StorageFull`, `StorageReadOnly` or `StorageUnavailable` (CLI exit code 4)
(`tests/test_review_round2_batch3.py::test_cd5_a_full_disk_is_a_typed_storage_error_not_contention`,
`::test_cd5_sqlite_full_is_storage_full`, `::test_cd5_a_read_only_vault_raises_a_typed_error`). Long
batched jobs (a repository snapshot's commit) commit in bounded transactions and yield the write lock
to waiting writers between them (`Database.yield_to_writers`). `storage.db.Database.close` is
thread-safe: it closes only the calling thread's connections and those of finished threads. Another
live thread's connection is closed on that thread's next access, which raises
`MemoryEngineError("database is closed")` and never crashes the process
(`tests/test_db_close.py::test_engine_close_while_other_thread_works`,
`::test_close_from_another_thread_defers_busy_connections`).

FTS5 is used when the interpreter's SQLite has it (the bundled Locus runtime, CPython 3.14.6 with
SQLite 3.53.1, does). It is not assumed (R3.6): retrieval falls back to a pure-Python BM25 index
(`retrieval.index.PythonIndex`; `tests/test_retrieval.py::test_python_fallback_path`) and reports the
fallback in its coverage.

---

## 5. Partition and AccessContext model

### 5.1 Three layers of separation

1. **Partition, the security domain.** `models.PartitionRef(edition, profile)`, for example
   `("locus", "default")` or `("locusx", "default")`. Each partition has its own directory, database,
   ledger and keys. No API reads across partitions, and statistics never span partitions (R7.3).
   Services refuse an `AccessContext` that belongs to another partition (`storage.partition.partition_bound`;
   `tests/test_review_group1.py::test_services_reject_an_access_context_of_another_partition`).
   Tests: `tests/test_core.py::test_profiles_are_separate_stores`,
   `tests/test_retrieval.py::test_cross_profile_isolation`, `tests/test_context.py::test_cross_profile_isolation`.
2. **Scope, inside a partition.** `models.Scope` is a set of `(dimension, value)` constraints over
   `project`, `repository`, `worktree`, `agent`, `team`, `session`, `device` and `legacy_target` (the
   last holds Locus target hashes that cannot yet be mapped to a host id). Constraints intersect: a
   record scoped `{project: P, agent: A}` is visible only to a caller granted both P and A. An empty
   scope is profile-global: global within that partition only (R5.2).
3. **Kind and lifecycle,** which are independent of scope: kinds `preference`, `fact`, `decision`,
   `constraint`, `relationship`, `repository_observation`, `episode`, `procedure`, `summary`;
   lifecycles `candidate`, `approved`, `rejected`, `stale`, `superseded`, `expired`, `forgotten`.

### 5.2 AccessContext

`models.AccessContext` carries `principal`, `partition`, `actor` (`user`, `agent`, `tool`, `system`,
`host`, `provider`), `grants` (`models.ScopeGrants`: a set of allowed values per dimension),
`operations` (`read`, `write`, `propose`, `approve`, `forget`, `export`, `ingest`, `maintain`, `admin`),
`purpose` and `issuer`.

The host builds it from authenticated state only. Nothing read from the store, a transcript, a
repository or a provider can widen it (R7.1, R7.4):

* `ScopeGrants.allows(scope)` is true only when every constraint value of the scope is granted.
* Scope filters in queries can only narrow the grants (`policy.narrow`;
  `tests/test_core.py::test_scope_filter_narrows_and_cannot_widen`).
* A missing record and an unauthorized record give the same `NotFound` (`policy.require_visible`).
* Approval needs an actor the host lists in `HostCapabilities.approval_actors` (default `{user}`).
  Model confidence never approves anything, and an agent can approve only if the host deliberately
  adds it to that set.

| Operation | What it permits | Extra actor rule |
|---|---|---|
| `read` | get, list, explain, search, build/revalidate/explain context, history search/scroll/browse, status; also required, together with `export`, by `MemoryEngine.export(include_history=True)` | none |
| `write` | remember, correct, pin | actor `user` or `host` (`policy.require_author`) |
| `write` or `admin` | register a repository (`RepositoryService.register`) | actor `user` or `host`, checked by `RepositoryService.register` itself |
| `write` or `ingest` | record an episode (`EpisodeService.record`, `_require_report_permission`) | none: agents may record episodes (`tests/test_learning.py::test_episode_permissions_and_scope_bounds`); the outcome is still derived from host receipts (§6.9) |
| `propose` | propose candidates, nominate procedures, propose episode lessons, import a repository interchange document (`RepositoryService.import_interchange`) | a non-attesting actor's basis claim is downgraded to `model_interpretation` and some kinds are refused |
| `approve` | approve, reject, supersede; approve or reject procedures | actor in `approval_actors` (`policy.require_reviewer`) |
| `forget` | forget, preview_forget; `ProviderHub.withdraw_external` (`forget` or `admin`) | actor `user` or `host`; broad targets that cover records hidden from the caller need `admin`; without `admin`, `withdraw_external` refuses when the provider holds items outside the caller's grants |
| `export` | plaintext export document, procedure export, repository interchange export (`RepositoryService.export_interchange`), external sync (with `read`) | export of procedures: actor `user` or `host` |
| `ingest` | history ingestion; repository snapshots (also `write` or `admin`) | none |
| `maintain` | maintain, consolidate, invalidate, procedure evaluation; provider outbox, `reconcile_external`, provider usage and `drop_unregistered_models` (these four also accept `admin`) | none |
| `admin` | key rotation, reconciliation, profile forget, legacy import and cutover (`migrations`) | actor `user` or `host` for key rotation and reconciliation |

Tests: `tests/test_core.py::test_scoped_records_are_visible_only_with_every_grant`,
`::test_every_record_operation_hides_out_of_scope_records`,
`::test_non_user_actors_cannot_write_review_or_forget_even_with_every_operation`,
`::test_agent_proposals_are_bounded_by_grants_and_verifiable_evidence`,
`tests/test_review_group1.py::test_agent_cannot_assert_user_stated_basis`.

### 5.3 Where the check happens

Every read starts with the operation check and the partition check. Scope is then enforced in one of
two ways:

* **Collection reads filter in SQL before decrypting.** list, search, context compilation, export
  and repository-registration loads filter by scope **in SQL** over keyed scope tokens
  (`storage.records.RecordStore.authorized` over `record_scopes`; `RepositoryService._load` over
  `repo_scopes`). Only rows that pass are decrypted. After decryption the row's own scope is checked
  against the grants again, and the plaintext scope index must match the authenticated scope's
  index rows exactly (`RecordStore.iter_authorized`, `RecordStore.scope_index_rows`); any
  disagreement raises `IntegrityError` instead of serving the row
  (`tests/test_review_round4_batch1.py::test_tamper2_a_stripped_scope_index_fails_closed_instead_of_serving`).
* **Single-record reads by id decrypt, then check.** `CoreService.load_visible` calls
  `RecordStore.get`, which decrypts the addressed row (`RecordStore._decode`), and then
  `policy.require_visible`, which refuses it with `NotFound` when its scope is outside the grants.
  This path serves get, explain, approve, reject, correct, pin and supersede.
  `ProcedureService._load_visible` and a forget of a `memory` target (`ForgettingService._authorize`
  via `ForgettingService._load`) work the same way. An out-of-scope row is therefore decrypted in
  memory, but its content is never returned, and the caller cannot tell it from a missing one. No test
  asserts the decryption order on this path.

On both paths every decrypted record is checked against its clear columns: `RecordStore._decode`
refuses a row whose clear revision, lifecycle, kind or scope token, or whose time columns
`expires_at`, `valid_from`, `valid_until` and `pinned`, differ from the authenticated payload
(`records._time_columns_match`). An edited time column therefore fails closed with `IntegrityError`
instead of being served or steering maintenance and external withdrawal
(`tests/test_review_round4_batch3.py::test_tamper6_relabelled_time_columns_are_never_served`).

Observations of paths the **current** exclusion set covers (the registration's exclusions plus the
host's, even when the exclusion was added after ingest) are hidden on every read path:
`RepositoryService.excluded_observations` is applied by get, list and explain
(`CoreService._excluded`), search, context compilation and revalidation, export, and every egress
path (through `CoreService.unservable`). This covers interchange-imported records and records derived
from or citing such an observation, up to a depth bound (`RepositoryService._DERIVATION_DEPTH`, 8)
(§6.8).

There is no "rank the whole corpus, then filter" path (R7.3;
`tests/test_storage.py::test_scope_index_tampering_never_leaks_a_record`,
`tests/test_retrieval.py::test_cross_scope_isolation_hits_and_counts`). Counts in status, coverage
and receipts are computed over the authorized namespace only
(`tests/test_core.py::test_status_counts_only_the_authorized_namespace`).

The history archive (`history_session_scopes`) and repository registrations (`repo_scopes`) keep
keyed scope-token indexes of the same kind; procedures are memory records and use `record_scopes`
(loaded by id as described above). A history session is bound to the scope of its first event, and a
later event under another scope is refused.

---

## 6. Data flows

Every write returns a `models.Receipt` that is created inside the committing transaction, so a
receipt never exists for a change that did not commit (R6.7). Writes that change canonical records
bump the partition `generation`, which invalidates search projections and compiled context packets.

### 6.1 remember

`MemoryEngine.remember(access, RememberRequest)`:

1. `MemoryEngine._fence` asks `HostCapabilities.ownership` (if set) whether the package may write the
   `memories` family of this partition; if not, `OwnershipFenced` (§7.2).
2. `core.CoreService.remember` checks `policy.require_author` (operation `write`, actor `user` or
   `host`) and `policy.require_scope` for the requested scope. Episode and procedure kinds are refused
   here; they have their own services.
3. `core.gate_scan` (over `safety.scan`) runs over content, title and tags (what search and context
   render) and over the other free text the record stores (reason, subject, predicate). A
   credential in any of them raises `SensitiveContent`; so does a sensitive personal category,
   unless the host sets `allow_sensitive` because the user explicitly asked (R5.3). Only the
   rendered text sets the `instruction_like` flag; instruction-like text is stored but flagged. The
   same helper gates proposals (`CoreService._check_proposal`: rationale, subject and predicate too,
   and the proposer label for credentials only) and corrections (`CoreService.correct`: the reason
   too); `CoreService.reject` redacts secrets from its reason instead of refusing it.
4. In one write transaction: an idempotency replay returns the original receipt; an id that belongs
   to a forgotten memory is refused; sources are verified (`CoreService.verify_sources`); the record is
   created as `approved` with the user's scope; structured conflicts are linked;
   `CoreService._commit_write` re-checks the ownership fence inside the transaction, bumps the
   generation, and `RecordStore.write` seals the payload and writes the scope and source tokens and a
   revision row.
5. The receipt (with conflicts and possible conflicts) and the idempotency row are written in the same
   transaction. The caller gets a `WriteResult` whose record is a presentation: links to records it
   cannot see are removed.

`CoreService.possible_conflicts` (the legacy-compatible topic-overlap heuristic) runs inside that
write transaction, so it is bounded: it reads only approved records of exactly the new record's
scope (selected in SQL by scope token), decrypts at most `core.CONFLICT_SCAN_LIMIT` (200) of them,
most recently updated first, and returns at most 12 ids. When the scope holds more, the receipt
carries `core.CONFLICT_SCAN_LIMITATION`
(`tests/test_review_round2_batch4.py::test_rob7_remember_decrypts_a_bounded_number_of_records_in_its_write_transaction`).

Tests: `tests/test_core.py::test_idempotent_remember_replays_without_a_second_record`,
`::test_corrections_and_memories_never_store_secrets`,
`tests/test_review_group1.py::test_remember_refuses_a_forgotten_memory_id`,
`tests/test_review_round3_batch3.py::test_api3_remember_refuses_secrets_in_every_stored_field`,
`::test_api3_agent_proposals_are_gated_on_every_stored_field`,
`::test_api3_correct_and_reject_never_store_a_credential_in_the_reason`.

### 6.2 propose

`MemoryEngine.propose(access, CandidateProposal)` → `CoreService.propose`:

1. Fence, then `CoreService._check_proposal`: operation `propose`, granted scope, no managed kinds.
   An actor that is not a trusted attester (`agent`, `tool`, `provider`) may propose only
   `preference`, `fact`, `decision`, `constraint`, `relationship` and `summary` records
   (`core.PROPOSABLE_KINDS`), and its claim that the user stated or that it observed something is
   downgraded to `model_interpretation`. Secrets in any stored field are refused (`core.gate_scan`,
   §6.1); sensitive content is refused unless the basis is `user_stated` from an attesting actor.
2. In the write transaction, `verify_sources` checks each cited source with the sibling service that
   owns it: messages and sessions with `history`, episodes and task attempts with `episodes`, commits
   and blob ranges with `repository`, verification receipts with the host `VerificationAuthority`.
   An agent cannot cite evidence that cannot be verified (R6.4).
3. `CoreService.evidence_scope` narrows the declared scope to the union of the constraints of its
   `derived_from` parents and of every cited source whose owner reports a scope
   (`CoreService.source_scope`: a memory's own scope, the session of a message, the episode of a task
   attempt, the registration of a repository commit or blob range), so a project transcript cannot
   surface as a profile-global candidate. A declaration that conflicts with its evidence raises
   `ValidationError`, and the merged scope must be granted
   (`tests/test_review_round4_batch1.py::test_eg1_derived_from_parent_scope_narrows_the_proposal`,
   `::test_eg1_episode_and_task_attempt_evidence_narrow_the_proposal`,
   `::test_eg1_repository_evidence_is_narrowed_to_the_repository_scope`).
4. A self-asserted calibrated confidence from a model is relabelled `model_uncalibrated` (R6.5).
5. The candidate gets a TTL (`EngineConfig.candidate_ttl_seconds`, 30 days, as in Locus), capped at
   the earliest expiry of its transient inputs: its `derived_from` parents and the cited memories it
   follows (`CoreService.followed_citations`). The cap is recorded as `extra.inherited_retention`
   (`tests/test_review_round4_batch2.py::test_eg2_a_citer_candidate_inherits_the_capped_ttl`).
   `CoreService._derivation_inputs` refuses a proposal derived from, or citing, a memory that is
   rejected or expired (also at read time) with `StaleDerivation`, and one whose input is an
   observation of a now-excluded path with `NotFound`
   (`tests/test_review_round3_batch2.py::test_eg4_a_proposal_is_never_derived_from_a_rejected_memory`);
   a forgotten input no longer exists and is refused before that (`verify_sources`,
   `ForgettingService.blocked_reason`). A forgotten or suppressed source refuses it
   (`SuppressedError`); an identical live record makes it a `noop` pointing at that record.

Candidates are never served in search by default or injected into context, and nothing becomes
approved silently (`tests/test_core.py::test_candidates_are_never_served_or_silently_approved`).

### 6.3 approve, reject, correct

`MemoryEngine.approve(access, id, expected_revision=..., resolution=..., expected_conflicts=...)` →
`CoreService.approve`:

1. Fence; `policy.require_reviewer`.
2. Load the record as visible to the caller, check `expected_revision` (`RevisionConflict` on a
   mismatch), refuse a candidate past its TTL, check the transition against `core.ALLOWED`, and refuse
   a suppressed record or one whose derivation inputs changed.
3. `resolution="supersede"` retires only the conflicts the reviewer saw: those recorded on the
   candidate, or exactly `expected_conflicts` (a different visible set raises `RevisionConflict`).
   Conflicts that appeared after review stay and are reported as `new_conflicts`.
4. Commit a new revision as `approved` and return the receipt. Approval drops a candidate's TTL,
   except that a derived candidate (a summary, an extraction, any proposal with `derived_from` or
   followed citations) takes over the retention of its transient inputs
   (`CoreService._approved_retention`); approval raises `StaleDerivation` once that retention has
   ended
   (`tests/test_review_round2_batch2.py::test_sl5_a_summary_cannot_be_approved_once_its_inputs_expired`,
   `tests/test_review_round3_batch2.py::test_eg3_an_approved_derivation_keeps_its_inputs_expiry`).
   Re-approving a record whose validity ended clears its `valid_until`.

`reject` and `supersede` use the same reviewer check. Superseding (`resolution="supersede"` and
`CoreService.supersede`) stales approved records derived from the superseded memory and expires
pending ones, at any depth, but never the superseder itself, even when it is derived from the
memory it replaces (`tests/test_review_round4_batch2.py::test_eg4_supersede_invalidates_every_level`,
`tests/test_review_round4_batch1.py::test_rg1_approve_supersede_with_an_update_derived_from_the_superseded_memory`).

`correct` (author check) writes a new revision, re-runs the secret and sensitive gates (§6.1) and
recomputes the record's structured conflicts. When the content changes it also:

* records the history sources of the corrected-away revision, so archived messages are flagged
  `superseded_by_correction`;
* marks every record derived from the old content stale (approved) or expired (pending),
  transitively at any depth: summaries, extractions, proposals with `derived_from` or
  `input_revisions`, and records that cite it and follow the citation (`CoreService._stale_derived`,
  an iterative work list; `CoreService.followed_citations`);
* suppresses relearning the old statement from the same sources;
* re-attests the basis as `user_stated` by the corrector (`extra.basis_attested_by`), which
  forgetting reads (§6.7);
* marks a corrected derived record `inputs_detached`, so it no longer follows its inputs.

Tests: `tests/test_core.py::test_stale_expected_revision_is_a_conflict`,
`::test_approve_supersede_retires_the_conflicting_memory`,
`tests/test_review_group1.py::test_supersede_retires_only_the_conflicts_the_reviewer_saw`,
`tests/test_core.py::test_transition_table_is_exactly_the_documented_one`,
`tests/test_review_round4_batch2.py::test_eg4_correction_invalidates_every_level`,
`tests/test_review_round3_batch2.py::test_eg3_correcting_an_input_stales_approved_and_expires_pending_derivations`,
`tests/test_review_round2_batch2.py::test_fg6_a_user_correction_reattests_the_basis_so_other_evidence_keeps_the_memory`.

### 6.4 search

`MemoryEngine.search(access, Query | str)` → `retrieval.service.RetrievalService.search`. Each stage
checks cancellation and the deadline; an interrupted search returns what completed, marked `partial`
or `cancelled`.

1. **Authorized namespace.** Operation `read`, grants narrowed by `Query.scope_filter`, scope enforced
   in SQL. Unauthorized rows are never decrypted, ranked or counted.
2. **Exact lookups.** Query tokens that look like memory ids are looked up directly; identifiers,
   paths and dates form an `exact` ranker.
3. **Lexical.** An in-memory projection of the authorized records: FTS5 BM25 over text, whole
   identifiers, the exact phrase and prefixes (`retrieval.index.Fts5Index`), or the Python BM25
   fallback. FTS input is built from quoted literals only (`retrieval.query`;
   `tests/test_retrieval.py::test_fts_syntax_injection_is_inert`).
4. **Semantic (optional).** `providers.hub.ProviderHub.semantic_scores` when an embedding provider is
   registered and usable (§6.12). Not configured is not a coverage gap; a provider failure marks the
   result `partial` and never fails the lexical path
   (`tests/test_retrieval.py::test_semantic_failure_degrades_to_partial`).
5. **Fusion.** Reciprocal Rank Fusion with k = 60 (`retrieval.ranking.rrf_fuse`). BM25 values and
   cosine similarities are never added together; scores are labelled (`score_kind`) and are not
   probabilities (R11.4). Direction and fusion arithmetic:
   `tests/test_retrieval.py::test_bm25_direction_fts5_lower_is_better`,
   `::test_rrf_formula_and_duplicates`. The `score_kind="rrf"` label:
   `::test_ordinary_text_returns_relevant_record_first`, `::test_index_status_and_engine_status`.
6. **Validity.** Future `valid_from` is excluded; ended validity and stale, superseded or expired
   lifecycles are historical (`current=False`) and demoted. Stale records need `include_stale`. A
   candidate past its TTL is never returned, even before maintenance runs.
7. **De-duplication** by normalized content, then **diversity** by MMR (`retrieval.ranking.mmr_select`).
8. **Bounded result.** At most `limit` hits. If the partition changed during the search, hits are
   re-verified (still present, same revision, still authorized). Snippets are secret-redacted and
   markup-neutralized.

Status: `complete` when at least one hit is a lexical or exact match; `insufficient_evidence` when
there is no hit or only weak (semantic-only) hits; `partial` when coverage is incomplete (projection
bounds, deadline, unreadable rows, failed ranker); `unavailable` when authorized records exist but none
could be indexed; a locked vault raises `VaultLocked` rather than returning "no results" (R19.6).
Projections are cached per (generation, grants fingerprint, filters) and bounded by
`EngineConfig.max_projection_records` and `max_projection_bytes`; records past the bound are reported
in `coverage.missing` (`tests/test_retrieval.py::test_projection_bound_records_partial_and_never_silent`).

Search never writes: no use counts, confidence or timestamps change
(`tests/test_retrieval.py::test_search_does_not_write_or_inflate_confidence`), and a concurrent forget
drops the hit (`tests/test_retrieval.py::test_concurrent_forget_during_search_drops_hit`).

### 6.5 build_context and revalidate_context

`MemoryEngine.build_context(access, ContextRequest)` → `context.compiler.ContextCompiler.build`. Hot
memory is a compiled view, never a separate writable store (R9.1).

1. After the `read` and partition checks, `EngineConfig.serving_mode == "disabled"` returns an empty
   packet with status `unavailable`: no record is read and no receipt is written, although the engine
   has already opened (and, by default, created) the partition (§7.1).
2. In one read snapshot it loads the caller's authorized **approved** records (candidates, rejected,
   stale, superseded, expired and forgotten are never injected) and the sources the caller may see.
   Episodes and procedures are injected only when their own service governs them.
3. **Selection.** `ContextRequest.slices` are caps, not targets. The default slices are user
   preferences (500), profile facts (800), project and repository (1200), agent (400), episodes (600)
   and procedures (600) tokens. All slices compete round-robin for the host's `token_allowance`.
   Relevance slices order by `RetrievalService.rank` when a query is given; if ranking fails they fall
   back to pinned and recency order and the packet is `partial`. `exclude_ids` (already injected by
   another path) and content duplicates are skipped. `max_items` caps the count. Conflicts are
   annotated visibly, or both sides omitted with `conflict_policy="omit"`.
4. **Budget.** Everything rendered is counted: wrapper, preamble, labels, ids, flags and conflict
   notes. The count comes from the host `TokenCounter` when one is given (`measured`), otherwise from a
   conservative estimator (`estimated`). Tokenizers are not additive, so the final text is re-counted
   and trimmed until it fits. A memory that does not fit is omitted, never truncated: with reason
   `budget` when the shared allowance cannot hold it, `slice_cap` when its slice's cap cannot, each
   with its measured token count. Empty or irrelevant memory yields empty text and zero tokens (R9.3).

   Rendering (redaction, safety scan, neutralization) and tokenizing is the expensive part, so
   selection is bounded independently of the number of approved records: a slice stops evaluating
   its queue after refusing 32 candidates that would have fit it empty (it is crowded,
   `compiler._MAX_SLICE_MISSES`) or 64 candidates too large for it on their own
   (`_MAX_SLICE_OVERSIZED`; those are not evidence that it is full, so a small memory queued behind
   large ones is still selected). The memories it did not evaluate are omitted as `budget` /
   `slice_cap` only when not even the shortest possible line fits the room left (once that holds, the
   slice renders nothing more). Otherwise they are
   omitted as `not_evaluated` (no token count: one of them might have fit) and the packet is `partial`
   with `R_SELECT_TRUNCATED`. That outcome is deterministic for a store generation and request, so the
   packet is cached like a complete one.
5. **Rendering.** One block between `context.CONTEXT_WRAPPER_OPEN` and `CONTEXT_WRAPPER_CLOSE`, with
   a preamble that marks the records as data, not instructions. Wrapper-like markup inside records is
   neutralized. Hosts use `context.contains_context_block` to recognise injected blocks and archive
   them with `is_memory_injection=True` (§6.6).
6. **Deadline.** `ContextRequest.deadline_ms` and cancellation are checked cooperatively in every
   stage, and each cut is a content-free partial reason (`context.compiler`):
   * `R_LOAD_DEADLINE`: records are decrypted and planned in chunks in pinned/recency order (the
     first chunk always), so an expired deadline builds the packet from the pinned/most recent ones;
   * `R_RANK_DEADLINE`: relevance ranking was skipped, relevance slices used pinned/recency order;
   * `R_SELECT_DEADLINE`: selection stopped before every queued memory was evaluated, so fewer
     memories may have been selected than would fit.

   Relevance ranking and history search are forwarded only part of the deadline
   (`_UPSTREAM_DEADLINE_SHARE`, 80%): both spend what they are given (history keeps hydrating its
   projection until its deadline expires; a semantic provider may answer at the last moment), and the
   rest is kept for selection and the commit. Selection always completes its first round (every slice
   has one turn) and evaluates at least `_SELECT_MIN_EVALUATIONS` (64) candidates before an expired
   deadline stops it, so a deadline spent upstream never reduces a packet to one memory per slice. A
   packet degraded by a deadline (or by a ranker, history or token-counter failure) is never cached;
   a retry compiles again. Other partial reasons include `R_RANK_UNAVAILABLE` / `R_RANK_FAILED` /
   `R_RANK_PARTIAL` / `R_RANK_PARTIAL_TRANSIENT` (ranking), `R_HISTORY_UNAVAILABLE` /
   `R_HISTORY_FAILED` / `R_HISTORY_PARTIAL` (history search), `R_COUNTER_FAILED` (host tokenizer),
   `R_TRUNCATED` (more approved records than `max_projection_records`), `R_SELECT_TRUNCATED` (bounded
   selection, step 4) and `R_FILTERED` (revalidation without the original request).
7. **Commit.** The receipt is written only if the partition generation is unchanged since the read;
   otherwise the compile is retried (up to three attempts, then `Contention`). A forget or correction
   that lands mid-compile therefore never leaks into a returned packet
   (`tests/test_context.py::test_forget_racing_a_compile_never_leaks`). Receipts hold ids, revisions,
   slice names, token counts, the snapshot hash and generations; never content, queries or paths. They
   are scrubbed when a referenced memory is forgotten.

`ContextPacket` returns the text plus selected ids and revisions, reasons, omissions, conflicts, token
count and kind, coverage, costs, the snapshot hash and content-free evidence flags
(`weak_evidence_only`, `history_weak_only`) (R9.4).

`MemoryEngine.revalidate_context(access, packet)` runs right before the model call (R9.5). Every
selected `(id, revision)` must still exist, be approved at that revision, be visible under the
**current** grants, be current, and not be tombstoned since compilation; the text must still match
the snapshot hash. If anything changed, the same request is recompiled (or, after a restart when the
request is no longer known, the old selection minus the changed items is returned). A packet that
carries a transient partial reason (`compiler._TRANSIENT_REASONS`: a ranker, history or
token-counter failure, or a deadline cut) is recompiled even when nothing changed, as long as its
request is still known
(`tests/test_review_round2_batch2.py::test_sl6_a_semantic_provider_failure_is_neither_cached_nor_revalidated`).
Tests:
`tests/test_context.py::test_correction_invalidates_cache_and_revalidate_detects`,
`::test_permission_revocation_excludes_project_records`,
`::test_historical_replay_never_overrides_current_deletion_or_access`,
`::test_measured_budget_counts_wrapper_and_never_exceeds`,
`::test_only_approved_current_records_are_injected`,
`::test_malicious_memory_cannot_change_allowance_or_access`.

### 6.6 ingest (session history)

`MemoryEngine.ingest_event(access, IngestionEvent)` → `history.archive.HistoryArchive.ingest`, which
runs the one event through `HistoryArchive.ingest_batch`. The public engine API has no batch method:
hosts that need atomic batches of up to 5,000 events (`history.archive.MAX_BATCH_EVENTS`) call
`MemoryEngine.services(access).history.ingest_batch`. The archive is retention only: nothing here
extracts, proposes or injects memories (R5.9).

1. Operation `ingest`, and the event's scope must be granted. `IngestionEvent` accepts only roles
   `user`, `assistant` and `tool`; hidden reasoning is rejected at validation
   (`tests/test_history.py::test_hidden_reasoning_roles_are_rejected`).
2. In one write transaction per `ingest_batch` call (all or nothing; one event for `ingest_event`),
   for each event:
   * a session is bound to the scope of its first event; another scope is refused before any
     duplicate or suppression answer, so other scopes cannot probe it;
   * forgotten sessions and events are not re-archived from a host replay (`noop` receipt);
   * idempotency by `(session_ref, event_id)` with a keyed content fingerprint: an identical replay is
     a `duplicate`, different content is `IdempotencyConflict`; a sequence number belongs to exactly
     one event;
   * `is_memory_injection` and `is_generated_summary` events are recorded in `history_skipped` and
     never archived as evidence (R10.5);
   * otherwise secrets are redacted, then the text, refs and attachment references are sealed;
     sequence gaps and per-producer cursors are updated.
3. Appends bump `history_generation`, not the partition generation, so a busy chat does not keep
   invalidating context packets.

Search (`search_history`) runs over an in-memory projection of authorized sessions only
(`history.archive._Projection`): FTS5 when available; otherwise, or when FTS5 finds nothing (for
example CJK text), substring matching whose hits are labelled `score_kind="substring_recency"`. The
projection is hydrated newest-first in bounded, resumable batches (`EngineConfig.history_hydration_batch`,
`max_history_messages_hydrated`). Uncovered ranges are reported in `Coverage.missing` with status
`partial`. `scroll_history` returns a bounded window around a hit in exact retained order, and
`browse_history` pages through one session with its known gaps.

Tests: `tests/test_history.py::test_identical_reingest_is_duplicate_without_state_change`,
`::test_injected_memory_and_generated_summaries_are_not_evidence`,
`::test_secrets_are_redacted_before_storage_and_not_searchable`,
`::test_cursors_are_per_producer_and_durable_across_restart`,
`::test_search_is_authorized_only_including_counts`,
`::test_partial_hydration_reports_partial_with_missing_range`.

In handoff 0002 archiving is opt-in (`LOCUS_MEMORY_ARCHIVE=1`, shadow or enabled mode only). The
adapter feeds committed user and assistant messages from `AgentCore._add_message`, and skips
synthetic, unpersisted and reasoning content.

### 6.7 forget (ledger-first)

`MemoryEngine.forget(access, ForgetTarget, policy=ForgetPolicy())` →
`forgetting.ForgettingService.forget`. Targets: `memory`, `source`, `session`, `project`, `repository`,
`agent`, `profile`. Forgetting is never fenced by ownership: deletion must work in every migration
state (how a deletion reaches the copies a migration keeps is in §7.2). The protocol in detail:
[storage-and-encryption.md](storage-and-encryption.md) §12 and
[security-and-privacy.md](security-and-privacy.md) §7.

```
 caller ──forget──▶ authorize (operation, actor, grants; admin for hidden or profile targets)
                     │
                     ▼
              (2) Partition.record_forget_request ◀── sealed request row in forget_requests
                     │                                (caller's access, the target's kind -
                     │                                never its ref -, policy, keyed
                     │                                idempotency token; same ledger file;
                     │                                deleted once applied, §4)
                  then DeletionLedger.append      ◀── write-ahead, separate file, durable,
                     │                                MAC-chained; the entry holds keyed
                     │                                tokens + policy only
                     ▼
              (3) one main-DB transaction:
                     apply earlier unapplied ledger entries
                     apply_tombstone: purge records, revisions, vectors, archive messages,
                       repository rows, episodes, procedures, summaries, context receipts
                       (each service's purge hook); record suppressions; a memory tombstone
                       for every removed record besides the target; queue external deletions
                       of the removed records by derived replica refs
                       (ProviderHub.queue_removed_records)
                     record tombstone; record the outcome (removed ids, suppression keys,
                       aliases) MACed in ledger_outcomes (Partition.record_outcome);
                       advance deletion_generation and its keyed checkpoint (never
                       backwards); bump generation
                     queue external deletions by the replica mapping; write the receipt
                     │
                     ▼
              (4) drop the sealed request (Partition.drop_forget_requests); drop in-memory
                  caches; checkpoint the main and the ledger WAL so purged pages leave the
                  disk (Partition._checkpoint_all); LedgerMirror.write(high-water mark);
                  propagate to migration copies (after a cutover, §7.2); add limitations
                  for the ownership state; return ForgetReceipt
```

* **Crash safety.** If step 3 fails or the process dies between steps 2 and 3, the partition is
  marked unreconciled. Before serving anything, every caller (this process, another process whose
  ledger head is ahead of its store, and every open) runs `storage.partition.Partition.reconcile`,
  which re-applies the entry with the policy the user chose
  (`tests/test_forgetting.py::test_crash_between_ledger_and_apply_is_repaired_before_serving`,
  `::test_an_unfinished_forget_in_another_process_is_applied_before_serving`,
  `::test_replay_applies_the_policy_the_user_chose`).
* **Restore safety (R17.5).** Restoring an old main database next to a newer ledger re-applies the
  newer deletions before serving
  (`tests/test_forgetting.py::test_restoring_an_old_database_cannot_resurrect_forgotten_memories`).
  Replay is anchored to authenticated state: `Partition.reconcile` decides which ledger entries to
  replay from the keyed deletion checkpoint (`Partition._applied_generation`, `Partition._checkpoint`),
  never from the plaintext `deletion_generation` counter; a checkpoint that does not verify counts as
  nothing applied, and a store written before checkpoints existed is trusted only below the first
  entry a checkpointing build appended. On every reconcile, `Partition._restore_deletion_state`
  also rebuilds tombstones, suppressions and source aliases from the authenticated ledger entries and
  their MACed outcomes, and removes again any record a forget removed that is back in the main
  database
  (`tests/test_review_round4_batch1.py::test_tamper1_restored_old_database_with_an_edited_counter_still_replays`,
  `::test_tamper1_deleted_suppression_rows_are_restored_from_the_ledger`,
  `::test_tamper1_deleted_tombstone_rows_are_restored_from_the_ledger`,
  `::test_tamper1_an_unaltered_store_reopens_without_repairs`).
  If the ledger was rolled back but the store is newer, the store's tombstones are adopted back into
  the ledger (`tests/test_forgetting.py::test_a_rolled_back_ledger_is_rebuilt_from_the_store`). If both
  are older than the host's `LedgerMirror`, opening raises `ReconciliationRequired` until an operator
  either restores the newer ledger or calls `MemoryEngine.reconcile(..., acknowledge_mirror_gap=True)`,
  which is recorded durably (`::test_restoring_database_and_ledger_against_a_newer_mirror`). Edits or
  holes in the ledger break the MAC chain and are detected on open
  (`::test_ledger_tampering_is_detected_on_open`). Tail truncation is detectable only with a mirror.
* **Derived state (R17.3).** Evidence-dependent records (`ForgettingService._evidence_dependent`:
  summaries, records with a `model_interpretation` or `hypothesis` basis, candidates, and records
  whose basis no user, host or system actor attested; approval is not attestation) that are derived
  from or cite a forgotten input are removed transitively by iterative work lists, never recursion:
  `ForgettingService._cascade` follows derivations, and `cite_removed` in `ForgettingService._apply`
  treats records that cite any removed record as `SourceRef(kind=memory)` like citers of a forgotten
  source, at any depth. Every removed record gets its own memory tombstone
  (`storage.partition.DERIVED_TOMBSTONE_POLICY`), so later citations and derivations of it are
  refused. Victims are found from decrypted payloads (`forgetting._PayloadIndex`), not only from the
  plaintext indexes `record_scopes`, `record_sources` and `derivations`. A removed record that also
  had other inputs is listed in `regenerate_required`. An attested derivation is kept with the
  removed parent severed (`ForgettingService._sever_derivation`, change `derivation_severed`) and is
  counted under `retained_by_policy["user_confirmed_derivations"]`. `include_derived=False` turns the
  derivation cascade off; records citing the target are still processed
  (`tests/test_review_round2_batch1.py::test_rob1_forgetting_a_chain_deeper_than_the_interpreter_stack`,
  `tests/test_review_round3_batch1.py::test_mf2_a_citer_of_a_cascade_removed_record_is_removed`,
  `::test_mf2_a_citation_chain_of_any_depth_is_followed`,
  `tests/test_review_round2_batch2.py::test_fg6_approval_alone_does_not_attest_an_agents_basis`,
  `tests/test_review_round4_batch1.py::test_tamper2_cascade_finds_a_derived_record_whose_derivation_edge_was_stripped`,
  `::test_tamper2_scope_forget_finds_a_record_whose_scope_index_was_stripped`,
  `::test_tamper2_replayed_scope_forget_after_restore_ignores_a_stripped_index`). Derived work that
  observed the store before the deletion is refused at commit time by `ForgettingService.commit_guard`
  (`tests/test_forgetting.py::test_commit_guard_refuses_stale_derived_commits`). With
  `suppress_relearning`, the same source cannot teach the memory again
  (`::test_suppression_prevents_relearning_from_the_same_source`).
* **Memory vs source (R17.2).** Forgetting a memory never deletes the archived messages it cites.
  Forgetting a source (for example one message) removes the evidence-dependent records learned from
  it; an attested record with other live evidence is kept with that citation dropped
  (`ForgettingService._drop_source`, counted under `retained_by_policy["memories_with_other_evidence"]`).
  The archived message is kept unless `delete_source_archive=True`; forgetting a session also removes
  the session's archived messages. Records citing a forgotten memory as `SourceRef(kind=memory)` are
  treated the same way. A repository forget also reaches records in other scopes that cite the
  repository's commits or blobs, and needs `admin` when those are hidden from the caller
  (`tests/test_history.py::test_forget_message_without_archive_deletion_retains_message`,
  `::test_forget_message_with_archive_deletion_records_gap`,
  `::test_forget_session_removes_search_scroll_cursor_and_derived_memory`,
  `tests/test_review_round3_batch1.py::test_mf2_an_attested_citer_with_independent_evidence_keeps_its_other_source`,
  `tests/test_review_round2_batch2.py::test_sl4_a_corrected_agent_proposal_survives_forgetting_its_message_source`,
  `tests/test_review_round4_batch1.py::test_eg1_repository_forget_removes_restatements_cited_from_other_scopes`,
  `::test_eg1_a_repository_forget_reaching_hidden_citers_needs_admin`).
* **External copies.** Deletions are queued in the provider outbox for every external service that
  received the data - by the replica mapping, and by each deleting service's own replica ref of every
  removed record that was ever approved, so a lost or tampered mapping never cancels one; they are
  `done` only on the provider's confirmation and are reported as `pending_external` until then
  (`tests/test_providers.py::test_forget_queues_external_deletion_and_outbox_confirms`,
  `tests/test_review_round4_batch1.py::test_tamper5_deleted_replica_mapping_never_cancels_the_external_deletion`).
* **Physical purge.** `secure_delete` zeroes freed pages, and a checkpoint of both the main and the
  ledger WAL (the ledger file holds the sealed `forget_requests`) follows the commit
  (`Partition._checkpoint_all`); deletions applied by a reconcile are checkpointed the same way
  (`Partition.ensure_purged`). If a concurrent reader blocks the checkpoint, the receipt says
  `physical_purge_pending` and the partition retries on later calls, on open and on close. The
  receipt also says `physical_purge_pending` when a migration's rollback copy (the legacy vault or a
  migration snapshot) could not be updated yet (`forgetting._MIGRATION_RESIDUE`, §7.2). A replayed
  receipt reports the purge state as it stands now (`Partition.purge_complete`)
  (`tests/test_review_group1.py::test_forget_with_a_concurrent_reader_finishes_the_physical_purge_later`,
  `tests/test_storage.py::test_forget_removes_the_ciphertext_itself`,
  `tests/test_review_round2_batch3.py::test_cd2_a_forget_reconciled_after_a_crash_is_physically_purged`,
  `::test_cd2_an_idempotent_retry_after_reconcile_reports_the_real_purge_state`,
  `::test_cd4_a_completed_forget_leaves_no_sealed_request_on_disk`,
  `tests/test_review_round2_batch1.py::test_cd1_a_busy_legacy_store_is_reported_and_finished_later`).
* **Damaged rows** are deleted by any target that covers them without being decrypted
  (`tests/test_forgetting.py::test_damaged_records_can_still_be_forgotten`).
* **Receipts.** `ForgetReceipt` reports deleted counts (only items the caller may see, unless admin),
  `retained_by_policy`, `regenerate_required`, `pending_external`, `deletion_generation`,
  `physical_purge_pending` and limitations. It makes no claim about prompts already sent, unconfirmed
  external copies or backups (R17.7). `ForgettingService._finish_result` adds, to live, replayed and
  reconcile-recorded receipts alike and as of the moment the receipt is handed out, whether the
  legacy store still serves its copy (`forgetting._LEGACY_AUTHORITY`: legacy is the authority, before
  a cutover or after a rollback, so the deletion reached only the package store;
  `_ROLLBACK_PENDING`; `_CUTOVER_PENDING`) and whether a migration copy still holds data
  (`_MIGRATION_RESIDUE`). When a concurrent reconciliation applied the entry without recording a
  receipt, `ForgettingService.forget` returns one that says counts are unavailable
  (`_APPLIED_ELSEWHERE`)
  (`tests/test_review_round2_batch2.py::test_fg5_receipts_say_whether_the_legacy_store_still_holds_the_memory`,
  `tests/test_review_round3_batch2.py::test_mf6_a_replay_under_legacy_authority_keeps_the_legacy_limitation`).
* **Preview.** `MemoryEngine.preview_forget` runs the same apply inside a transaction that is always
  rolled back; nothing reaches the ledger.

End-to-end check across derived stores: `tests/test_integration.py::test_forgetting_a_memory_reaches_vectors_projections_and_context`.

### 6.8 repository snapshot

`MemoryEngine.register_repository` and `MemoryEngine.snapshot_repository` →
`repository.service.RepositoryService`.

1. **Register** (operation `write` or `admin`, actor `user` or `host`, both checked in
   `RepositoryService.register`; not fenced by ownership, §7.2). Repository memory is disabled
   unless the host lists allowed roots in `HostCapabilities.allowed_repository_roots`. The root must
   resolve inside an allowed root, must not be the filesystem root, the home directory or one of its
   ancestors, and must be the top level of a git work tree with at least one commit. The stable
   identity is the repository id, the encrypted root path and the initial commit. Default secret
   exclusions apply; the host can only add to them.
2. **Snapshot** (fenced; operation `ingest`, `write` or `admin`). Bounded by file count, bytes per file,
   total bytes, a deadline and a cancellation token. Inventory comes from `git ls-files -s -z`, dirty
   state from `git status --porcelain=v2 -z`, unmodified content from the object store, and modified
   content through no-follow reads beneath the root. Every git call goes through `repository.git.Git`:
   argv only (no shell), a scrubbed environment, repository hooks, filters, external diff, pager and
   credential helpers disabled, bounded time and output. Snapshot identity is HEAD, a hash of the
   dirty state, the work-tree path and the exclusion set.
3. **Parse without executing** (`repository.observations`): Python through `ast.parse`, JavaScript and
   TypeScript imports through labelled heuristic regular expressions, other languages inventory only
   (`unsupported`).
4. **Commit.** `ForgettingService.commit_guard` refuses the commit if a deletion landed while the
   snapshot was reading. Unchanged blobs reuse their observation; changed and deleted paths turn their
   observation `stale` (historical, still searchable); a returning blob revives its observation; a
   rename is detected heuristically by an identical blob at a new path and keeps lineage. A partial
   snapshot never stales paths it did not visit.
5. Each supported file yields one `MemoryRecord(kind=repository_observation, basis=observed,
   lifecycle=approved)` citing a `blob_range` source, so it is searchable and can enter the
   project-and-repository context slice.

`repository_history` and `read_repository_file` are bounded and apply the same exclusions, including
to historical blobs. The interchange format (`repository.interchange`, v1) exports and imports
inventory and observations; imported documents are untrusted, imported observations become
unapproved candidates with basis `source_attributed`, and imported summaries become unapproved
candidates with basis `model_interpretation` ([repository-interchange.md](repository-interchange.md)).

Exclusions apply to what is already stored. An observation of a path the current exclusion set
covers, an interchange-imported record citing one, and the records derived from or citing those (up
to the depth bound) are hidden at once from every read and egress path (§5.3); the next snapshot
purges them (`RepositoryService._purge_excluded`, which removes their derivations and citers through
`ForgettingService.remove_derived`)
(`tests/test_review_round2_batch2.py::test_sl2_revalidation_never_passes_a_now_excluded_observation`,
`::test_sl2_explain_and_export_hide_a_now_excluded_observation`,
`tests/test_review_round4_batch2.py::test_eg2_citers_of_an_excluded_observation_are_hidden_then_purged`).
Tests:
`tests/test_repository.py::test_registration_disabled_without_allowed_roots`,
`::test_python_ast_observation_without_executing_code`,
`::test_modified_file_marks_old_observation_stale_and_new_current`,
`::test_rename_keeps_observation_lineage`, `::test_partial_snapshot_never_stales_unvisited_paths`,
`::test_excluded_secret_files_are_never_read_stored_or_named`,
`::test_repository_config_hooks_and_filters_never_execute`, `::test_snapshot_racing_a_forget_is_refused`,
`::test_imported_summaries_are_candidates_never_approved`.

### 6.9 episodes

`MemoryEngine.record_episode(access, EpisodeReport)` → `learning.episodes.EpisodeService.record`
(fenced; operation `write` or `ingest`, with no actor restriction, so an agent may record an
episode; `tests/test_learning.py::test_episode_permissions_and_scope_bounds`).

1. Receipt ids in `EpisodeReport.verification` are resolved with the host `VerificationAuthority`,
   outside any transaction. A crash, unknown receipt or malformed result counts as unverified.
2. `learning.episodes.derive_outcome` assigns the outcome. `verified_success` needs every referenced
   receipt trusted, matching this task, at least one required check, and all required checks passed;
   none of the receipts may have been forgotten, and none may already back another attempt of this
   episode or (when task-bound) another episode. After a receipt-backed failure, success needs
   receipts issued after that failure (`VerificationResult.issued_at`; an undated receipt never
   overrides it) (`tests/test_review_group1.py::test_a_replayed_receipt_cannot_turn_a_failure_into_success`).
   A trusted failed required check is `failure` even when success was claimed. Claimed `failure`,
   `partial`, `cancelled` and `interrupted` are recorded as reported. Anything else, including "done"
   without trusted receipts, is `unknown` (R14.2).
3. One logical episode is one `MemoryRecord(kind=episode, lifecycle=approved)`. A resumed attempt
   with the same `episode_id` adds a revision and an attempt; the outcome is that of the latest
   attempt, so retries never become a second independent success.
4. In the same transaction, `proposed_lessons` become unapproved `fact` candidates with basis
   `model_interpretation`, derived from the episode (only if the caller has `propose`).

Tests: `tests/test_learning.py::test_claimed_done_without_receipts_is_unknown`,
`::test_host_receipts_with_all_checks_passing_is_verified_success`,
`::test_failed_required_check_is_failure_even_when_success_claimed`,
`::test_resumed_attempt_updates_the_same_episode_and_is_not_double_counted`,
`::test_lessons_become_unapproved_candidates_linked_to_the_episode`.

### 6.10 procedures

`learning.procedures.ProcedureService`, through `MemoryEngine.nominate_procedure`,
`evaluate_procedure`, `approve_procedure`, `reject_procedure` and `export_procedure`:

```
nominate (propose) ──▶ unsafe | insufficient_evidence | candidate
candidate ──evaluate (maintain; host EvaluationRunner)──▶ evaluated | failed_evaluation
evaluated ──approve (reviewer, expected_version)──▶ approved ──export (user/host)──▶ exported
any live state ──evidence forgotten or downgraded──▶ revoked_evidence
                                                    host activation and rollback: outside the package
```

* **Evidence.** Only distinct verified-success tasks that the caller may see and that lie inside the
  procedure's scope count. Retries, attempts, replays and copies that share a receipt collapse into
  one. At least 2 independent tasks are required (`MIN_INDEPENDENT_EVIDENCE`). The evidence gate and
  revocation read the authenticated episode payloads; the plaintext `episodes` and
  `procedure_evidence` indexes are only hints (`ProcedureService._assess`,
  `ProcedureService.reconcile_evidence`, run by every forget and by `maintain`). An approved
  procedure whose evidence episode is gone is `unbacked` (`ProcedureService.unbacked`): context
  compilation skips it, `CoreService.unservable` keeps it out of every egress path, and
  `export_procedure` re-assesses before writing
  (`tests/test_review_round4_batch2.py::test_tamper8_an_aliased_episode_index_never_counts_as_verified_evidence`,
  `::test_tamper9_forgetting_evidence_revokes_without_the_plaintext_evidence_index`,
  `::test_tamper9_export_reassesses_before_writing`).
* **Safety screen** (`learning.procedures.screen_draft`): heuristic patterns for verification
  bypasses, destructive or privileged commands, remote-code piping, credential exfiltration, governance
  edits (AGENTS.md, approval policy, secret exclusions, provider settings, evaluation rules), and
  capability requests broader than the host-attested evidence.
* **Evaluation** sends a fixed, allow-listed manifest to the host runner. Without a runner it raises
  `UnsupportedCapability`; the engine never executes a step.
* **Export** writes `<destination>/<slug>/v<N>/manifest.json` and `SKILL.md` with exclusive create, so
  an existing version is never overwritten. Approval and export grant no capability.

Tests: `tests/test_learning.py::test_retries_of_one_task_are_insufficient_evidence`,
`::test_two_independent_verified_tasks_make_a_candidate`, `::test_unsafe_procedures_are_stored_as_unsafe`,
`::test_evaluate_without_runner_is_unsupported`,
`::test_manifest_is_allow_listed_and_never_carries_runner_rules`,
`::test_approve_only_after_evaluation_and_only_by_reviewer`,
`::test_export_writes_versioned_proposal_and_never_overwrites`,
`::test_forgetting_an_evidence_episode_revokes_the_procedure`.

### 6.11 maintenance and consolidation

The engine has no scheduler; the host calls these when it chooses (R16.6).

* `MemoryEngine.maintain` (operation `maintain`) is one bounded unit. It persists time-based
  lifecycle transitions through `CoreService.expire_due`: candidates past their TTL become
  `expired`, approved records whose validity ended become `stale`, and unpinned, non-durable
  approved or stale records whose `retention.expires_at` has passed become `expired`
  (`transient_expired`). Records derived from such inputs follow them at any depth: when an input's
  TTL or retention ends, every record derived from it expires (`derived_expired`); when its validity
  ends, approved derivations go stale and pending ones expire (`derived_stale`). These writes are
  skipped while another writer owns the records (§7.2). `maintain` also re-assesses procedures from
  authenticated payloads and revokes those whose evidence episode is gone
  (`ProcedureService.reconcile_evidence`; never fenced), trims old jobs, processes the provider outbox
  if one is offered (whose first step withdraws external replicas of records that are no longer
  current, §6.12), and verifies the ledger MAC chain. It reports only changes the caller may see and
  leaves a receipt (`tests/test_review_round4_batch2.py::test_eg4_validity_and_retention_end_reach_every_level`,
  `tests/test_review_round2_batch2.py::test_sl5_maintenance_expires_summaries_whose_input_retention_ended`,
  `tests/test_review_round4_batch2.py::test_tamper9_read_paths_and_maintenance_catch_an_unrevoked_procedure`).
* `MemoryEngine.consolidate` (fenced; operation `maintain`) runs or resumes a job with durable,
  sealed progress. It reports exact duplicates as supersession suggestions without merging or
  approving anything. Optional summarization runs only with a registered `summarize` provider
  (consented, if it is an egress provider; §6.12). Its output becomes unapproved `summary`
  candidates derived from their inputs, and each commit passes `commit_guard`.
* `MemoryEngine.invalidate(access, reason)` (`ConsolidationService.invalidate`) is the host signal
  for a scope or consent change. It requires `maintain`. It bumps the generation and marks
  **every** consolidation job of the partition in state `pending`, `running` or `cancelled` (a
  cancelled job is resumable, that is, paused) as `invalidated`, not only jobs the change affects.

Tests: `tests/test_learning.py::test_maintain_expires_due_candidates_and_reports_only_visible`,
`::test_consolidation_suggests_duplicates_without_merging_or_approving`,
`::test_summaries_are_candidates_derived_from_inputs`, `::test_invalidate_bumps_generation_and_stops_jobs`;
`tests/test_core.py::test_pinned_memories_never_expire_from_disuse` (retention expiry, calling
`CoreService.expire_due` directly).

### 6.12 providers

`providers.hub.ProviderHub`, one per partition. Nothing is enabled by default: a host registers
provider objects in `HostCapabilities.providers` and, for any provider whose descriptor says
`egress=True`, a `ConsentPolicy` in `HostCapabilities.consent`.

| Path | What happens | Reached through |
|---|---|---|
| Semantic enrichment | `semantic_scores` embeds the query and the authorized candidate records, reuses stored vectors, and returns cosine scores for retrieval to fuse (§6.4). Vectors are stored encrypted in `embeddings`, keyed by a model key over provider, model, version, dimensions and preprocessing; vectors under different keys are never compared; writes are compare-and-swap on the record revision. | `RetrievalService` automatically |
| Rerank | `rerank` returns labelled scores that are never stored. | `ProviderHub.rerank`; the search pipeline does not call it |
| Extraction | `extract_candidates` (operations `propose` and `read`) sends caller-supplied, authorized evidence to an extractor after scope, source, excerpt and consent checks: the evidence text must be an excerpt of the cited source, and consent must also cover the source's authoritative scope. The data class follows from the cited source kind (`hub._evidence_data_class`: messages and sessions are transcripts, commits and blob ranges repository source, memories memory text, raised to repository source for observations and their restatements); transcripts and repository source need the grant's explicit flags, a caller's label can only make the class stricter, and other source kinds are refused (`tests/test_review_round3_batch1.py::test_eg2_transcript_evidence_needs_transcript_consent_whatever_its_label`, `::test_eg2_cited_transcript_text_must_be_an_excerpt`, `tests/test_review_round4_batch2.py::test_eg3_observation_evidence_needs_repository_source_consent`). Valid output goes through `CoreService.propose` as actor `provider` with only `{propose, read}`, so it lands as candidates or is refused. | `MemoryEngine.services(access).providers` |
| Summarization | `summarizer` / `summarize` return validated text only; consolidation stores it as a candidate. | `MemoryEngine.consolidate` |
| External memory | `sync_external` sends approved, authorized, consent-covered records (`read` and `export` required) and marks them synced only on confirmation. Consent is checked per record for its scope and its data class: repository observations and anything that restates them are `repository_source` (`ProviderHub._record_data_class`), never sent under `memory_text` alone. Records `CoreService.unservable` reports (expired at read time, observations of now-excluded paths, unbacked procedures) and records stale at read time are never sent. Forgetting queues deletions; `process_outbox` sends them and marks them `done` only on confirmation. `process_outbox` and `reconcile_external` first run a bounded withdrawal sweep, decrypted in a read snapshot outside the write lock (`ProviderHub._sweep_plan` / `_sweep_apply`), that queues deletion of replicas of records that are superseded, stale, expired, rejected or forgotten (`hub._WITHDRAW_LIFECYCLES`; stale or expired at read time included) or that an exclusion now hides. `reconcile_external` refuses to resurrect forgotten or rejected records and judges each reported item on its authenticated local record (`tests/test_review_round3_batch2.py::test_eg6_superseded_and_stale_replicas_are_withdrawn`, `tests/test_review_round4_batch2.py::test_eg3_external_sync_never_sends_observations_under_memory_text`, `tests/test_review_round4_batch3.py::test_perf1_maintain_and_reconcile_never_decrypt_under_the_write_lock`, `::test_tamper6_reconcile_judges_the_authenticated_record`); `withdraw_external` (for example after consent is revoked) queues deletion of everything sent to that provider (`forget` or `admin`, actor `user` or `host`; without `admin` it refuses when the provider holds items outside the caller's grants), and `process_outbox` then sends the deletions and marks each `done` only on provider confirmation. | `MemoryEngine.services(access).providers`, `MemoryEngine.process_provider_outbox`, `maintain` |

Every call goes through `providers.base.GuardedCall`: a deadline (a late reply is discarded), cancellation,
a local token bucket, a circuit breaker on the injected clock, at most two retries for retryable errors,
and one usage receipt per attempt. Unknown cost is recorded as unknown, not zero. Provider selection
is deterministic (local before egress, registration order, consent) and ignores health, so an outage
never moves data to another provider or account (R16.3). A capability declared without its methods is
reported as unsupported, never faked.

Tests: `tests/test_providers.py::test_no_consent_policy_means_no_egress`,
`::test_unsupported_capability_is_explicit_never_faked`,
`::test_extractor_output_lands_as_provider_candidate_only`,
`::test_incompatible_model_versions_are_never_mixed`,
`::test_outage_keeps_pending_and_never_switches_provider`,
`::test_retries_are_bounded_and_only_for_retryable_errors`,
`::test_usage_receipts_distinguish_unknown_from_zero_cost`,
`::test_external_reconcile_refuses_resurrection`, `::test_vectors_and_provider_state_are_encrypted`.

Status: the contracts and the hub are implemented and tested **with the deterministic fakes in
`providers.fake` only**. `FakeEmbeddingProvider` hashes words into buckets; it measures lexical overlap,
not meaning. No real model or external service adapter ships, and no live provider call has been made.

---

## 7. Rollout dimensions

There are two independent controls (R19.1). One decides whether memory is served; the other decides
which store is the authoritative writer.

### 7.1 Serving mode: `disabled | shadow | enabled`

**Package defaults.** `host.EngineConfig` defaults to `serving_mode="enabled"` and
`canonical_backend="package"`. A host that passes no `EngineConfig` gets context serving enabled, and
status reports `canonical_backend` `"package"` whatever `OwnershipControl` says. The `disabled`
default in the table below is only the Locus `LOCUS_MEMORY_ENGINE_MODE` default from handoff 0002,
which explicitly passes `EngineConfig(serving_mode=mode, canonical_backend="legacy")`.

In the package, `EngineConfig.serving_mode` has a narrow effect: with `disabled`,
`ContextCompiler.build` and `ContextCompiler.revalidate` (reached through
`MemoryEngine.build_context` and `MemoryEngine.revalidate_context`) return an empty packet with
status `unavailable`, reason "context serving is disabled by host configuration", and no receipt
(`receipt_id` is empty; `ContextCompiler._disabled`). The test covers `build`
(`tests/test_context.py::test_serving_disabled_returns_unavailable_empty_packet`). `shadow` and
`enabled` behave the same inside the package. All three are reported in `EngineStatus.serving_mode`.

Package-side `disabled` does **not** mean that nothing is touched on disk.
`MemoryEngine.build_context` and `revalidate_context` call `MemoryEngine._ctx(access)` before the
compiler checks `serving_mode`. That opens the partition and reconciles it, and with the default
`create_partitions=True` it creates the vault and its keys if they are absent.
`ContextCompiler._disabled` also reads the partition generation. Only the host adapter avoids all of
this, by not constructing the engine at all in `disabled` mode (handoff 0002).

The full semantics are host behavior, implemented in handoff 0002 through `LOCUS_MEMORY_ENGINE_MODE`
(read once per `ChatService`; unknown values fall back to `disabled`):

| Mode | Prompt | Files | Engine work |
|---|---|---|---|
| `disabled` (default) | Stage-1 prompt, byte for byte, on ordinary turns. The one change is D40: saved-agent turns recall with the profile's agent id. | none; the engine is never constructed | none |
| `shadow` | Unchanged: the legacy layer is injected. | `APP_DIR/memory-engine/**`, ciphertext only | After the legacy recall, the engine builds a packet over the derived copy; only content-free counts and timings are recorded. |
| `enabled` | Exactly one `## Approved memory` layer holding the engine packet within `max_automatic_tokens`, revalidated right before the model call; no layer when nothing is recalled. | as in shadow | Engine failures fail closed: no memory layer, a failure counter, the turn continues. |

Learning, retention, sync and activation are controlled separately (R19.4): history archiving needs
`LOCUS_MEMORY_ARCHIVE=1`; providers run only if the host registers them, and egress providers
(descriptor `egress=True`) only with a covering `ConsentPolicy` grant (a registered local provider
needs no consent: `ProviderHub._auto`); procedures are never activated by the package. Identity
mode disables the adapter entirely.

### 7.2 Canonical backend: `legacy | package`

`EngineConfig.canonical_backend` (default `"package"`, §7.1) is reported in status only and is
never compared with the ownership state. Enforcement is
`migrations.state.OwnershipControl`, a durable state machine in `<root>/control.sqlite3`, one row per
(partition, record family). Families: `memories`, `context_snapshots`, `skill_observations`; the engine
fence checks `memories`.

| State | Authoritative | Permitted writers |
|---|---|---|
| `legacy_authoritative` (default when no row exists) | legacy | legacy |
| `shadow_prepared` | legacy | legacy |
| `validated` | legacy | legacy |
| `cutover_in_progress` | none (quiesced) | none |
| `package_authoritative` | package | package |
| `rollback_in_progress` | none (quiesced) | none |
| `legacy_retired` (terminal) | package | package |

Transitions are compare-and-swap on an ownership generation, and every change is logged, so two
migrators cannot both advance the state (`tests/test_migrations.py::test_illegal_transitions_and_concurrent_migrators`).

How the fence is applied:

* **Package side.** When `HostCapabilities.ownership` is set, `MemoryEngine._fence` checks it before
  every canonical write (remember, propose, approve, reject, correct, pin, supersede, record_episode,
  nominate/evaluate/approve/reject procedure, snapshot_repository, import_repository_interchange,
  consolidate), and `CoreService._check_owner` checks again inside the write transaction
  (`CoreService._commit_write`, which every record write goes through, including sibling services'
  `CoreService.write_internal`). `ConsolidationService.maintain` skips lifecycle writes while
  fenced.
* **Calls not fenced up front.** `MemoryEngine.export_procedure` writes a new procedure record
  revision (state `exported`) through `write_internal`, so it is fenced only inside that
  transaction, after the export files were written; the files and the version directory it created
  are removed when the transaction fails. `MemoryEngine.register_repository` is not fenced at all:
  it writes the `repositories` table directly and bumps the generation.
* **Exempt writes.** Forgetting is never fenced, nor are deletion-driven rewrites (changes
  `source_forgotten`, `evidence_revoked` and `derivation_severed`, `core._UNFENCED_CHANGES`).
* **Migration writes: the inverse fence.** The legacy importer's writes (`imported`,
  `legacy_delta`) commit only while the legacy store is the authority, a rollback's
  `legacy_adopted` only during the rollback, and `legacy_readopted` (`Migrator._repair_rollback_commit`,
  run by `prepare_shadow` and `resume` to repair a rollback whose adoptions an earlier build lost)
  only while `legacy_authoritative` (`core._MIGRATION_CHANGES`, checked inside the write transaction
  by `CoreService._check_migration_state`). During `cutover_in_progress` only the Migrator's own final
  delta may import: `core.CUTOVER_IMPORT` is set around it, under its legacy write barrier.
  `LegacyImporter` also refuses up front with `OwnershipFenced` once the legacy store is no longer
  the authority.
* **No control.** When `ownership` is `None`, there is no other writer and the engine writes freely;
  the CLI passes a control only once a migration has recorded state for the partition.
* **Legacy side.** `LegacyMemoryVault(write_guard=OwnershipControl.writer_guard(partition_id, "memories", "legacy"))`
  calls the guard before every mutation; a fenced legacy store is served read-only.

Tests: `tests/test_migrations.py::test_engine_canonical_writes_are_fenced_until_package_is_authoritative`,
`::test_full_cutover_fences_legacy_writer`,
`tests/test_review_group1.py::test_canonical_record_writes_are_fenced_beyond_the_core_api`,
`tests/test_compat_legacy.py::test_write_guard_fences_mutations_but_not_reads`.

Moving ownership goes through `migrations.cutover.Migrator` only, never a feature flag (R19.5):
`prepare_shadow` (encrypted snapshot plus manifest, import from the snapshot) → `validate` (delta import
from the live legacy file, read-only, then decrypt-and-compare verification) → `cutover` (fence legacy
writers, drain host work through the `quiesce` hook, hold the legacy write lock, final delta, verify,
then `package_authoritative`). Any failure before the final transition aborts to
`legacy_authoritative`. `resume` finishes or aborts an interrupted cutover or rollback, and
`abort_cutover` is the operator escape hatch. `rollback` reverse-syncs representable records with the
package write lock held, preserves post-cutover corrections and deletions, and refuses records the
legacy format cannot represent unless `allow_partial`. There is no dual-write: exactly one writer is
permitted in each state. Tests: `tests/test_migrations.py::test_crash_during_cutover_resumes_without_losing_writes`,
`::test_cutover_aborts_to_legacy_when_verification_fails`,
`::test_rollback_preserves_post_cutover_corrections_and_deletions`,
`::test_rollback_refuses_unrepresentable_records_unless_partial`,
`::test_migration_artifacts_contain_no_plaintext`. The full protocol is in
[migrations-and-rollback.md](migrations-and-rollback.md).

Rollback details:

* A record scoped to an agent the `LegacyMapping` does not know is unrepresentable
  (`Migrator._legacy_shape`), so rollback refuses it unless `allow_partial`
  (`tests/test_review_round4_batch1.py::test_mf2_rollback_refuses_records_of_an_agent_the_mapping_does_not_know`).
* Rollback applies pending deletions and deletions that arrive while it runs (`_apply_late_deletions`,
  the last check under the ledger's write lock), and deletes every legacy row of the cutover set
  (`migration_cutover_ids`, which also holds the ids the rollback writes back) that has no live
  package record. A legacy row the package never held is
  deleted only when a package forget covers it; otherwise it is kept as live legacy data
  (`Migrator._delete_gone`).
* After a rollback, a legacy edit of a record back to the statement a post-cutover correction of that
  record suppressed is imported: the importer lifts that suppression, keyed on the record's own
  identity (`ForgettingService.lift_suppression`)
  (`tests/test_review_round4_batch3.py::test_rg2_a_legacy_edit_back_to_the_corrected_away_statement_is_imported`).

Forgetting across migration states (forgetting is never fenced, so these copies are handled
explicitly):

* **After a cutover.** Every forget (`ForgettingService._finish_result`), every open (with
  `recheck=True`, `MemoryEngine.partition_context`) and every reconcile that applied entries
  (`MemoryEngine.partition_context`, `MemoryEngine.reconcile`) call
  `ForgettingService.propagate_to_migration_copies`, which runs
  `migrations.cutover.propagate_forgets_to_legacy` while the package is authoritative. It removes the
  migration snapshots and deletes forgotten rows from the live legacy vault with `secure_delete` and
  a truncating checkpoint. Its progress marker (meta `legacy_residue_generation`) carries a keyed tag,
  so a missing, altered or forged marker never skips the purge. Until it completes, receipts carry
  `forgetting._MIGRATION_RESIDUE` (§6.7)
  (`tests/test_review_round2_batch1.py::test_cd1_forget_after_cutover_leaves_no_legacy_or_snapshot_copy`,
  `tests/test_review_round4_batch2.py::test_tamper7_a_forged_residue_marker_never_skips_the_legacy_purge`).
* **During a cutover.** `abort_cutover(..., ctx=...)` (and the Migrator's own abort) first deletes from
  the legacy file the rows of every record a package deletion removed since the fence
  (`fence_generation`)
  (`tests/test_review_round3_batch2.py::test_mf5_a_forget_during_cutover_reaches_the_legacy_store_when_the_cutover_aborts`).
* **While legacy is authoritative** (before a cutover, or after a rollback), an engine forget reaches
  only the package store, and its receipt says so (`forgetting._LEGACY_AUTHORITY`; §9).

Snapshot residue: `Migrator.prepare_shadow` records the snapshot directory in the ownership details
(`OwnershipControl.update_details`, which changes details without changing the state or the
ownership generation) before it writes the snapshot. Snapshots of failed or crashed attempts are
removed on failure, on the next attempt, on abort and after the cutover
(`tests/test_review_round4_batch2.py::test_mf3_a_failed_prepare_shadow_removes_its_snapshot`,
`::test_mf3_abort_removes_the_recorded_snapshot`,
`::test_mf3_update_details_never_changes_state_or_generation`).

### 7.3 How the two combine

| Serving \ Canonical | `legacy` | `package` |
|---|---|---|
| `disabled` | Stage 1 and the Stage-2 default. No engine at all in Locus. | Writes stay with the package; only context injection stops, while search, list and export keep working. Serving mode never touches `OwnershipControl`, so disabling it cannot move writes back to legacy (R19.5). Not executed in Locus. |
| `shadow` | Stage 2: derived copy, legacy injected, content-free comparison. Handoff. | Not used. |
| `enabled` | Stage 2: derived copy served, canonical writes fenced, legacy routes unchanged. Handoff. | End state after Stage 3. **Not executed.** |

---

## 8. Extensibility points

All extension points are injected by the host; the package never discovers them (no keychain, no
app-data scanning, no network, no scheduling).

### 8.1 HostCapabilities (`host.HostCapabilities`)

| Field | Default | Used by | Effect of the default |
|---|---|---|---|
| `clock` | `time.time` | every service (validity, TTL, receipts, circuit breaker) | wall clock |
| `token_counter` | `None` | `context.budget.TokenMeter` | conservative estimate, labelled `estimated` |
| `verification` | `None` | episodes, `CoreService.verify_sources`, procedure capability checks | outcomes stay `unknown` unless a negative outcome is claimed; receipt evidence is refused |
| `evaluation_runner` | `None` | `ProcedureService.evaluate` | `UnsupportedCapability` |
| `allowed_repository_roots` | `()` | `RepositoryService.register` | repository memory disabled |
| `repository_exclude_patterns` | `()` | repository exclusions | built-in defaults only (patterns can only add) |
| `ownership` | `None` | `MemoryEngine._fence`, `CoreService._check_owner` / `_check_migration_state`, `ConsolidationService.maintain`, `ForgettingService` (receipt limitations, `propagate_to_migration_copies`), `MemoryEngine.partition_context` / `reconcile` / `ownership_state`, `migrations.legacy.LegacyImporter` | no fence |
| `ledger_mirror` | `None` | `Partition.reconcile`, `ForgettingService.forget` | restore detection relies on the local ledger only |
| `consent` | `None` | `ProviderHub` | no egress for any provider marked `egress=True` |
| `providers` | `{}` | `ProviderHub` | semantic, rerank, extraction, summarization and external sync unavailable |
| `approval_actors` | `{user}` | `policy.require_reviewer` | only users approve |

`EngineConfig` holds tunables, not capabilities: candidate TTL, the two rollout values (defaults
`serving_mode="enabled"`, `canonical_backend="package"`; §7.1), projection and hydration bounds, busy
timeout, git timeout and estimator parameters.

### 8.2 KeyProvider (`crypto.KeyProvider`)

`current_key_id() -> str` and `get_key(key_id) -> bytes` (32 bytes). Raise `VaultLocked` when locked.
`crypto.PartitionKeyring` uses it to wrap and unwrap data keys. A new data key
(`PartitionKeyring.new_data_key`) is wrapped under every master key that wraps the current data key
and that the `KeyProvider` can supply; master keys it cannot supply are skipped, and if none can be
supplied the new key is wrapped under `current_key_id()`. Rotation: `MemoryEngine.rotate_master_key` re-wraps (cheap)
and `rotate_data_key` re-encrypts rows in bounded batches; both are admin actions and report whether
old key material was flushed from the files (`admin.flush_key_material`).

Shipped: `StaticKeyProvider` (in-memory bytes, for hosts that already hold keys, and for tests) and
`FileKeyProvider` (private key files; used by the CLI and the quickstart). Host side: `LocusKeyProvider`
exists only in handoff 0002. A Keychain-backed provider does not exist.

### 8.3 Providers (`providers.base`)

Protocols `EmbeddingProvider.embed`, `Reranker.rerank`, `Extractor.extract`, `Summarizer.summarize` and
`ExternalMemoryService.sync / delete / list_items`. Each registered object exposes a host-written
`ProviderDescriptor` (capabilities, `egress`, accepted data classes, dimensions, model and version,
cost per unit or `None` for unknown, rate and circuit settings). Consent is a `ConsentPolicy` returning
`ConsentGrant`s that cover provider, scope and data class; transcripts and repository source need
explicit flags. `StaticConsentPolicy` is a simple in-memory implementation.
**Contract-only** for real providers; only the deterministic fakes in `providers.fake` exist.

### 8.4 VerificationAuthority (`host.VerificationAuthority`)

`resolve(receipt_id) -> VerificationResult | None`. A `VerificationResult` says whether the receipt is
trusted, which checks passed and whether they were required, when it was issued (`issued_at`, which
`derive_outcome` uses after a recorded failure, §6.9), which task it belongs to, and optionally which
capabilities the verified work used. It is the only way an episode becomes `verified_success`
and the only capability evidence procedures accept. **Contract-only:** no Locus implementation exists;
tests use doubles (`tests/test_learning.py`).

### 8.5 EvaluationRunner (`host.EvaluationRunner`)

`evaluate(manifest, *, deadline_s) -> dict`. Receives the allow-listed procedure manifest; its result
is validated strictly, and a crash is a `ProviderError` that leaves the procedure unchanged. It is not
related to the benchmark in `locus_memory.evaluation`. **Contract-only:** no host runner exists, and
benchmark arm F (evaluated procedures) is **not executed** ([evaluation.md](evaluation.md) §1).

### 8.6 LedgerMirror (`storage.ledger.LedgerMirror`)

`read(partition_id) -> (generation, mac) | None` and `write(partition_id, generation, mac)`. A
host-held high-water mark of the deletion ledger that survives file restores, for example in the
Keychain. When the store and its ledger are both older than the mirrored mark (a restored backup of
both files, or a ledger whose tail was cut off together with the store), opening raises
`ReconciliationRequired` (§6.7). Without a mirror that case cannot be detected. Shipped: `MemoryLedgerMirror`, in memory, for tests. **Contract-only** for real hosts; handoff 0002
does not pass one.

### 8.7 OwnershipControl (`migrations.state.OwnershipControl`)

A concrete class rather than a protocol. The host constructs it on the engine root and passes it as
`HostCapabilities.ownership`; the engine calls `assert_writer` and `get`. Its `writer_guard(...)`
returns a zero-argument callable for the legacy writer's `write_guard` hook. Handoff 0002 passes it
with ownership left at `legacy_authoritative`, so every canonical write through the engine API
(remember, propose, approve, reject, correct, pin, supersede, episodes, procedures, snapshots,
interchange import, consolidate) raises `OwnershipFenced`. The legacy importer's writes carry the
inverse fence instead (`core._MIGRATION_CHANGES`): they commit only while the legacy store is the
authority, which is how 0002 builds its derived copy (`migrations.legacy.LegacyImporter` writes
through `CoreService.write_internal` with change `imported` or `legacy_delta`). After a cutover the
importer refuses with `OwnershipFenced`, so a host that keeps calling it (0002's `_sync`) fails
closed instead of overwriting the authoritative store; such a host must stop importing once
`ownership_state()` reports `package_authoritative`. Forgetting is never fenced, and
`register_repository` is not fenced (§7.2). Because 0002 leaves ownership at `legacy_authoritative`,
every forget receipt from its engine carries the `forgetting._LEGACY_AUTHORITY` limitation: the
deletion reached the package's derived copy only, and the legacy store keeps serving its copy until
the memory is forgotten there or a later cutover applies the deletion (§6.7).

### 8.8 Other contracts

* **RepositoryIntelligenceProvider** (`repository.interchange`): `describe()` and
  `export(repository_id, since_snapshot)` returning an interchange v1 document; consumed by
  `RepositoryService.import_from_provider` (reached through `MemoryEngine.services(access).repository`).
  **Contract-only;** no Agent Dispatcher exporter exists.
* **TokenCounter** (`host.TokenCounter`): `__call__(text) -> int`, the host's model tokenizer. A
  failing counter falls back to the labelled estimate
  (`tests/test_context.py::test_broken_token_counter_falls_back_to_labelled_estimate`).
* **Context markers** (`context.markers`): `CONTEXT_WRAPPER_OPEN`, `CONTEXT_WRAPPER_CLOSE`,
  `is_context_block`, `contains_context_block`, so hosts can avoid double injection and avoid
  archiving injected memory (`tests/test_context.py::test_public_context_block_markers`).
* **Service hooks** (`services`): `purge(...)` and `reencrypt(...)` are the internal contract a new
  service must implement to take part in forgetting and data-key rotation.

---

## 9. Limits the architecture does not remove

* **Metadata.** Ids, kinds, lifecycle, revisions, timestamps and keyed tokens are outside the
  ciphertext. File sizes and operation timing can reveal how much activity a partition has.
* **Threat model.** Encryption protects app-managed data at rest. It does not protect against a
  compromised running process, swap, a stolen master key, or every backup; SSD erasure and perfect
  zeroization are not promised (R8.7).
* **Forgetting.** No claim about prompts already sent to a model, external copies whose deletion is
  not confirmed, or backups older than the ledger the store reconciles against. Without a
  `LedgerMirror`, losing the newest ledger together with the store cannot be detected.
* **Forget cost.** Every forget except a profile forget decrypts every record of the partition once
  (`forgetting._PayloadIndex`, built lazily on its first lookup, which every such forget makes) so
  that victims whose plaintext index rows were stripped are still found: O(N) decryptions per
  forget, inside its write transaction.
* **Forgetting while legacy is authoritative.** Before a cutover and after a rollback (so throughout
  handoff 0002), an engine forget reaches only the package store; the legacy store keeps its copy,
  and the receipt says so (`forgetting._LEGACY_AUTHORITY`).
* **Legacy creation times.** A scope forget decides whether a legacy row the package never held
  predates it from the legacy `created_at` column, which the legacy format does not authenticate.
  The importer records each decision once (`migration_scope_covered`), so a later edit cannot undo
  it; a keyless edit of a row the importer never saw before the forget can still move it from
  "before" to "after" the forget (`migrations.legacy._scope_forget_cover`;
  [migrations-and-rollback.md](migrations-and-rollback.md)).
* **Heuristics are labelled as such:** the procedure safety screen, JavaScript/TypeScript import
  extraction, rename detection, instruction-like flagging and secret detection.
* **One machine.** Multi-process access goes through SQLite locking on local files. There is no
  network synchronisation between devices.
* **Integration.** Everything on the Locus side is a handoff tested in a disposable copy; the real
  Locus checkout is unchanged. Stage 3 (canonical cutover, routes and tools on the adapter, Keychain
  custody, ephemeral delivery to native providers) is not executed.

---

## 10. Checking this document

Package tests and lint (run under each supported interpreter; the package declares
`requires-python >=3.10` and has been tested on CPython 3.10.22 and 3.14.6):

```bash
python -m pytest
ruff check src tests
```

Clean-environment wheel check (builds the wheel, installs it offline into new virtual environments
under `<work-dir>`, runs the narrower import check described in §1.1, and runs the quickstart and a
CLI smoke test of `init`, `remember` and `search`):

```bash
scripts/verify_wheel.sh <work-dir> <python> [<python> ...]
```

Prerequisites: the script builds the wheel with `<repo>/.venv/bin/python`, which must exist, and
installs with `--no-index` from `<work-dir>/wheelhouse`, which must already hold a `cryptography`
wheel for each interpreter (for example
`pip download --only-binary=:all: cryptography -d <work-dir>/wheelhouse --python-version X.Y`).
Without these the command fails. The environments are outside the checkout only if `<work-dir>` is.

The regression tests of the four adversarial review rounds are the evidence for most of the
hardening described here: round 1 in `tests/test_review_group1.py` to `tests/test_review_group3.py`,
round 2 in `tests/test_review_round2_batch1.py` to `tests/test_review_round2_batch4.py`, round 3 in
`tests/test_review_round3_batch1.py` to `tests/test_review_round3_batch3.py` and round 4 in
`tests/test_review_round4_batch1.py` to `tests/test_review_round4_batch3.py`. `tests/test_review_round3_batch3.py::test_rg2_select_deadline_is_documented`
reads this file and requires five names from §6.5 to appear in it (`R_SELECT_DEADLINE`,
`R_SELECT_TRUNCATED`, `R_LOAD_DEADLINE`, `R_RANK_DEADLINE`, `not_evaluated`); keep them when
editing.

Besides `scripts/verify_wheel.sh`, the wheel was also installed with `pip install --target` (the
install mode of Locus `Tools/PrepareAgentRuntime.sh`) and imported by the bundled Locus runtime's
CPython 3.14.6; that check is not scripted here, and it did not go through a hashed lock or the real
bundle staging ([integration-locus.md](integration-locus.md) §5).

Benchmark: `python -m locus_memory.evaluation --out <dir> --repetitions 1 --size small`
([evaluation.md](evaluation.md)). The final evaluation run is
`evals/results/2026-10-04-r5-seed20261004-final/` (synthetic fixtures; its `report.md` lists the
pre-registered criteria: 11 of 13 met, C5 and C8 not met, all hard invariants held). Locus-side
commands and results: [handoff/locus/README.md](../handoff/locus/README.md) §7. Test counts change
while review fixes land, so this document does not quote them; run the commands above.

`tests/test_compat_legacy.py::test_bidirectional_parity_with_real_locus_code` runs against real Locus
code only when a Locus checkout is readable (at `LOCUS_SOURCE_DIR`, or the default path named in the
test module); it copies the two source files to a temporary directory, so the checkout is never
written. Otherwise it is skipped.
