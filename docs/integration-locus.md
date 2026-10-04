# Integrating locus-memory into Locus

This document is the host contract and the staged extraction plan for moving Locus's memory
implementation onto `locus-memory`. It says what Locus must supply, what each stage changes, where
the host calls the adapter, how the package is bundled, what stays in Locus, and which host
defects only Locus can fix.

**Status.** Nothing described here has been applied to a real Locus checkout, published, pushed,
enabled or migrated for real. Stages 1 and 2 exist as patches in [`handoff/locus/`](../handoff/locus/)
and were tested in a disposable `git archive` copy of Locus. Stage 3 exists as package tooling
tested on disposable fixtures; the host wiring for it is not written and was not executed. Stage 4
is a list of criteria. This is not a production-readiness claim.

Sources:

* Locus at `/Users/nahid/Documents/locus`, commit `b332e4554e72956f949506207ffa034749360d79`
  (inspected read-only). Locus paths below are relative to `agent/ollama_code/` unless they start
  with `agent/`, `Tools/` or `Locus/`.
* The audits: [locus-compatibility.md](locus-compatibility.md) (formats, behavior, defect list
  `D1`-`D61` in §19) and [ownership-and-extraction.md](ownership-and-extraction.md) (ownership
  matrix, store inventory, host call sites in §5). Locus line numbers live in those documents; this
  one cites functions by name.
* The handoff: [handoff/locus/README.md](../handoff/locus/README.md) and the two patches.
* Package code is cited as `module.Class.method` under `src/locus_memory/`. Line numbers are not
  used because the package is still changing.
* Related package documents: [migrations-and-rollback.md](migrations-and-rollback.md) (the cutover
  protocol in detail), [storage-and-encryption.md](storage-and-encryption.md) (key hierarchy and
  rotation), [security-and-privacy.md](security-and-privacy.md), and, for optional consumers,
  [integration-workflows.md](integration-workflows.md) and
  [repository-interchange.md](repository-interchange.md).

---

## 1. Status at a glance

| Stage | What it does | Canonical store afterwards | Status | Evidence |
|---|---|---|---|---|
| 1. Delegation facades | `memory.py` and `continuity.py` in Locus become thin facades over `locus_memory.compat.legacy_vault` | legacy vault, unchanged format | Patch `0001` written; tested in a disposable Locus copy | §6.2 |
| 2. Adapter behind a rollout switch | New `memory_adapter.py` in Locus; the engine keeps a derived copy in `shadow`/`enabled` mode and serves it only in `enabled` mode | legacy vault (unchanged) | Patch `0002` written; tested in a disposable Locus copy | §6.2 |
| 3. Canonical cutover | `migrations.cutover.Migrator` moves the `memories` family to the package; writers move to the adapter | package partition | Package tooling implemented and tested on fixtures; **host wiring not written; not executed** | §3.3 |
| 4. Retirement | Remove the facades and legacy readers once the criteria hold | package partition | **Not started** | §3.4 |
| Bundling | Pinned wheel through the hashed runtime lock | n/a | Steps written; **not applied to Locus**; wheel verified in clean venvs outside the checkout | §5 |

---

## 2. Host contract

### 2.1 Dependency direction

```
Locus (Swift UI, FastAPI server, AgentCore)
   -> agent/ollama_code/memory_adapter.py   (host code: trusted access, mapping, seams, rollout)
      -> locus_memory                       (pinned wheel in AgentRuntime/site-packages)
         -> encrypted SQLite files under the host-chosen root
```

The package imports nothing from Locus, LangGraph or Agent Dispatcher, and importing it does no
I/O (tests: `tests/test_packaging_imports.py::test_import_is_side_effect_free_and_pulls_in_no_host_or_network_stack`,
`::test_importing_every_submodule_stays_local`, `::test_constructing_and_closing_an_engine_creates_nothing`).
All integration code lives in Locus (R1.4). The adapter is one object per `ChatService`, with no
module-level engine state (Stage-2 test: two `ChatService` instances with different `APP_DIR`s share
nothing; see [handoff README §7](../handoff/locus/README.md)).

### 2.2 What Locus supplies

| Capability | Package contract | What Stage 2 supplies | What Stage 3 needs |
|---|---|---|---|
| Master keys | `crypto.KeyProvider`: `current_key_id()`, `get_key(key_id)`; raise `VaultLocked` when locked, `KeyError` when unknown | `memory_adapter.LocusKeyProvider` (§2.3) | Same, or a Keychain-backed provider (open decision 8.2 in the ownership doc) |
| Trusted access | `models.AccessContext` per call (§2.4) | `MemoryAdapter.access(core, purpose, ...)` | Use the `user` and `tool` purposes in the routes and model tools, after widening `user` or adding purposes: as patched it lacks `EXPORT`, `PROPOSE` and `ADMIN` (§3.3 step 6) |
| Ownership fencing | `HostCapabilities.ownership` = `migrations.state.OwnershipControl` | `OwnershipControl(APP_DIR/memory-engine)`; state stays `legacy_authoritative` | Same file; plus `writer_guard` on the legacy vault (§2.7) |
| Deletion-ledger high-water mark | `HostCapabilities.ledger_mirror` = `storage.ledger.LedgerMirror` | **None** | A host-held mirror outside `APP_DIR` (§2.6) |
| Tokenizer | `HostCapabilities.token_counter` | None (token counts are labelled estimates) | Optional |
| Verification authority | `HostCapabilities.verification` = `host.VerificationAuthority` | None (no episodes are recorded) | Needed before task episodes are recorded |
| Procedure evaluation | `HostCapabilities.evaluation_runner` = `host.EvaluationRunner` | None | Needed before procedures are evaluated |
| Repository roots | `HostCapabilities.allowed_repository_roots` (empty = repository memory disabled) | Empty | Host decision |
| External providers and consent | `HostCapabilities.providers`, `HostCapabilities.consent` (`None` = no egress) | None | Host decision |
| Reviewer attestation | `HostCapabilities.approval_actors` (default `{Actor.USER}`) | Default | Default |
| Rollout reporting | `host.EngineConfig.serving_mode`, `EngineConfig.canonical_backend` | `serving_mode=<mode>`, `canonical_backend="legacy"` | `canonical_backend="package"` after cutover |

`EngineConfig.serving_mode="disabled"` makes `context.compiler.ContextCompiler.build` and
`ContextCompiler.revalidate` return disabled packets. The Stage-2 adapter goes further: in disabled
mode it never constructs the engine at all.

### 2.3 Keys: `KeyProvider` through the existing custody

Locus keeps key custody (R8.1). The package never reads a keychain, and it never generates a new
master key over an existing vault:

* `crypto.PartitionKeyring.unlock` raises `VaultLocked` when no wrapping master key is available and
  `WrongKey` when an available key fails to authenticate the vault (tests:
  `tests/test_crypto.py::test_missing_master_key_raises_vault_locked`,
  `::test_wrong_master_key_bytes_raise_wrong_key`, `::test_initialize_refuses_an_existing_vault`,
  `tests/test_review_group1.py::test_missing_database_next_to_a_ledger_is_refused_without_new_keys`).
* `MemoryEngine(..., create_partitions=False)` opens existing partitions only: a missing vault raises
  `NotFound` and creates nothing (`tests/test_packaging_imports.py::test_an_open_existing_only_engine_creates_nothing_for_a_missing_vault`).
  Hosts should use this mode once the package is canonical.
* Master-key rotation is `MemoryEngine.rotate_master_key` (ADMIN) and data-key rotation is
  `MemoryEngine.rotate_data_key`. Both are implemented in the package; no host trigger exists.

How Stage 2 supplies the key (`memory_adapter.LocusKeyProvider` in patch `0002`):

* key id `locus-v1`, key bytes `crypto.derive_subkey(memory._master_key(...), "locus-memory/engine/v1")`;
* it reads the adapter's own `APP_DIR/memory/master.key`, so two app instances never share a key;
* a missing key for an existing legacy vault is reported as `VaultLocked`;
* a legacy key is created only where Stage 1's `memory._master_key` already creates one: no key file
  and no vault rows.

Consequence: replacing the legacy key makes the derived copy undecryptable (`WrongKey`/`VaultLocked`),
and the adapter then fails closed. The recovery is deleting `APP_DIR/memory-engine/`
([handoff README §6](../handoff/locus/README.md)).

### 2.4 `AccessContext` construction rules

Package rules (`models.AccessContext`, `policy`):

* The host builds every context from its own authenticated state: `principal`, `partition`
  (`models.PartitionRef(edition, profile)`, one security domain), `actor`, `grants`
  (`models.ScopeGrants`), `operations`, `purpose`, `issuer`. Nothing read from a client field, a
  transcript, the store or model output may widen it (R7.1).
* A record with an empty scope is profile-global and visible to every context of the partition. A
  scoped record is visible only when **every** one of its dimension values is granted
  (`ScopeGrants.allows`). Missing and unauthorized records are both reported as `NotFound`
  (`policy.require_visible`).
* Each operation needs its `Operation` in `access.operations` (`policy.require`). Explicit writes
  (`remember`, `correct`) also need actor `USER` or `HOST` (`policy.require_author`); agents and
  providers can only `propose`. `approve`/`reject` need `APPROVE` and an actor in
  `HostCapabilities.approval_actors` (`policy.require_reviewer`).
* A service bound to one partition refuses a context for another partition
  (`storage.partition.require_partition`).

Stage-2 rules, implemented in `MemoryAdapter.access` (patch `0002`):

* Partition: `PartitionRef(PRODUCT_NAME.lower(), "default")`, so `locus` or `locusx`.
* Workspace: `core.workspace_root or core.cwd`, which is host state. A task checkout therefore keys by
  its source root, not its worktree.
* Grants. The candidate grants are:
  * project `'ws-' + sha256(resolved workspace)[:32]` and legacy target `'workspace:' + sha256(resolved workspace)`;
  * agent `<active agent id>` and legacy target `'agent:' + sha256(agent id)`.

  For the `recall`, `user` and `tool` purposes, each grant is included only when the per-message
  `MemoryPolicy` scope allows it. `ingest` always carries the two workspace grants, whatever the
  scopes are, so that archived messages are scoped to the workspace, and never carries agent grants.
  `maintain` carries no grants.
* Ask mode (`just_chat`) drops both workspace grants for `recall`, `user` and `tool`. It has no effect
  on `ingest`.
* Actors and operations:

  | Purpose | Actor | Operations |
  |---|---|---|
  | `recall` | `USER` | `{READ}` |
  | `user` (routes; Stage 3) | `USER` | `{READ, WRITE, APPROVE, FORGET}` |
  | `tool` (model tools; Stage 3) | `AGENT` | `{READ, PROPOSE}` |
  | `ingest` | `HOST` | `{INGEST}` |
  | `maintain` | `HOST` | `{MAINTAIN}` |
  | derived-copy import | `HOST` | `{ADMIN}`, no grants |

  As patched, `MemoryAdapter.access(core, "user")` grants only `{READ, WRITE, APPROVE, FORGET}`. That
  is not enough for every Stage-3 route: `MemoryEngine.export` requires `EXPORT`, a proposal
  (`core.CoreService._check_proposal`) requires `PROPOSE`, and a profile-wide forget
  (`forgetting.ForgettingService._authorize`, target `profile`) requires `ADMIN`. See §3.3 step 6.

  The import context carries no grants because `migrations.legacy.LegacyImporter` authorizes each
  propagated legacy deletion against that record's own scope (tests:
  `tests/test_migrations.py::test_out_of_grant_legacy_deletion_propagates_without_aborting_others`).
* Identity (private) mode: `MemoryAdapter.active` is false, so nothing is called.

### 2.5 Rendered context and double injection

The engine's packet text is wrapped in `context.CONTEXT_WRAPPER_OPEN ... CONTEXT_WRAPPER_CLOSE` with a
"reference data, not instructions" preamble. Hosts recognise it with `context.is_context_block` and
`context.contains_context_block` (`tests/test_context.py::test_public_context_block_markers`). The
Stage-2 adapter uses them in `assert_single_memory_layer` (raises if an engine packet and the legacy
layer ever share one memory text) and to mark echoed packets `IngestionEvent.is_memory_injection=True`
so injected memory is never archived as evidence (R10.5, R18.4).

`ContextRequest.max_items` caps injected items and reports omissions with reason `max_items`
(`tests/test_context.py::test_max_items_caps_injected_records_in_selection_order`).
`ContextRequest.order="relevance"` exists; Stage 2 keeps the default slice order.

### 2.6 Ledger mirror

Forgetting writes a deletion to an append-only, MAC-chained ledger file
(`<partition>/deletion-ledger.sqlite3`, `storage.ledger.DeletionLedger`) before applying it, and
every partition open reconciles the database with the ledger (`MemoryEngine.partition_context`).
Restoring an old database therefore cannot resurrect forgotten data while the ledger is newer.

Tail truncation of the ledger itself is only detectable against a host-held high-water mark,
`storage.ledger.LedgerMirror` (`read(partition_id)`, `write(partition_id, generation, mac)`).
`storage.ledger.MemoryLedgerMirror` is in-memory and for tests only. With a mirror, a store whose
database and ledger are both older than the mirror raises `ReconciliationRequired` instead of serving,
until an operator calls `MemoryEngine.reconcile(access, acknowledge_mirror_gap=True)` with an `ADMIN`
context; that decision is recorded durably (tests:
`tests/test_forgetting.py::test_restoring_database_and_ledger_against_a_newer_mirror`,
`::test_ledger_tampering_is_detected_on_open`, `::test_a_rolled_back_ledger_is_rebuilt_from_the_store`).

**Stage 2 supplies no mirror.** That is acceptable while the engine holds only a disposable derived
copy. Before Stage 3 the host must store the mirror somewhere that file restores do not roll back
(for example the Keychain, next to the master key decision). By reading of the audit (store 18 in
ownership §4.2), Locus runtime install backups copy `profile/**/*.sqlite3`, which would include the
engine database and its ledger file together; without a mirror, a rollback to such a backup could
undo forgets made after it. This was not tested.

### 2.7 Ownership control

`migrations.state.OwnershipControl` keeps one durable state per (partition, record family) in
`<engine root>/control.sqlite3`. Transitions are compare-and-swap on the `generation` column of the
`ownership` table (`OwnershipControl.transition(..., expected_generation=...)`), and every transition
is logged in `ownership_log`:

| State | Authoritative | Permitted writers |
|---|---|---|
| `legacy_authoritative` | legacy | legacy |
| `shadow_prepared` | legacy | legacy |
| `validated` | legacy | legacy |
| `cutover_in_progress` | none (quiesced) | none |
| `package_authoritative` | package | package |
| `rollback_in_progress` | none (quiesced) | none |
| `legacy_retired` | package | package (terminal) |

Fencing on the package side: `MemoryEngine._fence` checks before every canonical write (remember,
propose, approve, reject, correct, pin, supersede, episodes, procedures, repository snapshots and
interchange imports, consolidation), and `core.CoreService._check_owner` re-checks inside the write
transaction (`CoreService._commit_write`). Forgetting is never fenced. The legacy importer's own writes
are unfenced on purpose (they run while legacy is authoritative). Tests:

* `tests/test_migrations.py::test_engine_canonical_writes_are_fenced_until_package_is_authoritative`
  (exercises `remember` only);
* `tests/test_review_group1.py::test_canonical_record_writes_are_fenced_beyond_the_core_api`
  (procedures, episodes, consolidation, and the in-transaction check);
* `tests/test_review_group1.py::test_a_write_that_passed_the_fence_before_rollback_is_fenced_not_lost`
  (a `remember` that passed the up-front check is refused inside the transaction);
* `propose` is covered only by the Stage-2 host test
  `test_canonical_writes_through_the_adapter_are_fenced_while_legacy_is_authoritative` in patch `0002`.

Fencing of `approve`, `reject`, `correct`, `set_pinned`, `supersede`, `snapshot_repository` and
`import_repository_interchange` is implemented through the same `_fence` call but has no test of its
own.

Fencing on the legacy side: `OwnershipControl.writer_guard(partition_id, "memories", "legacy")`
returns a callable for `LegacyMemoryVault(write_guard=...)`. A fenced legacy vault is served strictly
read-only (tests: `tests/test_compat_legacy.py::test_write_guard_fences_mutations_but_not_reads`,
`::test_fenced_reads_never_modify_the_store`, `tests/test_migrations.py::test_full_cutover_fences_legacy_writer`).
**Neither patch wires `write_guard` yet**; Stage 3 must, and the control file must then be opened in
every mode, not only when the engine is.

`OwnershipControl` accepts the family names `memories`, `context_snapshots` and `skill_observations`,
but `Migrator` handles only `memories`; the dry-run inventory (`migrations.legacy.inventory`, key
`not_migrated_tables`, from `migrations.legacy.NOT_MIGRATED_TABLES`) reports the other two as "not
migrated by this importer".

---

## 3. Staged extraction plan

Each stage lands with its characterization tests green before the next begins (ownership §6). Every
bridge has an exit criterion (R4.4).

### 3.1 Stage 1: delegation facades (patch `0001`)

Code moves; data does not. The legacy vault file, its AAD (`memory-v1|...`, `locus-context-v1|...`,
`locus-observation-v1|...`), payloads, ids and error messages are unchanged.

| Locus file | Change |
|---|---|
| `memory.py` | `MemoryVault` subclasses `locus_memory.compat.legacy_vault.LegacyMemoryVault`. Locus keeps the app-data path and key custody (`_fallback_key`, `_master_key`), plus the embedder hook `_embed` (which still calls `knowledge.embed_texts`). A missing key for a vault that has rows now raises instead of silently creating a new key (D6). |
| `continuity.py` | `ContinuityStore` subclasses `LegacyContinuityStore`; `format_context_snapshots` comes from the package. `workspace_changed_files` stays in Locus. |
| `memory_runtime.py` | The plaintext-note migration calls `LegacyMemoryVault.import_legacy_note`: a retry never overwrites an edited record and `created_at` is kept. |
| `agent/tests/test_product_backend.py` | The staged-`memory.py` check looks for `locus_memory.compat.legacy_vault` instead of `AESGCM` (D58). |

Behavior that changes for every facade caller, because it lives in `LegacyMemoryVault` (package tests
in `tests/test_compat_legacy.py`):

* an explicit empty `scopes` list returns nothing instead of everything (D1;
  `::test_empty_scope_list_returns_nothing_d1`). By reading `tools._impl_search_memory`, the model tool
  passes a filtered list, so its D1 path is closed by Stage 1. No host test exercises this;
* `approve` keeps a record's own target and never re-targets it (part of D2;
  `::test_approve_does_not_retarget_across_workspaces`);
* feedback is compare-and-swap (D23), editing title, content or tags drops the cached vector (D24),
  concurrent first-open column migration is tolerated (D25), non-finite confidence is rejected and a
  string `tags` value is one tag (part of D35);
* wrong keys fail closed (`::test_wrong_key_fails_closed_without_changing_records`).

Behavior that does **not** change in Stage 1: `enforce_target` stays off (so id-addressed delete,
feedback and update still act outside the caller's targets; the rest of D2), no `write_guard`, the
same routes, tools and recall. Format parity with the real Locus code is pinned by
`tests/test_compat_legacy.py::test_bidirectional_parity_with_real_locus_code`,
`::test_fixture_records_read_identically` and `::test_aad_and_payload_format`. The bidirectional test
runs only when the Locus checkout is present (its `locus_modules` fixture skips otherwise; the path can
be set with `LOCUS_SOURCE_DIR`); the two fixture tests run everywhere.

Exit criterion: the facade is deleted once nothing constructs `MemoryVault` or `ContinuityStore`
(Stage 4).

### 3.2 Stage 2: the adapter behind `LOCUS_MEMORY_ENGINE_MODE` (patch `0002`)

Two new Locus files (`memory_adapter.py`, `agent/tests/test_memory_adapter.py`) and edits to
`chat_service.py`, `server.py` and `core.py`. The canonical store stays the legacy vault and ownership
stays `legacy_authoritative`, so the adapter has no canonical write path.

Environment controls, read once when each `ChatService` is built (so they must be in the backend's
environment at launch):

| Variable | Values | Default | Effect |
|---|---|---|---|
| `LOCUS_MEMORY_ENGINE_MODE` | `disabled`, `shadow`, `enabled` | `disabled` | Any other value is treated as `disabled`, with a warning. |
| `LOCUS_MEMORY_ARCHIVE` | `1`, anything else | off | Archives committed user and assistant text into the engine's encrypted history. Only in `shadow` or `enabled`. |

| Mode | Prompt | Files written | Notes |
|---|---|---|---|
| `disabled` | Stage-1 prompt, byte for byte, on every ordinary turn | none; the engine is never constructed | Every hook returns immediately. The one change active here is D40 (below). |
| `shadow` | unchanged; the legacy layer is injected | `APP_DIR/memory-engine/**`, ciphertext only | After the legacy recall, the engine builds a packet over the derived copy; counts and timings go to `engine.metrics` and one content-free log line. Adds latency on the turn thread. |
| `enabled` | exactly one `## Approved memory` layer holding the engine packet, within `max_automatic_tokens`; no layer when nothing is recalled (D41) | as in shadow | Revalidated right before the model call. Engine failures fail closed: no memory layer, a `adapter.<stage>.failed` counter, and the turn continues. |

How the derived copy is kept current (`MemoryAdapter._sync`):

1. A content-free fingerprint of the legacy rows (ids, revisions, flags, targets, nonces; no
   ciphertext) decides whether anything changed.
2. If it changed, `migrations.legacy.LegacyImporter.run` imports read-only from the legacy file. The
   importer applies new revisions, metadata the legacy vault edits without a revision bump (`stale`,
   `superseded_by`, `pinned`, `expires_at`, tracked as `extra.legacy_fingerprint`), re-scoping, and
   legacy deletions as package tombstones (tests: `tests/test_migrations.py::test_delta_import_applies_legacy_edits_and_deletions`,
   `::test_legacy_feedback_incorrect_is_a_delta_marking_stale`,
   `::test_legacy_approve_replace_is_a_delta_superseding_with_link`,
   `::test_mapping_change_rescopes_legacy_target_to_project`).
3. The adapter supplies only `migrations.legacy.LegacyMapping`, a pure function of the legacy rows:
   each workspace hash maps to `ws-<hash[:32]>`; agent targets stay `legacy_target` because the hash
   does not reveal the agent id.
4. If the importer reports a change it could not apply (`decrypt_failures` or
   `deletion_propagation.failed`), the adapter serves no engine memory for that call and retries next
   call (`tests/test_migrations.py::test_failed_deletion_propagation_continues_and_blocks_verification`
   for the package side).
5. If the legacy vault or its `memories` table is gone, recall adds no layer and revalidation drops the
   pending packet.

Revalidation (`server._revalidate_memory_context` → `MemoryAdapter.revalidate_before_use`) runs right
before `AgentCore.run_turn` on solo turns and in the team writer slot. It re-syncs, then calls
`MemoryEngine.revalidate_context`; the package recompiles when anything the packet relied on changed
(R9.5; tests: `tests/test_context.py::test_correction_invalidates_cache_and_revalidate_detects`,
`tests/test_review_group1.py::test_revalidation_sees_a_conflict_approved_after_compilation`).

Other Stage-2 behavior:

* **D40, active in every mode.** Solo saved-agent (profile) turns recall with the profile's agent id
  instead of `"primary"`. Ordinary turns are unchanged. It can be split out of `0002` (the
  `agent_id` argument at the solo-turn call site and both cases of
  `test_profile_turns_recall_with_the_profile_agent_id`).
* **Maintenance.** `on_session_boundary` schedules `MemoryEngine.maintain` on a daemon thread, at most
  every 6 hours per adapter, never concurrently, never opening the engine just to maintain it (R16.6).
* **Scope change.** `set_cwd` and a new session with a `cwd` call `MemoryEngine.invalidate` and drop any
  pending packet.
* **Archive filters.** Only persisted user and assistant messages; never `_locus_context`,
  `_delivery_id`, `_dispatcher_control` or `_mcp_observation` messages, nor anything containing
  `<think`. GUI prompt decoration is stripped from user text.
* **No data migration.** `context_snapshots` and `skill_observations` stay legacy-owned. The legacy
  database is opened read-only; the only legacy file the adapter can create is `master.key`, under the
  Stage-1 custody rule.

Rollback: unset `LOCUS_MEMORY_ENGINE_MODE` (or set `disabled`) and restart; optionally delete
`APP_DIR/memory-engine/`; or reverse the patch with `patch -R -p1`. No legacy data format is touched.
Known limitations and remaining scope are listed in [handoff README §8](../handoff/locus/README.md).

### 3.3 Stage 3: canonical cutover through migrations (not executed)

What the package provides, tested on disposable fixtures only (R20.1):

| Step | Package call | State transition | Tests (`tests/test_migrations.py`) |
|---|---|---|---|
| Dry run | `migrations.legacy.inventory` (read-only, content-free) | none | `::test_inventory_is_read_only_and_content_free`, `::test_inventory_reports_unmapped_scopes_and_wrong_key` |
| Shadow | `Migrator.prepare_shadow` (encrypted snapshot + manifest via `migrations.legacy.snapshot`, import from the snapshot) | `legacy_authoritative` → `shadow_prepared` | `::test_snapshot_manifest_integrity_and_no_plaintext`, `::test_crash_during_shadow_leaves_legacy_authoritative` |
| Validate | `Migrator.validate` (delta from the live file, full decrypt-and-compare `migrations.legacy.verify`) | → `validated` | `::test_verify_compares_metadata_changed_without_revision_bump` |
| Cutover | `Migrator.cutover(quiesce=...)`: fence, drain via the host hook, hold the legacy write lock, final delta, verify | → `cutover_in_progress` → `package_authoritative` (or back to legacy on any failure) | `::test_full_cutover_fences_legacy_writer`, `::test_cutover_aborts_to_legacy_when_verification_fails`, `::test_unpropagated_legacy_deletion_aborts_cutover` |
| Crash recovery | `Migrator.resume`, `migrations.cutover.abort_cutover` | finish or abort | `::test_crash_during_cutover_resumes_without_losing_writes`, `::test_crash_during_rollback_resumes` |
| Rollback | `Migrator.plan_rollback`, `Migrator.rollback(allow_partial=False)` | `package_authoritative` → `rollback_in_progress` → `legacy_authoritative` | `::test_rollback_preserves_post_cutover_corrections_and_deletions`, `::test_rollback_writes_back_a_post_cutover_pin`, `::test_rollback_refuses_unrepresentable_records_unless_partial` |
| Concurrency | compare-and-swap transitions | — | `::test_illegal_transitions_and_concurrent_migrators` |
| Artifacts | — | — | `::test_migration_artifacts_contain_no_plaintext` |

The CLI exposes the same steps (`locus-memory migrate ...`); `cutover`, `abort` and `rollback` only
preview unless `--yes` is passed.

Host work for Stage 3, in order (from [handoff README §9](../handoff/locus/README.md), refined against
the code):

1. Pin a `locus-memory` build in the hashed lock (§5).
2. Supply a durable `LedgerMirror` (§2.6).
3. Wire `OwnershipControl.writer_guard(partition_id, "memories", "legacy")` into every legacy
   `MemoryVault` construction (`memory_runtime.memory_vault`, the model tools), with the control file
   opened in every mode.
4. Provide a `quiesce` context manager that drains in-flight turns and REST writes.
5. Run `Migrator(engine, control, access, legacy_db, key, mapping, work_dir=...)` with an `ADMIN`
   context: `prepare_shadow`, `validate`, then `cutover`. `Migrator` refuses a non-admin context. The
   host chooses `work_dir`; the package does not delete the snapshot there, so the host owns its
   retention (R20.6).
6. Move the writers to the adapter: the `/api/memory*` routes in `api/continuity.py` (`memory_create`,
   `memory_update`, `memory_approve`, `memory_delete`, `memory_delete_all`, `memory_feedback`,
   `memory_import`, `memory_export`) with the `user` purpose, and the model tools
   `tools._impl_search_memory` / `tools._impl_propose_memory` with the `tool` purpose. JSON shapes
   consumed by the Swift DTOs stay unchanged (ownership §7).

   As patched, `MemoryAdapter.access(core, "user")` grants only `{READ, WRITE, APPROVE, FORGET}`
   (§2.4), so Stage 3 must widen the `user` purpose or add purposes before these routes move:
   * `EXPORT` for `memory_export` (`MemoryEngine.export` calls `policy.require(access, Operation.EXPORT)`);
   * `PROPOSE` for saves that are not explicit user saves and for imported entries, which should become
     candidates (the D3 fix; `core.CoreService._check_proposal` requires `PROPOSE`);
   * `ADMIN`, with actor `USER` or `HOST`, for `memory_delete_all` if it maps to a profile-wide forget
     (`forgetting.ForgettingService._authorize` requires `ADMIN` for a `profile` target).

   Without these, the routes raise `AccessDenied`. The `tool` purpose (`{READ, PROPOSE}`, actor
   `AGENT`) carries the operations the two model tools need (`READ` to search, `PROPOSE` to propose).
7. Set `EngineConfig(canonical_backend="package")` and open with `create_partitions=False`.
8. Decide the `context_snapshots` and `skill_observations` families. No package importer or migrator
   exists for them yet (§2.7); fix D11, D12 and D31 there first.

Rules that hold after cutover (R19.5, R20.5): disabling injection never moves writes back to legacy;
reverting ownership goes through `Migrator.rollback`, never a flag; exactly one writer is permitted in
every state (no dual write). `Migrator.plan_rollback` counts archived history messages as
unrepresentable, so a profile that ever ran with `LOCUS_MEMORY_ARCHIVE=1` needs `allow_partial=True`
to roll back; the records the legacy format cannot hold then stay in a read-only package store.

Not tested: running `Migrator` on top of a Stage-2 derived copy in the same engine root. The importer
is idempotent and applies deltas (`tests/test_migrations.py::test_import_preserves_identity_lifecycle_scope_and_is_idempotent`,
`::test_records_imported_without_fingerprint_are_reimported_once`), but whether Stage 3 reuses the
derived copy or starts from an empty root is a host decision.

### 3.4 Stage 4: retirement (not started)

Retirement criteria (R20.7, R20.8, and the bridge-removal criteria in the ownership matrix):

* every memory read and write in Locus goes through the adapter; no Locus code constructs
  `MemoryVault` or `ContinuityStore`; `memory.py` and `continuity.py` are deleted or reduced to
  re-exports with no SQL or crypto;
* the `server._automatic_memory_context`, `server._automatic_continuity_context` and
  `server._capture_continuity_snapshot` seams are inlined only after the seven test files that
  monkeypatch them have moved (ownership §2 rule 5);
* the per-request plaintext-note migration is replaced by a one-shot migration with a marker, and the
  legacy knowledge-DB `memories` table is purged physically (D5, D28);
* characterization, route, approval, scope, deletion and recovery tests pass, with migration, restart
  and rollback evidence on the real bundled runtime;
* the ownership state moves `package_authoritative` → `legacy_retired` (terminal; no further rollback
  through the legacy format);
* the final ownership matrix lists no reusable memory algorithm left in Locus outside owned shims.

---

## 4. Host call sites per adapter action

Locus line numbers for every row are in ownership §5 (pre-patch) and
[handoff README §2](../handoff/locus/README.md) (post-patch). "Legacy" means the Stage-1 facade.

| Boundary (R18.2) | Locus call site | Stage 2 wiring | Engine call | Still to do |
|---|---|---|---|---|
| Before the model call: solo turn | `server._run_user_turn` → `server._automatic_memory_context` (seam kept) | routes to `MemoryAdapter.recall`; the Stage-1 body moved to `server._legacy_memory_recall` | `_sync` then `build_context` | — |
| Just before the model call | `server._revalidate_memory_context` before `AgentCore.run_turn` (solo and team writer slot) | new seam → `MemoryAdapter.revalidate_before_use` | `revalidate_context` | team members are not revalidated before each member call |
| Team members | per-profile `_memory_context` built through the seam | routed through the adapter | `build_context` | continuity is still labelled approved memory (D12) |
| Team writer slot | `server._run_team_writer` | recall and revalidation routed | `build_context`, `revalidate_context` | parallel writer cores have no adapter |
| Collaboration helpers, evaluation cores | `collaboration_bridge`, `evaluation_runtime` | none | — | decide (D51) |
| Continuity recall and capture | `server._automatic_continuity_context`, `server._capture_continuity_snapshot` | legacy; `MemoryAdapter.continuity_allowed` is false only in identity mode while the engine is active | — | Stage 3 family decision |
| Committed message | `AgentCore._add_message` | `MemoryAdapter.on_committed_message` | `ingest_event` (`LOCUS_MEMORY_ARCHIVE=1` only) | — |
| Session boundary | `AgentCore.start_new_session` | `on_scope_change` (with `cwd`) and `on_session_boundary` | `invalidate`; scheduled `maintain` | — |
| Scope change | `AgentCore.set_cwd` | `on_scope_change(..., "workspace_changed")` | `invalidate` | consent toggles (`api/knowledge.py`) do not purge memory (not found in the audit) |
| Identity mode | `core.identity_mode` (the server already skips the seams) | `MemoryAdapter.active` false; seams return `""` if called | none | — |
| App shutdown | server lifespan | `MemoryAdapter.close` | `close` | — |
| Explicit remember, correct, approve, reject, forget, export, import | `api/continuity.py` routes listed in §3.3 step 6; Swift `WorkspaceKnowledgeModel`, `/remember` | legacy | — | Stage 3 (`remember`, `propose`, `correct`, `approve`, `reject`, `forget`, `export`; needs the purpose changes in §3.3 step 6) |
| Model tools | `tools._impl_search_memory`, `tools._impl_propose_memory` | legacy | — | Stage 3 (`search`, `propose`) |
| Selected-chat review | `api/continuity.memory_reprocess` | legacy | — | gate identity mode and workspace (D13), then `propose` |
| Task or attempt boundary | run start and end in `server` (`memory_session_id`, `memory_run_id`) | none | — | `record_episode` once a `VerificationAuthority` is supplied, under a purpose with `WRITE` or `INGEST`; recorded episodes are approved records that can be injected ([integration-workflows.md §4.5](integration-workflows.md)) |
| Repository change | `workspace_changed` event → `POST /api/knowledge/reindex` | none | — | repository memory stays disabled until the host sets `allowed_repository_roots` |
| Retry, `/init`, response preview | `AgentCore.retry_last_response`, `/init`, `api/system` preview | none | — | recompute or clear stale `memory_context` (D43) |
| Native provider delivery | `core` native path, `claude_runtime`, `codex_app_server`, `context_preservation`, `orchestration` | none | — | memory must be per-turn and ephemeral (D4, D44) |

---

## 5. Dependency and bundling

Facts checked read-only in Locus at `b332e455`:

* `Tools/PrepareAgentRuntime.sh` installs the agent's third-party dependencies with
  `pip install --require-hashes --only-binary=:all: --target <runtime>/site-packages --requirement agent/requirements-runtime.lock`,
  then precompiles everything before the bundle is code-signed.
* `Tools/PrepareRemoteRuntime.py` does the same with `--platform` arguments and `--no-compile`.
* `Tools/StageBackendEdition.stage_backend` copies only the `ollama_code` package directory (D58), so
  `locus_memory` cannot arrive as copied source. It must come through the lock as a wheel (R18.1,
  R24.4: no copied tree, sibling path, floating git dependency or runtime download).
* `agent/requirements-runtime.in` pins `cryptography==50.0.0`; `agent/pyproject.toml` declares
  `requires-python = ">=3.10"`.

Package facts: pure-Python wheel `locus_memory-0.1.0-py3-none-any.whl`; `requires-python >=3.10`; only
dependency `cryptography>=42`, satisfied by the existing pin. The version stays `0.1.0` across builds,
so **the hash in the lock is what pins the build**. `chat_service.py` imports the adapter, which imports
`locus_memory.context`, so an older build without the context markers fails at backend start in every
mode.

Steps (not applied to Locus):

1. Build the wheel at the commit to ship: `python -m pip wheel --no-deps -w dist .`
   (`scripts/verify_wheel.sh` does this and prints the SHA-256).
2. Vendor it, for example at `agent/vendor/wheels/locus_memory-0.1.0-py3-none-any.whl`, or publish it to
   an index you control.
3. Add `locus-memory==0.1.0` to `agent/requirements-runtime.in` and regenerate the lock:
   `pip-compile --generate-hashes --no-emit-find-links --find-links agent/vendor/wheels --output-file=agent/requirements-runtime.lock agent/requirements-runtime.in`.
   The lock must contain `locus-memory==0.1.0 --hash=sha256:<wheel sha256>`; check it with
   `shasum -a 256` on the vendored file.
4. Add `--find-links "${backend_root}/vendor/wheels"` to the pip call in `Tools/PrepareAgentRuntime.sh`
   and the equivalent argument in `Tools/PrepareRemoteRuntime.py`, keeping
   `--require-hashes --only-binary=:all:`.
5. Add `"locus-memory==0.1.0"` to `agent/pyproject.toml` `dependencies` so dev and CI match the bundle.
6. Re-run `agent/tests/test_product_backend.py`; its staged-server tests import from the runtime's
   site-packages and prove the wheel is importable in the bundle.

Evidence so far: `scripts/verify_wheel.sh` built the wheel and installed it offline into clean
Python 3.10 and 3.14 virtualenvs outside the checkout, checked that the import does not come from the
checkout and pulls in no host packages, and ran `examples/quickstart.py` and a CLI smoke test. The
`PrepareRemoteRuntime.py` path (with `--platform`) was not exercised.

---

## 6. Test evidence and commands

### 6.1 Package

```bash
.venv/bin/python -m pytest          # CPython 3.14.6
.venv310/bin/python -m pytest       # CPython 3.10.22
ruff check src tests
scripts/verify_wheel.sh <work-dir> <python3.10> <python3.14>
```

Counts change while review fixes land; run the commands for current numbers. The tests most relevant to
this document are named inline above.

`scripts/verify_wheel.sh` has prerequisites:

* `<work-dir>/wheelhouse` must already hold a `cryptography` wheel for each interpreter, because the
  install runs offline (`pip install --no-index --find-links <work-dir>/wheelhouse`). The script's
  header gives the command to fill it:
  `pip download --only-binary=:all: cryptography -d <work-dir>/wheelhouse --python-version X.Y`.
* It builds with the checkout's `.venv/bin/python` and `--no-build-isolation`, so that environment
  needs the build backend (`setuptools>=68`, from `pyproject.toml`).
* It writes the wheel to `<work-dir>/dist`, and one `venv-<X.Y>` and `run-<X.Y>.*` directory per
  interpreter under `<work-dir>`.

### 6.2 Host (disposable copy only)

Both patches were applied to a disposable `git archive` copy of Locus `b332e455` (`agent/`, `Tools/`,
`Config/`, `ProtocolFixtures/`) and tested with the bundled runtime (CPython 3.14.6, SQLite 3.53.1)
plus `PYTHONPATH=<locus-memory>/src`:

| Run | Stage 1 | Stage 2 |
|---|---|---|
| Memory-related host tests (`EXTRA_PYTHONPATH=<locus-memory>/src run_host_tests.sh <host>`; see below) | 768 passed, 6 failed | 791 passed, 6 failed (the 23 new adapter tests added) |
| Whole host suite (`python3.14 -m pytest agent/tests -q -p no:cacheprovider`) | baseline | the same failing and erroring tests as the baseline; the only difference is the 23 added passes |

`run_host_tests.sh` is a session scratch script. It is **not shipped** in this repository, so the
first row cannot be reproduced from the repository alone. What it does:

* it runs the bundled runtime's interpreter
  (`/Applications/Locus.app/Contents/Resources/AgentRuntime/python/bin/python3.14`) with
  `python -m pytest <files> -q -p no:cacheprovider` inside the host copy;
* it selects every `agent/tests/*.py` file whose text matches the extended regular expression
  `MemoryVault|memory_vault|ContinuityStore|/api/memory|propose_memory|search_memory|context-snapshots|skill-observations|KnowledgeStore|_automatic_memory_context|memory_context`;
* it sets `PYTHONPATH` to `$EXTRA_PYTHONPATH`, then a scratch `pydeps` directory holding pytest and
  its dependencies (the bundled runtime ships no pytest), then the runtime's `site-packages`.

Any rerun of these host commands therefore needs pytest and its dependencies on `PYTHONPATH` as well.

The 6 failures are the same environmental `test_product_backend.py` staged-server tests in both
columns: their subprocesses lack third-party packages on `PYTHONPATH` in the sandbox. Exact whole-suite
numbers, the cross-tree byte-identity check of disabled mode, and the mutation check are in
[handoff README §7](../handoff/locus/README.md).

Not run: the Swift test suite, the real app bundle, the staged-server tests with the vendored wheel,
any test against real user data, and any real migration.

---

## 7. What stays in Locus by design

From the ownership matrix (R2.2, R2.3, R18.3, R18.6):

* key custody (file today; Keychain if decided) and the KeyProvider and LedgerMirror implementations;
* workspace authorization and the canonical workspace reference; agent identity and profile binding;
* memory policy parsing, consent and approval UI, and who may approve;
* recall orchestration: when to recall, for whom, with what cleaned query, and the identity, parity and
  Ask-mode gates;
* prompt-layer composition, the `## Approved memory` layer title, context-meter attribution, and
  delivery to native providers;
* every HTTP/WebSocket route, `PROTOCOL.md`, and the Swift DTOs (the JSON shapes are a shared contract);
* session transcripts (`sessions/*.jsonl`) as the authoritative chat record; the engine's history
  archive is a searchable projection of permitted messages, not a second session lifecycle;
* the run DB, task capsules, verification receipts and usage ledgers;
* scheduling: the package performs bounded maintenance units; Locus decides when;
* document extraction, compaction, notes, boards, UserDefaults, and every other host store in
  ownership §4.2, including the session-delete cascade into them.

---

## 8. Open host decisions

From ownership §8, plus decisions the stages raise:

1. Key custody: Keychain through the stdin bootstrap for the app editions and a file provider elsewhere?
   What recovery exists when the database exists but the key does not?
2. Where the `LedgerMirror` lives so that file restores and install backups cannot roll it back.
3. Ship D40 inside `0002` or separately.
4. A host-supplied list of known agent ids (for example saved profiles) so agent records can map to
   `agent=<id>` instead of `legacy_target`.
5. Whether Stage 3 reuses the Stage-2 derived copy or starts from an empty engine root.
6. The `context_snapshots` and `skill_observations` families: same file and key, or split; package
   episodes and procedural candidates; reusable checks.
7. Personal scope: shared with every agent (as implemented) or primary-only (as the UI says) (D53).
   Agent scope: global per agent or per workspace and agent.
8. Which principal helpers and team members use (D51).
9. Whether the workspace knowledge index and the transcript index become package-owned, and whether
   they are then encrypted.
10. Whether ambient recall writes use statistics.
11. Who owns erasure of host-side derived copies; the proposal is that the package erases its stores and
    Locus cascades into its own.
12. How memory reaches ChatGPT native parity turns and langgraph-workflow in-process jobs (see
    [integration-workflows.md](integration-workflows.md)).

---

## 9. Host defects the package cannot fix

These are in Locus-owned code (defect ids from compatibility §19). The package either has no access to
the code path or must preserve the legacy format until Stage 3. "Status" is after both patches.

| Id | Defect | Status after Stage 1 and 2 | Host action |
|---|---|---|---|
| D2 | Id-addressed delete, feedback and update act on any id; `PUT /api/knowledge/memories/{id}` forces workspace/approved; import overwrites foreign ids | approve no longer re-targets; the rest remains (`enforce_target` off) | pass `enforce_target=True` in the facade, or route through the adapter (Stage 3) |
| D3 | Routes approve without review: `PUT /api/memory/{id}` without `status`, `POST /api/memory` default, import keeps status | unchanged | Stage 3 routes: `remember` only for explicit user saves, `propose` otherwise (including imported entries), `approve` only from the review UI. The route access context needs `PROPOSE`, which the patched `user` purpose lacks (§3.3 step 6) |
| D4, D44 | Decrypted memory persisted in Claude `locus-sessions/*.json` and non-ephemeral Codex threads; prompt churn forks threads | unchanged | deliver memory per turn and ephemerally |
| D5 | Migrated plaintext notes still recoverable from the knowledge DB and WAL | unchanged | `secure_delete` or `VACUUM` after the one-shot migration |
| D7 | Key file sits next to the ciphertext | unchanged | custody decision (§8 item 1) |
| D8 | Legacy metadata (`pinned`, `stale`, `expires_at`, `use_count`, `last_used_at`, `superseded_by`, timestamps) sits outside the AAD, so it can be changed without detection | format-bound, like D9. By reading, the Stage-2 importer copies `pinned`, `stale`, `expires_at` and `superseded_by` into the derived copy (§3.2 step 2), so a change there also reaches the engine in `enabled` mode | ends when the legacy format retires (Stage 4) |
| D9 | Unsalted legacy target and event hashes | format-bound; the package's own tokens are keyed (`crypto.PartitionKeyring.token`) | ends when the legacy format retires (Stage 4) |
| D10 | Knowledge routes accept any directory | unchanged | authorize workspaces against opened or registered roots |
| D11, D12, D31 | Snapshot goals contain the decorated prompt; team continuity shown as approved memory; snapshot pin and overwrite races | unchanged (continuity stays legacy) | fix snapshot assembly and labelling before the continuity family moves |
| D13 | `memory_reprocess` ignores identity mode and workspace binding | unchanged | gate it in the route |
| D14, D22, D60 | Plaintext copies outside the vault; deletes do not cascade; install backups never pruned | unchanged | erase inventory and cascade (ownership §4.2); backup retention |
| D15 | Embedding requests follow redirects; host not in `NO_PROXY` | unchanged: the facade's embedder still calls `knowledge.embed_texts` | disable redirects, bound responses, add the host to `NO_PROXY` |
| D16, D20 | No auth without `LOCUS_AGENT_TOKEN`; non-constant-time token compare | unchanged | server auth |
| D17 | Knowledge snippets unfenced in the prompt | unchanged (the engine packet itself is fenced, §2.5) | fence knowledge snippets |
| D18 | `record_skill_observation` is an ungated SAFE tool | unchanged | policy flag on the tool |
| D19, D34, D50 | Knowledge secret filter gaps; index defects; per-worktree knowledge DBs | unchanged | knowledge-index fixes, or decide package ownership (§8 item 9) |
| D21 | LocusX writes the crew chat ledger under `Locus/` | unchanged | Swift path fix |
| D27 | Server ignores the client's `revision` | unchanged | pass `expected_revision` through the Stage-3 routes |
| D28 | Plaintext-note migration runs on every request, creates knowledge DBs, tools never migrate, unmigrated notes still served | crash-safety and `created_at` fixed (Stage 1) | one-shot migration with a marker (Stage 4 criterion) |
| D32 | `continuity.workspace_changed_files` mis-parses renames | unchanged (function stays in Locus) | fix the `-z` parsing |
| D39 | Recall depends on the knowledge capability | unchanged on the legacy path | decouple recall from `_knowledge_store` |
| D42, D43, D54 | Decorated recall query; stale `memory_context` on retry, `/init`, preview; steers do not refresh | engine query is stripped; legacy query unchanged; D43 and D54 unchanged | clean the legacy query; recompute or clear per turn |
| D45 | Uncaught `MemoryError` → HTTP 500 | unchanged | map errors in routes |
| D46 | Per-turn latency: a synchronous embed call (120 s timeout) on the legacy recall path before the model call, once per team member, plus other per-turn legacy work | unchanged in `disabled` mode. `shadow` mode runs the legacy recall and then adds the engine's sync and packet build on the same turn thread (§3.2). By reading `MemoryAdapter.recall`, `enabled` mode does not call the legacy recall. The other per-turn work listed under D46 was not re-checked against Stage 2 | move the embed off the turn thread or bound it; keep shadow runs short |
| D49 | No memory on ChatGPT parity turns | unchanged | decision (§8 item 12) |
| D52 | `/remember` saves under `'primary'` | unchanged | pass the active owner |
| D53 | Personal scope: UI and backend disagree | unchanged | decision (§8 item 7) |
| D55, D56, D57, D59 | Doc drift; test tripwire misses `sqlite3.connect`; WAL ignored in a ciphertext test; inconsistent error codes | unchanged | host docs and tests |
