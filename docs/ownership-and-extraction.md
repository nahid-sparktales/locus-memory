# Ownership and extraction plan

This document records two things for each memory responsibility that exists in Locus today: who owns it now, and who should own it once `locus-memory` is extracted. It also says how to get from one to the other without breaking existing data or clients. The evidence for every claim is in [locus-compatibility.md](locus-compatibility.md); defect ids (`D1`, `D2`, ...) refer to §19 of that document.

Path conventions match the compatibility document. Python paths with no directory refer to `agent/ollama_code/` in Locus at `b332e4554e72956f949506207ffa034749360d79`. Swift paths start with `Locus/`. Line numbers may be off by a few lines.

The temporary bridges, prerequisites and removal criteria in this document are **proposals**. Where a bridge mentions a package capability (for example "package vault" or "package extractor"), it means behavior the package must provide. It does not refer to an existing symbol.

---

## 1. Owners

| Owner | Meaning |
|---|---|
| `locus` | The host application, in Swift and Python. It owns the live session and turn lifecycle, provider accounts and native runtimes, tools and permissions, consent and the UI, workspace authorization, key custody (Keychain or file), task lifecycle, verification, usage accounting, and every route and wire protocol. |
| `locus-memory` | This package. It owns memory records and their crypto format, lifecycle, retrieval, context compilation, episodes, procedural candidates, history-archive search, repository observations, migration of legacy memory formats, erasure of its own stores, and memory diagnostics and evaluation. |
| `shared-contract` | A versioned interface that both sides depend on and neither may change alone: schemas, JSON shapes, hook payloads, identifiers and policies. |
| `external` | Owned by another project, for example the Codex app-server helper, the Claude runtime, langgraph-workflow or Agent Dispatcher. |

## 2. Ground rules for the extraction

These rules follow from the audited behavior.

1. **Byte compatibility.** Existing rows must keep decrypting. That covers:
   - AAD strings: `memory-v1|...`, `locus-context-v1|...`, `locus-observation-v1|...`
   - JSON canonicalization: memory uses `sort_keys` and `ensure_ascii=False`; continuity uses neither
   - target hashes, ids and the legacy migration id formula
2. **No raw client authority.** The package must not treat a client-supplied workspace path or agent id as authorization. Locus resolves and authorizes these first, then passes them in.
3. **Fail closed.** An empty scope set means no records (today it means all records, D1). An id-addressed operation must match the caller's scope target (today none do, D2). The package does not accept `status` from an untrusted save (D3).
4. **Keys come from outside.** The package receives key bytes or a key provider. It never silently generates a new key over an existing database (D6).
5. **Keep the seam names.** `server._automatic_memory_context`, `server._automatic_continuity_context` and `server._capture_continuity_snapshot` are monkeypatched by name in seven test files. Keep them as thin wrappers until those stubs have moved.
6. **Characterize first.** Pin the current behavior (compatibility §21) before fixing anything. Defect pins are flipped on purpose, one at a time.
7. **No decrypted memory at rest.** Decrypted memory must not be persisted outside the package except where Locus explicitly decides to deliver it to a provider. Today it is persisted in provider thread stores (D4).
8. **Packaging.** The Locus runtime installs dependencies with `pip --target` from a hashed lock (Python 3.14.6, cryptography 50.0.0). The package must therefore go through that lock, and `test_product_backend.py:89-90` (which requires the staged `memory.py` to contain `AESGCM`) has to change.

---

## 3. Ownership matrix

Columns: responsibility | present owner (path) | final owner | temporary bridge | migration prerequisite | bridge-removal criterion.

### 3.1 Storage and crypto

| Responsibility | Present owner (path) | Final owner | Temporary bridge | Migration prerequisite | Bridge-removal criterion |
|---|---|---|---|---|---|
| Memory record store: `memories` and `memory_events` schema, connections, pragmas | `memory.py:115-173` (`MemoryVault`) | locus-memory | `memory_runtime.memory_vault()` returns a package-backed vault that has the method surface the routes, tools and recall use today (`save`, `approve`, `list`, `search`, `delete`, `delete_all`, `feedback`, `record_event`, `diagnostics`, `maintain`, `status`, `export`, `import_values`), opened on the existing `APP_DIR/memory/memory.sqlite3` | A golden fixture DB from current code. A schema-version scheme (`user_version`) that accepts the 12-column pre-v2 layout and the 15-column layout, and survives concurrent first opens (D25). Connections are closed explicitly | Every Locus constructor (`memory_runtime.py:13`, `tools.py:1181,1198`) goes through the package. `memory.py` is deleted or reduced to a compatibility re-export with no SQL or crypto |
| Crypto envelope: AES-256-GCM, 12-byte nonce, 16-byte tag, memory-v1 AAD, canonical JSON | `memory.py:175-214` | locus-memory | Package codec reads and writes memory-v1 unchanged | Golden vectors: AAD bytes, nonce and tag lengths, canonical JSON (compat §21 cases 1-3) | A DB written by Locus HEAD round-trips through the package. Locus no longer imports `AESGCM` for memory |
| Continuity envelopes (`locus-context-v1`, `locus-observation-v1`) | `continuity.py:144-170,213-218,363-382` | locus-memory | Package codec covers all three AAD domains, each with its own JSON canonicalization | Golden vectors for both AADs, including the status re-encrypt on observations | `ContinuityStore` is removed from Locus |
| Optional v2 envelope that also binds pinned, stale, expires_at, superseded_by | none (D8) | locus-memory | Read v1, write v1 until v2 exists | A v2 AAD design plus a lazy re-seal path that keeps v1 readable | Every row is v2, or v1 is read-only |
| Key custody (where the 32 bytes live) | `memory.py:35-78` (`master.key` file, O_EXCL, 0600/0700) | locus | Locus reads the existing file with logic equivalent to `_fallback_key` and passes the bytes to the package. The package's file provider is used only by CLI or headless callers | A KeyProvider contract. A product decision on the Keychain (would mirror `IdentityVaultStore.swift:12-44`, delivered over the stdin bootstrap at `proxy.py:86-102`, never through the environment). Doc updates to `PROTOCOL.md:269-272` and `README.md:143-146` | No package code path opens `APP_DIR/memory/master.key` by default. Locus supplies the key on every runtime: app, chat workers, independent runtime, remote runtime |
| Key-mismatch detection | none (D6) | locus-memory | none | A canary or key-id row design that is written on first open and checked on every open | Opening with the wrong key fails loudly and never regenerates |
| Key rotation and re-wrap | none | locus (trigger), locus-memory (re-encrypt) | none | Key id in the envelope. A re-encrypt routine that preserves the AAD fields and revisions | A rotation test passes on a fixture DB |
| Private file modes (0700 dir, 0600 DB, key, WAL, SHM) | `memory.py:40,47,55,171`; continuity chmod | locus-memory | Package keeps the same modes | none | n/a (stays in package) |

### 3.2 Identity, scope and consent

| Responsibility | Present owner (path) | Final owner | Temporary bridge | Migration prerequisite | Bridge-removal criterion |
|---|---|---|---|---|---|
| Canonical workspace reference and its hashes | `memory.py:81-97` (vault); `continuity.py:32-39`; `knowledge.py:52-62`; `memory.py:689,715` (events, raw string); `memory_runtime.py:18-20` (legacy id) | shared-contract (Locus resolves; package hashes) | Package takes a resolved path and reproduces every legacy hash variant when reading | Choose one canonical form. A mapping table from legacy hashes to the new reference. A plan for event hashes (they are raw-string hashes, so old events may not map) | Every package store is keyed by one workspace reference. Legacy hash variants appear only in read-only compatibility code |
| Workspace authorization (may this request use this path?) | `memory_runtime.py:35-36`; `knowledge_runtime.py:11-16` (client string trusted) | locus | Locus keeps `memory_workspace()` and adds a check against opened or registered workspaces before calling the package | A source of truth for registered workspaces | Routes reject unregistered paths (D10). The package never sees an unauthorized path |
| Agent principal (`'primary'` or a profile UUID) | `core.py:834-857`; `server.py:571-587,2533-2546`; `tools.py:102`; `AgentTeamsSettingsView.swift:3100-3111` | locus (identity); locus-memory (hashing) | The adapter passes an explicit agent id on every call; no implicit default | Decide case normalization. Existing hashes come from uppercase `uuidString`, so normalizing needs a migration. Decide which principal helpers and team members use (D51) | Recall uses the profile id (D40). `/remember` uses the active owner (D52) |
| Personal-scope semantics | `memory.py:82-83`; `server.py:891-913`; UI copy `AgentTeamsSettingsView.swift:3619` | shared-contract | Keep current backend behavior: personal memories go to every agent whose policy includes `personal` | A product decision | UI copy and backend agree, and a test pins it (D53) |
| Memory policy (toggles, scopes, budgets) | `agent_config.py:54-65,129-196`; `AgentTeams.swift:147-205` | shared-contract | Locus parses the client policy and passes resolved scopes and limits to the package | none | The package enforces the passed policy and fails closed. It never sees raw client policy JSON |
| Who may approve (consent) | UI (`AgentTeamsSettingsView.swift:3146-3186`); `api/continuity.py:173-249` | locus | Routes call the package's propose and approve operations; create and update no longer take `status` from the client | An actor model for approve (user, import, migration) | `PUT`/`POST /api/memory` cannot approve (D3). Approve checks the target (D2) |
| Approval state transition | `memory.py:363-401` | locus-memory | Same as above | Target check; no re-targeting | Characterization pins flipped |
| Identity, parity and Ask-mode exclusions | `server.py:565-576,478-485`; `core.py:4727,849-858,863-865` | locus | The adapter is not called (or gets an explicit no-recall flag) in identity and parity modes. Ask mode passes scopes without `workspace` | none | n/a |
| Capability gates (`workspace_knowledge`, `transcript_search`) | `capabilities.py:18-35`; three copies of `_knowledge_store` (`api/knowledge.py:22`, `api/continuity.py:22`, `server.py:278`) | locus | Gates wrap package calls and never raise into recall | Embedding settings stop living in the knowledge DB | Recall and `/api/memory/search` work with knowledge disabled (D39) |

### 3.3 Records and lifecycle

| Responsibility | Present owner (path) | Final owner | Temporary bridge | Migration prerequisite | Bridge-removal criterion |
|---|---|---|---|---|---|
| Validation, normalization, update merge | `memory.py:244-361` | locus-memory | Package reproduces the current merge exactly (compat §4.10) | An explicit update contract (patch or replace). A revision compare-and-swap. Fixes for NaN, string tags and unbounded provenance (D35). Embedding invalidation (D24) | Swift's `revision` is enforced. Omitted fields behave as documented |
| Candidate TTL and expiry | `memory.py:23,331-333,403-419,429` | locus-memory | Lazy expiry stays inside `list()` at first | Per-target expiry, or a maintenance job; correct event attribution (D30) | `list()` no longer deletes rows |
| Conflict detection and supersession | `memory.py:462-502,363-401` | locus-memory | Reuse the heuristic | Handling for generic titles (D29); performance (D47) | `status()` is no longer O(N²) |
| Feedback signal | `memory.py:653-681`; route `api/continuity.py:334-349` | locus-memory | Package adds a revision CAS | none | The concurrency test from compat case 23 passes |
| Delete one, delete scope | `memory.py:635-651`; routes `api/continuity.py:199-206,252-270`; `api/knowledge.py:143-161` | locus-memory | Scoped delete. The `DELETE /api/memory` personal behavior stays as is until decided | Decide whether a workspace-scoped delete-all also removes personal memories (Swift toast `WorkspaceKnowledgeModel.swift:581` says yes) | Delete requires a target match. References (`superseded_by`, `supersedes`) are cleaned up |
| Pipeline events and diagnostics | `memory.py:683-744`; `api/continuity.py:363-396` | locus-memory (events); locus (adds tool-registry facts) | Package reproduces the events and reads legacy raw-string buckets | Resolved workspace hash for new events | Diagnostics buckets agree with targets |
| Maintenance (`valid_until` → stale, conflict summary) | `memory.py:746-779`; route `api/continuity.py:352-360` | locus-memory (logic); locus (trigger) | Route calls the package | A scheduler decision (none exists today) | n/a |
| Vault status report | `memory.py:781-804` | locus-memory (the JSON shape is a shared contract with `MemoryVaultStatus`) | Same JSON | none | n/a |
| Export and import (`locus-memory-export` v1 and v2) | `memory.py:806-835` | shared-contract | Package reads v1 and v2 and writes v2 | Transactional import; imported records go through review or an explicit actor; foreign ids are not overwritten | Import cannot approve silently or re-target |
| Legacy plaintext note migration | `memory_runtime.py:11-32`; legacy table `knowledge.py:120-131,538-557`; legacy search `knowledge.py:477-488` | locus-memory | A one-shot migration that Locus calls once per workspace at first vault open, guarded by a marker. The per-request call in `memory_vault()` is removed | Marker storage; skip invalid rows; keep `created_at`; never overwrite edited vault rows; catch `sqlite3.Error`; purge physically (`secure_delete` or `VACUUM` of the knowledge DB) (D5, D28) | Every profile has the marker. The legacy `memories` table is empty and vacuumed. `KnowledgeStore.search` no longer reads it. `settings().memory_count` no longer counts it |

### 3.4 Retrieval and context compilation

| Responsibility | Present owner (path) | Final owner | Temporary bridge | Migration prerequisite | Bridge-removal criterion |
|---|---|---|---|---|---|
| Hybrid lexical and semantic ranking | `memory.py:529-633` | locus-memory | Package copies the formula as is | Characterization tests (compat cases 24-27). Decide whether use stats stay inside search (D38) | Any change to the formula is a deliberate, tested change |
| Embedder (Ollama `/api/embed`, loopback guard, cosine) | `knowledge.py:590-642` (imported lazily by `memory.py:553`) | shared-contract (protocol in the package; provider settings from Locus) | Package ships a default loopback adapter. Locus passes the model and host | Move the embedding settings out of the per-workspace knowledge DB (`server.py:325`, `api/continuity.py:282`, `tools.py:1174-1180`). Turn off redirects and bound the response size (D15). Proxy handling | Memory search no longer opens a `KnowledgeStore` |
| Encrypted embedding cache (CAS reseal) | `memory.py:504-527` | locus-memory | Reuse | Invalidate on content, title or tag edits | Compat case 16 flipped |
| Context compilation (formatting, budgets) | `memory.py:838-849`; `continuity.py:518-542`; truncation at `server.py:338` and `core.py:848-851` | locus-memory | The Locus seam functions call the package's compile step and return its text | One shared token estimator (today three disagree; compat §9.4). An empty result returns `''` (D41) | Seams are pass-throughs. Budgets pack whole records |
| Automatic recall orchestration (when, for whom, with what query) | `server.py:309-366,571-582,891-916,2079-2089` | locus | Keep the three `server.*` function names as wrappers | Clean the query with `strip_prompt_decoration` and drop the plan JSON (D42). Explicit `agent_id` (D40). Catch package errors without failing the turn (D39). Clear or recompute `memory_context` per turn (D43) | Test stubs in `test_identity_vault.py`, `test_goal_runtime.py`, `test_task_reliability.py`, `test_verified_tasks.py`, `test_agent_world.py`, `test_capsule_execution.py` no longer depend on these names, after which the wrappers can be inlined |
| Prompt layer composition | `agent_config.py:251-299`; `core.py:875-933`; `orchestration.py:257-267` | locus | n/a | Team continuity gets its own layer, not `Approved memory` (D12) | n/a |
| Delivering memory to native providers | `core.py:2289,2295-2303,2452-2457`; `claude_runtime.py:242-247`; `codex_app_server.py:617-623`; `context_preservation.py:150`; `orchestration.py:2891-2911` | locus (governed by a shared-contract rule that memory is ephemeral) | none | Decide between per-turn input items and `base_instructions`, keeping thread fingerprints stable (D4, D44) | No decrypted memory text in `claude-accounts/*/locus-sessions/*.json` or in non-ephemeral Codex threads |
| Query and text cleaning (prompt decoration) | `sessions.py:1562-1596`; Swift `AppModel+ChatWorkers.swift:831-946` | shared-contract | The package calls a cleaner that Locus injects | Confirm which hosts decorate (CLI, schedules, triggers; unverified) | Recall queries and episode goals never contain decoration |
| Context meter attribution | `context_usage.py:24-59` | locus | n/a | Layer titles remain a contract | n/a |

### 3.5 Episodes, procedural memory, history and repository observation

| Responsibility | Present owner (path) | Final owner | Temporary bridge | Migration prerequisite | Bridge-removal criterion |
|---|---|---|---|---|---|
| Context snapshots (store, TTL, pin, prune, search) | `continuity.py:105-361` | locus-memory | Package opens the same `context_snapshots` table in the same file under the same key | Fix the ignored `pinned` argument and the same-turn overwrite (D31); bound plan and checkpoint; add a relevance floor | `ContinuityStore` is removed. Routes call the package |
| Building a snapshot from the live turn | `server.py:369-406,2171-2181`; tool `tools.py:1279-1310` | locus | Locus passes a cleaned goal and prose outcome | Decide whether plan and checkpoint belong in an episode or stay as Locus references | n/a |
| Skill observations (procedural candidates) | `continuity.py:124-136,363-515`; tool `tools.py:1255-1277` | locus-memory | Package opens the same table | Stable numbering (D33); a policy flag on the tool (D18) | `ContinuityStore` is removed |
| Selected-chat candidate extraction | `api/continuity.py:399-527` | locus-memory (pure extractor); locus (route, session load, `memory_review` run) | The route calls the package extractor with the user messages it loaded | Refuse identity-mode sessions; bind the session to the target workspace (D13) | The regex logic no longer lives in a route handler |
| Automatic candidate extraction at turn, task or session end | not found | locus-memory | none | A committed-message or end-of-attempt hook (§5) | n/a |
| Reusable checks (constraints learned from corrections) | `reusable_checks.py`; `api/reusable_checks.py`; migration 17 in `agent-runs.sqlite3` | undecided: Locus today; candidate for locus-memory's procedural store | none | A decision. Untangle them from the run DB schema chain (`runstore.py:745-777`). Encrypt the correction text | n/a |
| History archive (transcript FTS) | `transcript_search.py`; `session_runtime.py:20-31` | locus-memory | Package reads the session JSONL through a session-source adapter that Locus injects (replacing direct imports of `SessionStore`, `SessionMeta`, `strip_prompt_decoration`) | Filter identity-mode, `_locus_context` and `_display_only` content. Decide on encryption. Stable message ids | `/api/sessions/search` calls the package. `transcript_search.py` is removed |
| Session JSONL record contract (record types, `message_index`) | `sessions.py:567-1515` | shared-contract | n/a | A written, versioned description | n/a |
| Stable ids for user and tool messages | `core.py:2084` (assistant only) | shared-contract | Provenance uses `session_id + run_id + message_index` | Locus adds ids | Memory provenance cites message ids |
| Repository observation: git changed files | `continuity.py:53-79` | locus-memory | Package takes an injected environment or subprocess runner (today `proxy.sanitized_child_environment`) | Fix rename parsing (D32) | n/a |
| Workspace knowledge index | `knowledge.py`; `knowledge_runtime.py` | locus-memory (an open question in the audit) | Package opens the existing per-workspace DBs | Separate the settings record; Locus keeps the consent toggles. Index defects (D34). Plaintext at rest | Knowledge routes call the package |
| Document extraction jobs | `document_library.py`; `document_extract.py` | locus | Publishes through the index ingestion API (`index_extracted_document`, `remove_document_chunks`, `has_document_hash`, `document_path_allowed`) | Purge `result.json` on erase | n/a |
| Compaction and protected task context | `context_preservation.py` | locus | n/a | Make compaction threads ephemeral, or strip memory from their instructions | n/a |

### 3.6 Erasure, retention, evaluation and accounting

| Responsibility | Present owner (path) | Final owner | Temporary bridge | Migration prerequisite | Bridge-removal criterion |
|---|---|---|---|---|---|
| One erase across memories, snapshots and observations | not found | locus-memory (API) and locus (cascade into host stores) | `DELETE /api/memory` and `DELETE /api/knowledge` keep their current behavior | The inventory in §4 | One user action removes a memory and its derived copies from every listed store, or reports which stores cannot be erased |
| Session-delete cascade | not found (`api/sessions.py:349-401` trashes only the JSONL and the index) | locus | none | A cascade list: questions, collaboration, snapshots, provider homes, runtime events, crew ledger | n/a |
| Retention of package stores | scattered (`memory.py:703-711`; `continuity.py:244-263`) | locus-memory | Keep the current values | none | n/a |
| Retention of host stores (install backups, runtime events, task tables) | none (D60) | locus | n/a | n/a | n/a |
| Retrieval-quality evaluation | not found (signals only: `recall/*` events, feedback counts) | locus-memory | none | Fixture corpora | n/a |
| Reporting usage of the package's own model calls | not found | shared-contract | none | A callback contract into `usage_ledger` / `task_usage_ledger` | n/a |

### 3.7 Surfaces and packaging

| Responsibility | Present owner (path) | Final owner | Temporary bridge | Migration prerequisite | Bridge-removal criterion |
|---|---|---|---|---|---|
| REST routes `/api/memory*`, `/api/context-snapshots*`, `/api/skill-observations*`, `/api/knowledge*` | `api/continuity.py:31-584`; `api/knowledge.py:22-274` | locus | Handlers call the package; JSON shapes stay the same | Route fixture `agent/tests/fixtures/server-routes.txt` unchanged; `test_reviewability_report.py:75-110` | n/a |
| Legacy `/api/knowledge/memories*` CRUD and `/api/knowledge/changes` | `api/knowledge.py:74,97-151` (no Swift caller) | locus (deprecate) | Route them through scoped package calls | A decision on whether any non-Swift client uses them | Removed from the route fixture, or scoped |
| Agent tools | `tools.py:1140-1310,1406-1476`; `tool_registry.py:40-76`; `core.py:113-131`; `solo_swarm.py:41-51` | locus | Tools call the package | Fail-closed scope (D1); policy flag for observations (D18); `search_memory` is no longer marked parallel-safe if it keeps writing (D38) | n/a |
| Swift client and DTOs | `Locus/WorkspaceKnowledgeModel.swift`; `Locus/AgentTeams.swift:123-205,2013-2347`; `Locus/Models/BackendResponses.swift:272-296` | locus (the JSON is a shared contract) | Unchanged | none | n/a |
| Protocol and user docs | `agent/PROTOCOL.md:196-292,877,1346`; `README.md:143-146` | locus | Update whenever a contract changes | Remove or implement the `knowledge_indexing` event (D55) | n/a |
| Bundling into the app runtime | `Tools/StageBackendEdition.py`; `agent/requirements-runtime.lock`; `test_product_backend.py:89-90` | locus | Vendor the package into `AgentRuntime/site-packages` through the hashed lock | Update the packaging test | `memory.py` is no longer required in the staged tree |

### 3.8 External and reference systems

| Responsibility | Present owner (path) | Final owner | Temporary bridge | Migration prerequisite | Bridge-removal criterion |
|---|---|---|---|---|---|
| Codex helper state (`memories_1.sqlite`, `state_5.sqlite`, `sessions/`) | Codex app-server binary; Locus writes `config.toml` (`codex_app_server.py:230-275`) | external | n/a | Find out whether it persists `baseInstructions` and memories (unverified) | n/a |
| Claude runtime homes (`projects/`, `sessions/`); Locus-written `locus-sessions/*.json` | Claude runtime; `claude_runtime.py:35-38,219-247` | external (runtime files); locus (`locus-sessions`) | n/a | Stop writing decrypted memory into `instructions` | n/a |
| langgraph-workflow memory port | none (`ports.py:5-6` hands memory to the host) | external (consumer) | Plugin mode gets memory through ordinary Locus chat turns | A package recall API that a production `LocusHost` can call per job | n/a |
| Agent Dispatcher experience, episodic, semantic and learning stores | agent-skills `repo_store.py`, `repository_memory.py`, `learning.py` | external (design reference) | n/a | If ever imported: a versioned exporter (none exists), redaction fixes, and withholding credential paths | n/a |

---

## 4. Data store inventory

"Memory content" means the store holds memory records, or text derived from or injected alongside them. Locations use `APP_DIR` (§1 of the compatibility document: `~/.ollama-code` for standard Locus and the CLI, `~/Library/Application Support/LocusX/Agent` for LocusX, `<root>/profile` for the remote runtime).

### 4.1 Stores the package should own

| # | Store | Location | Format | Encryption | Writers | Readers | Disposition |
|---|---|---|---|---|---|---|---|
| 1 | Memory records and events | `APP_DIR/memory/memory.sqlite3`, tables `memories` and `memory_events` (plus `-wal`, `-shm`) | SQLite in WAL mode; schema in compat §4.3 | AES-256-GCM per record (memory-v1 AAD). Metadata columns and all of `memory_events` are plaintext but content-free. Mode 0600 | `MemoryVault.save/approve/expire_candidates/search/feedback/_store_embedding/maintain/delete/delete_all/record_event/import_values`; legacy migration | `MemoryVault` (routes, tools, recall) | locus-memory; opened in place |
| 2 | Context snapshots | same file, table `context_snapshots` | SQLite | AES-256-GCM (`locus-context-v1`); `session_id`, `workspace_hash`, `pinned` and timestamps are plaintext | `server._capture_continuity_snapshot`; `capture_context_snapshot` tool; snapshot routes; pruning | recall; `GET /api/context-snapshots`; Swift | locus-memory |
| 3 | Skill observations | same file, table `skill_observations` | SQLite | AES-256-GCM (`locus-observation-v1`); `number`, `status` and `workspace_hash` are plaintext | `record_skill_observation` tool; observation routes | observation routes; Swift | locus-memory |
| 4 | Vault key | `APP_DIR/memory/master.key` | 32 raw bytes | none (it is the key); 0600 file in a 0700 directory | `memory._fallback_key` (O_EXCL on first run, and silently whenever the file is missing) | `_master_key` via `MemoryVault` and `ContinuityStore` | Custody moves to locus; the package receives bytes |
| 5 | Legacy plaintext workspace notes | `APP_DIR/knowledge/<sha256(resolved)[:24]>/knowledge.sqlite3`, table `memories` | SQLite (columns in compat §5) | none | none at HEAD (only deletes by the migration and `delete_all`) | `memory_runtime.memory_vault` (migration); `KnowledgeStore.search` (as `approved_memory`); `settings().memory_count` | Migrate once, purge physically, stop reading |
| 6 | Workspace knowledge index | same file, tables `settings`, `documents`, `chunks`, `chunks_fts` | SQLite WAL with FTS5; float32 BLOB vectors | none; 0600 file, directory created with the umask (0755 observed) | `KnowledgeStore.configure/reindex/_embed_missing/index_extracted_document/remove_document_chunks/delete_all` | `KnowledgeStore.search/settings`; knowledge routes; tools; recall (settings only) | locus-memory (open question); consent toggles stay in locus |
| 7 | Transcript FTS index | `APP_DIR/transcript-index.sqlite3` | SQLite WAL with FTS5 (`schema_version` 2) | none; 0600 | `TranscriptIndex.sync/_index_file/_forget/delete_all` | `TranscriptIndex.search` via `/api/sessions/search` | locus-memory (history archive) |
| 8 | Memory export documents | file chosen by the user (NSSavePanel) or the HTTP response | JSON `locus-memory-export` v2 | none (deliberately readable) | `MemoryVault.export` | `MemoryVault.import_values` | shared-contract format |
| 9 | Skill observation exports | file chosen by the user or the HTTP response | JSON `locus-skill-observations` v1 | none | `ContinuityStore.export_observations` | the user (no importer) | shared-contract format |

### 4.2 Host stores that carry memory content or memory-adjacent data (stay in Locus)

| # | Store | Location | Format | Encryption | Writers | Readers | Disposition and why it matters |
|---|---|---|---|---|---|---|---|
| 10 | Session transcripts | `APP_DIR/sessions/*.jsonl`, `sessions/media/<id>/`, `session-metadata.json` (+ `.lock`), `chat-organization.json`, `session-trash/<batch>/` | Append-only JSONL plus JSON | none | `AgentCore._add_message`, `steer`, compaction, `ChatService.emit` (agent_activity), duplicate, retry branch, trash and restore | `SessionStore`, `TranscriptIndex`, `memory_reprocess`, `dispatcher_runtime.py:274` | locus. The source for the history archive and candidate extraction |
| 11 | Run DB | `APP_DIR/agent-runs.sqlite3` (+ `.schema-N.backup`) | SQLite, `schema_meta` v20: runs, run_events, checkpoints, `task_*`, `usage_*`, `reusable_checks`, `goals*`, `evaluation_*`, `routing_samples`, `turn_usage`, `capsule_attempts`, `task_file_changes`, `runtime_*` | none | RunStore, ChatService.emit, TaskVerifier, journal, ledgers, ReusableCheckStore, `memory_reprocess` (`memory_review` runs), RuntimeStore | many | locus. Holds plaintext tool receipts (`result[-8000:]`), correction text, untruncated `message_end` content, runtime commands. Only `runs` are pruned |
| 12 | Task file history | `<run DB dir>/task-file-history/<sha256>` | Content-addressed raw bytes | none; 0700 directory | `FileHistory` | `FileHistory` | locus. Up to 128 MiB per task, never pruned |
| 13 | Task capsules | `APP_DIR/task-capsules.sqlite3` | SQLite | none | `CapsuleStore` | capsule routes, task details | locus |
| 14 | Optional questions | `APP_DIR/questions.sqlite3` | SQLite: `questions`, `question_deliveries`, `question_responses` | none; 0600 | `QuestionService` (`question_service.py:107-275`) | ChatService | locus. User answers in plaintext; no delete path; erase cascade needed |
| 15 | Collaboration | `APP_DIR/collaboration.sqlite3` | SQLite WAL: `helpers`, `runs`, `mailbox`, `receipts`, `attempts` | none; 0600 | `CollaborationStore`; `collaboration_bridge.py:655-700` | collaboration bridge | locus. Helper transcripts and the parent's last 50 messages; may contain recalled memory; no delete path |
| 16 | Claude account homes | `APP_DIR/claude-accounts/<account_id>/` (`locus-sessions/<thread>.json`, `projects/`, `sessions/`, `backups/`, `telemetry/`) | JSON plus runtime files | none; 0700 directory, 0600 `locus-sessions` files | `claude_runtime.py` `_save`; the Claude runtime | `claude_runtime.py` `_load`; the Claude runtime | locus and external. **`instructions` holds decrypted memory** (D4) |
| 17 | Codex helper homes | `~/Library/Application Support/<Edition>/Codex` (`LOCUS_CODEX_HOME`), else `APP_DIR/codex`; per-account `<base>-accounts/<home_id>` | `config.toml`, `auth.json`, `sessions/...`, `state_5.sqlite`, `memories_1.sqlite`, `logs_2.sqlite`, `goals_1.sqlite`, `queue_1.sqlite` | none known | Codex helper; `codex_app_server.py:230-275` (`config.toml`) | Codex helper | external. Non-ephemeral threads receive memory in `baseInstructions` (D4). Contents unverified |
| 18 | Runtime install backups | `<runtime root>/install-backups/<journal id>/profile/**/*.sqlite3` (default root `~/.local/share/locus-runtime`) | SQLite online-backup copies | same as the source (memory rows encrypted, others plaintext); 0600/0700 | `runtime_install.backup_databases` (`runtime_install.py:252-268,371`) | rollback (`runtime_install.py:284-290`) | locus. Includes `memory.sqlite3` (not the key) and plaintext indexes; never pruned (D60) |
| 19 | Document library and job cache | `APP_DIR/knowledge/<digest>/document-library.sqlite3`, `document-jobs/<id>/{source,result.json}`; locks under `APP_DIR/document-extraction-locks/` | SQLite plus JSON | none; 0600/0700 | `DocumentStore` | `DocumentStore`, document routes | locus. Extracted text is plaintext and survives `DELETE /api/knowledge` |
| 20 | Agent config | `APP_DIR/config.json` | JSON (`model_windows` and `model_window_caps` keyed by `host\|model`) | none | `core.py:1197-1285` via `save_config` | `core.py` | locus. Operational learning, not memory |
| 21 | Extensions and skills | `APP_DIR/extensions/state.json` (v3), `extensions/skills/<name>/`, plugin cache and data (`extensions/plugins/data/...`) | JSON plus directories | none | `ExtensionManager` | `ExtensionManager`, `tool_registry` | locus |
| 22 | Model-call leases | `APP_DIR/model-call-leases-<16 hex>.sqlite3`; legacy `model-call-leases.sqlite3` (never swept) | SQLite | none | `CrossProcessModelCallScheduler` | same | locus; not memory |
| 23 | Notes | `~/Library/Application Support/<Edition>/{Workspace Notes, Chat Notes, Shared Notes, Notebook Notes}/<sha256>.txt` and `.styled`; `Notes Index.json`; `Notebook Catalog.json` | Text, NSKeyedArchiver, JSON | none; 0700/0600 | Notes UI; agent `notes_update` (`tool_registry.py:731-764`) | Notes UI; agent `notes_read` | locus. An agent-writable memory channel outside the vault |
| 24 | Workspace boards | `~/Library/Application Support/<Edition>/Workspace Boards/<sha256(workspace)>.json` | JSON (≤8 MiB) | none | Board UI; agent `board_*` tools | same | locus; task state |
| 25 | Crew chat ledger | `~/Library/Application Support/Locus/AgentCrewChat/<sha256(workspace)>.json` (hard-coded `Locus` even for LocusX) | JSON Ledger v1 | none; default permissions | `AgentCrewChatModel.persist` | `AgentCrewChatModel.init` | locus. Edition-isolation defect (D21) |
| 26 | UserDefaults | bundle plist keys `Locus.promptHistory`, `Locus.checkpoints`, `Locus.sessionOverviewStates.v1`, `Locus.AgentWorld.conversations.v1`, `Locus.AgentWorld.profileHistory.v1` | plist / JSON Data | none | `AppModel+WorkspaceProfiles.swift:202-251`; `AppModel+PlanAndCheckpoints.swift:11-33`; `SessionState.swift:637-647`; `AgentWorldModel.swift:222-266` | same; checkpoint restore re-injects text (`AppModel+ChatWorkers.swift:942-943`) | locus. Plaintext transcripts and prompts; must be in the erase inventory |
| 27 | Project instruction files | `<workspace>/AGENTS.md`, `OLLAMA.md`, `CLAUDE.md` | Markdown | none | the user; `/init` (`core.py:4816-4818`) | `core.py:780-789`; `orchestration.py:2822-2826` | locus; user-owned project memory |
| 28 | Dispatcher project map | `<workspace>/.agent-dispatcher/project-map.json` | JSON | none | agent-skills tooling (not Locus) | `dispatcher_runtime.py:309-323` via the bundled `context.py` | external |

### 4.3 Orphans (no writer at Locus HEAD)

| # | Store | Location | Origin | Disposition |
|---|---|---|---|---|
| 29 | REPL prompt history | `~/.ollama-code/history` | Removed `app.py` (commit `e09f41bb`) | Locus one-time cleanup decision; include in erase |
| 30 | Reverted Locus-native LangGraph runtime | `~/.ollama-code/langgraph/runs.sqlite`, `~/.ollama-code/langgraph/workflows/` | Locus PR #3 and #4, reverted in `518df429` and `cd47af5e` | Do not confuse with langgraph-workflow data; user-driven cleanup |
| 31 | Run DB in an unused location | `~/Library/Application Support/Locus/Agent/agent-runs.sqlite3` | Unknown; standard Locus does not set `OLLAMA_CODE_HOME` | Investigate |
| 32 | Leftover config backup | `~/.ollama-code/config.json.agent-clobbered.bak` | Written only by a worktree tool (`.claude/worktrees/agent-page-ux/Tools/PruneAgentTestLitter.py`) | Not memory |

### 4.4 External repositories (for reference)

| # | Store | Location | Format | Encryption | Notes |
|---|---|---|---|---|---|
| 33 | Dispatcher deep index | `~/.cache/agent-dispatcher/state-v1/<id>/repository-index.sqlite` | SQLite, schema 1 | none (owner-only) | Not present on this machine |
| 34 | Dispatcher experience | `.../experience.sqlite` | SQLite: events, corrections | none | Not present on this machine; not rebuildable; no migration |
| 35 | Dispatcher learning | `.../learning.sqlite`; `~/.cache/agent-dispatcher/learning-v1/profile-<digest32>/learning.sqlite` | SQLite | none | Not present on this machine |
| 36 | Dispatcher episodic, semantic and working memory | `.../repository-memory.json`, `memory-semantic.json`, `working-memory/*.json` (plus an in-project legacy fallback that is still read) | JSON schema 1 | none; not HMAC-signed | Only `working-memory` and the map and graph JSON exist on this machine |
| 37 | Dispatcher parser cache | `~/.cache/agent-dispatcher/parser-v1/` | HMAC-signed JSON plus a key file | integrity only | |
| 38 | langgraph-workflow checkpoints | in-process `<profile>/langgraph-workflow/checkpoints.sqlite3`; plugin `<PLUGIN_DATA>/workspaces/<key>/checkpoints.sqlite3` | SQLite WAL (LangGraph saver plus `lgw_*` tables) | optional host cipher; the plugin passes none | Job outputs may echo recalled memory |
| 39 | langgraph-workflow agent host | `<PLUGIN_DATA>/workspaces/<key>/agent-host.sqlite3`, `definitions/*.json`, `workspaces.json`, `locus-settings.json`, `venv-*` | SQLite and JSON | none; umask permissions for the DB and `workspaces.json` | Never pruned |

---

## 5. Host call sites mapped to adapter actions

Each table lists where Locus does the thing today and what the adapter would do. "Adapter action" describes the intended responsibility of the Locus-side adapter that calls the package; the names are descriptive, not existing symbols. **Not found** means the audit found no such call site.

### 5.1 Before the model call (recall and context)

| Call site | Location | Today | Adapter action |
|---|---|---|---|
| Solo turn: memory recall | `server.py:571-573` | `_automatic_memory_context(core, text, cfg, just_chat=...)`; `agent_id` defaults to `'primary'`; the query is the decorated text plus plan JSON | Recall with the cleaned request, an authorized workspace, the explicit agent id and the policy's resolved scopes and limits. Return a compiled block, or `''` |
| Solo turn: continuity recall | `server.py:574` | `_automatic_continuity_context` → `search_snapshots` (`server.py:358`) | Recall episodes, excluding the current session, with a relevance floor |
| Handoff to core | `server.py:577-587` → `core.py:824-873` (store at 848-851) | `configure_agent(memory_context, continuity_context, agent_id)` | Pass the compiled blocks; Locus composes the prompt |
| Gates | `server.py:565-570` (parity), `571-576` (identity, parity), `320` and `core.py:853-858` (Ask) | Skip, or drop the workspace scope | Do not call the adapter, or pass resolved scopes without `workspace` |
| Team members | `server.py:891-916` (memory 902, continuity 909) → `orchestration.py:219,257-267` | Per-profile `_memory_context`, with continuity labelled as approved memory | Recall per member agent id; continuity as its own layer |
| Team writer slot | `server.py:2079-2089` (recall 2082) | Memory only | Recall for the writer id |
| Writer snapshot and restore | `server.py:2211-2212,2296-2304` | Saves and restores contexts | none (Locus) |
| Profile boundary | `agent_profile_runtime.py:41-71` | Snapshot and restore around profile turns | none (Locus) |
| Prompt composition | `agent_config.py:283-286`; `core.py:898-906` | Builds the `Approved memory` and `Cross-chat workspace context` layers | Consumes the compiled block (no adapter call) |
| Classic route delivery | `core.py:3811-3850` (sent at 3934) | `messages[0]` | none |
| Native non-parity delivery | `core.py:2289,2295-2303,2452-2457` | `base_instructions`, hashed into the thread fingerprint | Shared-contract: memory is per turn and ephemeral (D4, D44) |
| Compaction | `context_preservation.py:150` | `start_thread(base_instructions=messages[0])`, non-ephemeral | Same contract |
| Team member on claude_plan | `orchestration.py:2891-2911` | `broker.complete(base_instructions=system)`, which persists | Same contract |
| Model-initiated memory search | `tools.py:1160-1192` | `MemoryVault().search` (no migration; empty scopes mean all scopes) | Package search; empty scopes return nothing |
| Model-initiated knowledge search | `tools.py:1140-1157` | `KnowledgeStore(ctx.cwd).search` (worktree DBs) | Package index search keyed by the authorized `workspace_root` |
| Solo-swarm knowledge closure | `server.py:596-612` | `knowledge_search` over `workspace_root`, limit 8 | Package index search |
| Collaboration helpers | `collaboration_bridge.py:194-207,279-281` | No `memory_context`; `agent_id = spec.agent_id` | Decide: recall for the parent principal, or none |
| Evaluation cores | `evaluation_runtime.py:109` | Configured without memory | none |
| Response preview | `api/system.py:283-284` (route at 300) | Shows the stale previous-turn layer | Recompute, or show no memory layer |
| Retry and `/init` | `server.py:2833-2841` → `core.py:3348-3417`; `core.py:4817` | Reuse the stale `memory_context` | Recompute, or clear |
| Mid-turn steer | `core.py:559-597` | Recall is not refreshed | **not found** (optional refresh) |
| Restored checkpoint text (Swift) | `Locus/AppModel+ChatWorkers.swift:942-943`; `AppModel+SendPipeline.swift:214-215,410` | Prepends `'Restored session context:'` from UserDefaults checkpoints | none (Locus); erase inventory |
| Project instruction files | `core.py:780-789` | `AGENTS.md`, `OLLAMA.md`, `CLAUDE.md` (8,000 characters) into the prompt | none |
| Skill index injection | `core.py:3782-3787` | Enabled skills index | none |
| Dispatcher context inspection | `dispatcher_runtime.py:309-323` | Reads the in-workspace project map | none |
| langgraph-workflow in-process jobs | `integrations/locus/adapter_reference.py:246-293` (langgraph-workflow repo) | No memory | Future: recall per job via Locus |

### 5.2 Explicit remember, correct and forget

| Call site | Location | Today | Adapter action |
|---|---|---|---|
| UI Remember | `WorkspaceKnowledgeModel.swift:300-341` → `POST /api/memory` `api/continuity.py:173-196` (save 179, event 185) | Saves `approved` (the server default is also approved) | Remember as approved with `actor=user`, scope target checked |
| `/remember` slash command | `SlashCommands.swift:140-142` → `AppModel+Commands.swift:69-75` → `LocusApp.swift:1091-1163` (agent `'primary'` at 1141-1148) | Same route | Same, with the active memory owner |
| Model proposal | `tools.py:1195-1253` (save at 1223) | Candidate with a 30-day TTL and events | Propose a candidate |
| Selected-chat review | `WorkspaceKnowledgeModel.swift:453-485` → `api/continuity.py:399-527` (save at 476) | Regex extraction, up to 20 candidates | Locus loads the session; the package extracts and proposes |
| Approve candidate | `WorkspaceKnowledgeModel.swift:403-430` → `api/continuity.py:227-249` (approve at 234) | Id-only lookup; re-targets | Approve with a target check, the actor, and keep_both or replace |
| Edit (a correction) | `WorkspaceKnowledgeModel.swift:373-401` → `PUT api/continuity.py:209-224` (save at 216) | Full replace; a missing status means approved; revision ignored | Update with a revision check; never approves implicitly |
| Pin, unpin, mark stale or current | `AgentTeamsSettingsView.swift:3462-3487` (via update) | Update route | Field-level update |
| Feedback (helpful, ignored, incorrect) | `api/continuity.py:334-349` (feedback at 340); no Swift caller | Unscoped; no CAS; `incorrect` marks stale | Scoped feedback with CAS |
| Supersede (replace older) | `AgentTeamsSettingsView.swift:3146-3186` → approve with `resolution='replace'` | Marks conflicts stale and superseded | Supersede |
| Reject candidate | `WorkspaceKnowledgeModel.swift:344-370` (`outcome=reject`) → `DELETE api/continuity.py:252-270` | Hard delete plus `rejection/recorded` | Reject with a target check |
| Forget one | same route, `outcome=delete` | Unscoped hard delete | Forget with a target check; clean up references |
| Forget all for an owner | `DELETE /api/memory` `api/continuity.py:199-206` (delete_all at 205); Swift delete-all (`WorkspaceKnowledgeModel.swift:545-563`, toast 581) | All scopes, personal included | Forget scope set (decision on personal) |
| Delete the workspace index and memory | `DELETE /api/knowledge` `api/knowledge.py:154-161` | Index rows plus workspace-scope memories; leaves snapshots, observations and document results | Erase the workspace across package stores, then cascade in Locus |
| Legacy notes CRUD | `api/knowledge.py:97-151`; no Swift caller | Forces workspace and approved; unscoped delete | Deprecate, or route through scoped calls |
| Export and import | `api/continuity.py:306-331`; Swift `WorkspaceKnowledgeModel.swift:486-512` (export), `529` (import) | Plaintext export; import keeps ids and status | Export; import through review or as an explicit actor |
| Snapshot pin, delete, clear | `api/continuity.py:50-90`; Swift `WorkspaceKnowledgeModel.swift:139-250` | Scoped to the workspace | Episode pin and forget |
| Explicit handoff capture | `tools.py:1279-1310` | Upsert, later overwritten by the automatic capture | Capture an episode, marked explicit |
| Skill observation record, status, delete, export | `tools.py:1255-1277`; `api/continuity.py:93-147` | Encrypted; per-workspace numbers | Procedural candidate lifecycle |
| Reusable check from a correction | `api/reusable_checks.py:39-137` | Proposed, then approved, versioned | Out of scope until decided (§3.5) |
| Notes edits by the agent | `tool_registry.py:731-764` → `chat_service.py:1143-1172` → `AppModel+PermissionsAndCapabilities.swift:223-259` | Plaintext notes | none (Locus); erase inventory |
| Correction of a retrieved file or experience (Dispatcher-style `correct`) | **not found** in Locus | — | Possible future package action |

### 5.3 Committed message

| Call site | Location | Today | Adapter action |
|---|---|---|---|
| Committed-message choke point | `core.py:2072-2116` (`AgentCore._add_message`); callers `core.py:2250` (native user), `3119` (classic user), `3140` (runtime_context), `595` (steer), `605` (before_finalize), `server.py:856` (team user) | Persists to JSONL; assistant messages get `_item_id` | Observe the message (session, run, role, item id, cleaned text) for the archive and candidate extraction. **No memory hook exists today** |
| Session append | `sessions.py:610-631` | `append` (best effort) and `append_strict` (fsync) | none (Locus) |
| Event bus | `chat_service.py:356-559` (`message_end` and `assistant_item_end` persisted at 464-495) | Run events | An alternative observation point |
| Archive ingestion | `transcript_search.py:122-194` | Pull-based stat-diff sync before each search | The package archive pulls through the session-source adapter until a push hook exists |
| Memory hook on committed messages | **not found** | — | — |

### 5.4 Task and attempt boundary

| Call site | Location | Today | Adapter action |
|---|---|---|---|
| Run start and provenance | `server.py:502-516` (start_run), `517-518` (`TaskJournal.bind`), `553-554` (`memory_session_id`, `memory_run_id`) | Run ids flow into candidates as `source_session_id` and `source_run_id` | Begin attempt (provenance ids) |
| Solo turn end | `server.py:760-768` (capture in `finally`), `791` (clear `memory_run_id`) | Rolling snapshot upsert; `memory_context` not cleared | End attempt: capture an episode from the cleaned goal and prose outcome; clear the recall context |
| Team completion | `server.py:1256-1281` (capture at 1273) | Snapshot with mode `build` | End attempt |
| Terminal and turn_done | `chat_service.py:413-419,496-511`; goal finish `512-523`; `start_turn` `1653-1705` | Run state | A possible trigger for candidate extraction (**not found** today) |
| Verification and receipts | `task_state.py:220-360`; `server.py:723-737`; tool receipts `core.py:4270-4290` | Execution evidence | Reference as provenance only |
| Plan save | `core.py:4638-4660` | Immutable plans | none |
| Reusable checks frozen at admission | `task_state.py:154-161` | Frozen into `task_records` | none (unless reusable checks move) |
| Memory review run | `api/continuity.py:417-433,509-520` | `run_kind='memory_review'` | Locus keeps the run bookkeeping |
| Evaluation runs | `evaluation_runtime.py:32-435` | Disposable worktrees, no memory | none |
| langgraph-workflow admit and publish | `integrations/locus/adapter_reference.py:136-147,339-345` (langgraph-workflow repo) | RunStore run, `workflow_event` rows | Future: candidate ingestion from verified outcomes |
| Automatic candidate extraction at end of task | **not found** | — | — |

### 5.5 Repository change

| Call site | Location | Today | Adapter action |
|---|---|---|---|
| Mutating tool finished | `chat_service.py:47,550-559` emits `workspace_changed` → Swift `AppModel+BackendEvents.swift:363-366` → `WorkspaceKnowledgeModel.swift:54-85` (650 ms debounce) → `POST /api/knowledge/reindex` `api/knowledge.py:67` | Always a full reindex | Observe the repository change (incremental reindex; optionally mark memories stale where they cite changed files) |
| Incremental changes route | `api/knowledge.py:74`; no Swift caller | Unused | Same, with paths |
| Changed-file inventory for episodes | `continuity.py:53-79`, called from `server.py:401/402` and `tools.py:1300/1302` | git status; rename bug | Package repository observation with an injected runner |
| Task file history | `core.py:4287-4289` (`file_history.py`) | Before and after blobs | none |
| Task checkout enter and leave | `core.py:1738-1775`; `server.py:1634-1637` | `workspace_root` = source root, `cwd` = worktree | Adapter must key by `workspace_root` |
| Working directory change | `server.py:2868-2876` (`set_cwd`) | Changes cwd | Re-resolve the authorized workspace |
| Document reconcile during reindex | `knowledge.py:218-310` | Submits document jobs | none (Locus) |
| Invalidating memories when cited files change | **not found** | — | — |

### 5.6 Session and maintenance boundary

| Call site | Location | Today | Adapter action |
|---|---|---|---|
| New session or clear | `core.py:1862-1900`; WS `server.py:2848,2891`; `/clear` `core.py:4811`; `POST /api/sessions/new` `api/sessions.py:187` | Resets the conversation; `PROTOCOL.md:897` says new_session resets memory | Session start (clear the recall context) |
| Resume | `core.py:5019-5102`; `api/sessions.py:797/800` | Reloads context | Session resume (no recall until the next turn) |
| Retry | `core.py:3348-3417` (branch at 3363-3365, 3396-3398); `server.py:2833-2841` | New SessionStore branch; stale memory | Recompute recall |
| Duplicate | `api/sessions.py:651`; `sessions.py:864` | Copies messages; drops `account_id` | Archive notification |
| Handoff | `api/sessions.py:844/856` | Environment change | Re-resolve the workspace |
| Delete one session | `api/sessions.py:373` → `sessions.py:1358` (`move_to_trash`) | Trash only; the index catches up lazily | Session deleted → cascade to episodes, archive and derived stores |
| Clear all sessions | `api/sessions.py:349-367` (`transcript_index().delete_all()` at 365) | Trash plus index wipe | Same, as a bulk operation |
| Restore | `api/sessions.py:517`; `sessions.py:1443` | Untrash | Archive notification |
| Identity mode enabled | `core.py:4717-4731` (clears contexts at 4727) | Clears memory and continuity | No-recall flag |
| Explicit maintenance | `POST /api/memory/maintenance/run` `api/continuity.py:352-360` | `maintain()` | Maintenance |
| Lazy maintenance | `memory.py:429` (expire on list), `703-711` (event retention); `continuity.py:244-263` (snapshot prune on save and list) | Runs inside reads | Move into explicit maintenance |
| Run DB retention | `runstore.py:4095-4124` | Runs only | none |
| Legacy migration | `memory_runtime.py:11-32` | Every vault open | One-shot migration at first open |
| Process startup or one-time migration hook | **not found** | — | — |
| Scheduled maintenance | **not found** | — | — |
| langgraph-workflow plugin prune | `mcp_server.py:225-228` (langgraph-workflow repo) | Terminal attempts older than `keep_finished_days` | none |

### 5.7 Scope and consent change

| Call site | Location | Today | Adapter action |
|---|---|---|---|
| Memory policy on every message | `server.py:2472` → `core.py:852-865` | `MemoryPolicy` parsed from the client | Pass the resolved policy per call |
| Ask mode | `server.py:320,350`; `core.py:849-858,863-865` | Drops the workspace scope; no continuity | Scopes without `workspace` |
| Private identity | `server.py:478-485,571-576,761`; `core.py:4727` | No recall, no capture | Do not call the adapter |
| ChatGPT parity | `server.py:565-570`; `tool_registry.py:1478-1530` | No recall, no memory tools; capture still runs | Decision: memory delivery for parity (§3.4) |
| Profile binding | `server.py:2420-2437,2533-2546` | Session-bound profile check | Explicit agent principal |
| Memory owner picker and policy editors (Swift) | `AgentTeamsSettingsView.swift:3100-3111,1371-1411,1477-1485,2249-2273` | Sent with each message or REST call | none (Locus) |
| Knowledge consent toggles | `api/knowledge.py:38-64` (`cancel_persistent` at 62-63) → `knowledge.py:174-216` (non-text documents purged at 213-215) | Disabling purges documents immediately | Consent change → purge the corresponding package data |
| Capability environment flags | `capabilities.py:18-35` | Gate routes and tools | Gate adapter calls without breaking recall |
| Notes control | `server.py:2733-2738` (`set_notes_control`) | Enables agent notes tools | none (Locus) |
| Workspace switch | `server.py:2868-2876` | `set_cwd` | Re-authorize |
| Edition and data-root selection | `AppEdition.swift:57-65`; `BackendProcess.swift:102-148` | Sets `OLLAMA_CODE_HOME` for LocusX only | Locus passes the storage root and key to the package |
| Purging stored memory when recall or a scope is disabled | **not found** (disabling only stops recall; data stays) | — | — |
| Key change or rotation | **not found** | — | — |

---

## 6. Suggested extraction order

Each step should land with its characterization tests green before the next begins.

1. **Pin current behavior.** Build golden fixtures from Locus HEAD:
   - a vault DB with candidate, approved, stale, pinned and superseded rows plus events;
   - continuity tables;
   - a legacy knowledge DB with plaintext notes.

   Write the cases in compat §21. No host change is needed.
2. **Read in place.** The package opens `memory.sqlite3`, all four tables, under an injected key. Locus's `memory_vault()` and the tool constructors switch to the package (§3.1 bridge). The `server.*` seam names stay.
3. **Key custody.** Locus becomes the only reader of `master.key` (or of the Keychain item, if that is decided). Add the canary so a missing key fails loudly. Update `PROTOCOL.md` and `README.md` if custody changes.
4. **One-shot legacy migration** with a marker and physical purge. Remove the per-request call.
5. **Fail-closed fixes.** One at a time, each flipping its defect pin: empty scopes (D1), target checks (D2), server-side approval (D3), feedback CAS (D23), embedding invalidation (D24), migration-race tolerance (D25).
6. **Recall orchestration.** Decouple from the knowledge capability (D39), pass the explicit agent id (D40), clean the query (D42), return empty when nothing is recalled (D41), stop reusing stale context (D43).
7. **Native delivery contract.** Stop persisting decrypted memory in provider homes (D4). Decide how parity turns get memory.
8. **Episodes and procedural candidates.** Fix snapshot assembly (D11, D31) and label team continuity correctly (D12). Move `ContinuityStore` into the package.
9. **History archive and knowledge index**, if in scope: inject a session-source adapter, filter identity and synthetic content, decide on encryption.
10. **Unified erase and cascade** across the inventory in §4, then retention for host stores.

## 7. Invariants every bridge must preserve

- The memory-v1, locus-context-v1 and locus-observation-v1 AAD bytes, the JSON canonicalization of each, the nonce and tag layout, and the column order of all four tables.
- The target hash formulas, the id regex, and the legacy id formula (`'legacy-' + sha256(f'{Path(ws).resolve()}|{id}')[:40]`).
- The `/api/memory*`, `/api/context-snapshots*`, `/api/skill-observations*` and `/api/knowledge*` paths and JSON shapes consumed by the Swift DTOs (compat §13.5). The route snapshot must stay unchanged unless a route is deliberately removed.
- `locus-memory-export` v1/v2 and `locus-skill-observations` v1 documents.
- Status values (`candidate`, `approved`), scope values (`personal`, `workspace`, `agent`), kinds, observation statuses, and event stage/outcome strings.
- Policy bounds (0-20, 0-4000, 0-10, 0-4000) and defaults.
- Identity mode never recalls or captures. Ask mode never sees workspace memory, which also means fixing D1 rather than preserving it.
- `APP_DIR` selection per edition and runtime. LocusX must stay isolated from standard Locus.

## 8. Ownership decisions still open

1. Is the workspace knowledge index (files and documents) owned by `locus-memory`, or does it stay a Locus feature that the package only consumes?
2. Key custody: Keychain via stdin bootstrap for the app editions, and a file provider for CLI and remote runtimes? What recovery should exist when the DB exists but the key does not?
3. Do context snapshots stay in the same file under the same key, or split from the memory vault?
4. Personal scope: shared with every agent (as implemented) or primary-only (as the UI says)?
5. Should agent scope be global per agent (as implemented) or per workspace and agent?
6. Should reusable checks and skill observations become one procedural-candidate store in the package?
7. Should the transcript index and the knowledge index be encrypted once they are owned by the package?
8. Should ambient recall write use statistics (`use_count`, `last_used_at`) or only explicit use?
9. Who owns erasure of host-side derived copies (questions, collaboration, provider homes, install backups, UserDefaults, Notes, crew ledger)? The proposal here is that the package exposes erase and Locus cascades it.
10. How should memory reach ChatGPT native parity turns and langgraph-workflow in-process jobs?
