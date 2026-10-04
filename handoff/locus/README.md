# Locus handoff patches

Patches that move Locus's memory implementation onto `locus-memory`, one stage at a
time. They are written against Locus `b332e4554e72956f949506207ffa034749360d79`
(`agent/` tree). Each patch was built and tested in a disposable copy of that tree.
No real Locus checkout and no user data were touched.

| Order | Patch | Stage | Canonical store after applying |
|---|---|---|---|
| 1 | `0001-stage1-delegate-memory-vault-to-locus-memory.patch` | 1: code extraction | legacy vault (`APP_DIR/memory/memory.sqlite3`) |
| 2 | `0002-stage2-memory-adapter.patch` | 2: engine adapter behind a rollout switch | legacy vault (unchanged) |

## 1. Apply order

Do the dependency step in section 3 first. Both patches import `locus_memory`, so
the bundled runtime needs the package before either one ships.

From the Locus repository root, at `b332e455`:

```sh
patch --dry-run -p1 < 0001-stage1-delegate-memory-vault-to-locus-memory.patch
patch -p1 < 0001-stage1-delegate-memory-vault-to-locus-memory.patch
patch --dry-run -p1 < 0002-stage2-memory-adapter.patch
patch -p1 < 0002-stage2-memory-adapter.patch
```

`git apply -p1` works too. Paths are `a/agent/...` and `b/agent/...`, relative to the
repository root. 0002 is a `diff -ruN` of the Stage-2 tree against the Stage-1 tree,
so it applies only on top of 0001. It was checked with `patch --dry-run -p1` (and then
a real apply) in a fresh copy of the Stage-1 tree. The applied result is
byte-identical to the tested tree. `patch -R --dry-run -p1` (rollback) and
`git apply --check -p1` also succeed.

## 2. What each patch changes

### 0001: Stage 1, the vault code moves into the package

- `agent/ollama_code/memory.py` becomes a facade over
  `locus_memory.compat.legacy_vault.LegacyMemoryVault`. The tables, AAD
  (`memory-v1|...`), payloads, ids and error messages are all unchanged. Locus keeps
  key custody (`_fallback_key`/`_master_key`), and a missing key for a vault that
  has rows is now an error instead of a silently regenerated key (D6).
- `agent/ollama_code/continuity.py` becomes a facade over `LegacyContinuityStore`,
  with the same `locus-context-v1` and `locus-observation-v1` envelopes.
- `agent/ollama_code/memory_runtime.py`: the plaintext-note migration calls
  `import_legacy_note`, which is crash-safe and never overwrites an edited record.
- `agent/tests/test_product_backend.py:89-91`: the staged-`memory.py` check now
  looks for the delegation instead of `AESGCM` (D58).

### 0002: Stage 2, the engine adapter (canonical store stays legacy)

Two new files and three edited ones, all under `agent/`. Line numbers below are
after the patch.

| File | Change |
|---|---|
| `ollama_code/memory_adapter.py` (new) | `MemoryAdapter`, one per `ChatService`. It also contains `LocusKeyProvider` (the engine key comes from the existing custody) and `LegacyRecall`. |
| `ollama_code/chat_service.py:118-120,202-208` | Builds the adapter from the environment with `paths.APP_DIR` and the product edition (`PRODUCT_NAME`). It sets `core.memory_adapter` and passes a background scheduler for maintenance. There are no module globals. |
| `ollama_code/server.py:313-335` | `_automatic_memory_context` keeps its name and signature. It routes through `adapter.recall(...)`, and with no adapter it runs the legacy recall. |
| `ollama_code/server.py:338-370` | `_legacy_memory_recall`: the Stage-1 body, moved unchanged except that it also returns the recalled ids. |
| `ollama_code/server.py:373-377` | New `_revalidate_memory_context(core)` seam. |
| `ollama_code/server.py:388,427` | `_automatic_continuity_context` and `_capture_continuity_snapshot` keep their names. They ask `adapter.continuity_allowed(core)`, which is false only in identity mode while the engine is active. Snapshots stay legacy-owned in Stage 2. |
| `ollama_code/server.py:617-620` | Solo turn recall passes `agent_id=agent_profile.id` on saved-agent (profile) turns. This fixes D40. |
| `ollama_code/server.py:758` | Solo turn: `_revalidate_memory_context(svc.core)` runs immediately before `core.run_turn`. |
| `ollama_code/server.py:2138` | Team writer slot: the same revalidation, immediately before `core.run_turn`. |
| `ollama_code/server.py:237-239` | App shutdown (lifespan) closes the adapter. |
| `ollama_code/core.py:2125-2128` | `_add_message`: after a message is persisted, it calls `adapter.on_committed_message(...)`. This is the committed-message seam from audit `core.py:2072-2116`. |
| `ollama_code/core.py:1902-1906` | `start_new_session`: calls `on_scope_change` (when `cwd` is given) and `on_session_boundary`. |
| `ollama_code/core.py:1736-1738` | `set_cwd`: calls `on_scope_change(..., "workspace_changed")`. |
| `tests/test_memory_adapter.py` (new) | 18 tests (17 functions, one parametrized over two modes). See section 7. |

The call sites below were not edited, but they now route through the adapter
because they call the seams. Team members use `server.py:950,957`, the team snapshot
uses `server.py:1321`, the solo snapshot uses `server.py:810`, and the writer slot
recalls at `server.py:2130`.

What the adapter does, and what it does not do:

- **Trusted access only.** Each `AccessContext` is built from host state:
  `core.workspace_root or core.cwd`, the agent id the server passes, and the
  per-message `MemoryPolicy`. Nothing comes from a client field or from model output.
  - Partition: `PartitionRef(PRODUCT_NAME.lower(), "default")`, which is `locus` or `locusx`.
  - Grants:
    - project `'ws-' + sha256(resolved workspace)[:32]`
    - legacy target `'workspace:' + sha256(resolved workspace)`
    - agent `<active agent id>`
    - legacy target `'agent:' + sha256(agent id)`
  - Each grant is included only when the policy scope allows it.
  - Ask mode (`just_chat`) drops both workspace grants, matching `server.py:320`.
  - Actor and operations:

    | Caller | Actor | Operations |
    |---|---|---|
    | Automatic recall and user routes | `USER` | recall `{READ}`; user routes `{READ, WRITE, APPROVE, FORGET}` |
    | Model tools | `AGENT` | `{READ, PROPOSE}` |
    | Ingest | `HOST` | `{INGEST}` |
    | Maintenance and invalidate | `HOST` | `{MAINTAIN}` |
    | Shadow import | `HOST` | `{READ, ADMIN, FORGET}` |

- **Key.** `LocusKeyProvider` returns
  `derive_subkey(memory._master_key(...), "locus-memory/engine/v1")` under key id
  `locus-v1`. It reads that adapter's own `APP_DIR/memory/master.key`, so two app
  instances never share a key. If the key is missing for an existing vault, the
  provider reports the vault as locked. A legacy key is created only where
  `memory._master_key` already creates one: no key file and no vault rows.
- **Engine root.** The engine lives in `APP_DIR/memory-engine/` (mode 0700): one
  partition directory, plus `control.sqlite3`, the `OwnershipControl` set as
  `HostCapabilities.ownership`.
  - Ownership stays `legacy_authoritative`, so `remember`, `propose`, `approve`,
    `correct` and the other canonical writes raise `OwnershipFenced`.
  - The adapter has no canonical write path at all.
- **Derived copy.** In shadow and enabled modes, each recall first synchronizes:
  1. It reads a content-free fingerprint of the legacy rows read-only (ids,
     revisions, flags, targets, nonces; no ciphertext, nothing decrypted).
  2. If the fingerprint changed, it runs `LegacyImporter` (read-only on the legacy
     file) with a `LegacyMapping`:
     - workspaces: every workspace hash maps to `ws-<hash[:32]>`, which is the same
       function as the project grant;
     - agents: the active agent id.
  3. Deltas and legacy deletions propagate, deletions as package tombstones.
- **Budget and empty recall.**
  - `max_automatic_tokens` is the `token_allowance`.
  - `recall_enabled=false` disables recall, and so does `max_automatic_memories=0`
    or `max_automatic_tokens=0`.
  - Policy scopes choose the grants and the slices. Without `personal`, unscoped
    records are not requested.
  - An empty packet returns `""`, so no layer is added (fixes D41).
- **Never both layers.** In enabled mode the legacy recall callable is never
  invoked. `assert_single_memory_layer` raises if an engine packet and the legacy
  layer ever end up in the same memory text.

## 3. Dependency and bundling (required before shipping either patch)

The Locus runtime installs dependencies with
`pip install --require-hashes --only-binary=:all: --target <runtime>/site-packages -r agent/requirements-runtime.lock`.
The install runs in `Tools/PrepareAgentRuntime.sh:81-85` and `Tools/PrepareRemoteRuntime.py:158-162`.
`Tools/StageBackendEdition.py` copies only the `ollama_code` tree (audit D58). So
`locus_memory` has to come in through the hashed lock as a wheel. It must not be
copied as source.

1. Build the wheel from the `locus-memory` repository, at the commit you intend to
   ship:
   `python -m pip wheel --no-deps -w dist .` gives `locus_memory-0.1.0-py3-none-any.whl`.
   The wheel is pure Python. Its only dependency is `cryptography>=42`, which the
   existing lock pin `cryptography==50.0.0` satisfies.
2. Vendor the wheel in Locus, for example at
   `agent/vendor/wheels/locus_memory-0.1.0-py3-none-any.whl`. Alternatively, publish
   it to an index you control.
3. Add `locus-memory==0.1.0` to `agent/requirements-runtime.in`. Regenerate the lock
   with
   `pip-compile --generate-hashes --no-emit-find-links --find-links agent/vendor/wheels --output-file=agent/requirements-runtime.lock agent/requirements-runtime.in`.
   The lock must contain `locus-memory==0.1.0 --hash=sha256:<wheel sha256>`. Verify
   it with `shasum -a 256` on the vendored file.
4. Add `--find-links "${backend_root}/vendor/wheels"` to the pip call in
   `Tools/PrepareAgentRuntime.sh`, and the equivalent argument in
   `Tools/PrepareRemoteRuntime.py`. Keep `--require-hashes --only-binary=:all:`.
   The runtime cache stamp already covers the lock, so the cache refreshes.
5. Add `"locus-memory==0.1.0"` to `agent/pyproject.toml` `dependencies`, so dev and
   CI installs match the bundled runtime.
6. Re-run `test_product_backend.py`. Its staged-server tests start `ollama_code.server`
   from the staged copy with the runtime's site-packages, so they prove that the
   wheel is importable in the bundle.

## 4. Environment controls (Stage 2)

Each `ChatService` reads these controls once, when it is built. The backend
process must therefore have them in its environment at launch: export them before
starting the backend, or add them to the backend environment in `BackendProcess`.

| Variable | Values | Default | Effect |
|---|---|---|---|
| `LOCUS_MEMORY_ENGINE_MODE` | `disabled`, `shadow`, `enabled` | `disabled` | See the table below. Any other value is treated as `disabled`, with a warning. |
| `LOCUS_MEMORY_ARCHIVE` | `1` or anything else | off | Archives committed user and assistant text into the engine's encrypted history. Takes effect only when the mode is `shadow` or `enabled`. |

| Mode | Prompt | Files | Notes |
|---|---|---|---|
| `disabled` | The Stage-1 prompt, byte for byte (tested). The one exception is D40 below. | None; the engine is never constructed | Every hook returns immediately. |
| `shadow` | Unchanged: the legacy layer is injected (tested byte-identical) | `APP_DIR/memory-engine/**`, ciphertext only (canary-tested) | After the legacy recall, the engine builds a packet over the derived copy. The result goes to `engine.metrics` (`adapter.shadow.*`, `adapter.sync*`) and one content-free log line on `ollama_code.memory_adapter`, in the format `memory engine shadow: legacy_items=<n> engine_items=<n> overlap=<n> legacy_tokens~<n> engine_tokens=<n>(<measured\|estimated>) legacy_ms=<ms> engine_ms=<ms>`. The same counts are in `adapter.last_shadow`. |
| `enabled` | Exactly one `## Approved memory` layer, containing the engine's `<memory-context ...>` packet within `max_automatic_tokens`. No layer when nothing is recalled. | As in shadow | Revalidated right before the model call (see below). Engine failures fail closed: no memory layer and an `adapter.<stage>.failed` counter. Turns never fail because of the engine. |

Revalidation runs right before the model call. It first synchronizes the derived
copy (picking up legacy deletes and edits), then calls `revalidate_context`. A
memory deleted, superseded or flagged incorrect between recall and use is dropped,
and the packet is recompiled for the same request.

Two costs to know about before rolling out:

- **Shadow mode adds latency.** The engine's recall runs synchronously on the turn
  thread after the legacy recall. Its cost is measured as
  `adapter.shadow.engine_context`, alongside `adapter.shadow.legacy_recall`.
- **The first sync decrypts every legacy row once.** This happens in shadow or
  enabled mode, on the first turn of each process. Later turns re-import only when
  the content-free fingerprint changes; otherwise they skip the import.
  `adapter.sync` records each import's duration, and the per-row cost depends on the
  vault size.

These hold in every mode:

- **Identity mode** disables the adapter entirely. There is no recall, no engine
  open, no archive and no maintenance. The server already skips the seams in identity
  mode; with the engine active, the seams also return `""` if called.
- **D40 (one deliberate change outside the switch).** Solo saved-agent turns now
  recall with the profile's agent id instead of `"primary"`, which affects the legacy
  path too. Team turns already did this. Ordinary (non-profile) turns are unchanged.
- **Maintenance.** `on_session_boundary` (new or cleared session) schedules
  `engine.maintain` on a daemon thread. It runs at most once every 6 hours per
  adapter, never concurrently, and never opens the engine just to maintain it.
- **Scope change.** On `set_cwd` and on a new session with a `cwd`, the adapter
  calls `engine.invalidate` (which bumps the generation and drops caches) and
  discards any pending packet.
- **Archive filters.** The archive skips:
  - roles other than user and assistant, and unpersisted messages;
  - `_locus_context`, `_delivery_id`, `_dispatcher_control` and `_mcp_observation`
    messages;
  - anything containing `<think`.

  User text is stripped of the GUI's prompt decoration. Injected memory blocks are
  marked `is_memory_injection`, so the engine never stores them as evidence.

## 5. Migration decision

Stage 2 does **no data migration**. The canonical backend stays **legacy**, and
ownership stays `legacy_authoritative`, so package canonical writes are fenced.
`APP_DIR/memory-engine` is an explicit, isolated, encrypted, derived copy that can
be thrown away. If it is deleted while the backend is stopped, the next shadow or
enabled turn rebuilds it from the legacy vault.

`context_snapshots` and `skill_observations` are not imported; they stay
legacy-owned. The adapter opens the legacy database read-only. The only legacy file
it can create is `master.key`, through the existing custody rule above.

## 6. Rollback

- **Runtime:** unset `LOCUS_MEMORY_ENGINE_MODE` (or set it to `disabled`) and restart
  the backend. Nothing reads `APP_DIR/memory-engine` after that.
- **Optional:** delete `APP_DIR/memory-engine/`. It holds only the derived copy and
  context receipts, plus the history archive if `LOCUS_MEMORY_ARCHIVE=1` was ever
  set. Deleting it is also the recovery if the legacy key is ever replaced. A derived
  copy under the old key reports `WrongKey` or `VaultLocked`, and the adapter then
  fails closed.
- **Code:** reverse the patch with `patch -R -p1 < 0002-stage2-memory-adapter.patch`.
  This touches no data format, so the legacy vault needs nothing done to it.

## 7. Test evidence

Tested on a disposable copy of Locus `b332e455` (`agent/`, `Tools/`, `Config/`,
`ProtocolFixtures/`) with 0001 applied, then 0002. The tests ran on the bundled
Locus runtime: CPython 3.14.6 and its site-packages, plus
`PYTHONPATH=<locus-memory>/src`.

| Command | Stage 1 (baseline) | Stage 2 |
|---|---|---|
| `EXTRA_PYTHONPATH=<locus-memory>/src run_host_tests.sh <host>` (every `agent/tests` file that touches memory) | 768 passed, 6 failed | **786 passed, 6 failed** (768 + 18 new) |
| `python3.14 -m pytest agent/tests -q -p no:cacheprovider` (the whole host suite) | 2730 passed, 107 failed, 42 errors | **2748 passed, 107 failed, 42 errors**: an identical set of 149 failing or erroring test ids (wallet, UI-matrix and packaging tooling are absent in the sandbox) |
| `python3.14 -m pytest agent/tests/test_memory_adapter.py -q` | n/a | 18 passed |
| `ruff check` on the five changed or new files (Locus `agent/pyproject.toml` config) | n/a | all checks passed |

The 6 failures are the same 6, before and after, and they are environmental. These
`test_product_backend.py` staged-server tests start a subprocess whose runtime lacks
third-party packages in this sandbox (for example `ModuleNotFoundError: No module named
'uvicorn'`):

- `test_packaged_locus_rejects_wallet_control_and_guessed_tools`
- `test_packaged_locusx_keeps_native_capability_bridge_and_route_checks`
- `test_packaged_oauth_callback_uses_fixed_product[locus|locusx]`
- `test_two_products_keep_parallel_profiles_separate`
- `test_staged_servers_run_together_with_isolated_http_and_websocket_state`

`agent/tests/test_memory_adapter.py` covers:

- **Disabled mode:** no engine and no files, and the prompt is identical to the
  Stage-1 seam with no adapter.
- **Shadow mode:**
  - the prompt is byte-identical to disabled mode;
  - a canary scan of every file under `APP_DIR` (WAL included) finds no plaintext;
  - the log line is content-free.
- **Enabled mode:**
  - exactly one layer, with `token_count <= max_automatic_tokens`, and the
    double-injection guard;
  - empty recall injects no layer (D41);
  - a memory deleted between recall and use is dropped by revalidation;
  - a record flagged incorrect or superseded is never served, at recall or at
    revalidation;
  - policy scopes bound what can be injected;
  - a sync failure fails closed.
- **Ask mode:** no workspace memory, and no workspace grants for the recall or tool
  actor (the D1 class).
- **Identity mode:** disables everything, including the archive and the hooks.
- **Two `ChatService` instances with different `APP_DIR`s:** separate engines,
  metrics, roots and derived keys, and no module-level engine state.
- **Profile turns:** recall with the profile's agent id in disabled and enabled
  modes (D40).
- **Fencing:** canonical writes through the adapter's engine raise `OwnershipFenced`
  while legacy is authoritative.
- **Archive:** opt-in. It skips reasoning, synthetic, injected and unpersisted
  messages.
- **Maintenance and invalidation:** maintenance is bounded and runs on a host
  schedule, and a scope change invalidates.
- **Unknown mode values:** fail safe to disabled.

Mutation check: 18 targeted mutations of `memory_adapter.py` and `server.py` were
run against the final code. Each one breaks a guarantee, for example no revalidation,
Ask mode keeping the workspace, no D40, shadow altering the prompt, double injection,
an ignored identity mode, the engine opened while disabled, swallowed sync errors,
unbounded maintenance, a personal-scope leak, no stale or superseded exclusion, no
invalidation, or an archive that ignores its opt-in. The tests caught 17 of them. The
18th survived because it is equivalent to the original: it drops the adapter's
empty-packet guard, and the compiler already renders an empty packet as `""`.

The adapter's engine path was also smoke-tested outside the host runtime, on Python
3.10.22 and 3.14.6, through a minimal shim package. It covered recall, a delete
followed by revalidation, the archive, and a plaintext scan.

## 8. Known limitations and requests to the package

These are package-side issues found while building the adapter. Each has an adapter
mitigation, and each should be fixed in `locus-memory` before Stage 3.

1. **`LegacyImporter._propagate_deletions` authorizes each forget against the
   importer's access grants.** "ADMIN does not widen grants", so a legacy deletion of
   a record outside those grants raises `NotFound` and aborts propagation for the
   remaining records. The importer is the migration actor; it should authorize
   against each record's own scope.
   - Mitigation: the import access grants every workspace and agent target this
     process has seen, plus the active ones, so the failure needs a target that
     disappeared before this process ever saw it. Any sync failure fails closed in
     enabled mode.
2. **The importer's delta check compares only `legacy_revision`.** Legacy
   `feedback('incorrect')` sets `stale`, and `approve(resolution='replace')` sets
   `stale` and `superseded_by`, without bumping the revision. The derived copy
   therefore keeps those records `approved`.
   - Mitigation: the adapter passes the canonical inactive ids (plain `stale` and
     `superseded_by` columns, nothing decrypted) as `ContextRequest.exclude_ids`, at
     build and at revalidation.
3. **A mapping change never re-scopes rows that were already imported.**
   - Mitigation: the workspace mapping is deterministic over every workspace hash.
     Agent records of non-active agents stay `legacy_target` scoped and are reached
     through the `agent:<hash>` legacy-target grant and the agent and workspace
     slices.
4. **There is no public marker for the context wrapper.** The adapter imports
   `WRAPPER_OPEN` from `locus_memory.context.compiler`. Export a marker or an
   `is_context_block()` helper.
5. **`ContextRequest` has no item cap.** `max_automatic_memories` (0-20) is honoured
   only as on/off; the engine budget is token-based.

These Stage-2 scope limits remain:

- Parallel team writer cores, collaboration helpers and evaluation cores have no
  adapter, so they keep the legacy recall.
- Team members' memory goes into the orchestrator's profile copy and is not
  revalidated again before each member's call.
- Model tools (`search_memory`, `propose_memory`) and the `/api/memory*` routes
  still use the legacy vault.
- Enabled mode does not run the per-request plaintext-note migration (D28), which
  still runs on every `/api/memory*` route.
- The engine query has the GUI prompt decoration stripped (D42). The legacy query
  is unchanged.

## 9. What remains for Stage 3 (canonical extraction)

1. Land the package fixes in section 8 (importer authorization, metadata deltas,
   re-scoping, the public wrapper marker, an item cap), then drop the matching
   adapter bridges.
2. Run the cutover with `locus_memory.migrations.cutover.Migrator`, in this order:
   1. `prepare_shadow`, which snapshots and imports;
   2. `validate`, which applies the delta and runs verify;
   3. `cutover`, with a host `quiesce` hook that drains turns and REST writes.

   Wire `OwnershipControl.writer_guard(...)` into the legacy vault (`write_guard=`)
   first, so legacy writes are fenced after cutover. Rollback goes through
   `Migrator.rollback`, never a feature flag.
3. Move the writers to the adapter with `USER` and `AGENT` access contexts:
   - the `/api/memory*` routes (save, approve, feedback, delete, export, import);
   - the model tools (`search_memory` with fail-closed empty scopes, D1;
     `propose_memory` as a candidate).

   Delete the facade in `memory.py` once nothing constructs `MemoryVault`.
4. Make the `context_snapshots` and `skill_observations` families package-owned
   (episodes and procedural candidates). Fix D11 and D12, and stop labelling team
   continuity as approved memory.
5. Give the adapter to parallel writer, helper and evaluation cores (or decide
   against it). Revalidate team-member packets right before each member's call.
6. Settle key custody: Keychain via stdin bootstrap (decision 8.2 in
   `docs/ownership-and-extraction.md`), and add a canary for the legacy key itself.
7. Deliver memory to native providers: per-turn and ephemeral, so decrypted memory
   is never persisted in provider homes (D4, D44).
