# Host extraction in 0.2.0

The reusable memory implementation lives in this repository. Locus supplies
application capabilities and keeps its existing Python entry points as thin
wrappers. No package module imports `ollama_code`, FastAPI, an app keychain, or a
model client. Constructing a package object requires explicit host inputs.

| Responsibility | Package implementation | Locus supplies |
|---|---|---|
| Canonical memory API, approval, revisions, feedback, forgetting, import/export | `compat.canonical_vault.CanonicalMemoryVault` | Engine root, key provider, partition, trusted caller identity and grants |
| Legacy envelopes, continuity snapshots, skill observations, search and retention | `compat.legacy_vault` | Database path, host key and optional embedder |
| Recall packets, shadow comparisons, archive lifecycle, revalidation and maintenance | `runtime` | Trusted contexts, rollout settings, core callbacks and scheduling |
| Memory settings and automatic recall limits | `policies.MemoryPolicy` | Saved agent configuration and user consent |
| Selected-chat candidates | `learning.selected_chat` | Authorized transcript, cleaned user messages and provenance |
| Continuity payload composition | `context.continuity` | Current task state and workspace git inventory |
| Saved-chat FTS indexing, tail synchronization, ranking and result snippets | `history.transcript_search.TranscriptIndex` | Explicit transcript inventory, metadata, display cleanup and restore limits |
| Read-only ownership, writer fencing, shared/exclusive leases | `migrations.ownership` | Exact partition, engine root and lease path |
| Offline inventory, snapshots, validation, cutover, rollback and recovery | `migrations.session.LegacyMigrationSession` and `migrations.cutover.Migrator` | Existing key provider, source mapping, exclusive lease and quiescence checks |

The host still owns HTTP and tool routing, user review UI, session persistence,
workflow/run scheduling, model calls, application paths, key custody and identity
authorization. Those capabilities belong to the application. The host cannot
substitute model-provided workspace or agent claims for trusted grants.

## Data compatibility

This release extracts code without changing the on-disk schemas or migrating
data again. Existing package-authoritative profiles remain authoritative;
missing ownership or keys still fail closed. The rollback path still preserves
package-era corrections, deletions and session/run provenance.

The `context_snapshots` and `skill_observations` implementation was already in
the package; these records retain the legacy encrypted envelopes and family
ownership. Converting snapshots to verified episodes or observations to governed
procedures would change their meaning and requires a separate data migration.
No old observations are treated as verified outcomes or approved procedures.

Saved-chat search retains its existing derived SQLite FTS format and JSONL
transcript inputs. It is separate from the opt-in encrypted history archive.
Extraction does not enable transcript archival or change the host's consent.

## Public integration

Use `compat.canonical_vault.CanonicalMemoryVault` when preserving Locus-shaped
memory records and API behavior, or `MemoryEngine` for native typed operations.
The compatibility facade needs a `KeyProvider` and `PartitionRef`; it does not
discover host keys. Its existing restrictions on new governed procedures and
scope/kind changes remain explicit errors.

For offline migration, construct `LegacyMigrationSession` with explicit source
and destination paths, a legacy-key callback, mapping callback, exclusive lease
factory and quiescence callback. Enter it as a context manager before invoking
inventory, snapshot, validate, cutover or rollback. The lease covers the entire
operation and releases on failures.

For saved-chat search, construct `TranscriptIndex(path, source, limits)` using
`TranscriptSource(list_paths, metadata, clean_user_text)` and `TranscriptLimits`.
Only the files returned by that source are indexed. Removing a session from the
source removes its search hits on the next synchronization.

Package tests exercise the new modules independently of Locus. Existing host
tests exercise the same UI/API/tool behavior through the extracted modules.
Wheel tests verify all submodule imports without application or network stacks.


## Automatic fresh-profile setup in 0.2.1

`bootstrap.initialize_fresh_profile` accepts explicit paths, partition, key
provider and host lease. When both native and legacy stores are absent, it creates
an empty package partition and durable ownership in a private staging directory,
closes the databases, then atomically publishes the directory. An initialization
lock serializes first launches. Existing stores, rollback state and migration
recovery files prevent fresh initialization; they are never overwritten.

Locus invokes this before opening its normal vault or acquiring the service's
shared profile lease. Fresh profiles therefore use canonical package memory and
enabled recall without setting an environment variable. Host consent, scope,
identity and provider policies still govern whether a given turn uses memory.
Existing legacy profiles retain the guarded migration path.

Locus's dependency declaration points at the fixed GitHub release wheel with its
SHA-256. Its builders download and verify that wheel before signing the app;
users receive the engine with the app and can initialize memory offline. No
first-launch installation modifies the signed bundle.
