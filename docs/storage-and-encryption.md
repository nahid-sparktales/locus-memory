# Storage and encryption

This document specifies how `locus-memory` stores data:

* the files on disk and which columns of each table group are plaintext;
* the key hierarchy, the sealing format and the nonce policy;
* key rotation;
* the SQLite configuration, in-memory search, and handling of WAL residue;
* the deletion ledger and its reconcile protocol;
* how the legacy Locus vault format is read.

It covers requirements R8.1-R8.7 and R17.4-R17.5 in [requirements.md](requirements.md). The threat
model and the limits of these mechanisms are in [security-and-privacy.md](security-and-privacy.md),
which has the same conventions:

* code is cited by module (relative to `locus_memory`) and function or class;
* evidence is cited as a test node id;
* "implemented" means present in the package and covered by its tests.

Everything in this document is implemented in the package unless it is marked otherwise. Nothing here
has been run against a real Locus vault or real user data.

---

## 1. Files on disk

```text
<root>/                                  engine root passed to MemoryEngine(root, keys)
  <partition_id>/                        one directory per security partition, mode 0700
    memory.sqlite3      (+ -wal, -shm)   main database, mode 0600
    deletion-ledger.sqlite3 (+ -wal, -shm)  deletion ledger, outcomes, forget requests; mode 0600
  control.sqlite3      (+ -wal, -shm)    migration ownership state; only when OwnershipControl is used
  keys/                                  CLI only: FileKeyProvider default (--key-dir overrides)
    <key_id>.key                         32 raw bytes, mode 0600, created with O_EXCL
    current                              id of the current master key (atomic replace)
```

* **The ledger file holds three tables** (section 2): the append-only, MAC-chained `ledger`; its
  `ledger_outcomes`, one row per applied entry, written with `INSERT OR REPLACE`
  (`storage.ledger.DeletionLedger.record_outcome`); and the transient sealed `forget_requests`, dropped
  once their entry is applied (`storage.partition.Partition.drop_forget_requests`). For memory targets,
  `forget_requests.target_token` is the opaque record id in plaintext, as in `ledger`.
* **Partition id.** `models.PartitionRef.partition_id` is `"p"` followed by the first 31 hex digits of
  `sha256("locus-memory/partition/v1|<edition>|<profile>")`. A length-prefixed v2 form is used when a
  label contains `|`. The hash is not keyed (see security-and-privacy.md 5.3).
* **Modes.** `storage.partition.Partition.__init__` sets the directory to 0700 on every open.
  `storage.db.Database._connect` sets a newly created database file to 0600, and SQLite creates the
  `-wal` and `-shm` files with the database's mode
  (`tests/test_storage.py::test_sqlite_side_files_are_not_world_readable`).
* **Lazy opening.** Nothing is opened at import or at engine construction
  (`tests/test_storage.py::test_constructing_an_engine_touches_nothing`). A partition opens on the first
  call that names it.
* **Open-existing-only mode.** With `MemoryEngine(..., create_partitions=False)`, a missing or
  schema-less database raises `NotFound` and creates nothing. The CLI uses this for every command
  except `init`
  (`tests/test_storage.py::test_open_existing_only_engine_refuses_a_missing_vault_and_creates_nothing`).
* **Refusal to initialize over a ledger.** If `deletion-ledger.sqlite3` records deletions but the main
  database is missing or empty, opening raises `IntegrityError` and creates no keys. A database with
  fresh keys could never authenticate the old ledger, and dropping the ledger would let forgotten data
  return
  (`tests/test_review_group1.py::test_missing_database_next_to_a_ledger_is_refused_without_new_keys`).
* **Atomic creation; a failed open deletes nothing.** A new partition's schema and keys are written
  to a private staging file (`.memory.sqlite3.<random>.creating`), which is then published at
  `memory.sqlite3` with a hard link that fails if a database already exists there
  (`storage.partition.Partition._create_vault`). A concurrent first opener therefore either publishes
  its own fully keyed vault or opens the other one; nobody ever sees a half-initialized database. A
  failed first open (for example a locked key provider) removes only its own staging file, never
  `memory.sqlite3`, `-wal` or `-shm`: another opener may already have created and written that vault
  (`tests/test_review_round2_batch3.py::test_cd3_a_failed_first_open_never_deletes_another_openers_vault`,
  `::test_cd3_a_failed_first_open_leaves_no_database_and_a_later_open_works`,
  `tests/test_storage.py::test_locked_provider_on_a_fresh_root_creates_no_keys`).
* **Plaintext files.** The package itself writes no other plaintext files. Plaintext leaves the vault
  only when a caller asks for it:
  * `MemoryEngine.export` returns a document and writes nothing
    (`tests/test_storage.py::test_export_writes_nothing_to_disk`);
  * `locus-memory export --yes` writes a 0600 file outside the vault;
  * `MemoryEngine.export_procedure` writes a proposal directory.
* **Encrypted migration snapshots.** Outside the vault the package also writes encrypted copies of the
  legacy Locus database (`migrations.legacy.snapshot`):
  * the Migrator (CLI `migrate import`) writes them under `--work-dir/snapshot-<ms>/` and removes them
    automatically (section 14);
  * the CLI `migrate snapshot` writes one at `--out`, and it stays until the operator deletes it.

  Each holds `legacy-snapshot.sqlite3`, a copy of the legacy database's ciphertext
  (`journal_mode=DELETE`, mode 0600), and `manifest.json`: legacy row ids, SHA-256 row fingerprints,
  the copy's SHA-256 and, for the Migrator's, the owner partition id. The manifest is written with
  the process's default file mode (no `chmod`). No plaintext content is in either
  (`tests/test_migrations.py::test_snapshot_manifest_integrity_and_no_plaintext`), but the legacy key
  opens the copy.

---

## 2. Schema overview: what is plaintext, keyed and sealed

The partition schema is `storage.schema` (`SCHEMA_VERSION = 1`, forward-only migrations applied
inside a write transaction).

* A store whose schema is newer than the package supports is refused without changes.
* A store whose `meta.partition_id` differs from the partition being opened is refused
  (`tests/test_storage.py::test_a_newer_schema_is_refused_without_changes`,
  `tests/test_storage.py::test_a_store_of_another_partition_is_refused`).

Column categories used in the table:

* **Plaintext** columns are stored as-is.
* **Keyed** columns hold `PartitionKeyring.token(purpose, value)`, a truncated HMAC (section 6).
  Deterministic within a partition, not reversible without the HMAC key.
* **Sealed** columns are `dek_id`, `nonce` and `ciphertext` (AES-256-GCM, section 4). The table says
  what the sealed payload contains and which fields its associated data (AAD) binds, in addition to
  the format tag, partition id, table, row id and DEK id that every seal binds.

| Group | Tables | Plaintext | Keyed tokens | Sealed payload (AAD fields) |
|---|---|---|---|---|
| Keys and state | `meta`, `key_wraps` | `meta`: schema version, partition id, created time, `generation`, `deletion_generation`, `current_dek_id`, `hmac_dek_id`, `idempotency_format`, `dek_rotation` (JSON of DEK ids, counts and start time), `pending_purge_checkpoint`, `purge_checkpointed_generation` (the deletion generation the last completed post-purge checkpoint covered), `history_generation` (an archive append counter bumped by `history.archive.HistoryArchive._ingest_one`; written but never read, it reveals how many archive appends have happened, including messages later forgotten). `ledger_head` is initialized but not used. `deletion_checkpoint` (`storage.partition.DELETION_CHECKPOINT_KEY`, `<generation>:<tag>`: the authenticated copy of `deletion_generation`, 12.2). Migration progress markers, each a generation plus a keyed MAC: `legacy_residue_generation` (`migrations.cutover.RESIDUE_KEY`, `<generation>:<MAC>`, section 11), `migration_rollback_generation` with `migration_rollback_generation_mac` (`migrations.legacy.ROLLBACK_WATERMARK_KEY`, `ROLLBACK_WATERMARK_MAC_KEY`). Flags `migration_cutover_set` (`migrations.legacy.CUTOVER_SET_KEY`) and `repo_derived_indexed` (`repository.service.RepositoryService._DERIVED_INDEX_KEY`). Provider sweep state (`providers.hub._SWEEP_META`): `provider_sweep:cursor:<lane>` (lanes `time`, `exclusion`, `all`; opaque record ids) and `provider_sweep:exclusions_pass`, `provider_sweep:exclusions_checked` (a keyed token of the repository exclusion state). A key that carries a MAC is trusted only when the MAC verifies; otherwise the code takes the fail-closed reading (replay every ledger entry, run the legacy purge again, rollback watermark 0). `key_wraps`: `dek_id`, host `master_key_id`, purpose (`data`/`hmac`), `created_at` | | `key_wraps.wrapped`: a DEK or the HMAC key, AES-GCM-wrapped under a master key (wrap AAD, section 4.3) |
| Canonical records (all kinds, including episodes and procedures) | `records`, `record_scopes`, `record_sources`, `record_revisions`, `derivations` | `records`: `id`, `kind`, `lifecycle`, `revision`, `pinned`, `created_at`, `updated_at`, `expires_at`, `valid_from`, `valid_until`, `write_generation`. `record_scopes.dim`; `record_sources.kind`. `record_revisions`: record id, revision, lifecycle, `change` label, actor, time, `purged`. `derivations`: derived id and kinds | `records.scope_token`, `subject_token`, `content_token`; `record_scopes.value_token`; `record_sources.source_token`; `derivations.input_token` | `records`: the whole `MemoryRecord` (title, content, tags, scope values, basis, confidence, subject and predicate, sources, validity, retention, links, reason, `extra`) (AAD: `kind`, `lifecycle`, `revision`, `scope` token). `record_revisions`: the record as of that revision (AAD: `lifecycle`, `change`); a purged revision has NULL sealed columns |
| Deletion state | `tombstones`, `tombstone_aliases`, `suppressions`, `forget_outcomes`, `migration_forgets`, `migration_cutover_ids`, `migration_recovery_ids`, `migration_scope_covered` | target kind, generation, time, policy flags (JSON); receipt id per generation; for `migration_forgets` and memory tombstones, the opaque record id; `migration_scope_covered.generation`. A forget records a memory tombstone with policy `{"derived":true}` (`storage.partition.DERIVED_TOMBSTONE_POLICY`) for every record it removes besides its own target; those rows are never adopted into the ledger (`Partition.reconcile` filters them, 12.3). `migration_forgets` is written only by earlier builds: it is read only for a format-1 ledger entry, and only when bound to exactly that entry's generation (`migrations.legacy._migration_forget`) | `target_token` (for `memory` targets it is the record id itself; for `profile` it is the partition id); alias `source_token`; suppression `fingerprint_token` and `source_token`; `migration_cutover_ids.token` (purpose `migration-cutover-id`: legacy ids the last cutover verified, plus the package ids a rollback writes back), `migration_recovery_ids.token` (`migration-recovery-id`), `migration_scope_covered.token` (`migration-scope-covered`). A profile forget keeps the three migration tables, like tombstones | none |
| Idempotency and receipts | `idempotency`, `idempotency_records`, `receipts`, `context_receipt_items` | operation name, receipt id, time; record ids that a receipt created or a context packet referenced | `idempotency.key_token` (operation, caller binding and key); `request_hash` (keyed since format 2; unkeyed format-1 rows are dropped on open) | `receipts`: the full `Receipt`, including counts, details and limitations (AAD: `operation`) |
| Session history | `history_sessions`, `history_session_scopes`, `history_messages`, `history_gaps`, `history_skipped`, `history_suppressed`, `history_corrections`, `cursors` | first and last times, message count; message `id` (keyed-derived), `seq`, `role`, `occurred_at`, `ingested_at`, `redacted` flag; gap ranges and reasons; skip reasons; correction times | `session_token`, `scope_token`, scope `value_token`, `event_token`, message `source_token`, `content_token`, skip `fingerprint_token`, suppressed tokens, cursor `source` and `stream_token` | `history_sessions`: session ref and scope (AAD: `scope` token). `history_messages`: text, session ref, event id, tool name, attachments, host refs, redaction categories, producer (AAD: `session`, `seq`, `role`, `event`, `at`) |
| Repository memory | `repositories`, `repo_scopes`, `repo_snapshots`, `repo_files`, `repo_observations`, `repo_derived` | times, snapshot `state` and `index_generation`, observation `current` flag; row ids derived from keyed tokens. `repo_derived` (interchange-imported observations and summaries): `record_id`, `repo_id` (the registration's row id) and the `staled` flag; nothing sealed. It indexes imported records by the (path, blob) they cite, so an exclusion purges them and a file change stales them | `scope_token`, scope `value_token`, `path_token`, `blob_token` (including `repo_derived.path_token`, `blob_token`) | `repositories`: repository id, root path, scope, git common dir, initial commit, object format, extra exclusion patterns (AAD: `scope`). `repo_snapshots`: snapshot and repository ids, state, head, branch, dirty flag, worktree path, counts, coverage (AAD: `repo`, `state`). `repo_files`: path, blob, origin, kind, mode, size, language, support, status, observation id (AAD: `blob` token) |
| Episodes and procedures (indexes over `records`) | `episodes`, `episode_attempts`, `episode_sources`, `procedures`, `procedure_evidence` | **host-supplied** `episode_id`, `outcome`, times; random `procedure_id`, `state`, `version` | `task_token`, `attempt_token`, `source_token`, `name_token` | the episode or procedure payload lives in its `records` row. An episode keeps only its current revision's sealed payload: each new attempt drops the payloads of older revisions (their `record_revisions` metadata rows stay, `purged=1`); a report's narrative fields are capped at 256 KiB together and a sealed episode at 8 MiB (`learning.episodes`) |
| Providers | `embeddings`, `provider_outbox`, `provider_sync`, `usage_log` | provider name, operation, state, attempts, error **code**, units, cost, `cost_known`, outcome, times; record id and revision | `embeddings.model_key` (from provider, model, version, dimensions, preprocessing); `external_ref` (per provider); `cause_token` | `embeddings`: record id, model key, revision, dimensions, text token, vector (AAD: `model_key`, `revision`, `index_generation`) |
| Maintenance | `jobs`, `job_state`, `events` | job kind, state, observed generations, times, content-free `progress` JSON; events: `stage`, `outcome`, `reason_code`, time (kept 90 days or 20,000 rows, `storage.partition.Partition.event`) | | `job_state`: grants, cursor and suggestions (AAD: `kind`) |

Ledger file (`deletion-ledger.sqlite3`, `storage.ledger.DeletionLedger` and
`storage.partition.Partition._REQUESTS_DDL`):

| Table | Plaintext | Keyed | Sealed |
|---|---|---|---|
| `ledger` | `generation`, `target_kind`, `created_at`, `policy` flags, `extra` (canonical JSON, authenticated by the entry MAC; today only `{"origin":"migration"}`, which marks the legacy importer's propagated deletions) | `target_token` (same rule as `tombstones`), `mac` | none |
| `ledger_outcomes` | `generation`; `payload` JSON: the opaque ids of the records the entry's forget removed, plus suppression keys and alias tokens (keyed) | `mac` | none |
| `forget_requests` | marker id, generation, target kind, policy, time | `target_token` (for memory targets the opaque record id, as in `ledger`), `key_token` | the in-flight forget request: caller access, the target's kind (never its ref), policy, keyed idempotency tokens (AAD: `kind`, `token`, `key`) |

Control file (`control.sqlite3`, `migrations.state.OwnershipControl`): `ownership` and
`ownership_log` hold partition ids, record families, states, generations, times, transition reasons
and details JSON. They are **plaintext and not authenticated**. They contain no memory content. The
details JSON includes absolute filesystem paths in plaintext: the legacy database (`legacy_db`), the
migration work directory (`work_dir`) and the snapshot directories (`snapshot_dirs`,
`snapshot_dir`). It also holds `fence_generation` and `cutover_at`.
`OwnershipControl.update_details` changes the details without a state change, by compare-and-swap
on the ownership generation, which it leaves unchanged
(`tests/test_review_round4_batch2.py::test_mf3_update_details_never_changes_state_or_generation`).

What this means for an offline reader (adversary A4) is listed in
[security-and-privacy.md](security-and-privacy.md) section 5.3:

* sizes, since ciphertext length is plaintext length plus 16 bytes;
* times, lifecycle and kind distributions;
* host-supplied ids;
* equality of keyed tokens;
* which (opaque) record ids each deletion removed, from `ledger_outcomes`.

Tests that check specific identifiers stay off disk:

* `tests/test_history.py::test_no_plaintext_on_disk_after_ingest_and_search`: session refs, event ids,
  tool names, attachment paths, host refs, producer labels and scope values;
* `tests/test_repository.py::test_no_plaintext_paths_or_content_on_disk`: file names, docstrings, the
  repository path and the repository id.

---

## 3. Key hierarchy

```text
host KeyProvider ── master key "k1" (32 bytes, never stored by the package)
   │  AES-256-GCM wrap, AAD = locus-memory/v1|wrap|<partition>|<dek_id>|<master_id>|<purpose>
   ▼
key_wraps (per partition)
   ├── data DEK  "d<12 hex>"  (current; older DEKs stay until retired)
   └── HMAC key  "h<12 hex>"  (one per partition, never rotated in place)
          │                         │
          ▼                         ▼
  seal/open every sealed row   keyed tokens (scope values, sources, subjects,
  (records, history, repo,     content fingerprints, ids, ledger MACs)
   embeddings, receipts, ...)
```

* **Custody is the host's.** `crypto.KeyProvider` is a protocol with two methods:
  * `current_key_id()`;
  * `get_key(key_id)`, which returns 32 bytes, raises `VaultLocked` when locked, and raises `KeyError`
    when the key is unknown.

  The package never reads a keychain and never discovers keys
  (`host`, `crypto` module docstrings).
  * The `crypto` module docstring also says that Locus backs the provider with the macOS Keychain,
    and the `storage.ledger.LedgerMirror` docstring suggests the Keychain for the mirror. Both
    sentences describe intended custody, not current custody. The Stage-2 handoff derives the engine
    key from the file key `APP_DIR/memory/master.key` and configures no mirror (12.4), and Keychain
    custody is an open decision ([ownership-and-extraction.md](ownership-and-extraction.md)).
* **`crypto.StaticKeyProvider`** holds keys that the host passes in memory. It has a `locked` flag for
  tests and for hosts that model locking.
* **`crypto.FileKeyProvider`** is the standalone and CLI custody: `<dir>/<key_id>.key` plus a
  `current` pointer.
  * `create` uses `O_CREAT|O_EXCL` with mode 0600 on a 0700 directory, and never overwrites.
  * `set_current` validates the key file and replaces the pointer atomically (temporary file, fsync,
    `os.replace`, directory fsync).
  * Evidence: `tests/test_crypto.py::test_file_provider_creates_private_keys_and_never_overwrites`,
    `tests/test_crypto.py::test_file_provider_set_current_is_atomic_when_the_replace_fails`,
    `tests/test_crypto.py::test_key_files_are_not_world_readable_even_with_permissive_umask`.
* **`crypto.derive_subkey(master, info)`** returns `HMAC-SHA256(master, "locus-memory/v1|" + info)`.
  This is a single PRF call with domain separation, not RFC 5869 HKDF. The Stage-2 Locus handoff uses
  it to derive the engine key from Locus's existing `master.key` (`LocusKeyProvider`, key id
  `locus-v1`; not executed in the real app; see [handoff/locus/README.md](../handoff/locus/README.md)).
* **Partition keys.** When a partition is created, `crypto.PartitionKeyring.initialize` generates one
  data DEK and one HMAC key with `secrets.token_bytes(32)` and wraps each under the provider's current
  master key. It refuses if `key_wraps` already has rows
  (`tests/test_crypto.py::test_initialize_refuses_an_existing_vault`).
* **Wraps.** One row per (DEK, master key) pair: a partition can be wrapped under several master keys
  at once, for example during rotation with `drop_old=False`.

---

## 4. Sealing format

### 4.1 Cipher and plaintext

* AES-256-GCM, from `cryptography`'s `AESGCM`. `crypto.CIPHER_NAME` is `"AES-256-GCM"`.
* Plaintext is `models.canonical_json(value)` encoded as UTF-8: sorted keys, compact separators,
  `allow_nan=False`.
* Ciphertext is `AESGCM.encrypt(nonce, plaintext, aad)`, with the 16-byte tag appended.
* The format tag is `crypto.FORMAT_TAG = b"locus-memory/v1"`.

### 4.2 Row AAD

`crypto.PartitionKeyring.aad` builds:

```text
locus-memory/v1 | <partition_id> | <table> | <row_id> | canonical_json({...fields, "dek": <dek_id>})
```

`seal` always adds the DEK id to the fields. Changing any of the following makes `open` fail with
`IntegrityError` ("a stored record failed authentication"), whose message never names the field or the
content:

* the table;
* the row id;
* any bound field, or adding an extra field;
* the nonce;
* the ciphertext;
* the partition.

At the keyring level, a DEK id the keyring does not hold raises `WrongKey`. Above it,
`Partition.open_json` turns an id that is absent from `key_wraps` into `IntegrityError` (4.4)
(`tests/test_crypto.py::test_any_change_to_bound_context_fails_authentication`,
`tests/test_crypto.py::test_ciphertext_is_bound_to_its_partition`,
`tests/test_storage.py::test_ciphertext_moved_between_rows_fails`).

The bound fields per table are in the section 2 table. For `records`, the scope is bound as the keyed
scope token. After decryption, `storage.records.RecordStore._decode` also compares the plaintext columns
`kind`, `lifecycle`, `revision` and `scope_token` with the authenticated payload, and the columns
that select records for expiry, staling and external withdrawal - `expires_at`, `pinned`,
`valid_from`, `valid_until` - with its retention and validity. A relabelled row (for example a
candidate edited to `approved`, or a transient memory whose `expires_at` was cleared) raises
`IntegrityError` and is never served
(`tests/test_storage.py::test_relabelled_metadata_is_never_served`,
`tests/test_review_round4_batch3.py::test_tamper6_relabelled_time_columns_are_never_served`).

**Not bound** are the other plaintext columns:

* `created_at`, `updated_at`;
* `write_generation`;
* the subject and content tokens;
* index tables such as `record_scopes`, `record_sources` and `derivations`.

What editing them can still change:

* ordering, SQL pre-filtering, conflict and duplicate detection, and counts;
* whether a record shows up at all: a `record_scopes` row with a token no grant matches hides the
  record from reads, and an index that disagrees with the authenticated scope makes reads fail
  (below).

What it cannot change: what an authenticated record says
([security-and-privacy.md](security-and-privacy.md) 8.9), or which caller may read it.
`storage.records.RecordStore.iter_authorized` has always refused a row whose authenticated scope the
caller's grants do not allow. Since review round 4, such edits also cannot:

* **Pass unnoticed on reads.** `iter_authorized` also compares every row's `record_scopes` rows with
  the rows its authenticated scope implies (`RecordStore.scope_index_rows`). Any mismatch, such as a
  stripped or relabelled index, raises `IntegrityError`, so the read fails closed and serves nothing.
  History sessions get the same check (`history.archive.HistoryArchive._authorized_session`)
  (`tests/test_storage.py::test_scope_index_tampering_never_leaks_a_record`,
  `tests/test_review_round4_batch1.py::test_tamper2_a_stripped_scope_index_fails_closed_instead_of_serving`).
* **Hide a record from a forget.** Victims are also found from authenticated payloads
  (`forgetting._PayloadIndex`, section 6), live and on ledger replay
  (`tests/test_review_round4_batch1.py::test_tamper2_*`).
* **Keep an external replica alive.** Provider replica withdrawal no longer trusts the plaintext
  columns alone. A deleted `provider_sync` mapping still lets a forget queue the external deletion,
  and edited expiry, validity or lifecycle columns still lead to the replica's withdrawal
  (`tests/test_review_round4_batch1.py::test_tamper5_*`,
  `tests/test_review_round4_batch3.py::test_tamper6_*`).

### 4.3 Wrap AAD

```text
locus-memory/v1 | wrap | <partition_id> | <dek_id> | <master_key_id> | <purpose>
```

`crypto.PartitionKeyring._wrap_aad` binds the partition id, DEK id, master key id and purpose, so a
wrap moved to another partition, DEK, master id or purpose does not open. That relocation case is
implemented but not directly tested: no test moves a wrap or rewrites `key_wraps.dek_id`,
`master_key_id` or `purpose`.
`tests/test_storage.py::test_tampered_key_wrap_or_partition_label_refuses_to_open` covers two related
cases: a data wrap with one flipped byte (`WrongKey`), and a `meta.partition_id` relabelled to another
id (`MigrationError` from `storage.schema.migrate`).

### 4.4 Multi-process consistency

* `storage.partition.Partition.seal_json` re-reads `meta.current_dek_id` inside the write transaction,
  and reloads the keyring if another process rotated the DEK. A stale cached DEK can therefore never
  strand new rows under a key that is being retired.
* `Partition.open_json` reloads the key wraps when it meets a DEK id it does not hold. An id absent
  from `key_wraps` raises `IntegrityError`.

(`tests/test_storage.py::test_a_second_engine_follows_a_data_key_rotation`.)

---

## 5. Nonce policy

* Every seal and every wrap draws a fresh 96-bit nonce from `secrets.token_bytes(12)`
  (`crypto.NONCE_BYTES`). Nonces are never derived from content or counters.
* Every update re-seals the whole payload with a new nonce. Nothing is encrypted in place.
* The nonce is stored next to the ciphertext.
* No per-DEK seal counter is kept. Data-key rotation (section 8.2) starts a fresh DEK if a host ever
  wants to bound per-key usage.

Evidence: `tests/test_crypto.py::test_nonces_are_unique` (2,000 seals, all distinct) and
`tests/test_crypto.py::test_seal_open_roundtrip_and_ciphertext_hides_plaintext`.

---

## 6. Keyed tokens

`crypto.PartitionKeyring.token(purpose, value)` is
`HMAC-SHA256(hmac_key, purpose + "\x00" + value)`, truncated to 40 hex characters (160 bits).

* **Separation.** Each purpose is a separate namespace, and each partition has its own HMAC key
  (`tests/test_crypto.py::test_tokens_are_keyed_and_purpose_separated`).
* **Purposes.** Purposes include:
  * `scope`, `scope-value`, `source`, `session`, `subject`, `content`, `suppress`;
  * `message`, `history-cursor`, `repository-id`, `repo-snapshot`;
  * `embedding-model`, `embedding-text`, `external-ref:<provider>`, `provider-cause`;
  * `idempotency`, `idempotency-request`, `ledger`;
  * `memory` (derivation and cascade edges: the input token of a record derived from a memory),
    `subject-v2` (subjects or predicates containing `|`, `storage.records.RecordStore.subject_token`);
  * MACs that authenticate plaintext `meta` values: `deletion-checkpoint`, `legacy-residue`,
    `migration-rollback-watermark`;
  * migration id sets: `migration-cutover-id`, `migration-recovery-id`, `migration-scope-covered`.
* **What they allow.** Tokens let SQL authorize, join and deduplicate without decrypting. They also
  let the ledger name a forget target without any content: an entry holds only the target's token.
* **Applying a forget is not decryption-free.** Since review round 4, every forget apply except a
  profile forget, live or replayed, decrypts every record once (`forgetting._PayloadIndex`, built by
  `ForgettingService._apply`). It uses each record's authenticated scope, sources and `derived_from` to
  find victims, so a tampered `record_scopes`, `record_sources` or `derivations` table cannot hide a
  record. A scope forget of history likewise opens every session payload once
  (`history.archive.HistoryArchive._sessions_with_scope_value`). Each victim is also decrypted
  (`ForgettingService._load`), to check what evidence remains and, when the policy suppresses
  relearning, to compute its suppression fingerprint (`ForgettingService.suppress`). Rows that no
  longer authenticate are still removed wherever the index tables place them
  (`ForgettingService._purge_damaged`). Evidence:
  `tests/test_review_round4_batch1.py::test_tamper2_scope_forget_finds_a_record_whose_scope_index_was_stripped`,
  `::test_tamper2_source_forget_finds_a_citer_whose_source_index_was_stripped`,
  `::test_tamper2_cascade_finds_a_derived_record_whose_derivation_edge_was_stripped`,
  `::test_tamper2_replayed_scope_forget_after_restore_ignores_a_stripped_index`,
  `::test_tamper2_scope_forget_finds_a_session_whose_scope_index_was_stripped`.
* **Cost.**
  * Within a partition, equal inputs give equal tokens, so an offline reader can see equality.
  * Anyone holding the HMAC key can confirm a guessed value, for example a project name, a content
    fingerprint or a suppressed statement.
  * The HMAC key is never rotated, so this holds for the life of the partition.
  * Format-1 idempotency rows held an *unkeyed* SHA-256 of the request, which was an offline content
    oracle. They are dropped on open (`storage.schema.IDEMPOTENCY_FORMAT`;
    `tests/test_review_group1.py::test_legacy_unkeyed_idempotency_rows_are_dropped_on_open`,
    `tests/test_review_group1.py::test_forgotten_project_name_is_not_confirmable_from_idempotency`).

---

## 7. Unlock, locked and wrong-key behavior

`crypto.PartitionKeyring.unlock` tries every wrap whose master key the provider holds. It succeeds
when the current data DEK and the HMAC key both open. One bad wrap does not block unlocking while
another wrap of the same key works
(`tests/test_crypto.py::test_unlock_survives_one_bad_wrap_when_another_wrap_opens_the_keys`).

| Condition | Result |
|---|---|
| Provider locked (`current_key_id`/`get_key` raise `VaultLocked`) | `VaultLocked` |
| Provider holds none of the wrapping master ids (`KeyError`) | `VaultLocked` ("no available master key opens this vault") |
| A held key fails to authenticate the needed wraps | `WrongKey` ("the supplied key does not authenticate this vault") |
| Provider returns a key that is not 32 bytes | `WrongKey` |
| `FileKeyProvider`: the key file for a wrapping id is missing or unreadable | `VaultLocked` |
| `FileKeyProvider`: the key file is not 32 bytes | `WrongKey` |
| `FileKeyProvider`: no `current` pointer, where a current key is needed (creating a partition, or wrapping a new DEK when no wrapping master is held) | `VaultLocked` ("run `locus-memory init`") |
| A row references a DEK that is wrapped but not unwrappable | `WrongKey` ("the data key for this record is unavailable") |
| A row references a DEK id absent from `key_wraps` | `IntegrityError` |
| A row fails authentication | `IntegrityError` |
| The deletion ledger fails its MAC chain | `IntegrityError` on open |

* **No new keys over an existing vault.** None of these conditions ever generates a new key. Key
  wraps are byte-for-byte unchanged after a refused open:
  * `tests/test_storage.py::test_wrong_key_is_refused_and_never_replaced`;
  * `tests/test_storage.py::test_missing_or_locked_key_is_vault_locked_and_never_replaced`;
  * `tests/test_crypto.py::test_wrong_master_key_bytes_raise_wrong_key`;
  * `tests/test_crypto.py::test_missing_master_key_raises_vault_locked`.
* **Errors are typed, not empty results.** A locked vault raises during search and context building;
  it never returns "no results" (`retrieval.service` module docstring).
* **Forgetting damaged rows.** A memory forget authorizes against the SQL scope index when a row no
  longer authenticates, so damaged or tampered rows can still be forgotten
  (`tests/test_forgetting.py::test_damaged_records_can_still_be_forgotten`).
* **Recovery.** Losing every master key that wraps a partition makes that partition unreadable. There
  is no escrow.

---

## 8. Key rotation

All rotation entry points require an `ADMIN` context whose actor is `USER` or `HOST`
(`admin.require_admin`).

### 8.1 Master-key rotation

Entry point: `MemoryEngine.rotate_master_key`, then `admin.rotate_master_key`, then
`crypto.PartitionKeyring.rewrap`. The CLI command is `keys rotate-master`.

1. The new master key must be available from the provider before anything changes.
2. Every DEK and the HMAC key are unwrapped. If any cannot be unwrapped, the rotation raises
   `WrongKey` ("keep the old master key") and changes nothing.
3. Each key is re-wrapped under the new master in one write transaction. With `drop_old=True` (the
   default), wraps under other master keys are deleted only after every key has its new wrap.
4. After commit, `admin._confirm_flush` checkpoints the WAL with `TRUNCATE`. The receipt reports
   `details.flushed`.

The DEKs and the HMAC key do not change. The receipt always carries
`admin.PRE_ROTATION_COPIES_LIMITATION`: copies of the vault made before the rotation still open with
the old master key.

Evidence: `tests/test_crypto.py::test_rewrap_moves_every_key_to_the_new_master`,
`tests/test_crypto.py::test_rewrap_to_an_unavailable_master_changes_nothing`,
`tests/test_storage.py::test_master_key_rotation`,
`tests/test_review_group2.py::test_master_rotation_drop_old_removes_old_wraps_from_the_vault_files`.

The CLI creates the new key file, re-wraps, and only then moves the `current` pointer. It never deletes
key files (`cli.cmd_keys_rotate_master`).

### 8.2 Data-key (DEK) rotation

Entry point: `MemoryEngine.rotate_data_key`, then `admin.rotate_data_key`. The CLI command is
`keys rotate-data`. Rotation is progressive and resumable, and each call does one bounded batch:

1. **First call.** Records every existing data DEK as "retiring". Creates a new DEK
   (`crypto.PartitionKeyring.new_data_key`), wrapped under every master key that wraps the current DEK
   and that the provider holds, not just the provider's `current` pointer. Makes it current at once,
   and persists the state in `meta.dek_rotation`
   (`tests/test_crypto.py::test_new_data_key_follows_the_vault_masters_not_a_stale_provider_pointer`).
2. **Each call.** Re-seals at most `batch` rows still under a retiring DEK.
   * Foundation tables (`records`, `record_revisions`, `receipts`) are handled in `admin`.
   * Every sibling service that owns sealed tables implements
     `reencrypt(conn, old_dek_ids, limit)`, usually through `admin.reencrypt_table`:
     * `history.archive.HistoryArchive`;
     * `repository.service.RepositoryService`;
     * `providers.hub.ProviderHub` (embeddings);
     * `learning.consolidation.ConsolidationService` (`job_state`).
   * Each row is authenticated with its original AAD before it is re-sealed. A tampered row aborts the
     batch with `IntegrityError` and is never laundered into a valid ciphertext
     (`tests/test_storage.py::test_data_key_rotation_refuses_to_reseal_a_tampered_row`,
     `tests/test_integration.py::test_data_key_rotation_refuses_to_launder_a_tampered_sibling_row`).
3. **Completion.**
   * When no row in any sealed table of the main database still references a retiring DEK
     (`admin.sealed_tables`, `admin.remaining_rows`), the retiring DEKs' wraps are deleted
     (`PartitionKeyring.retire_data_key`) and the state is cleared.
   * If rows remain that no service re-encrypts, the state is `blocked` and the old DEK is kept.
     Rotation never strands data (`tests/test_storage.py::test_data_key_rotation_never_strands_rows_nobody_can_reencrypt`).
   * The completing call checkpoints and reports `flushed`.

More evidence: `tests/test_storage.py::test_data_key_rotation_is_progressive_and_keeps_old_data_readable`,
`tests/test_storage.py::test_data_key_rotation_resumes_after_restart`,
`tests/test_integration.py::test_data_key_rotation_reencrypts_every_sibling_sealed_table`,
`tests/test_review_group2.py::test_completed_data_key_rotation_removes_retired_dek_material_from_the_vault_files`.

`MemoryEngine.data_key_rotation_status` reports progress.

The `forget_requests` rows in the ledger file are not part of DEK rotation. They are short-lived: they
are dropped once applied, and unbound ones (an append that never happened) after 10 minutes; the ledger
WAL is then checkpointed with the main database (section 11). A request that no longer opens degrades to
an unattributed replay (`storage.partition.Partition._open_request`). A request record that could not
be written at all has the same effect; see 12.2 and [security-and-privacy.md](security-and-privacy.md)
3.1.

### 8.3 HMAC key

Never rotated in place (`crypto` module docstring). Master rotation re-wraps it. Data-key rotation
does not touch it. Rotating it would require re-deriving every keyed token, ledger MAC and
suppression fingerprint. That is deferred.

### 8.4 Flushing key material: `admin.flush_key_material`

A committed deletion of a wrap or a DEK reaches the main file only when a checkpoint copies the newer
pages over the old ones. Until the WAL is reset, its older frames still hold the old wraps.

* A reader pinned to an older snapshot makes `wal_checkpoint(TRUNCATE)` report busy. The rotation
  then retries a bounded number of times (`admin.FLUSH_ATTEMPTS`), and if it still fails, reports
  `flushed: False` with `admin.UNFLUSHED_LIMITATION`.
* Until a later call to `admin.flush_key_material(ctx, access)` returns `True`, the host must treat the
  replaced master key (or the retired DEK) as still able to open the live files. `ctx` is the result
  of `MemoryEngine.partition_context(ref)`. This function has no `MemoryEngine` wrapper and no CLI
  command.
* Delete an old master key only after `flushed` is `True`, and remember that pre-rotation backups
  still need it.

Evidence: `tests/test_review_group2.py::test_master_rotation_reports_unflushed_when_a_reader_pins_the_old_snapshot`,
`tests/test_review_group2.py::test_completed_data_key_rotation_reports_unflushed_when_a_reader_pins_the_old_snapshot`,
`tests/test_review_group2.py::test_flush_key_material_is_a_user_or_host_admin_action`.

---

## 9. SQLite configuration

Every app-managed database connection (main, ledger, control) is opened by `storage.db.Database`. The
one exception is a short read-only peek at the ledger before a partition whose main database is
missing or empty is initialized (`storage.partition._ledger_has_entries`, section 1):

| Setting | Value | Purpose |
|---|---|---|
| `journal_mode` | `WAL` (set with bounded retries; `Database._ensure_wal`). Exception: a new vault is first built in a private staging file opened with `Database(..., wal=False)`, so in rollback-journal mode (`storage.partition.Partition._create_vault`). The staging file and its `-journal`, `-wal` and `-shm` are unlinked afterwards, and the published `memory.sqlite3` is switched to WAL on its first `Database` open | concurrent readers during a write |
| `secure_delete` | `ON` | freed cells and pages are zeroed when rewritten, so deleted ciphertext does not linger in the file |
| `temp_store` | `MEMORY` | sorter and temporary b-trees stay in RAM, not in temp files |
| `trusted_schema` | `OFF` | defense in depth: schema objects (views, triggers) cannot call SQL functions that are not marked innocuous. The package registers none on these connections |
| `synchronous` | `FULL` | committed writes and receipts survive power loss in WAL mode |
| `foreign_keys` | `ON` | cascades from records and sessions to their index rows |
| `busy_timeout` | `EngineConfig.busy_timeout_ms` (default 5,000 ms) for the main database (`storage.partition.Partition.__init__` passes it on). The ledger (`storage.ledger.DeletionLedger`) and control (`migrations.state.OwnershipControl`) files always use the `Database` default of 5,000 ms and ignore `EngineConfig` | bounded wait for locks |

* **Transactions.** Writes use `BEGIN IMMEDIATE`. A busy store is retried a bounded number of times
  and then raises the typed `Contention`. Reads use a deferred transaction, which gives a consistent
  snapshot (`Database.write`, `Database.read`). Connections are per thread. Connections of finished
  threads are closed, and `close()` never closes another live thread's connection under it
  (`tests/test_db_close.py`).
* **Typed storage errors** (since review round 2). Only lock contention becomes `Contention`.
  `storage.db.storage_error` maps the other storage failures to typed errors: disk full to
  `StorageFull` (`storage_full`), a read-only file or directory to `StorageReadOnly`
  (`storage_read_only`), and an I/O error or unopenable file to `StorageUnavailable`
  (`storage_unavailable`; the other two are its subclasses). `Database` applies the mapping when it
  connects, on `BEGIN`, inside the transaction and on `COMMIT`; a `COMMIT` that fails for any other
  non-busy reason also raises `StorageUnavailable`. Evidence:
  `tests/test_review_round2_batch3.py::test_cd5_a_full_disk_is_a_typed_storage_error_not_contention`,
  `::test_cd5_sqlite_full_is_storage_full`, `::test_cd5_a_read_only_vault_raises_a_typed_error`,
  `::test_cd5_the_cli_maps_storage_errors_to_their_own_exit_code`.
* **SQL safety.** Values are always bound as parameters. SQL text is assembled only from:
  * fixed table names;
  * placeholder lists;
  * internally built authorization clauses;
  * identifiers read from `sqlite_master` and quoted.

  The `ORDER BY` fragment that `RecordStore.authorized` accepts is checked against a pattern
  (`tests/test_core.py::test_record_store_rejects_injected_order_and_filters_ids_in_sql`).
* **The legacy vault's connections** (`compat.legacy_vault._connect_legacy`) are not opened by
  `Database`. They set `secure_delete=ON`, `temp_store=MEMORY`, `trusted_schema=OFF` and
  `busy_timeout=10000` (10,000 ms), plus WAL. The original Locus vault sets only WAL and the busy
  timeout. The migration tooling opens the legacy file with its own short-lived `sqlite3`
  connections (for example the cutover's write barrier, `migrations.cutover.Migrator._legacy_write_barrier`,
  waits up to 30,000 ms).

---

## 10. Search without a plaintext sidecar

No search index is ever written to disk (R8.4).

* **Memory search** (`retrieval.index`) builds a projection per grants fingerprint, lifecycle set and
  kind set, from records already filtered by `RecordStore.authorized`:
  * it lives on a private `storage.db.memory_connection()`, which is `:memory:` with
    `temp_store=MEMORY` and `trusted_schema=OFF`;
  * it uses two *contentless* FTS5 tables (`content=''`, `fts_text` and `fts_ident`), so only the
    inverted index is kept, not a second copy of the text;
  * the decrypted records are held in Python objects of the same process.
* **History search** (`history.archive`) builds a similar in-memory projection: a `msgs` table plus an
  external-content FTS5 table, hydrated newest-first in bounded batches.
* **Without FTS5.** Both fallbacks run in memory. There is never a plaintext fallback on disk.
  * Memory search uses FTS5 only when `retrieval.index.fts5_usable()` is true: FTS5 is present
    (`storage.db.fts5_available`), the tokenizer options it needs work, and the fallback is not forced.
    Otherwise it uses a pure-Python BM25 and reports this in `coverage.partial_reasons`
    (`lexical_fallback:bm25_python (...)`, from `retrieval.index.build_index`).
  * History search checks `storage.db.fts5_available` and otherwise falls back to substring matching.
    It does not mark coverage partial for this. The fallback is visible through `fts5_available` in
    `history.archive.HistoryArchive.coverage_status` and through each hit's `score_kind`
    (`substring_recency`). That score kind also appears with FTS5 when FTS5 finds nothing, for
    example for CJK text (`history.archive` module docstring).
* **Bounds and lifetime.** Projections are bounded by `EngineConfig.max_projection_records`,
  `max_projection_bytes` and `max_history_messages_hydrated`; anything left uncovered is reported as
  partial coverage. They are discarded when the generation (memory) or deletion generation (history)
  changes, and on close.
* **Evidence.** `tests/test_retrieval.py::test_search_never_writes_plaintext_to_disk` points `TMPDIR`
  and `SQLITE_TMPDIR` at an empty directory, then searches 120 canary records through both the FTS5
  and the Python paths. Afterwards no canary or query text is in any store file, and the temp
  directory is still empty.
* **Not claimed.** This is tested for search. It is not claimed for every SQLite code path.

---

## 11. WAL residue handling

In WAL mode a committed change is first written to `-wal` as whole-page images. Older page images can
remain there until a checkpoint resets the log. For ordinary writes this is harmless: the older images
hold ciphertext under keys that are still live, and the content is either current or kept in revision
history anyway. Only two operations checkpoint after deleting:

1. **Forgetting.** After the purge commits, `storage.partition.Partition.flush_purged` runs
   `wal_checkpoint(TRUNCATE)` (`storage.db.Database.checkpoint`, which returns `True` only when every
   frame was copied and the log reset) on the main database **and** on the deletion-ledger file, whose
   WAL still holds the dropped sealed forget request.
   * A completed checkpoint records the deletion generation it covered in
     `meta.purge_checkpointed_generation`.
   * If a reader blocks it, the partition sets `pending_purge_checkpoint` in memory and durably in
     `meta`. The forget receipt says `physical_purge_pending=True`.
   * The checkpoint is retried without waiting on later calls (`MemoryEngine.partition_context`) and
     on open (`Partition.retry_purge_checkpoint`), and once more on close (`Partition.close`, which
     waits up to the busy timeout). On open, deletions above `purge_checkpointed_generation` (a
     process that died between its purge and its checkpoint) are pending too.
   * Deletions applied by `Partition.reconcile` (a crash after the ledger append, a failed apply,
     another process's forget, a restore) and by a migration rollback are flushed the same way
     (`Partition.ensure_purged`, never waiting for readers).
   * An idempotent replay of a forget reports the purge as it stands now
     (`Partition.purge_complete`), not as its stored receipt recorded it
     (`tests/test_review_round2_batch3.py::test_cd2_a_forget_reconciled_after_a_crash_is_physically_purged`,
     `::test_cd2_an_idempotent_retry_after_reconcile_reports_the_real_purge_state`,
     `::test_cd2_a_replay_while_the_checkpoint_is_still_blocked_stays_pending`,
     `::test_cd4_a_completed_forget_leaves_no_sealed_request_on_disk`).
   * Evidence: `tests/test_storage.py::test_forget_removes_the_ciphertext_itself` (the forgotten
     record's ciphertext bytes are absent from every file after the forget),
     `tests/test_review_group1.py::test_forget_with_a_concurrent_reader_finishes_the_physical_purge_later`,
     `tests/test_review_group1.py::test_forget_without_readers_reports_no_pending_purge`.
2. **Key retirement.** Master and DEK rotation checkpoint after commit (section 8.4).

Purges outside forgetting are **not** followed by a checkpoint:

* **Exclusion purge.** When a repository path becomes excluded, the next snapshot
  (`repository.service.RepositoryService._purge_excluded`, inside the snapshot's write transaction)
  deletes the observations of that path, the imported records that cite it (`repo_derived`) and the
  records derived from or citing them that a forget's cascade rule would remove
  (`ForgettingService.remove_derived`). That content is neither current nor kept in revision history.
* **Episode revision compaction** (`learning.episodes.EpisodeService._compact_revisions`) drops the
  sealed payloads of an episode's older revisions. Those payloads are mostly redundant with the
  current revision.

Their deleted ciphertext, under live keys, can stay in `memory.sqlite3` until a checkpoint copies
the rewritten pages over it, and earlier page images can stay in `memory.sqlite3-wal` until later
frames overwrite them or a truncating checkpoint empties the file. SQLite's automatic checkpoint
(passive, the package keeps SQLite's default) does the first; only a truncating checkpoint, such as
the next forget's or key retirement's, guarantees the second. Section 16 lists this as open.

Together, `secure_delete` and the checkpoint remove the bytes from the files SQLite manages. They do
not erase the storage medium: filesystem snapshots, copy-on-write and SSD remanence are out of scope.

The legacy vault is different. `compat.legacy_vault.LegacyMemoryVault.delete` does not checkpoint.
Deleted legacy ciphertext, which the live legacy key can decrypt, may stay in the legacy `-wal`
until SQLite's next checkpoint resets the log. The migration tooling scrubs the legacy file itself
in these cases:

* **Rollback.** The migrator's rollback checkpoints the legacy file
  (`migrations.cutover.Migrator._checkpoint_legacy`).
* **Forgets while the package is authoritative** (since review round 2). Every forget is also
  applied to the copies a migration keeps for rollback (`migrations.cutover.propagate_forgets_to_legacy`,
  called through `forgetting.ForgettingService.propagate_to_migration_copies` after each forget, on
  open with `recheck=True`, after a reconcile that applied entries or acknowledged a mirror gap, and
  at cutover completion). It
  runs when the host passes the ownership control (`HostCapabilities.ownership`; the CLI does so
  once a migration has recorded state for the partition).
  * The legacy rows of records whose package record no longer exists are deleted by id, with
    `secure_delete` followed by `wal_checkpoint(TRUNCATE)`, and no key is needed
    (`migrations.cutover._delete_legacy_rows`). A row qualifies when its id is in the cutover set or
    the authenticated ledger proves the package forgot it.
  * The Migrator's snapshots are removed (section 14).
  * A busy or missing legacy file, or a snapshot that could not be removed, leaves the receipt with
    the limitation `forgetting._MIGRATION_RESIDUE` and `physical_purge_pending=True`. The step is
    retried after the next forget, on the next open and after the next reconcile that applies
    entries.
  * Progress is recorded in the partition `meta` key `legacy_residue_generation`
    (`migrations.cutover.RESIDUE_KEY`), authenticated with the keyed token purpose `legacy-residue`.
    Only a marker this partition's keys produced for exactly the current deletion generation skips
    the purge; a forged or altered marker never does.
* **Cutover abort.** An abort of a `cutover_in_progress`, given the partition context, deletes from
  the legacy file the rows of records removed since the fence (with `secure_delete`), then
  checkpoints it when it deleted any (`migrations.cutover.abort_cutover`, `_abort_with_deletions`,
  `_checkpoint_legacy_file`).

Evidence: `tests/test_review_group1.py::test_legacy_deletes_scrub_the_file` (`secure_delete` scrubs the
main file after a checkpoint),
`tests/test_review_round2_batch1.py::test_cd1_forget_after_cutover_leaves_no_legacy_or_snapshot_copy`,
`::test_cd1_a_busy_legacy_store_is_reported_and_finished_later`,
`tests/test_review_round3_batch2.py::test_mf6_a_retry_applied_by_reconcile_reaches_the_legacy_vault`,
`tests/test_review_round4_batch2.py::test_tamper7_a_forged_residue_marker_never_skips_the_legacy_purge`,
`::test_tamper7_reopening_purges_whatever_the_marker_says`,
`::test_tamper7_a_stripped_cutover_set_still_purges_ledger_forgotten_rows`.

---

## 12. Deletion ledger, mirror and reconcile protocol

### 12.1 The ledger

`storage.ledger.DeletionLedger` is a separate SQLite file. Each entry is
`(generation, target_kind, target_token, created_at, mac, policy, extra)`.

* **MAC chain.** Format 2 (every entry this build writes): the MAC is the keyed token `ledger` over
  `ledger-v2|` + canonical JSON of `[prev_mac, generation, kind, token, created_at, policy, extra]`.
  Format 1 (earlier builds, still verified): `prev_mac|generation|kind|token|created_at[|policy]`.
  Each entry chains to the previous one and covers the forget policy and `extra` - authenticated
  entry attributes, today only `{"origin": "migration"}` on the legacy importer's propagation of a
  legacy deletion. That forget is issued by `migrations.legacy.LegacyImporter._propagate_deletions`
  through `ForgettingService.forget(..., origin=storage.partition.MIGRATION_ORIGIN)`, and read back by
  `migrations.legacy._migration_forget` and `storage.partition.DeletionView.migration_forget`.
* **Policy decoding** (since review round 3). Every policy this build records is a validated
  `ForgetPolicy` with bool fields (12.2 step 0). An earlier build recorded policies without
  validation, so `storage.partition.decode_forget_policy` reads an authenticated policy that is valid
  JSON but not an object as the default policy, and reads non-bool fields by truthiness, as that
  build applied them. Such an entry no longer wedges reconcile; unparseable policy JSON is still an
  `IntegrityError`
  (`tests/test_review_round3_batch1.py::test_api1_a_bad_policy_recorded_by_an_earlier_build_no_longer_wedges_the_partition`).
* **Outcomes.** `ledger_outcomes(generation, payload, mac)`: what applying the entry removed and
  recorded - record ids, suppression keys (keyed fingerprint, source token) and source-alias tokens;
  opaque ids and keyed tokens only. The MAC (keyed token `ledger` over `ledger-outcome|` + JSON of
  `[generation, entry_mac, payload]`) binds it to its entry. It is written inside the applying
  main-database transaction, before that commits. Outcomes are not chained: a deleted outcome row
  is not detected (it only loses the rebuild of 12.3 for its entry).
* **What is detected.** `DeletionLedger.verify` runs on every open and detects edits, reordering and
  holes (`tests/test_forgetting.py::test_ledger_tampering_is_detected_on_open`). A truncated tail is
  rebuilt from the store's tombstones on the next open (12.3). Truncation combined with an older
  database is detectable only with a host mirror (12.4).
* **Content.** Entries carry tokens and policy flags, never content. A `memory` entry's token is the
  opaque record id.

### 12.2 Write-ahead order

`forgetting.ForgettingService.forget`:

0. Refuses a malformed request before anything is hashed or appended: `forgetting._check_request`
   requires a `ForgetTarget` and a `ForgetPolicy` (whose fields must be bools), and
   `storage.partition.encode_forget_policy` refuses a non-policy too. A ledger entry is permanent, so
   a policy that could not be decoded again would wedge every later reconcile
   (`tests/test_review_round3_batch1.py::test_api1_a_non_policy_is_refused_before_anything_is_recorded`,
   `::test_api1_policy_fields_must_be_bools`).
1. Records the sealed request (`Partition.record_forget_request`; the target's kind, never its ref).
   This is best effort: a failure is swallowed (`except Exception: marker = None`) and the forget
   continues without a request record.
2. Appends the entry to the ledger (durable, `synchronous=FULL`).
3. In one main-database transaction:
   * applies earlier unapplied entries and then this one (`apply_tombstone`);
   * records the tombstone, and a memory tombstone with policy `{"derived":true}` for every other
     record the apply removed (`ForgettingService._apply`; since review round 3);
   * advances `meta.deletion_generation` (never backwards,
     `tests/test_forgetting.py::test_deletion_generation_never_moves_backwards`) together with its
     authenticated copy `meta.deletion_checkpoint` (`generation:tag`, the tag a keyed token over
     the partition id and the generation);
   * keeps the entry's outcome in the ledger (12.1).
4. Drops the applied requests, checkpoints, and writes the new head `(generation, mac)` to the mirror.
5. Builds the receipt as the deletion stands now (`ForgettingService._finish_result`; since review
   round 3). It reports the physical-purge state, applies the deletion to the copies a migration
   keeps for rollback (`propagate_to_migration_copies`, section 11), and adds the legacy-authority,
   rollback-pending or cutover-pending limitation when the legacy store still holds a copy. None of
   this is stored with the receipt: a live forget, an idempotent replay and a receipt recorded by a
   reconcile all go through this step.

The invariant (`storage.partition` module docstring): every ledger entry at or below the main
database's `deletion_generation` has been applied to it. Which generation that is, is read from the
authenticated checkpoint, never from the plaintext counter alone (12.3).

### 12.3 Reconcile

`storage.partition.Partition.reconcile` runs on every open and before serving whenever
`Partition.needs_reconcile()` says the ledger head is ahead of the store (two indexed lookups). It can
also be invoked explicitly with `MemoryEngine.reconcile`, which requires `ADMIN` and a `USER` or
`HOST` actor.

| State found | Action |
|---|---|
| ledger generation > store `deletion_generation` (crash after append, failed apply, another process's unfinished forget, an older database restored next to a newer ledger) | apply the missing entries with their recorded policy inside one write transaction, then bump the generation (`tests/test_forgetting.py::test_crash_then_reopen_applies_the_tombstone_before_serving`, `tests/test_forgetting.py::test_a_crashed_entry_is_not_lost_when_a_later_forget_succeeds`, `tests/test_forgetting.py::test_restoring_an_old_database_cannot_resurrect_forgotten_memories`) |
| store generation > ledger generation (the ledger was rolled back or replaced) | re-append the store's newer tombstones to the ledger (`DeletionLedger.adopt`), skipping tombstones whose policy is `{"derived":true}` (`DERIVED_TOMBSTONE_POLICY`), so only real ledger targets are re-appended. Adopted entries get no outcomes (`tests/test_forgetting.py::test_a_rolled_back_ledger_is_rebuilt_from_the_store`, `tests/test_review_round2_batch1.py::test_fg3_a_restored_ledger_adopts_the_forget_not_the_lessons_tombstone`) |
| host mirror generation > ledger head (database **and** ledger restored from an older backup) | raise `ReconciliationRequired` with both generations. Serve nothing until the newer ledger is restored, or until an operator calls `MemoryEngine.reconcile(access, acknowledge_mirror_gap=True)`, which appends a durable `gap_acknowledged` marker so the decision is recorded and not asked again (`tests/test_forgetting.py::test_restoring_database_and_ledger_against_a_newer_mirror`) |
| main database missing or empty next to a ledger with entries | `IntegrityError`; no keys are created (section 1) |

The store's applied generation is the authenticated checkpoint's (`Partition._applied_generation`):

* a checkpoint that does not verify (altered, or copied from another partition) is trusted for
  nothing: every entry is replayed;
* a missing checkpoint (a store last written by a build without checkpoints, or one removed by a
  tamperer) falls back to the plaintext counter, capped below the first format 2 entry (a store that
  applied one carries a checkpoint), so only format 1 entries rely on the plaintext value
  (`tests/test_review_round4_batch1.py::test_tamper1_restored_old_database_without_its_checkpoint_still_replays`).

Every reconcile then restores the deletion state the ledger proves, inside the same write transaction
(`Partition._restore_deletion_state`): each entry's tombstone; the memory tombstones, suppressions
and source aliases its outcome lists; and the removal (as a forget of that memory, with the entry's
policy, recording no receipt) of any record a forget removed that is in the main database again - the
target of a memory forget that was not the legacy importer's propagation, or any id an outcome lists
(`tests/test_review_round4_batch1.py::test_tamper1_old_database_with_the_current_deletion_state_transplanted_is_repaired`,
`::test_tamper1_deleted_suppression_rows_are_restored_from_the_ledger`). The report counts these as
`resurrected_removed`.

Replay applies each entry with the policy the user chose
(`tests/test_forgetting.py::test_replay_applies_the_policy_the_user_chose`). When the original request
record can be opened, replay also records that caller's real receipt and idempotency row
(`tests/test_review_group1.py::test_receipt_recorded_when_another_process_applies_the_entry`). When it
cannot be opened, or was never written (12.2 step 1), replay applies the entry with no caller
(`forgetting.ForgettingService.apply_tombstone` with `access=None`): everything the target covers is
deleted, and no receipt or idempotency row is recorded. The original caller, if still running, gets a
placeholder receipt with empty counts and the limitation `forgetting._APPLIED_ELSEWHERE`. No test
exercises this path.

Deletions that reconcile applies reach a migration's rollback copies as a live forget's do: on open
(`MemoryEngine.partition_context` calls `ForgettingService.propagate_to_migration_copies(recheck=True)`
whenever the host passes the ownership control) and, since review round 3, after a reconcile that
applied entries or acknowledged a mirror gap later in `MemoryEngine.partition_context` or in
`MemoryEngine.reconcile` (section 11;
`tests/test_review_round3_batch2.py::test_mf6_a_retry_applied_by_reconcile_reaches_the_legacy_vault`,
`::test_mf6_a_reconcile_on_an_open_engine_propagates_without_a_retry`).

Sibling services purge their own tables from the entry's kind and token, with no caller (a scope
purge of history also opens every session payload once, section 6), so restored history,
repository rows and external replicas are handled too:

* `tests/test_history.py::test_ledger_replay_purges_a_restored_backup`;
* `tests/test_repository.py::test_ledger_replay_purges_repository_rows_after_restore`;
* `tests/test_providers.py::test_ledger_replay_after_restore_requeues_external_deletion`.

### 12.4 The host mirror

`storage.ledger.LedgerMirror` is a host-supplied protocol with `read(partition_id)` and
`write(partition_id, generation, mac)`. It must survive file restores; for example, it could be kept in
the OS keychain.

* `storage.ledger.MemoryLedgerMirror` is an in-memory implementation for tests.
* Without a mirror, restoring both files from an older backup brings back data forgotten after that
  backup, undetected. This is the documented lost-ledger limitation (R17.5).
* The Stage-2 Locus adapter does not configure a mirror: its `HostCapabilities` sets only
  `ownership` (handoff patch 0002; not executed in the real app).

---

## 13. Migration control file

`migrations.state.OwnershipControl` keeps one row per (partition, record family) with a state machine
(`migrations.state.TRANSITIONS`):

| From | Allowed next states | Permitted writer |
|---|---|---|
| `legacy_authoritative` | `shadow_prepared` | legacy |
| `shadow_prepared` | `validated`, `legacy_authoritative` | legacy |
| `validated` | `cutover_in_progress`, `shadow_prepared`, `legacy_authoritative` | legacy |
| `cutover_in_progress` | `package_authoritative`, `legacy_authoritative` | none |
| `package_authoritative` | `rollback_in_progress`, `legacy_retired` | package |
| `rollback_in_progress` | `legacy_authoritative`, `package_authoritative` | none |
| `legacy_retired` | (terminal) | package |

* A transition is a compare-and-swap on `generation` under `BEGIN IMMEDIATE`.
* `assert_writer` raises `OwnershipFenced` for a writer the current state does not permit.
* The file uses the same `Database` pragmas, with the default 5,000 ms busy timeout (section 9).
* `OwnershipControl(root)` writes `<root>/control.sqlite3`. The CLI's migration commands and the
  Stage-2 adapter pass the engine root, so one file is shared by every partition under that root
  ([security-and-privacy.md](security-and-privacy.md) 5.1).
* It is plaintext and not MAC-protected, so a local writer could edit the state and the details,
  including the legacy, work-directory and snapshot paths (section 2). That is a migration-safety
  control, not a security boundary.

---

## 14. Legacy Locus vault format (`compat.legacy_vault`)

`compat.legacy_vault.LegacyMemoryVault` and `LegacyContinuityStore` read and write the existing
Locus files without migrating them. This is code extraction, not data migration (R4.3). The format
is documented in [locus-compatibility.md](locus-compatibility.md) sections 4 and 6, and its defects in
section 19 ("Defects and risks found in current host code"), which the `compat.legacy_vault` module
docstring also points to.

| Aspect | Legacy format |
|---|---|
| Location (in Locus) | `APP_DIR/memory/memory.sqlite3`, key file `APP_DIR/memory/master.key` |
| Keys | One 32-byte key used directly. No wraps, no key id, no rotation. The caller (Locus) supplies it. The library never opens `master.key` by itself. The `locus-memory migrate` commands `inventory`, `import`, `verify`, `cutover` and `rollback` read a legacy key file, and only from their explicit, required `--key-file` path (`cli._legacy_key`) |
| Cipher and nonce | AES-256-GCM, a random 12-byte nonce per seal in its own column. Memory payloads (`LegacyMemoryVault._seal`) are JSON with sorted keys, compact separators and non-ASCII characters kept. Continuity payloads (`LegacyContinuityStore`) are compact JSON whose keys are not sorted, with default ASCII escaping |
| Memory AAD | `memory-v1\|<id>\|<status>\|<scope>\|<target_hash>\|<revision>` (`LegacyMemoryVault._aad`) |
| Continuity AAD | `locus-context-v1\|<id>\|<session_id>\|<target>` and `locus-observation-v1\|<id>\|<number>\|<target>\|<status>` |
| Not bound | `pinned`, `stale`, timestamps, `last_used_at`, `use_count`, `superseded_by` |
| Scope targets | unsalted `sha256` of the resolved workspace path or agent id, stored in plaintext `target_hash` |
| Deletion | plain `DELETE`; no tombstones, ledger or mirror, so a restored legacy backup brings deleted rows back |

Deliberate differences from the Locus original are listed in the module docstring. Tests for them are
in `tests/test_compat_legacy.py` (wrong key, approve targeting, non-finite values and string tags,
write guard and fenced reads), plus the two tests from `tests/test_review_group1.py` cited below:

* **Wrong key.** `verify_key` fails closed with `LegacyWrongKey`. A wrong or regenerated key cannot
  read as an empty store or add rows under a second key
  (`tests/test_compat_legacy.py::test_wrong_key_fails_closed_without_changing_records`,
  `tests/test_review_group1.py::test_continuity_store_fails_closed_on_a_wrong_key`).
  * It runs lazily before the first operation.
  * `LegacyMemoryVault.verify_key` tries up to three `memories` rows. `LegacyContinuityStore.verify_key`
    tries up to three rows each of `context_snapshots` and `skill_observations`, then up to three
    `memories` rows of the same file as a canary.
  * It succeeds if any of them decrypts.
  * An empty file accepts any key, because there is nothing to check.
* **Approve.** Approve never re-targets a record. `enforce_target=True` refuses cross-target mutations.
* **Values.** Non-finite numbers are rejected, and a string `tags` value is one tag.
* **Fencing.** A `write_guard` hook fences writes after a cutover, re-checked inside the write
  transaction, and a fenced store is served strictly read-only.
* **Recall.** Semantic recall takes an injected embedder. There is no network I/O.
* **Pragmas.** `secure_delete`, `temp_store=MEMORY` and `trusted_schema=OFF` are set (section 9).

Format compatibility is checked against a fixture vault that the real Locus code produced
(`tests/fixtures/locus_legacy`):

* a fixture row decrypts with the AAD layout above, and flipping a bound column breaks authentication
  (`tests/test_compat_legacy.py::test_aad_and_payload_format`);
* fixture records read identically (`tests/test_compat_legacy.py::test_fixture_records_read_identically`).

`tests/test_compat_legacy.py::test_bidirectional_parity_with_real_locus_code` checks that Locus's own
`MemoryVault` and `ContinuityStore` and the package classes read each other's writes over one file. It
runs only when a Locus checkout is readable (at `LOCUS_SOURCE_DIR`, or the default path in the test
module), and it copies `memory.py` and `continuity.py` to a temporary directory, so the checkout is
never written.

Physical migration into the package format (`migrations.legacy`, `migrations.cutover`) is a separate,
explicit operation:

* it decrypts with the legacy key and re-seals under the partition's DEK;
* `migrations.legacy.snapshot` writes an encrypted copy of the legacy database plus a manifest of row
  ids and SHA-256 row fingerprints. A fingerprint (`migrations.legacy._row_fingerprint`) covers the
  row's `id`, `status`, `scope`, `target_hash`, `revision`, `nonce` and `ciphertext`, not the
  ciphertext alone. A snapshot the Migrator writes also records `owner` (the partition id);
* no plaintext is written
  (`tests/test_migrations.py::test_snapshot_manifest_integrity_and_no_plaintext`,
  `tests/test_migrations.py::test_migration_artifacts_contain_no_plaintext`).

**Snapshot lifetime.** Until a snapshot is removed, the legacy key opens it.

* **Migrator snapshots** (CLI `migrate import`, under `--work-dir/snapshot-<ms>/`) are tracked since
  review rounds 2 and 4. `migrations.cutover.Migrator.prepare_shadow` records the directory and the
  work directory in the ownership details before it writes the snapshot. It removes earlier
  attempts' snapshots, and a failed attempt removes its own at once. Recorded snapshots, and any
  other this partition's Migrator wrote into the recorded work directory (found by the manifest's
  `owner`), are removed (`migrations.cutover._remove_snapshots`):
  * by the next attempt and by a failed attempt;
  * at cutover completion and by every later forget, on every open and after every reconcile that
    applies entries while the package is authoritative (`propagate_forgets_to_legacy`);
  * on abort and on a completed rollback (`_drop_snapshots`).

  If a removal fails while the package is authoritative, the forget receipt carries
  `forgetting._MIGRATION_RESIDUE` with `physical_purge_pending=True` (section 11). Removal deletes
  only the files the Migrator writes, and the directory only when it is then empty. Evidence:
  `tests/test_review_round2_batch1.py::test_cd1_forget_after_cutover_leaves_no_legacy_or_snapshot_copy`,
  `tests/test_review_round4_batch2.py::test_mf3_a_failed_prepare_shadow_removes_its_snapshot`,
  `::test_mf3_a_retried_prepare_shadow_removes_the_earlier_attempts_copy`,
  `::test_mf3_abort_removes_the_recorded_snapshot`,
  `::test_mf3_a_crashed_prepare_shadow_leaves_no_snapshot_after_cutover`,
  `::test_mf3_an_unrecorded_owned_snapshot_is_found_and_reported_until_removed`.
* **A standalone snapshot** written by the CLI `locus-memory migrate snapshot --out`
  (`migrations.legacy.snapshot` called without `owner`) is never tracked or removed. It has no
  expiry: it stays until the operator deletes it.

All of this is tested only on disposable fixtures; no real vault has been migrated.

---

## 15. Canary and tamper tests that back these claims

The canary is a fixed marker string (`CANARY` in `tests/conftest.py`). The helper
`scan_for_plaintext` in `tests/conftest.py` reads every byte of every file under a directory and
reports the files that contain it.

| Claim | Tests |
|---|---|
| Memory content, titles and rejection reasons never reach the database, WAL, ledger, logs or error messages, across remember, propose, correct, approve, reject, explain, status, forget and close. Tags are sealed in the same payload but are not canary-tested: the test's tag is the plain word `canary`, not the marker | `tests/test_storage.py::test_canary_never_reaches_disk_logs_or_errors` |
| Forgotten ciphertext leaves every file | `tests/test_storage.py::test_forget_removes_the_ciphertext_itself` |
| Search writes no plaintext and spills nothing to temp, on the FTS5 and Python paths | `tests/test_retrieval.py::test_search_never_writes_plaintext_to_disk` |
| Search writes nothing at all (database and WAL digests unchanged) | `tests/test_retrieval.py::test_search_does_not_write_or_inflate_confidence` |
| History text and identifiers stay sealed | `tests/test_history.py::test_no_plaintext_on_disk_after_ingest_and_search` |
| Context packets and their persisted receipts hold no content or query text | `tests/test_context.py::test_no_plaintext_content_or_query_on_disk` |
| Repository paths, contents and ids stay sealed | `tests/test_repository.py::test_no_plaintext_paths_or_content_on_disk` |
| Procedure, job and summary plaintext stays sealed | `tests/test_learning.py::test_procedure_plaintext_never_hits_disk`, `tests/test_learning.py::test_jobs_keep_no_plaintext_in_clear_columns`, `tests/test_learning.py::test_provider_summary_path_keeps_plaintext_off_disk` |
| Vectors and provider state are encrypted; provider error text is not stored | `tests/test_providers.py::test_vectors_and_provider_state_are_encrypted`, `tests/test_providers.py::test_provider_exception_text_never_leaks` |
| CLI writes leave no plaintext under the root | `tests/test_cli.py::test_no_plaintext_canary_in_root_after_cli_writes` |
| Migration snapshots and artifacts hold no plaintext | `tests/test_migrations.py::test_snapshot_manifest_integrity_and_no_plaintext`, `tests/test_migrations.py::test_migration_artifacts_contain_no_plaintext` |
| Idempotency rows are keyed and cannot confirm forgotten content | `tests/test_review_group1.py::test_idempotency_request_hash_is_keyed_and_detached_after_forget`, `tests/test_review_group1.py::test_forgotten_project_name_is_not_confirmable_from_idempotency` |
| Rotated-out wraps and retired DEKs leave the files | `tests/test_review_group2.py::test_master_rotation_drop_old_removes_old_wraps_from_the_vault_files`, `tests/test_review_group2.py::test_completed_data_key_rotation_removes_retired_dek_material_from_the_vault_files` |
| Relabelled rows, moved ciphertext, a forged DEK reference, tampered revisions, receipts, key wraps, the partition label and the scope index are detected and never mis-served | `tests/test_storage.py::test_relabelled_metadata_is_never_served`, `tests/test_storage.py::test_ciphertext_moved_between_rows_fails`, `tests/test_storage.py::test_tampered_revision_receipt_and_dek_reference`, `tests/test_storage.py::test_tampered_key_wrap_or_partition_label_refuses_to_open`, `tests/test_storage.py::test_scope_index_tampering_never_leaks_a_record` |
| Legacy deletes are scrubbed from the main file after a checkpoint | `tests/test_review_group1.py::test_legacy_deletes_scrub_the_file` |
| A forget after cutover leaves no legacy or snapshot copy; a busy legacy file is reported and finished later | `tests/test_review_round2_batch1.py::test_cd1_forget_after_cutover_leaves_no_legacy_or_snapshot_copy`, `tests/test_review_round2_batch1.py::test_cd1_a_busy_legacy_store_is_reported_and_finished_later` |
| A forged residue marker or a stripped cutover set never skips the legacy purge | `tests/test_review_round4_batch2.py::test_tamper7_*` |
| A restored old database with an edited counter, without its checkpoint, or with the current deletion state transplanted still replays or is repaired; deleted tombstone and suppression rows come back from the ledger | `tests/test_review_round4_batch1.py::test_tamper1_*` |
| Stripped index rows (`record_scopes`, `record_sources`, `derivations`, `history_session_scopes`) never hide forget victims, and a stripped scope index fails closed | `tests/test_review_round4_batch1.py::test_tamper2_*` |
| Storage failures raise typed errors, not `Contention` | `tests/test_review_round2_batch3.py::test_cd5_*` |
| After a completed forget, the sealed forget request is in no partition file, the ledger WAL included, also while another engine holds the ledger open | `tests/test_review_round2_batch3.py::test_cd4_a_completed_forget_leaves_no_sealed_request_on_disk`, `tests/test_review_round2_batch3.py::test_cd4_the_ledger_is_scrubbed_while_another_engine_keeps_it_open` |

**Review rounds.** Four adversarial review rounds found and fixed 63, 29, 21 and 20 reproduced
defects, with regression tests (`tests/test_review_group*.py` for round 1, then
`tests/test_review_round2_batch*.py`, `tests/test_review_round3_batch*.py` and
`tests/test_review_round4_batch*.py`). Round 1 came before this document was first written; rounds 2
to 4 changed the behaviour it describes, and the sections above cite their tests. On this checkout
the full package suite (1495 tests) passes on CPython 3.14.6 and 3.10.22
(`python -m pytest -o addopts="" -q`).

The offline benchmark's hard criterion C7 ("nothing plaintext on disk: 0 answer phrases in store
files") was met in the final run, `evals/results/2026-10-04-r5-seed20261004-final` (`report.md`; 5
repetitions on a synthetic corpus): 0 answer phrases in store files for arms B, C, D and E, and all
hard invariants held. The earlier r5 runs (`2026-10-04-r5-seed20261004` and
`2026-10-04-r5-seed20261004-f3`) report the same C7 values ([evaluation.md](evaluation.md)).

What these tests do not cover:

* swap, hibernation or crash-dump files;
* filesystem snapshots;
* host-made backups;
* the storage medium below the filesystem.

These are listed as non-guarantees in [security-and-privacy.md](security-and-privacy.md) section 8.

To re-run the crypto, storage, forgetting, legacy-format and review-round tests this document cites,
from the repository root (`.venv310/bin/python` for CPython 3.10):

```bash
.venv/bin/python -m pytest -o addopts="" -q tests/test_crypto.py tests/test_storage.py \
    tests/test_forgetting.py tests/test_compat_legacy.py tests/test_db_close.py \
    tests/test_review_group1.py tests/test_review_group2.py \
    tests/test_review_round2_batch1.py tests/test_review_round2_batch3.py \
    tests/test_review_round3_batch1.py tests/test_review_round3_batch2.py \
    tests/test_review_round4_batch1.py tests/test_review_round4_batch2.py \
    tests/test_review_round4_batch3.py
```

On this checkout it ran 473 tests, all passing (CPython 3.14.6). The other test files cited above
(retrieval, history, context, repository, learning, providers, CLI, migrations, integration) run
with the full suite (`python -m pytest -o addopts="" -q`).

---

## 16. Not done or open

* **Key custody in Locus** (Keychain versus file) is an open host decision. The Stage-2 handoff
  derives the engine key from Locus's file key, which lives under the same `APP_DIR` as the engine
  root ([security-and-privacy.md](security-and-privacy.md) 8.3). Not executed in the real app.
* **The ledger mirror** is a contract only. No host implementation exists yet.
* **HMAC-key rotation** is deferred.
* **A page-encrypted SQLite backend** (an alternative allowed by R8.4) was not built. The package uses
  row-level sealing plus in-memory projections.
* **No real vault has been migrated.** The cutover, rollback and snapshot tooling is tested only on
  disposable fixtures.
* **Purges outside forgetting are not checkpointed.** The exclusion purge
  (`repository.service.RepositoryService._purge_excluded`) and episode revision compaction
  (`learning.episodes.EpisodeService._compact_revisions`) can leave the deleted ciphertext, under
  live keys, in `memory.sqlite3` and `memory.sqlite3-wal` until a later checkpoint (section 11).
* **Standalone snapshots are never tracked or removed.** A copy written by the CLI
  `migrate snapshot --out` stays until the operator deletes it, and the legacy key opens it
  (section 14).
* **The control file's details are plaintext and unauthenticated**, including the legacy database,
  work-directory and snapshot paths (section 2).
* **The applied-elsewhere placeholder receipt** (`forgetting._APPLIED_ELSEWHERE`, 12.3) is still not
  exercised by any test: no test references it.
