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
    deletion-ledger.sqlite3 (+ -wal, -shm)  append-only deletion ledger, mode 0600
  control.sqlite3      (+ -wal, -shm)    migration ownership state; only when OwnershipControl is used
  keys/                                  CLI only: FileKeyProvider default (--key-dir overrides)
    <key_id>.key                         32 raw bytes, mode 0600, created with O_EXCL
    current                              id of the current master key (atomic replace)
```

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
* **Cleanup after a failed first open.** If the first open of a new partition fails (for example
  because the key provider is locked), `storage.partition.Partition.__init__` removes the database
  file and its `-wal`, `-shm` and `-journal` files when the database did not exist before the open.
  `tests/test_storage.py::test_locked_provider_on_a_fresh_root_creates_no_keys` shows that no key wraps
  are created on a locked fresh root. It allows the file to exist, so no test asserts the removal.
* **Plaintext files.** The package itself writes no other files. Plaintext leaves the vault only when
  a caller asks for it:
  * `MemoryEngine.export` returns a document and writes nothing
    (`tests/test_storage.py::test_export_writes_nothing_to_disk`);
  * `locus-memory export --yes` writes a 0600 file outside the vault;
  * `MemoryEngine.export_procedure` writes a proposal directory;
  * migration snapshots are written to a directory the operator chooses.

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
| Keys and state | `meta`, `key_wraps` | `meta`: schema version, partition id, created time, `generation`, `deletion_generation`, `current_dek_id`, `hmac_dek_id`, `idempotency_format`, `dek_rotation` (JSON of DEK ids, counts and start time), `pending_purge_checkpoint`, `history_generation` (an archive append counter bumped by `history.archive.HistoryArchive._ingest_one`; written but never read, it reveals how many archive appends have happened, including messages later forgotten). `ledger_head` is initialized but not used. `key_wraps`: `dek_id`, host `master_key_id`, purpose (`data`/`hmac`), `created_at` | | `key_wraps.wrapped`: a DEK or the HMAC key, AES-GCM-wrapped under a master key (wrap AAD, section 4.3) |
| Canonical records (all kinds, including episodes and procedures) | `records`, `record_scopes`, `record_sources`, `record_revisions`, `derivations` | `records`: `id`, `kind`, `lifecycle`, `revision`, `pinned`, `created_at`, `updated_at`, `expires_at`, `valid_from`, `valid_until`, `write_generation`. `record_scopes.dim`; `record_sources.kind`. `record_revisions`: record id, revision, lifecycle, `change` label, actor, time, `purged`. `derivations`: derived id and kinds | `records.scope_token`, `subject_token`, `content_token`; `record_scopes.value_token`; `record_sources.source_token`; `derivations.input_token` | `records`: the whole `MemoryRecord` (title, content, tags, scope values, basis, confidence, subject and predicate, sources, validity, retention, links, reason, `extra`) (AAD: `kind`, `lifecycle`, `revision`, `scope` token). `record_revisions`: the record as of that revision (AAD: `lifecycle`, `change`); a purged revision has NULL sealed columns |
| Deletion state | `tombstones`, `tombstone_aliases`, `suppressions`, `forget_outcomes`, `migration_forgets` | target kind, generation, time, policy flags (JSON); receipt id per generation; for `migration_forgets` and memory tombstones, the opaque record id | `target_token` (for `memory` targets it is the record id itself; for `profile` it is the partition id); alias `source_token`; suppression `fingerprint_token` and `source_token` | none |
| Idempotency and receipts | `idempotency`, `idempotency_records`, `receipts`, `context_receipt_items` | operation name, receipt id, time; record ids that a receipt created or a context packet referenced | `idempotency.key_token` (operation, caller binding and key); `request_hash` (keyed since format 2; unkeyed format-1 rows are dropped on open) | `receipts`: the full `Receipt`, including counts, details and limitations (AAD: `operation`) |
| Session history | `history_sessions`, `history_session_scopes`, `history_messages`, `history_gaps`, `history_skipped`, `history_suppressed`, `history_corrections`, `cursors` | first and last times, message count; message `id` (keyed-derived), `seq`, `role`, `occurred_at`, `ingested_at`, `redacted` flag; gap ranges and reasons; skip reasons; correction times | `session_token`, `scope_token`, scope `value_token`, `event_token`, message `source_token`, `content_token`, skip `fingerprint_token`, suppressed tokens, cursor `source` and `stream_token` | `history_sessions`: session ref and scope (AAD: `scope` token). `history_messages`: text, session ref, event id, tool name, attachments, host refs, redaction categories, producer (AAD: `session`, `seq`, `role`, `event`, `at`) |
| Repository memory | `repositories`, `repo_scopes`, `repo_snapshots`, `repo_files`, `repo_observations` | times, snapshot `state` and `index_generation`, observation `current` flag; row ids derived from keyed tokens | `scope_token`, scope `value_token`, `path_token`, `blob_token` | `repositories`: repository id, root path, scope, git common dir, initial commit, object format, extra exclusion patterns (AAD: `scope`). `repo_snapshots`: snapshot and repository ids, state, head, branch, dirty flag, worktree path, counts, coverage (AAD: `repo`, `state`). `repo_files`: path, blob, origin, kind, mode, size, language, support, status, observation id (AAD: `blob` token) |
| Episodes and procedures (indexes over `records`) | `episodes`, `episode_attempts`, `episode_sources`, `procedures`, `procedure_evidence` | **host-supplied** `episode_id`, `outcome`, times; random `procedure_id`, `state`, `version` | `task_token`, `attempt_token`, `source_token`, `name_token` | the episode or procedure payload lives in its `records` row |
| Providers | `embeddings`, `provider_outbox`, `provider_sync`, `usage_log` | provider name, operation, state, attempts, error **code**, units, cost, `cost_known`, outcome, times; record id and revision | `embeddings.model_key` (from provider, model, version, dimensions, preprocessing); `external_ref` (per provider); `cause_token` | `embeddings`: record id, model key, revision, dimensions, text token, vector (AAD: `model_key`, `revision`, `index_generation`) |
| Maintenance | `jobs`, `job_state`, `events` | job kind, state, observed generations, times, content-free `progress` JSON; events: `stage`, `outcome`, `reason_code`, time (kept 90 days or 20,000 rows, `storage.partition.Partition.event`) | | `job_state`: grants, cursor and suggestions (AAD: `kind`) |

Ledger file (`deletion-ledger.sqlite3`, `storage.ledger.DeletionLedger` and
`storage.partition.Partition._REQUESTS_DDL`):

| Table | Plaintext | Keyed | Sealed |
|---|---|---|---|
| `ledger` | `generation`, `target_kind`, `created_at`, `policy` flags | `target_token` (same rule as `tombstones`), `mac` | none |
| `forget_requests` | marker id, generation, target kind, policy, time | `target_token`, `key_token` | the in-flight forget request: caller access, target, policy, keyed idempotency tokens (AAD: `kind`, `token`, `key`) |

Control file (`control.sqlite3`, `migrations.state.OwnershipControl`): `ownership` and
`ownership_log` hold partition ids, record families, states, generations, times, transition reasons
and details JSON. They are **plaintext and not authenticated**. They contain no memory content.

What this means for an offline reader (adversary A4) is listed in
[security-and-privacy.md](security-and-privacy.md) section 5.3:

* sizes, since ciphertext length is plaintext length plus 16 bytes;
* times, lifecycle and kind distributions;
* host-supplied ids;
* equality of keyed tokens.

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
`kind`, `lifecycle`, `revision` and `scope_token` with the authenticated payload. A relabelled row (for
example a candidate edited to `approved`) raises `IntegrityError` and is never served
(`tests/test_storage.py::test_relabelled_metadata_is_never_served`).

**Not bound** are the other plaintext columns:

* `pinned`, the timestamps and the validity bounds;
* `write_generation`;
* the subject and content tokens;
* index tables such as `record_sources` and `derivations`.

Editing them can change ordering, SQL pre-filtering, conflict and duplicate detection, and counts. It
cannot change what an authenticated record says
([security-and-privacy.md](security-and-privacy.md) 8.9).

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
  * `idempotency`, `idempotency-request`, `ledger`.
* **What they allow.** Tokens let SQL authorize, join, deduplicate and forget without decrypting
  anything. Forgetting and ledger replay can work from the token alone, without reading the content
  they remove.
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
are dropped once applied, and unbound ones after 24 hours. A request that no longer opens degrades to
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
| `journal_mode` | `WAL` (set with bounded retries; `Database._ensure_wal`) | concurrent readers during a write |
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
history anyway. It matters in two cases, and both are handled:

1. **Forgetting.** After the purge commits, `storage.partition.Partition.flush_purged` runs
   `wal_checkpoint(TRUNCATE)` (`storage.db.Database.checkpoint`, which returns `True` only when every
   frame was copied and the log reset).
   * If a reader blocks it, the partition sets `pending_purge_checkpoint` in memory and durably in
     `meta`. The forget receipt says `physical_purge_pending=True`.
   * The checkpoint is retried without waiting on later calls (`MemoryEngine.partition_context`), on
     open and on close.
   * Evidence: `tests/test_storage.py::test_forget_removes_the_ciphertext_itself` (the forgotten
     record's ciphertext bytes are absent from every file after the forget),
     `tests/test_review_group1.py::test_forget_with_a_concurrent_reader_finishes_the_physical_purge_later`,
     `tests/test_review_group1.py::test_forget_without_readers_reports_no_pending_purge`.
2. **Key retirement.** Master and DEK rotation checkpoint after commit (section 8.4).

Together, `secure_delete` and the checkpoint remove the bytes from the files SQLite manages. They do
not erase the storage medium: filesystem snapshots, copy-on-write and SSD remanence are out of scope.

The legacy vault is different. `compat.legacy_vault.LegacyMemoryVault.delete` does not checkpoint.
Deleted legacy ciphertext, which the live legacy key can decrypt, may stay in the legacy `-wal`
until SQLite's next checkpoint resets the log. The migrator's rollback checkpoints the legacy file
(`migrations.cutover.Migrator._checkpoint_legacy`).
`tests/test_review_group1.py::test_legacy_deletes_scrub_the_file` checks that `secure_delete` scrubs
the main file after a checkpoint.

---

## 12. Deletion ledger, mirror and reconcile protocol

### 12.1 The ledger

`storage.ledger.DeletionLedger` is a separate SQLite file. Each entry is
`(generation, target_kind, target_token, created_at, mac, policy)`.

* **MAC chain.** The MAC is the keyed token `ledger` over
  `prev_mac|generation|kind|token|created_at[|policy]`. Each entry chains to the previous one and
  covers the forget policy.
* **What is detected.** `DeletionLedger.verify` runs on every open and detects edits, reordering and
  holes (`tests/test_forgetting.py::test_ledger_tampering_is_detected_on_open`). A truncated tail is
  rebuilt from the store's tombstones on the next open (12.3). Truncation combined with an older
  database is detectable only with a host mirror (12.4).
* **Content.** Entries carry tokens and policy flags, never content. A `memory` entry's token is the
  opaque record id.

### 12.2 Write-ahead order

`forgetting.ForgettingService.forget`:

1. Records the sealed request (`Partition.record_forget_request`). This is best effort: a failure is
   swallowed (`except Exception: marker = None`) and the forget continues without a request record.
2. Appends the entry to the ledger (durable, `synchronous=FULL`).
3. In one main-database transaction:
   * applies earlier unapplied entries and then this one (`apply_tombstone`);
   * records the tombstone;
   * advances `meta.deletion_generation` (never backwards,
     `tests/test_forgetting.py::test_deletion_generation_never_moves_backwards`).
4. Drops the applied requests, checkpoints, and writes the new head `(generation, mac)` to the mirror.

The invariant (`storage.partition` module docstring): every ledger entry at or below the main
database's `deletion_generation` has been applied to it.

### 12.3 Reconcile

`storage.partition.Partition.reconcile` runs on every open and before serving whenever
`Partition.needs_reconcile()` says the ledger head is ahead of the store (two indexed lookups). It can
also be invoked explicitly with `MemoryEngine.reconcile` (ADMIN).

| State found | Action |
|---|---|
| ledger generation > store `deletion_generation` (crash after append, failed apply, another process's unfinished forget, an older database restored next to a newer ledger) | apply the missing entries with their recorded policy inside one write transaction, then bump the generation (`tests/test_forgetting.py::test_crash_then_reopen_applies_the_tombstone_before_serving`, `tests/test_forgetting.py::test_a_crashed_entry_is_not_lost_when_a_later_forget_succeeds`, `tests/test_forgetting.py::test_restoring_an_old_database_cannot_resurrect_forgotten_memories`) |
| store generation > ledger generation (the ledger was rolled back or replaced) | re-append the store's newer tombstones to the ledger (`DeletionLedger.adopt`) (`tests/test_forgetting.py::test_a_rolled_back_ledger_is_rebuilt_from_the_store`) |
| host mirror generation > ledger head (database **and** ledger restored from an older backup) | raise `ReconciliationRequired` with both generations. Serve nothing until the newer ledger is restored, or until an operator calls `MemoryEngine.reconcile(access, acknowledge_mirror_gap=True)`, which appends a durable `gap_acknowledged` marker so the decision is recorded and not asked again (`tests/test_forgetting.py::test_restoring_database_and_ledger_against_a_newer_mirror`) |
| main database missing or empty next to a ledger with entries | `IntegrityError`; no keys are created (section 1) |

Replay applies each entry with the policy the user chose
(`tests/test_forgetting.py::test_replay_applies_the_policy_the_user_chose`). When the original request
record can be opened, replay also records that caller's real receipt and idempotency row
(`tests/test_review_group1.py::test_receipt_recorded_when_another_process_applies_the_entry`). When it
cannot be opened, or was never written (12.2 step 1), replay applies the entry with no caller
(`forgetting.ForgettingService.apply_tombstone` with `access=None`): everything the target covers is
deleted, and no receipt or idempotency row is recorded. The original caller, if still running, gets a
placeholder receipt with empty counts and the limitation `forgetting._APPLIED_ELSEWHERE`. No test
exercises this path.
Sibling services purge their own tables from the token alone, so restored history, repository rows
and external replicas are handled too:

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
* It is plaintext and not MAC-protected, so a local writer could edit the state. That is a
  migration-safety control, not a security boundary.

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
  * It runs lazily before the first operation and tries up to three rows.
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
  ids and SHA-256 fingerprints over each row's ciphertext;
* no plaintext is written
  (`tests/test_migrations.py::test_snapshot_manifest_integrity_and_no_plaintext`,
  `tests/test_migrations.py::test_migration_artifacts_contain_no_plaintext`).

The snapshot directory has no automatic expiry, and the legacy key opens it. It is tested only on
disposable fixtures; no real vault has been migrated.

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

The offline benchmark's hard criterion C7 ("nothing plaintext on disk: 0 answer phrases in store
files") was met in every run on its synthetic corpus ([evaluation.md](evaluation.md)).

What these tests do not cover:

* swap, hibernation or crash-dump files;
* filesystem snapshots;
* host-made backups;
* the storage medium below the filesystem.

These are listed as non-guarantees in [security-and-privacy.md](security-and-privacy.md) section 8.

To re-run, from the repository root (`.venv310/bin/python` for CPython 3.10):

```bash
.venv/bin/python -m pytest tests/test_crypto.py tests/test_storage.py tests/test_forgetting.py \
    tests/test_review_group1.py tests/test_review_group2.py tests/test_compat_legacy.py
```

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
