"""Partition database schema and forward-only migrations.

Plaintext metadata kept outside ciphertext (documented in docs/storage-and-encryption.md):
ids, kinds, lifecycle states, revisions, timestamps, pinned flags, DEK ids,
keyed HMAC tokens (scope values, sources, subjects, fingerprints), counts and
content-free operational events. Everything a user wrote or a source said -
titles, content, tags, scope values, provenance, messages, paths, snippets,
embeddings - is inside AES-256-GCM ciphertext.
"""
from __future__ import annotations

import sqlite3
import time

from ..errors import MigrationError

SCHEMA_VERSION = 1

_V1 = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS key_wraps(
    dek_id TEXT NOT NULL, master_key_id TEXT NOT NULL, purpose TEXT NOT NULL,
    nonce BLOB NOT NULL, wrapped BLOB NOT NULL, created_at REAL NOT NULL,
    PRIMARY KEY(dek_id, master_key_id)
);

-- Canonical memory records (all kinds, including episodes and procedures).
CREATE TABLE IF NOT EXISTS records(
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    scope_token TEXT NOT NULL,
    revision INTEGER NOT NULL,
    pinned INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    expires_at REAL,
    valid_from REAL,
    valid_until REAL,
    subject_token TEXT,
    content_token TEXT,
    write_generation INTEGER NOT NULL,
    dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS records_lookup ON records(lifecycle, kind, updated_at);
CREATE INDEX IF NOT EXISTS records_subject ON records(subject_token);
CREATE INDEX IF NOT EXISTS records_content ON records(content_token);

CREATE TABLE IF NOT EXISTS record_scopes(
    record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    dim TEXT NOT NULL, value_token TEXT NOT NULL,
    PRIMARY KEY(record_id, dim)
);
CREATE INDEX IF NOT EXISTS record_scopes_value ON record_scopes(dim, value_token);

CREATE TABLE IF NOT EXISTS record_sources(
    record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    source_token TEXT NOT NULL, kind TEXT NOT NULL,
    PRIMARY KEY(record_id, source_token)
);
CREATE INDEX IF NOT EXISTS record_sources_token ON record_sources(source_token);

-- Revision history (encrypted payload snapshots). Purged by forgetting.
CREATE TABLE IF NOT EXISTS record_revisions(
    record_id TEXT NOT NULL, revision INTEGER NOT NULL, lifecycle TEXT NOT NULL,
    change TEXT NOT NULL, actor TEXT NOT NULL, created_at REAL NOT NULL,
    purged INTEGER NOT NULL DEFAULT 0,
    dek_id TEXT, nonce BLOB, ciphertext BLOB,
    PRIMARY KEY(record_id, revision)
);

-- Derivation graph: derived artefact -> input (memory id, source token, message id...).
CREATE TABLE IF NOT EXISTS derivations(
    derived_id TEXT NOT NULL, derived_kind TEXT NOT NULL,
    input_token TEXT NOT NULL, input_kind TEXT NOT NULL,
    PRIMARY KEY(derived_id, input_token)
);
CREATE INDEX IF NOT EXISTS derivations_input ON derivations(input_token);

-- Authoritative deletion state (mirrored in the separate ledger file).
CREATE TABLE IF NOT EXISTS tombstones(
    target_kind TEXT NOT NULL, target_token TEXT NOT NULL,
    generation INTEGER NOT NULL, created_at REAL NOT NULL,
    policy TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(target_kind, target_token)
);
-- Receipt of the forget that applied each deletion generation (ids only), so a forget whose
-- entry was applied by someone else (a concurrent reconcile) still returns its real receipt.
CREATE TABLE IF NOT EXISTS forget_outcomes(
    generation INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL, created_at REAL NOT NULL
);
-- Source identities that died with a forgotten record (e.g. ``episode:<id>`` and its task
-- attempts when the episode record is forgotten): keyed tokens only. Evidence citing them is
-- refused like evidence of a forgotten source. Kept on a profile wipe, like tombstones.
CREATE TABLE IF NOT EXISTS tombstone_aliases(
    source_token TEXT PRIMARY KEY, generation INTEGER NOT NULL, created_at REAL NOT NULL
);
-- Memory forgets issued by the legacy importer to propagate a legacy-side deletion (record id and
-- the tombstone generation it wrote): a legacy row re-created later under the same id is new legacy
-- data, not forgotten data - unlike a user's forget, which no re-import may undo.
CREATE TABLE IF NOT EXISTS migration_forgets(
    record_id TEXT PRIMARY KEY, generation INTEGER, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS suppressions(
    fingerprint_token TEXT NOT NULL, source_token TEXT NOT NULL,
    generation INTEGER NOT NULL, created_at REAL NOT NULL,
    PRIMARY KEY(fingerprint_token, source_token)
);
CREATE INDEX IF NOT EXISTS suppressions_source ON suppressions(source_token);

CREATE TABLE IF NOT EXISTS idempotency(
    key_token TEXT PRIMARY KEY, operation TEXT NOT NULL, request_hash TEXT NOT NULL,
    receipt_id TEXT NOT NULL, created_at REAL NOT NULL
);
-- Records an idempotency row's receipt created (ids only): forgetting a record detaches the
-- row (it then replays as "no longer exists") so no row maps to forgotten data.
CREATE TABLE IF NOT EXISTS idempotency_records(
    key_token TEXT NOT NULL, record_id TEXT NOT NULL,
    PRIMARY KEY(key_token, record_id)
);
CREATE INDEX IF NOT EXISTS idempotency_records_record ON idempotency_records(record_id);

CREATE TABLE IF NOT EXISTS receipts(
    id TEXT PRIMARY KEY, operation TEXT NOT NULL, created_at REAL NOT NULL,
    dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS receipts_time ON receipts(created_at);
-- Record ids a persisted context receipt references (ids only, scrubbed when a record is forgotten).
CREATE TABLE IF NOT EXISTS context_receipt_items(
    receipt_id TEXT NOT NULL, record_id TEXT NOT NULL,
    PRIMARY KEY(receipt_id, record_id)
);
CREATE INDEX IF NOT EXISTS context_receipt_items_record ON context_receipt_items(record_id);

-- Session archive.
CREATE TABLE IF NOT EXISTS history_sessions(
    session_token TEXT PRIMARY KEY, scope_token TEXT NOT NULL,
    first_at REAL, last_at REAL, message_count INTEGER NOT NULL DEFAULT 0,
    dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS history_session_scopes(
    session_token TEXT NOT NULL REFERENCES history_sessions(session_token) ON DELETE CASCADE,
    dim TEXT NOT NULL, value_token TEXT NOT NULL,
    PRIMARY KEY(session_token, dim)
);
CREATE TABLE IF NOT EXISTS history_messages(
    id TEXT PRIMARY KEY,
    session_token TEXT NOT NULL REFERENCES history_sessions(session_token) ON DELETE CASCADE,
    event_token TEXT NOT NULL, source_token TEXT NOT NULL,
    seq INTEGER NOT NULL, role TEXT NOT NULL,
    occurred_at REAL NOT NULL, ingested_at REAL NOT NULL,
    content_token TEXT NOT NULL, redacted INTEGER NOT NULL DEFAULT 0,
    dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
    UNIQUE(session_token, seq), UNIQUE(event_token)
);
CREATE INDEX IF NOT EXISTS history_messages_order ON history_messages(session_token, seq);
CREATE INDEX IF NOT EXISTS history_messages_time ON history_messages(occurred_at);
CREATE INDEX IF NOT EXISTS history_messages_source ON history_messages(source_token);
CREATE TABLE IF NOT EXISTS history_gaps(
    session_token TEXT NOT NULL, from_seq INTEGER NOT NULL, to_seq INTEGER NOT NULL,
    reason TEXT NOT NULL, created_at REAL NOT NULL,
    PRIMARY KEY(session_token, from_seq)
);
CREATE TABLE IF NOT EXISTS cursors(
    source TEXT NOT NULL, stream_token TEXT NOT NULL, position INTEGER NOT NULL,
    updated_at REAL NOT NULL, PRIMARY KEY(source, stream_token)
);
CREATE INDEX IF NOT EXISTS history_session_scopes_value ON history_session_scopes(dim, value_token);
-- History events accepted but deliberately not archived as evidence (injected memory
-- blocks, generated summaries): tokens only, for idempotency, cursors and honest gaps.
CREATE TABLE IF NOT EXISTS history_skipped(
    event_token TEXT PRIMARY KEY,
    session_token TEXT NOT NULL REFERENCES history_sessions(session_token) ON DELETE CASCADE,
    seq INTEGER NOT NULL, reason TEXT NOT NULL, fingerprint_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(session_token, seq)
);
-- Sessions / events purged by forgetting: a host replay does not re-archive them.
CREATE TABLE IF NOT EXISTS history_suppressed(
    kind TEXT NOT NULL, token TEXT NOT NULL, created_at REAL NOT NULL,
    PRIMARY KEY(kind, token)
);
-- Archived evidence superseded by a content correction (keyed tokens and the opaque record id
-- only; no message ids, session refs or content). One row per (cited source, corrected memory):
-- source_token is the keyed source token the memory cited (for a MESSAGE it equals
-- history_messages.source_token); session_token is set for a SESSION source (it equals
-- history_messages.session_token). History search annotates matching hits
-- 'superseded_by_correction'. Rows go with the memory (ON DELETE CASCADE) and are purged by
-- forgetting of the source, session, scope or profile.
CREATE TABLE IF NOT EXISTS history_corrections(
    source_token TEXT NOT NULL,
    record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    session_token TEXT,
    corrected_at REAL NOT NULL,
    PRIMARY KEY(source_token, record_id)
);
CREATE INDEX IF NOT EXISTS history_corrections_session ON history_corrections(session_token);
CREATE INDEX IF NOT EXISTS history_corrections_record ON history_corrections(record_id);

-- Repository memory.
CREATE TABLE IF NOT EXISTS repositories(
    id TEXT PRIMARY KEY, scope_token TEXT NOT NULL, created_at REAL NOT NULL,
    updated_at REAL NOT NULL, current_snapshot TEXT,
    dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS repo_snapshots(
    id TEXT PRIMARY KEY, repo_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    created_at REAL NOT NULL, state TEXT NOT NULL, index_generation INTEGER NOT NULL,
    dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS repo_files(
    snapshot_id TEXT NOT NULL REFERENCES repo_snapshots(id) ON DELETE CASCADE,
    path_token TEXT NOT NULL, blob_token TEXT NOT NULL,
    dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
    PRIMARY KEY(snapshot_id, path_token)
);
CREATE INDEX IF NOT EXISTS repo_files_blob ON repo_files(blob_token);
-- Scope index of a registration (authorization in SQL and scope forgetting by token).
CREATE TABLE IF NOT EXISTS repo_scopes(
    repo_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    dim TEXT NOT NULL, value_token TEXT NOT NULL,
    PRIMARY KEY(repo_id, dim)
);
CREATE INDEX IF NOT EXISTS repo_scopes_value ON repo_scopes(dim, value_token);
-- Observation lineage index: keyed path/blob tokens -> observation record (current=0: historical).
CREATE TABLE IF NOT EXISTS repo_observations(
    record_id TEXT PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path_token TEXT NOT NULL, blob_token TEXT NOT NULL, current INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS repo_observations_path ON repo_observations(repo_id, path_token, current);
CREATE INDEX IF NOT EXISTS repo_observations_blob ON repo_observations(blob_token);

-- Episodes / procedures: indexes over records of kind episode / procedure.
CREATE TABLE IF NOT EXISTS episodes(
    episode_id TEXT PRIMARY KEY, record_id TEXT NOT NULL, task_token TEXT NOT NULL,
    outcome TEXT NOT NULL, updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS episodes_task ON episodes(task_token);
CREATE TABLE IF NOT EXISTS episode_attempts(
    episode_id TEXT NOT NULL, attempt_token TEXT NOT NULL, recorded_at REAL NOT NULL,
    PRIMARY KEY(episode_id, attempt_token)
);
CREATE TABLE IF NOT EXISTS procedures(
    procedure_id TEXT PRIMARY KEY, record_id TEXT NOT NULL, state TEXT NOT NULL,
    version INTEGER NOT NULL, name_token TEXT NOT NULL, updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS episodes_record ON episodes(record_id);
CREATE INDEX IF NOT EXISTS episode_attempts_token ON episode_attempts(attempt_token);
CREATE INDEX IF NOT EXISTS procedures_record ON procedures(record_id);
-- Keyed source tokens an episode payload cites (attempts, receipts, itself): token-only purge.
CREATE TABLE IF NOT EXISTS episode_sources(
    episode_id TEXT NOT NULL, source_token TEXT NOT NULL,
    PRIMARY KEY(episode_id, source_token)
);
CREATE INDEX IF NOT EXISTS episode_sources_token ON episode_sources(source_token);
-- Evidence episodes each procedure depends on (evidence revocation after forgetting).
CREATE TABLE IF NOT EXISTS procedure_evidence(
    procedure_id TEXT NOT NULL, episode_id TEXT NOT NULL,
    PRIMARY KEY(procedure_id, episode_id)
);
CREATE INDEX IF NOT EXISTS procedure_evidence_episode ON procedure_evidence(episode_id);

-- Providers.
CREATE TABLE IF NOT EXISTS embeddings(
    record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    model_key TEXT NOT NULL, revision INTEGER NOT NULL, index_generation INTEGER NOT NULL,
    dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
    PRIMARY KEY(record_id, model_key)
);
CREATE TABLE IF NOT EXISTS provider_outbox(
    id TEXT PRIMARY KEY, provider TEXT NOT NULL, operation TEXT NOT NULL,
    target_token TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL, updated_at REAL NOT NULL, last_error TEXT
);
CREATE TABLE IF NOT EXISTS usage_log(
    id TEXT PRIMARY KEY, provider TEXT NOT NULL, operation TEXT NOT NULL,
    created_at REAL NOT NULL, units INTEGER, cost_micros INTEGER, cost_known INTEGER NOT NULL,
    outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS embeddings_model ON embeddings(model_key);
CREATE INDEX IF NOT EXISTS provider_outbox_target ON provider_outbox(provider, target_token, state);
CREATE INDEX IF NOT EXISTS usage_log_time ON usage_log(created_at);
-- External memory services: which opaque external refs were sent to which provider
-- (no content). Kept until the provider confirms deletion, so forgetting propagates.
CREATE TABLE IF NOT EXISTS provider_sync(
    provider TEXT NOT NULL, external_ref TEXT NOT NULL, record_id TEXT NOT NULL,
    revision INTEGER NOT NULL, state TEXT NOT NULL, cause_token TEXT,
    created_at REAL NOT NULL, updated_at REAL NOT NULL,
    PRIMARY KEY(provider, external_ref)
);
CREATE INDEX IF NOT EXISTS provider_sync_record ON provider_sync(record_id);
CREATE INDEX IF NOT EXISTS provider_sync_cause ON provider_sync(cause_token);

-- Bounded maintenance jobs with durable progress.
CREATE TABLE IF NOT EXISTS jobs(
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, state TEXT NOT NULL,
    observed_generation INTEGER NOT NULL, observed_deletion_generation INTEGER NOT NULL,
    created_at REAL NOT NULL, updated_at REAL NOT NULL, progress TEXT NOT NULL DEFAULT '{}'
);
-- Sealed job state (grants, cursor, suggestions) for jobs whose progress is not content-free.
CREATE TABLE IF NOT EXISTS job_state(
    job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL
);

-- Content-free operational events (stage/outcome/reason codes only).
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT, stage TEXT NOT NULL, outcome TEXT NOT NULL,
    reason_code TEXT NOT NULL DEFAULT '', occurred_at REAL NOT NULL
);
"""

MIGRATIONS: dict[int, str] = {1: _V1}

META_DEFAULTS = {
    "generation": "0",
    "deletion_generation": "0",
    "ledger_head": "",
}

# Idempotency rows written before request hashes were keyed (format 1) held an unkeyed
# sha256 of the whole request - an offline content oracle. They only serve a retry window
# and cannot be re-keyed (the request is gone), so they are dropped once on open.
IDEMPOTENCY_FORMAT = "2"


def statements(sql: str) -> list[str]:
    """Split DDL into complete statements (semicolons inside comments/literals are safe)."""
    out: list[str] = []
    buffer = ""
    for line in sql.splitlines(keepends=True):
        stripped = line.strip()
        if not buffer and (not stripped or stripped.startswith("--")):
            continue
        buffer += line
        if sqlite3.complete_statement(buffer):
            out.append(buffer.strip())
            buffer = ""
    if buffer.strip() and not all(ln.strip().startswith("--") or not ln.strip() for ln in buffer.splitlines()):
        raise MigrationError("schema DDL ends with an incomplete statement")
    return out


def current_version(conn: sqlite3.Connection) -> int:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
    ).fetchone()
    if not exists:
        return 0
    row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    return int(row[0]) if row else 0


def migrate(conn: sqlite3.Connection, *, partition_id: str) -> tuple[int, int]:
    """Apply forward migrations inside the caller's write transaction."""
    before = current_version(conn)
    if before > SCHEMA_VERSION:
        raise MigrationError(
            f"store schema {before} is newer than this package supports ({SCHEMA_VERSION})"
        )
    if before:
        row = conn.execute("SELECT value FROM meta WHERE key='partition_id'").fetchone()
        if not row or row[0] != partition_id:
            raise MigrationError("store belongs to a different partition")
    for version in range(before + 1, SCHEMA_VERSION + 1):
        for statement in statements(MIGRATIONS[version]):
            conn.execute(statement)
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)", (str(version),))
    if before == SCHEMA_VERSION:
        # The current version's DDL is idempotent (CREATE ... IF NOT EXISTS only), so re-applying it
        # brings stores created by earlier builds of the same schema version up to date.
        for statement in statements(MIGRATIONS[SCHEMA_VERSION]):
            conn.execute(statement)
    if get_meta(conn, "idempotency_format") != IDEMPOTENCY_FORMAT:
        conn.execute("DELETE FROM idempotency")
        conn.execute("DELETE FROM idempotency_records")
        set_meta(conn, "idempotency_format", IDEMPOTENCY_FORMAT)
    if before == 0:
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('partition_id', ?)", (partition_id,))
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('created_at', ?)", (repr(time.time()),))
        for key, value in META_DEFAULTS.items():
            conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)", (key, value))
    return before, SCHEMA_VERSION


def get_meta(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))


def bump(conn: sqlite3.Connection, key: str = "generation") -> int:
    value = int(get_meta(conn, key, "0") or 0) + 1
    set_meta(conn, key, str(value))
    return value
