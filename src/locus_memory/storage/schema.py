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
    PRIMARY KEY(target_kind, target_token)
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

CREATE TABLE IF NOT EXISTS receipts(
    id TEXT PRIMARY KEY, operation TEXT NOT NULL, created_at REAL NOT NULL,
    dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS receipts_time ON receipts(created_at);

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

-- Bounded maintenance jobs with durable progress.
CREATE TABLE IF NOT EXISTS jobs(
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, state TEXT NOT NULL,
    observed_generation INTEGER NOT NULL, observed_deletion_generation INTEGER NOT NULL,
    created_at REAL NOT NULL, updated_at REAL NOT NULL, progress TEXT NOT NULL DEFAULT '{}'
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
        for statement in MIGRATIONS[version].split(";"):
            if statement.strip():
                conn.execute(statement)
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)", (str(version),))
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
