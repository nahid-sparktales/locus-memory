"""Encrypted saved-chat cache with a transient, memory-only SQLite FTS projection.

Only host-granted transcripts are indexed. Source cursors and display metadata
are authenticated along with message text in per-session AES-GCM envelopes.
The FTS connection never opens a disk database or disk temporary store.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..crypto import KeyProvider
from .transcript_cache import EncryptedTranscriptCache


@dataclass(frozen=True)
class TranscriptSource:
    """Only transcripts explicitly granted by the host are indexed.

    Metadata and display cleanup remain host capabilities; the index never scans
    an application directory or discovers sessions by itself.
    """

    list_paths: Callable[[], Sequence[Path]]
    metadata: Callable[[], Mapping[str, Mapping[str, Any]]]
    clean_user_text: Callable[[str], str]


@dataclass(frozen=True)
class TranscriptLimits:
    max_session_bytes: int
    max_line_bytes: int
    max_messages: int


SCHEMA_VERSION = 2
MAX_MESSAGE_CHARS = 100_000
MAX_QUERY_CHARS = 500
MAX_HITS_PER_SESSION = 3
#: Pending parse volume above which the first build moves off the request
#: thread. Small histories (and the tests) index inline and deterministically.
BACKGROUND_BUILD_BYTES = 8 * 1024 * 1024

_INDEXED_ROLES = {"user", "assistant"}
_SNIPPET_START = "\x01"
_SNIPPET_END = "\x02"


class TranscriptSearchError(RuntimeError):
    """Raised when the transcript index cannot serve a search."""


class TranscriptIndex:
    """Global FTS index over saved session transcripts."""

    def __init__(self, path: Path, source: TranscriptSource, limits: TranscriptLimits, *,
                 keys: KeyProvider, partition_id: str,
                 upgrade_lease: Callable | None = None,
                 background_build_bytes: int = BACKGROUND_BUILD_BYTES) -> None:
        self.path = Path(path).resolve()
        self.source, self.limits = source, limits
        self.background_build_bytes = background_build_bytes
        self._lock = threading.RLock()
        self._build_thread: threading.Thread | None = None
        self._abort_build = False
        self._granted_paths: dict[str, Path] = {}
        legacy = EncryptedTranscriptCache.is_legacy(self.path)
        if legacy and upgrade_lease is None:
            raise TranscriptSearchError("plaintext search upgrade requires an exclusive host profile lease")
        self._closed = False
        self._connection = sqlite3.connect(":memory:", check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA temp_store=MEMORY")
        self._initialize()
        staging = self.path.with_name(self.path.name + "." + secrets.token_hex(8) + ".encrypted")
        try:
            with upgrade_lease() if legacy else nullcontext():
                self._cache = EncryptedTranscriptCache(staging if legacy else self.path, keys, partition_id)
                self._hydrate()
                if legacy:
                    # Rebuild only from currently granted transcripts; the legacy database is
                    # never trusted as an authorized source. Publish only after decrypting every
                    # envelope successfully. The host lease excludes old application writers.
                    threshold = self.background_build_bytes
                    self.background_build_bytes = 2**63
                    self.sync()
                    self.background_build_bytes = threshold
                    self._cache.verify()
                    self._cache.close()
                    # Flush the old SQLite WAL before replacing its main file so a
                    # crash cannot pair new ciphertext pages with an old plaintext WAL.
                    old = sqlite3.connect(self.path)
                    try:
                        old.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    finally:
                        old.close()
                    for suffix in ("-wal", "-shm", "-journal"):
                        self.path.with_name(self.path.name + suffix).unlink(missing_ok=True)
                    os.replace(staging, self.path)
                    directory = os.open(self.path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                    self._cache = EncryptedTranscriptCache(self.path, keys, partition_id)
        except BaseException:
            cache = getattr(self, "_cache", None)
            if cache is not None:
                cache.close()
            self._connection.close()
            staging.unlink(missing_ok=True)
            raise

    # ---------------------------------------------------------------- schema

    def _connect(self) -> sqlite3.Connection:
        if self._closed:
            raise TranscriptSearchError("transcript search is closed")
        return self._connection

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._connect() as connection:
            connection.execute("PRAGMA journal_mode=MEMORY")
            version = 0
            try:
                row = connection.execute(
                    "SELECT schema_version FROM settings WHERE singleton=1"
                ).fetchone()
                version = int(row[0]) if row else 0
            except sqlite3.DatabaseError:
                version = 0
            if version != SCHEMA_VERSION:
                connection.executescript(
                    """
                    DROP TABLE IF EXISTS settings;
                    DROP TABLE IF EXISTS sessions;
                    DROP TABLE IF EXISTS messages_fts;
                    """
                )
            connection.executescript(
                f"""
                CREATE TABLE IF NOT EXISTS settings (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL DEFAULT {SCHEMA_VERSION},
                    built_at REAL
                );
                INSERT OR IGNORE INTO settings(singleton, schema_version)
                    VALUES(1, {SCHEMA_VERSION});
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    mtime REAL NOT NULL,
                    size INTEGER NOT NULL,
                    indexed_bytes INTEGER NOT NULL,
                    message_count INTEGER NOT NULL,
                    indexed_at REAL NOT NULL
                );
                CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                    content, session_id UNINDEXED, message_index UNINDEXED,
                    role UNINDEXED, phase UNINDEXED, item_id UNINDEXED,
                    reasoning_sections UNINDEXED, tokenize='unicode61'
                );
                """
            )
    def _hydrate(self) -> None:
        granted = {path.stem for path in self.source.list_paths()}
        with self._connection as connection:
            for payload in self._cache.payloads():
                sid = payload["session"][0]
                if sid not in granted:
                    self._cache.forget(sid)
                    continue
                connection.execute("INSERT OR REPLACE INTO sessions VALUES(?,?,?,?,?,?)", payload["session"])
                connection.executemany(
                    "INSERT INTO messages_fts(content,session_id,message_index,role,phase,item_id,reasoning_sections)"
                    " VALUES(?,?,?,?,?,?,?)", payload["messages"],
                )

    def _persist_session(self, session_id: str) -> None:
        row = self._connection.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        messages = self._connection.execute(
            "SELECT content,session_id,message_index,role,phase,item_id,reasoning_sections FROM messages_fts"
            " WHERE session_id=? ORDER BY message_index", (session_id,),
        ).fetchall()
        self._cache.store(session_id, {"session": list(row), "messages": [list(m) for m in messages]})

    def close(self) -> None:
        with self._lock:
            self._abort_build = True
        thread = self._build_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join()
        with self._lock:
            if not self._closed:
                self._cache.close()
                self._connection.close()
                self._closed = True

    # ----------------------------------------------------------------- sync

    def sync(self) -> dict[str, int]:
        """Bring the index up to date with the sessions directory.

        Returns ``{"updated": n, "removed": n, "pending": n}``. ``pending`` is
        nonzero only while a large first build continues on the background
        thread; callers surface it as ``indexing``.
        """
        with self._lock:
            on_disk: dict[str, Path] = {
                path.stem: path for path in self.source.list_paths()
            }
            self._granted_paths = on_disk
            with self._connect() as connection:
                known = {
                    str(row["session_id"]): row
                    for row in connection.execute("SELECT * FROM sessions").fetchall()
                }
            # Removals always run, even mid-build: a trashed session must stop
            # matching on the very next search, not when the build finishes.
            removed = 0
            for session_id in known:
                if session_id not in on_disk:
                    self._forget(session_id)
                    removed += 1
            if self._build_thread is not None and self._build_thread.is_alive():
                return {"updated": 0, "removed": removed, "pending": 1}
            stale: list[tuple[str, Path, sqlite3.Row | None]] = []
            pending_bytes = 0
            for session_id, path in on_disk.items():
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if stat.st_size > self.limits.max_session_bytes:
                    continue
                row = known.get(session_id)
                if row is not None and row["mtime"] == stat.st_mtime \
                        and row["size"] == stat.st_size:
                    continue
                stale.append((session_id, path, row))
                already = int(row["indexed_bytes"]) if row is not None else 0
                pending_bytes += max(stat.st_size - min(already, stat.st_size), 0)
            if not stale:
                return {"updated": 0, "removed": removed, "pending": 0}
            self._abort_build = False
            if pending_bytes > self.background_build_bytes:
                worker = threading.Thread(
                    target=self._index_many,
                    args=(stale,),
                    name="transcript-index-build",
                    daemon=True,
                )
                self._build_thread = worker
                worker.start()
                return {"updated": 0, "removed": removed, "pending": len(stale)}
            self._index_many(stale)
            return {"updated": len(stale), "removed": removed, "pending": 0}

    @property
    def is_indexing(self) -> bool:
        thread = self._build_thread
        return thread is not None and thread.is_alive()

    def _index_many(self, stale: list[tuple[str, Path, sqlite3.Row | None]]) -> None:
        for session_id, path, row in stale:
            # Per-file lock so a concurrent delete_all interleaves atomically;
            # its abort flag stops the rest of a build whose inputs it wiped.
            with self._lock:
                if self._abort_build:
                    return
                # A search may revoke a source while this background build is
                # queued. Its original list is never an enduring grant.
                if self._granted_paths.get(session_id) != path:
                    continue
                try:
                    self._index_file(session_id, path, row)
                except (OSError, sqlite3.DatabaseError):
                    continue

    def _forget(self, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM messages_fts WHERE session_id=?", (session_id,)
            )
            connection.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        self._cache.forget(session_id)

    def _index_file(
        self, session_id: str, path: Path, row: sqlite3.Row | None
    ) -> None:
        """Parse ``path`` from its last indexed byte and index new messages.

        ``message_index`` must count exactly the records ``SessionStore.load``
        keeps — every ``type == "message"`` record with a dict payload — so a
        hit addresses the same position the session-detail endpoint returns.
        """
        try:
            stat = path.stat()
        except OSError:
            return
        start_byte = 0
        message_index = 0
        if row is not None:
            if stat.st_size > int(row["size"]):
                start_byte = int(row["indexed_bytes"])
                message_index = int(row["message_count"])
            else:
                # Shrunk or rewritten at the same size: re-read from zero.
                # sync already excluded unchanged (mtime, size) pairs.
                self._forget(session_id)
        rows: list[tuple[str, str, int, str, str, str, str]] = []
        consumed = start_byte
        with path.open("rb") as handle:
            handle.seek(start_byte)
            while True:
                raw = handle.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    # A torn tail is mid-write; it re-parses on the next sync.
                    break
                consumed += len(raw)
                if len(raw) > self.limits.max_line_bytes or not raw.strip():
                    continue
                try:
                    record = _loads(raw)
                except ValueError:
                    continue
                if not isinstance(record, dict):
                    continue
                message = record.get("message")
                if record.get("type") != "message" or not isinstance(message, dict):
                    continue
                position = message_index
                message_index += 1
                if message_index > self.limits.max_messages:
                    break
                role = str(message.get("role") or "")
                if role not in _INDEXED_ROLES:
                    continue
                content = message.get("content")
                content = content if isinstance(content, str) else ""
                sections = [
                    str(section)
                    for section in message.get("_display_reasoning_sections") or []
                    if str(section).strip()
                ]
                if not content.strip() and sections:
                    content = "\n\n".join(sections)
                if not content.strip():
                    continue
                if role == "user":
                    content = self.source.clean_user_text(content)
                    if not content:
                        continue
                rows.append((
                    content[:MAX_MESSAGE_CHARS], session_id, position, role,
                    str(message.get("_phase") or ""),
                    str(message.get("_item_id") or ""),
                    json.dumps(sections, ensure_ascii=False) if sections else "",
                ))
        with self._connect() as connection:
            for content, sid, position, role, phase, item_id, sections in rows:
                connection.execute(
                    "INSERT INTO messages_fts(content, session_id, message_index, role,"
                    " phase, item_id, reasoning_sections) VALUES(?, ?, ?, ?, ?, ?, ?)",
                    (content, sid, position, role, phase, item_id, sections),
                )
            connection.execute(
                """INSERT INTO sessions(
                       session_id, mtime, size, indexed_bytes, message_count, indexed_at
                   ) VALUES(?, ?, ?, ?, ?, ?)
                   ON CONFLICT(session_id) DO UPDATE SET
                       mtime=excluded.mtime, size=excluded.size,
                       indexed_bytes=excluded.indexed_bytes,
                       message_count=excluded.message_count,
                       indexed_at=excluded.indexed_at""",
                (session_id, stat.st_mtime, stat.st_size, consumed,
                 message_index, time.time()),
            )
            connection.execute(
                "UPDATE settings SET built_at=? WHERE singleton=1", (time.time(),)
            )

        self._persist_session(session_id)

    # --------------------------------------------------------------- search

    def search(self, query: str, limit: int = 20) -> dict[str, Any]:
        started = time.monotonic()
        query = query.strip()[:MAX_QUERY_CHARS]
        if not query:
            raise TranscriptSearchError("transcript search requires a query")
        limit = min(max(int(limit), 1), 50)
        status = self.sync()
        terms = [
            term for term in re.findall(r"[\w.-]+", query, flags=re.UNICODE)
            if len(term) > 1
        ]
        fts_query = " OR ".join(
            f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms[:16]
        )
        results: list[dict[str, Any]] = []
        if fts_query:
            meta = self.source.metadata()
            per_session: dict[str, int] = {}
            with self._lock, self._connect() as connection:
                # Metadata callbacks and a queued build can run after sync.
                # Take fresh grants at the read boundary and revoke pending
                # work as well as excluding any cached hits from those sources.
                self._granted_paths = {
                    path.stem: path for path in self.source.list_paths()
                }
                granted_sessions = set(self._granted_paths)
                rows = connection.execute(
                    f"""SELECT session_id, message_index, role, phase, item_id,
                               reasoning_sections, bm25(messages_fts) AS rank,
                               snippet(messages_fts, 0, '{_SNIPPET_START}',
                                       '{_SNIPPET_END}', '…', 24) AS snippet
                        FROM messages_fts WHERE messages_fts MATCH ?
                        ORDER BY rank LIMIT ?""",
                    (fts_query, limit * 6),
                ).fetchall()
                stats = {
                    str(row["session_id"]): row
                    for row in connection.execute("SELECT * FROM sessions").fetchall()
                }
            for position, row in enumerate(rows):
                session_id = str(row["session_id"])
                if session_id not in granted_sessions:
                    continue
                if per_session.get(session_id, 0) >= MAX_HITS_PER_SESSION:
                    continue
                stat_row = stats.get(session_id)
                if stat_row is None:
                    continue
                per_session[session_id] = per_session.get(session_id, 0) + 1
                snippet, highlights = _split_snippet(str(row["snippet"] or ""))
                entry = meta.get(session_id, {})
                reasoning_sections: list[str] = []
                try:
                    decoded_sections = json.loads(str(row["reasoning_sections"] or "[]"))
                    if isinstance(decoded_sections, list):
                        reasoning_sections = [str(value) for value in decoded_sections]
                except json.JSONDecodeError:
                    pass
                result = {
                    "session_id": session_id,
                    "title": entry.get("title"),
                    "pinned": bool(entry.get("pinned", False)),
                    "mtime": float(stat_row["mtime"]),
                    "message_index": int(row["message_index"]),
                    "role": str(row["role"] or ""),
                    "snippet": snippet,
                    "highlights": highlights,
                    "score": 1.0 / (position + 1),
                }
                if row["phase"]:
                    result["phase"] = str(row["phase"])
                if row["item_id"]:
                    result["item_id"] = str(row["item_id"])
                if reasoning_sections:
                    result["reasoning_sections"] = reasoning_sections
                results.append(result)
                if len(results) >= limit:
                    break
        return {
            "query": query,
            "indexing": status["pending"] > 0 or self.is_indexing,
            "duration_ms": max(int((time.monotonic() - started) * 1_000), 0),
            "results": results,
        }

    def delete_all(self) -> None:
        with self._lock:
            # A background build started before the wipe must not re-insert
            # text for sessions the user just cleared.
            self._abort_build = True
            with self._connect() as connection:
                connection.execute("DELETE FROM messages_fts")
                connection.execute("DELETE FROM sessions")
            self._cache.clear()


def _loads(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8", errors="replace"))


def _split_snippet(marked: str) -> tuple[str, list[list[int]]]:
    """Convert sentinel-marked snippet text into plain text + highlight ranges."""
    plain: list[str] = []
    highlights: list[list[int]] = []
    length = 0
    open_at: int | None = None
    for char in marked:
        if char == _SNIPPET_START:
            open_at = length
            continue
        if char == _SNIPPET_END:
            if open_at is not None and length > open_at:
                highlights.append([open_at, length - open_at])
            open_at = None
            continue
        plain.append(char)
        length += 1
    return "".join(plain), highlights
