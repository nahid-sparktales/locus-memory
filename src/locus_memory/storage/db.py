"""SQLite connection management: explicit transactions, bounded contention, safe pragmas."""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from ..errors import Contention, MemoryEngineError

# Pragmas applied to every connection to an app-managed database.
#  * secure_delete: freed pages are zeroed so purged ciphertext does not linger.
#  * temp_store=MEMORY: sorter/temp b-trees never spill to temp files on disk.
#  * trusted_schema=OFF: schema cannot invoke application functions.
#  * synchronous=FULL: committed receipts survive power loss in WAL mode.
_PRAGMAS = (
    "PRAGMA foreign_keys=ON",
    "PRAGMA secure_delete=ON",
    "PRAGMA temp_store=MEMORY",
    "PRAGMA trusted_schema=OFF",
    "PRAGMA synchronous=FULL",
)


def fts5_available() -> bool:
    try:
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute("CREATE VIRTUAL TABLE t USING fts5(x)")
            return True
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def memory_connection() -> sqlite3.Connection:
    """In-memory connection for search projections (never touches disk)."""
    conn = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA trusted_schema=OFF")
    return conn


class Database:
    """One SQLite file. Connections are per thread; writes use BEGIN IMMEDIATE."""

    def __init__(self, path: Path, *, busy_timeout_ms: int = 5_000, max_busy_retries: int = 3,
                 wal: bool = True) -> None:
        self.path = Path(path)
        self.busy_timeout_ms = busy_timeout_ms
        self.max_busy_retries = max_busy_retries
        self.wal = wal
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self._closed = False

    def _connect(self) -> sqlite3.Connection:
        if self._closed:
            raise MemoryEngineError("database is closed")
        new_file = not self.path.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            self.path, timeout=self.busy_timeout_ms / 1000, isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
        for pragma in _PRAGMAS:
            conn.execute(pragma)
        if self.wal:
            conn.execute("PRAGMA journal_mode=WAL")
        if new_file:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        with self._lock:
            self._all.append(conn)
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        conn = self.conn
        if conn.in_transaction:
            raise MemoryEngineError("nested write transaction")
        for attempt in range(self.max_busy_retries + 1):
            try:
                conn.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) and "busy" not in str(exc):
                    raise
                if attempt == self.max_busy_retries:
                    raise Contention("the memory store stayed busy; retry later") from exc
                time.sleep(0.05 * (2 ** attempt))
        try:
            yield conn
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        else:
            try:
                conn.execute("COMMIT")
            except sqlite3.OperationalError as exc:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise Contention("commit failed under contention") from exc

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        """A consistent read snapshot (deferred transaction)."""
        conn = self.conn
        if conn.in_transaction:
            yield conn
            return
        conn.execute("BEGIN")
        try:
            yield conn
        finally:
            if conn.in_transaction:
                conn.execute("COMMIT")

    def checkpoint(self) -> None:
        """Fold the WAL back into the main file and truncate it (after purges)."""
        if self.wal:
            try:
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.OperationalError:
                pass

    def close(self) -> None:
        with self._lock:
            conns, self._all = self._all, []
            self._closed = True
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local = threading.local()
