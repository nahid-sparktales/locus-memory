"""SQLite connection management: explicit transactions, bounded contention, safe pragmas."""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import weakref
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


def _is_busy(exc: sqlite3.OperationalError) -> bool:
    message = str(exc).lower()
    return "locked" in message or "busy" in message


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
    """One SQLite file. Connections are per thread; writes use BEGIN IMMEDIATE.

    A connection belongs to the thread that opened it. Connections of threads that
    have exited are closed the next time any thread opens a connection, so hosts
    that call the engine from short-lived threads do not leak file descriptors.
    """

    def __init__(self, path: Path, *, busy_timeout_ms: int = 5_000, max_busy_retries: int = 3,
                 wal: bool = True) -> None:
        self.path = Path(path)
        self.busy_timeout_ms = busy_timeout_ms
        self.max_busy_retries = max_busy_retries
        self.wal = wal
        self._local = threading.local()
        # (owning thread, connection); sqlite3.Connection cannot be weakly referenced.
        self._all: list[tuple[weakref.ReferenceType[threading.Thread], sqlite3.Connection]] = []
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
        try:
            conn.row_factory = sqlite3.Row
            conn.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
            for pragma in _PRAGMAS:
                conn.execute(pragma)
            if self.wal:
                self._ensure_wal(conn)
        except BaseException:
            conn.close()
            raise
        if new_file:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        with self._lock:
            self._prune_dead_locked()
            self._all.append((weakref.ref(threading.current_thread()), conn))
        return conn

    def _ensure_wal(self, conn: sqlite3.Connection) -> None:
        """Enable WAL, tolerating concurrent openers.

        Switching (or confirming) the journal mode can report SQLITE_BUSY without
        consulting the busy handler while another process checkpoints/removes the
        WAL on close or runs WAL recovery; retry with bounded backoff, then raise
        the typed :class:`Contention` instead of a raw sqlite3 error.
        """
        attempts = self.max_busy_retries + 4
        for attempt in range(attempts):
            try:
                mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
                if str(mode).lower() != "wal":
                    conn.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError as exc:
                if not _is_busy(exc):
                    raise
                if attempt == attempts - 1:
                    raise Contention("the memory store stayed busy while opening; retry later") from exc
                time.sleep(min(0.02 * (2 ** attempt), 0.5))

    def _prune_dead_locked(self) -> None:
        alive = []
        for owner, conn in self._all:
            thread = owner()
            if thread is None or not thread.is_alive():
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            else:
                alive.append((owner, conn))
        self._all = alive

    @property
    def open_connections(self) -> int:
        with self._lock:
            return len(self._all)

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
                if not _is_busy(exc):
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
        for _owner, conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local = threading.local()
