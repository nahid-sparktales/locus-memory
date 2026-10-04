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

from ..errors import Contention, MemoryEngineError, StorageFull, StorageReadOnly, StorageUnavailable

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


def _error_name(exc: BaseException) -> str:
    """SQLite's primary result-code name (``SQLITE_FULL``, ...) where Python exposes it (3.11+)."""
    name = str(getattr(exc, "sqlite_errorname", "") or "")
    for primary in ("SQLITE_BUSY", "SQLITE_LOCKED", "SQLITE_FULL", "SQLITE_IOERR", "SQLITE_READONLY",
                    "SQLITE_CANTOPEN"):
        if name == primary or name.startswith(primary + "_"):
            return primary
    return name


def _is_busy(exc: sqlite3.Error) -> bool:
    name = _error_name(exc)
    if name:
        return name in ("SQLITE_BUSY", "SQLITE_LOCKED")
    message = str(exc).lower()
    return "locked" in message or "busy" in message


def storage_error(exc: BaseException) -> MemoryEngineError | None:
    """The typed error for an SQLite failure of the storage itself (disk full, I/O error,
    read-only or unopenable file), or None. Classified by SQLite's result code where Python
    exposes it, else by SQLite's fixed message. Lock contention is not a storage error."""
    if not isinstance(exc, sqlite3.Error) or _is_busy(exc):
        return None
    name = _error_name(exc)
    message = str(exc).lower()
    if name == "SQLITE_FULL" or "database or disk is full" in message:
        return StorageFull("the disk is full: the memory store cannot be written; free space and retry")
    if name == "SQLITE_READONLY" or "readonly database" in message or "read-only" in message:
        return StorageReadOnly("the memory store is read-only (file or directory permissions)")
    if name == "SQLITE_IOERR" or "disk i/o error" in message:
        return StorageUnavailable("a disk I/O error prevented the memory store from reading or writing")
    if name == "SQLITE_CANTOPEN" or "unable to open database file" in message:
        return StorageUnavailable("the memory store file could not be opened")
    return None


def _typed(exc: BaseException) -> BaseException:
    """``exc`` translated to its typed storage error (chained), or ``exc`` unchanged."""
    typed = storage_error(exc)
    if typed is None:
        return exc
    typed.__cause__ = exc
    return typed


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
        self._deferred: list[tuple[weakref.ReferenceType[threading.Thread], sqlite3.Connection]] = []
        self._waiting = 0  # threads of this process waiting for the write lock (BEGIN IMMEDIATE)

    def _connect(self) -> sqlite3.Connection:
        if self._closed:
            raise MemoryEngineError("database is closed")
        new_file = not self.path.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            conn = sqlite3.connect(
                self.path, timeout=self.busy_timeout_ms / 1000, isolation_level=None,
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise _typed(exc) from exc
        try:
            conn.row_factory = sqlite3.Row
            conn.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
            for pragma in _PRAGMAS:
                conn.execute(pragma)
            if self.wal:
                self._ensure_wal(conn)
        except sqlite3.Error as exc:
            conn.close()
            raise _typed(exc) from exc
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
                    raise _typed(exc) from exc
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
        if self._closed:
            # close() never closes a connection another live thread may be using (doing so can
            # crash the interpreter); each thread closes its own connection on its next access.
            if conn is not None:
                self._local.conn = None
                with self._lock:
                    self._deferred = [(o, c) for o, c in self._deferred if c is not conn]
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            raise MemoryEngineError("database is closed")
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    @property
    def waiting_writers(self) -> int:
        """Threads of this process currently waiting for the write lock. A long job that commits
        in batches yields between them while this is non-zero (SQLite's busy handler polls, so a
        lock released and retaken at once would otherwise starve the waiter)."""
        return self._waiting

    def yield_to_writers(self, *, pause: float = 0.02, limit: float = 0.5) -> None:
        """Between two write transactions of a long batched job: give waiting writers (another
        process's polling busy handler, and this process's threads) the lock first."""
        time.sleep(pause)
        until = time.monotonic() + limit
        while self._waiting and time.monotonic() < until:
            time.sleep(0.005)

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        conn = self.conn
        if conn.in_transaction:
            raise MemoryEngineError("nested write transaction")
        with self._lock:
            self._waiting += 1
        try:
            for attempt in range(self.max_busy_retries + 1):
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    break
                except sqlite3.OperationalError as exc:
                    if not _is_busy(exc):
                        raise _typed(exc) from exc
                    if attempt == self.max_busy_retries:
                        raise Contention("the memory store stayed busy; retry later") from exc
                    time.sleep(0.05 * (2 ** attempt))
        finally:
            with self._lock:
                self._waiting -= 1
        try:
            yield conn
        except BaseException as exc:
            self._rollback(conn)
            # A full disk, an I/O error or a read-only file inside the transaction is a typed
            # storage failure (never a raw sqlite3 error, never "contention").
            translated = _typed(exc)
            if translated is exc:
                raise
            raise translated from exc
        else:
            try:
                conn.execute("COMMIT")
            except sqlite3.OperationalError as exc:
                self._rollback(conn)
                if _is_busy(exc):
                    raise Contention("commit failed under contention") from exc
                typed = storage_error(exc)
                if typed is None:
                    typed = StorageUnavailable("the memory store could not commit")
                raise typed from exc

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> None:
        """Roll back if a transaction is still open (SQLite may already have rolled it back
        after an I/O or disk-full error); a failing rollback never hides the original error."""
        if conn.in_transaction:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        """A consistent read snapshot (deferred transaction)."""
        conn = self.conn
        if conn.in_transaction:
            yield conn
            return
        try:
            conn.execute("BEGIN")
        except sqlite3.Error as exc:
            raise _typed(exc) from exc
        try:
            yield conn
        except sqlite3.Error as exc:
            translated = _typed(exc)
            if translated is exc:
                raise
            raise translated from exc
        finally:
            if conn.in_transaction:
                try:
                    conn.execute("COMMIT")
                except sqlite3.Error:
                    self._rollback(conn)

    def checkpoint(self, *, wait: bool = True) -> bool:
        """Fold the WAL back into the main file and truncate it (after purges).

        Returns True only when the checkpoint completed: every WAL frame was copied
        into the main file and the log was reset. A concurrent reader (another
        thread's or process's read transaction) makes SQLite report ``busy`` *without
        raising* after ``busy_timeout``; the purged pages then still live in the WAL
        (and freed main-file pages were not rewritten), so callers that promise a
        physical purge must retry or record the pending checkpoint. ``wait=False``
        does not wait for readers at all (a cheap retry on later calls).
        """
        if not self.wal:
            return True
        conn = self.conn
        if conn.in_transaction:
            return False  # this thread's own snapshot would block it
        try:
            if not wait:
                conn.execute("PRAGMA busy_timeout=0")
            try:
                row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            finally:
                if not wait:
                    conn.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
        except sqlite3.OperationalError:
            return False
        if row is None:
            return True
        busy, log_frames, checkpointed = (int(row[0]), int(row[1]), int(row[2]))
        return busy == 0 and (log_frames <= 0 or log_frames == checkpointed)

    def close(self) -> None:
        """Close connections owned by this thread or by finished threads.

        Connections of other live threads are left to those threads: they are closed on the
        owning thread's next access (which then raises), so a host calling close() while
        another thread is mid-query gets an error in that thread, never a crashed process.
        """
        current = threading.current_thread()
        with self._lock:
            conns, self._all = self._all, []
            self._closed = True
            closable, deferred = [], []
            for owner, conn in conns:
                thread = owner()
                if thread is None or thread is current or not thread.is_alive():
                    closable.append(conn)
                else:
                    deferred.append((owner, conn))
            self._deferred = deferred
        for conn in closable:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        if getattr(self._local, "conn", None) in closable:
            self._local.conn = None
