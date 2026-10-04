"""Closing an engine while another thread is mid-call must not crash the interpreter."""
from __future__ import annotations

import threading

import pytest

from locus_memory.errors import MemoryEngineError
from locus_memory.models import RememberRequest
from locus_memory.storage.db import Database


def test_close_from_another_thread_defers_busy_connections(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    with db.write() as conn:
        conn.execute("CREATE TABLE t(x)")
    started, release, results = threading.Event(), threading.Event(), {}

    def worker() -> None:
        with db.read() as conn:  # this thread's connection is in use
            started.set()
            release.wait(5)
            results["rows"] = conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]
        try:
            _ = db.conn
        except MemoryEngineError as exc:
            results["after"] = str(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    assert started.wait(5)
    db.close()  # must not close the worker's connection under it
    release.set()
    thread.join(5)
    assert results == {"rows": 0, "after": "database is closed"}
    with pytest.raises(MemoryEngineError):
        _ = db.conn


def test_engine_close_while_other_thread_works(make_engine, user_access):
    engine = make_engine()
    engine.remember(user_access, RememberRequest("warm the partition"))
    errors: list[BaseException] = []
    stop = threading.Event()

    def worker() -> None:
        while not stop.is_set():
            try:
                engine.list(user_access)
            except MemoryEngineError:
                return  # expected once the engine is closed
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)
                return

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    engine.close()
    stop.set()
    for t in threads:
        t.join(5)
    assert not errors


def test_nested_access_after_close_keeps_the_outer_transactions_connection(tmp_path):
    """A nested ``db.conn`` access inside a thread's open read() (a key reload, for example)
    after another thread closed the database raises the typed error, and the outer block still
    ends its transaction on an open connection: never a raw sqlite3.ProgrammingError."""
    db = Database(tmp_path / "x.sqlite3")
    with db.write() as conn:
        conn.execute("CREATE TABLE t(x)")
    started, closed, results = threading.Event(), threading.Event(), {}

    def worker() -> None:
        try:
            with db.read() as conn:
                conn.execute("SELECT COUNT(*) FROM t").fetchone()
                started.set()
                closed.wait(5)
                _ = db.conn  # nested access after close()
        except BaseException as exc:
            results["error"] = exc
        try:
            _ = db.conn  # the next access closes this thread's connection
        except MemoryEngineError as exc:
            results["after"] = str(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    assert started.wait(5)
    db.close()
    closed.set()
    thread.join(5)
    assert type(results.get("error")) is MemoryEngineError, results
    assert str(results["error"]) == "database is closed"
    assert results["after"] == "database is closed"
    assert db._deferred == []
