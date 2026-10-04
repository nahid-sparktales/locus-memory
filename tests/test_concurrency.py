"""Concurrency: optimistic revisions across engines, multi-process writers, idempotency, threads."""
from __future__ import annotations

import multiprocessing
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import access_for
from foundation_support import (
    count,
    db_path,
    forget_process,
    idempotent_process,
    ledger_path,
    raw_db,
    writer_process,
)
from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.errors import Contention, RevisionConflict
from locus_memory.host import EngineConfig, HostCapabilities
from locus_memory.models import Correction, Lifecycle, Query, RememberRequest, Scope

PROJ_A = Scope.of(project="proj-a")
ACCESS = access_for(projects=("proj-a",))


def _remember(engine, content):
    return engine.remember(ACCESS, RememberRequest(content=content, scope=PROJ_A)).record


def _spawn():
    return multiprocessing.get_context("spawn")


def _run(processes, timeout=120):
    for proc in processes:
        proc.start()
    for proc in processes:
        proc.join(timeout)
    for proc in processes:
        if proc.is_alive():  # pragma: no cover - defensive
            proc.kill()
        assert proc.exitcode == 0, f"worker exited with {proc.exitcode}"


def _drain(queue, n):
    return [queue.get(timeout=60) for _ in range(n)]


def _assert_store_healthy(root):
    path = db_path(root, ACCESS)
    with raw_db(path) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    with raw_db(ledger_path(root, ACCESS)) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


# ---------------------------------------------------------------------------- engines in one process
def test_two_engines_racing_on_one_record_yield_exactly_one_conflict(make_engine):
    first, second = make_engine(), make_engine()
    record = _remember(first, "shared draft")
    assert second.get(ACCESS, record.id).revision == 1
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def correct(engine, text):
        barrier.wait(timeout=10)
        try:
            outcomes.append(engine.correct(ACCESS, record.id, Correction(content=text), expected_revision=1))
        except RevisionConflict as exc:
            outcomes.append(exc)

    threads = [threading.Thread(target=correct, args=(e, t)) for e, t in ((first, "from one"), (second, "from two"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    conflicts = [o for o in outcomes if isinstance(o, RevisionConflict)]
    winners = [o for o in outcomes if not isinstance(o, RevisionConflict)]
    assert len(conflicts) == 1 and len(winners) == 1
    final = first.get(ACCESS, record.id)
    assert final.revision == 2 and final.content == winners[0].record.content
    assert second.get(ACCESS, record.id).content == final.content


def test_single_engine_is_thread_safe_for_concurrent_writes_and_reads(engine):
    seed = [_remember(engine, f"seed {i}") for i in range(5)]
    errors: list[BaseException] = []
    written: list[str] = []
    lock = threading.Lock()

    def writer(n):
        try:
            for i in range(10):
                rec = _remember(engine, f"writer {n} item {i}")
                with lock:
                    written.append(rec.id)
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    def reader():
        try:
            for _ in range(20):
                items = engine.list(ACCESS, limit=1000)
                assert {s.id for s in seed} <= {r.id for r in items}
                assert all(r.lifecycle == Lifecycle.APPROVED for r in items)
                try:
                    engine.search(ACCESS, Query(text="seed"))
                except AttributeError:  # retrieval not implemented in this build
                    pass
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(writer, n) for n in range(4)] + [pool.submit(reader) for _ in range(4)]
        for f in futures:
            f.result(timeout=120)
    assert errors == []
    assert len(written) == 40 == len(set(written))
    assert {r.id for r in engine.list(ACCESS, limit=1000)} == {s.id for s in seed} | set(written)


def test_connections_of_finished_threads_are_released(engine):
    _remember(engine, "x")
    db = engine.partition_context(ACCESS.partition).partition.db

    def touch():
        engine.get(ACCESS, engine.list(ACCESS)[0].id)

    for _ in range(25):
        t = threading.Thread(target=touch)
        t.start()
        t.join()
    touch()  # opening/using a connection prunes those of dead threads
    assert db.open_connections <= 3


# ---------------------------------------------------------------------------- multiple processes
def test_multiprocess_writers_never_corrupt_the_store(make_engine, root):
    key = secrets.token_bytes(32)
    make_engine(key_provider=StaticKeyProvider({"k1": key})).close()  # create the partition
    ctx = _spawn()
    queue = ctx.Queue()
    workers, per_worker = 4, 15
    procs = [ctx.Process(target=writer_process, args=(str(root), key.hex(), w, per_worker, 250, queue))
             for w in range(workers)]
    _run(procs)
    results = _drain(queue, workers)
    assert all(not other for (_w, _ok, _c, other) in results), results
    succeeded = sum(ok for (_w, ok, _c, _o) in results)
    assert succeeded + sum(c for (_w, _ok, c, _o) in results) == workers * per_worker
    assert succeeded > 0
    _assert_store_healthy(root)
    engine = make_engine(key_provider=StaticKeyProvider({"k1": key}))
    records = engine.list(ACCESS, limit=1000)
    assert len(records) == succeeded == count(db_path(root, ACCESS), "SELECT COUNT(*) FROM records")
    assert count(db_path(root, ACCESS), "SELECT COUNT(*) FROM record_revisions") == succeeded


def test_cold_start_race_creates_exactly_one_vault(root):
    key = secrets.token_bytes(32)
    ctx = _spawn()
    queue = ctx.Queue()
    procs = [ctx.Process(target=writer_process, args=(str(root), key.hex(), w, 3, 5_000, queue)) for w in range(4)]
    _run(procs)
    results = _drain(queue, 4)
    assert all(not other for (_w, _ok, _c, other) in results), results
    path = db_path(root, ACCESS)
    assert count(path, "SELECT COUNT(*) FROM key_wraps") == 2
    with MemoryEngine(root, StaticKeyProvider({"k1": key}), host=HostCapabilities()) as engine:
        assert len(engine.list(ACCESS, limit=100)) == sum(ok for (_w, ok, _c, _o) in results)


def test_replayed_idempotent_remember_across_processes_yields_one_record(make_engine, root):
    key = secrets.token_bytes(32)
    make_engine(key_provider=StaticKeyProvider({"k1": key})).close()
    ctx = _spawn()
    queue, barrier = ctx.Queue(), ctx.Barrier(4)
    procs = [ctx.Process(target=idempotent_process, args=(str(root), key.hex(), w, 2_000, barrier, queue))
             for w in range(4)]
    _run(procs)
    results = _drain(queue, 4)
    assert all(err is None for (_w, _id, _replay, err) in results), "\n".join(str(e) for (_w, _i, _r, e) in results)
    ids = {record_id for (_w, record_id, _r, _e) in results}
    assert len(ids) == 1
    assert sorted(replay for (_w, _id, replay, _e) in results) == [False, True, True, True]
    assert count(db_path(root, ACCESS), "SELECT COUNT(*) FROM records") == 1
    _assert_store_healthy(root)


def test_concurrent_forgets_in_separate_processes_keep_ledger_and_store_in_step(make_engine, root):
    key = secrets.token_bytes(32)
    engine = make_engine(key_provider=StaticKeyProvider({"k1": key}))
    records = [_remember(engine, f"to forget {i}") for i in range(4)]
    keep = _remember(engine, "keep")
    engine.close()
    ctx = _spawn()
    queue, barrier = ctx.Queue(), ctx.Barrier(len(records))
    procs = [ctx.Process(target=forget_process, args=(str(root), key.hex(), r.id, 2_000, barrier, queue))
             for r in records]
    _run(procs)
    results = _drain(queue, len(records))
    assert all(err is None for (_id, _gen, err) in results), results
    assert sorted(gen for (_id, gen, _e) in results) == [1, 2, 3, 4]
    _assert_store_healthy(root)
    engine = make_engine(key_provider=StaticKeyProvider({"k1": key}))
    assert [r.id for r in engine.list(ACCESS)] == [keep.id]
    status = engine.status(ACCESS)
    with raw_db(ledger_path(root, ACCESS)) as conn:
        head = conn.execute("SELECT MAX(generation) FROM ledger").fetchone()[0]
    assert status.deletion_generation == head == 4


def test_bounded_contention_surfaces_as_contention(make_engine, root):
    engine = make_engine(config=EngineConfig(busy_timeout_ms=50))
    _remember(engine, "x")
    ctx = engine.partition_context(ACCESS.partition)
    ctx.partition.db.max_busy_retries = 1
    blocker = make_engine()
    bctx = blocker.partition_context(ACCESS.partition)
    hold = bctx.partition.db.write()
    hold.__enter__()  # another connection holds the write lock
    try:
        with pytest.raises(Contention):
            _remember(engine, "blocked")
    finally:
        hold.__exit__(None, None, None)
    assert _remember(engine, "after release").revision == 1
    assert {r.content for r in engine.list(ACCESS)} == {"x", "after release"}
