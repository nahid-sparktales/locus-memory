"""Helpers shared by the foundation hardening tests (raw store access, multi-process workers).

Workers live here (not in a test module) so ``multiprocessing`` spawn children can
import them without importing pytest test modules.
"""
from __future__ import annotations

import sqlite3
import traceback
from contextlib import contextmanager
from pathlib import Path

from locus_memory.models import AccessContext


def partition_dir(root: Path, access: AccessContext) -> Path:
    return Path(root) / access.partition.partition_id


def db_path(root: Path, access: AccessContext) -> Path:
    return partition_dir(root, access) / "memory.sqlite3"


def ledger_path(root: Path, access: AccessContext) -> Path:
    return partition_dir(root, access) / "deletion-ledger.sqlite3"


@contextmanager
def raw_db(path: Path):
    """A plain sqlite3 connection (an attacker / restore tool editing the file)."""
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def count(path: Path, sql: str, params: tuple = ()) -> int:
    with raw_db(path) as conn:
        return int(conn.execute(sql, params).fetchone()[0])


def key_wraps_snapshot(path: Path) -> list[tuple]:
    with raw_db(path) as conn:
        return [tuple(r) for r in conn.execute(
            "SELECT dek_id, master_key_id, purpose, nonce, wrapped FROM key_wraps ORDER BY dek_id, master_key_id")]


def files_containing(directory: Path, needle: bytes) -> list[Path]:
    hits = []
    for path in Path(directory).rglob("*"):
        if path.is_file():
            try:
                if needle in path.read_bytes():
                    hits.append(path)
            except OSError:
                continue
    return hits


# ---------------------------------------------------------------------------- process workers
def _engine(root: str, key_hex: str, busy_timeout_ms: int):
    from locus_memory import MemoryEngine, StaticKeyProvider
    from locus_memory.host import EngineConfig, HostCapabilities

    keys = StaticKeyProvider({"k1": bytes.fromhex(key_hex)})
    return MemoryEngine(root, keys, host=HostCapabilities(),
                        config=EngineConfig(busy_timeout_ms=busy_timeout_ms))


def _access():
    from locus_memory.models import AccessContext, Actor, Operation, PartitionRef, ScopeGrants

    return AccessContext(principal="user-1", partition=PartitionRef("standard", "default"), actor=Actor.USER,
                         grants=ScopeGrants(projects=frozenset({"proj-a"})), operations=frozenset(Operation))


def writer_process(root: str, key_hex: str, worker: int, count_: int, busy_timeout_ms: int, queue) -> None:
    """Remember ``count_`` records; report (worker, ok, contention, other_errors)."""
    from locus_memory.errors import Contention
    from locus_memory.models import RememberRequest, Scope

    ok = contention = 0
    other: list[str] = []
    engine = _engine(root, key_hex, busy_timeout_ms)
    try:
        access = _access()
        for i in range(count_):
            try:
                engine.remember(access, RememberRequest(content=f"worker {worker} fact {i}",
                                                        scope=Scope.of(project="proj-a")))
                ok += 1
            except Contention:
                contention += 1
            except Exception as exc:  # reported to the parent, which fails the test
                other.append(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
    finally:
        engine.close()
    queue.put((worker, ok, contention, other))


def idempotent_process(root: str, key_hex: str, worker: int, busy_timeout_ms: int, barrier, queue) -> None:
    """Every worker replays the same idempotent remember at (roughly) the same time."""
    from locus_memory.errors import Contention
    from locus_memory.models import RememberRequest, Scope

    engine = _engine(root, key_hex, busy_timeout_ms)
    try:
        access = _access()
        request = RememberRequest(content="exactly once", scope=Scope.of(project="proj-a"))
        barrier.wait(timeout=30)
        for _attempt in range(20):
            try:
                result = engine.remember(access, request, idempotency_key="same-key")
                queue.put((worker, result.record.id, result.receipt.idempotent_replay, None))
                return
            except Contention:
                continue
            except Exception as exc:
                queue.put((worker, None, None, f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"))
                return
        queue.put((worker, None, None, "contention on every attempt"))
    finally:
        engine.close()


def forget_process(root: str, key_hex: str, record_id: str, busy_timeout_ms: int, barrier, queue) -> None:
    from locus_memory.errors import Contention
    from locus_memory.models import ForgetTarget

    engine = _engine(root, key_hex, busy_timeout_ms)
    try:
        access = _access()
        barrier.wait(timeout=30)
        for _attempt in range(20):
            try:
                receipt = engine.forget(access, ForgetTarget("memory", record_id))
                queue.put((record_id, receipt.deletion_generation, None))
                return
            except Contention:
                continue
            except Exception as exc:
                queue.put((record_id, None, f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"))
                return
        queue.put((record_id, None, "contention on every attempt"))
    finally:
        engine.close()
