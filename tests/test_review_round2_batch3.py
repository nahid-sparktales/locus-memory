"""Regression tests for review round 2, batch 3 (reproduced defects).

R2-SL-7   a TTL-expired candidate could be superseded and then approved through approve()'s
          revert path (no TTL check on a superseded row), so a never-reviewed, expired candidate
          became approved and was injected into context; supersede also accepted a superseding
          record that was stale or expired at read time.
R2-CD-2   forgets applied by reconcile (a crash after the ledger append, a failed apply, another
          process) were never checkpointed or marked pending, and an idempotent replay reported the
          physical purge as complete while the forgotten ciphertext was still in memory.sqlite3.
R2-CD-3   a failed first open deleted the vault (memory.sqlite3, -wal, -shm) another opener had
          created and written to meanwhile.
R2-CD-4   the sealed forget request (target identity and caller grants) stayed in the deletion
          ledger's WAL after a forget that reported its purge complete.
R2-CD-5   disk-full and I/O failures surfaced as retryable Contention; read-only vault failures as
          a raw sqlite3.OperationalError outside the typed error contract.
R2-HC-1   the Stage-2 host adapter (handoff patch 0002) raised AssertionError - failing the turn -
          when an approved memory's text quoted the legacy results header.
R2-ROB-2  an LRU-evicting history search waited on a hydrating projection's lock while holding the
          archive lock that a forget's purge needs, so the forget (and its write lock) stalled.
R2-ROB-3  the repository snapshot commit ignored the deadline and cancellation and held the write
          lock for the whole commit, so a concurrent forget failed with Contention.

Each test reproduces the report's scenario and asserts the correct outcome. All data lives in
pytest tmp dirs.
"""
from __future__ import annotations

import importlib
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import textwrap
import threading
import time
import types
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

from conftest import access_for
from foundation_support import db_path, partition_dir
from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.cli import EXIT_STORAGE, main
from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.context import CONTEXT_WRAPPER_OPEN
from locus_memory.errors import (
    Contention,
    InvalidTransition,
    MemoryEngineError,
    NotFound,
    StorageFull,
    StorageReadOnly,
    StorageUnavailable,
    VaultLocked,
    WrongKey,
)
from locus_memory.forgetting import _PURGE_PENDING, ForgettingService
from locus_memory.history.archive import HistoryArchive
from locus_memory.host import CancellationToken, Deadline, EngineConfig, HostCapabilities
from locus_memory.models import (
    CandidateProposal,
    ContextRequest,
    ForgetTarget,
    IngestionEvent,
    Lifecycle,
    PartitionRef,
    RememberRequest,
    Retention,
    Scope,
    SourceKind,
    SourceRef,
    Validity,
)
from locus_memory.repository import service as repo_service
from locus_memory.repository.service import RepositoryService
from locus_memory.storage import partition as partition_mod
from locus_memory.storage.partition import Partition

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent
PROJ_A = Scope.of(project="proj-a")
USER = access_for(projects=("proj-a",))


def _alive(engine, access, record_id):
    try:
        return engine.get(access, record_id)
    except NotFound:
        return None


def _files_containing(directory: Path, needle: bytes) -> list[str]:
    return sorted(p.name for p in Path(directory).rglob("*") if p.is_file() and needle in p.read_bytes())


# =========================================================================== R2-SL-7
def _candidate(engine, content="the staging db rotates monthly"):
    record = engine.propose(USER, CandidateProposal(
        content=content, kind="fact", scope=Scope.of(),
        sources=(SourceRef(SourceKind.USER_ACTION, "u-" + uuid.uuid4().hex[:8]),))).record
    assert record.lifecycle == Lifecycle.CANDIDATE and record.retention.expires_at is not None
    return record


def _in_context(engine, text):
    return text in engine.build_context(USER, ContextRequest(token_allowance=2000)).text


def test_sl7_an_expired_candidate_cannot_be_superseded_or_revived(make_engine, clock):
    engine = make_engine()
    candidate = _candidate(engine)
    other = engine.remember(USER, RememberRequest(content="something else entirely", kind="fact",
                                                  scope=Scope.of())).record
    clock.advance(engine.config.candidate_ttl_seconds + 10)
    assert engine.get(USER, candidate.id).lifecycle == Lifecycle.EXPIRED
    with pytest.raises(InvalidTransition, match="expired"):
        engine.supersede(USER, candidate.id, other.id, expected_revision=None)
    with pytest.raises(InvalidTransition, match="expired"):
        engine.approve(USER, candidate.id, expected_revision=None)
    engine.maintain(USER)
    assert engine.get(USER, candidate.id).lifecycle == Lifecycle.EXPIRED
    assert not _in_context(engine, "staging db rotates")


def test_sl7_a_candidate_superseded_unreviewed_keeps_its_ttl_through_the_revert_path(make_engine, clock):
    engine = make_engine()
    candidate = _candidate(engine)
    other = engine.remember(USER, RememberRequest(content="something else entirely", kind="fact",
                                                  scope=Scope.of())).record
    # Superseded while still live (allowed), never reviewed.
    assert engine.supersede(USER, candidate.id, other.id, expected_revision=None).record.lifecycle \
        == Lifecycle.SUPERSEDED
    clock.advance(engine.config.candidate_ttl_seconds + 10)
    with pytest.raises(InvalidTransition, match="expired"):
        engine.approve(USER, candidate.id, expected_revision=None)
    engine.maintain(USER)
    assert engine.get(USER, candidate.id).lifecycle != Lifecycle.APPROVED
    assert not _in_context(engine, "staging db rotates")


def test_sl7_reverting_a_live_superseded_candidate_is_its_approval(make_engine, clock):
    engine = make_engine()
    candidate = _candidate(engine)
    other = engine.remember(USER, RememberRequest(content="something else entirely", kind="fact",
                                                  scope=Scope.of())).record
    engine.supersede(USER, candidate.id, other.id, expected_revision=None)
    approved = engine.approve(USER, candidate.id, expected_revision=None).record
    assert approved.lifecycle == Lifecycle.APPROVED
    assert approved.retention.expires_at is None  # the candidate TTL is dropped, not kept stale
    clock.advance(engine.config.candidate_ttl_seconds * 3)
    engine.maintain(USER)
    assert engine.get(USER, candidate.id).lifecycle == Lifecycle.APPROVED


def test_sl7_an_approved_record_superseded_then_reverted_still_reverts(make_engine, clock):
    engine = make_engine()
    old = engine.remember(USER, RememberRequest(content="old fact alpha", kind="fact", scope=Scope.of())).record
    new = engine.remember(USER, RememberRequest(content="new fact beta", kind="fact", scope=Scope.of())).record
    engine.supersede(USER, old.id, new.id, expected_revision=None)
    clock.advance(engine.config.candidate_ttl_seconds * 2)
    assert engine.approve(USER, old.id, expected_revision=None).record.lifecycle == Lifecycle.APPROVED


@pytest.mark.parametrize("ending", ["validity", "retention"])
def test_sl7_supersede_refuses_a_superseding_record_that_is_not_current(make_engine, clock, ending):
    engine = make_engine()
    old = engine.remember(USER, RememberRequest(content="old fact gamma", kind="fact", scope=Scope.of())).record
    extra = ({"validity": Validity(valid_until=clock.now + 60)} if ending == "validity"
             else {"retention": Retention(policy="transient", expires_at=clock.now + 60)})
    new = engine.remember(USER, RememberRequest(content="new fact delta", kind="fact", scope=Scope.of(),
                                                **extra)).record
    clock.advance(120)
    assert engine.get(USER, new.id).lifecycle == (Lifecycle.STALE if ending == "validity" else Lifecycle.EXPIRED)
    with pytest.raises(InvalidTransition, match="approved and current"):
        engine.supersede(USER, old.id, new.id, expected_revision=None)
    assert engine.get(USER, old.id).lifecycle == Lifecycle.APPROVED


# =========================================================================== R2-CD-2
CRASH_CHILD = textwrap.dedent('''
    import os, sys
    sys.path.insert(0, %(tests)r)
    from conftest import access_for
    from locus_memory import MemoryEngine, StaticKeyProvider
    from locus_memory.models import ForgetTarget
    from locus_memory.storage import ledger

    root, key_hex, memory_id, key = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    original = ledger.DeletionLedger.append

    def append(self, *args, **kwargs):
        original(self, *args, **kwargs)
        os._exit(0)  # power loss between the write-ahead append and the main-database apply

    ledger.DeletionLedger.append = append
    engine = MemoryEngine(root, StaticKeyProvider({"k1": bytes.fromhex(key_hex)}))
    engine.forget(access_for(projects=("proj-a",)), ForgetTarget("memory", memory_id), idempotency_key=key or None)
    os._exit(3)
''') % {"tests": str(TESTS)}
SECRET_FACT = "R2CD2 forgotten fact: the merger closes on the ninth "


def _seed(root: Path, key: bytes) -> tuple[str, bytes]:
    """One record whose ciphertext lives in the main file (the last close checkpointed it)."""
    engine = MemoryEngine(root, StaticKeyProvider({"k1": key}))
    record_id = engine.remember(USER, RememberRequest(content=SECRET_FACT * 4, scope=PROJ_A)).record.id
    engine.close()
    with sqlite3.connect(db_path(root, USER)) as conn:
        blob = bytes(conn.execute("SELECT ciphertext FROM records WHERE id=?", (record_id,)).fetchone()[0])
    assert blob in db_path(root, USER).read_bytes()
    return record_id, blob


def _crash_forget(tmp_path: Path, root: Path, key: bytes, record_id: str, idempotency_key: str = "") -> None:
    script = tmp_path / "crash_forget.py"
    script.write_text(CRASH_CHILD)
    done = subprocess.run([sys.executable, str(script), str(root), key.hex(), record_id, idempotency_key],
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr  # exited right after the ledger append


def _reader(root: Path) -> sqlite3.Connection:
    reader = sqlite3.connect(db_path(root, USER), isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM records").fetchone()
    return reader


def test_cd2_a_forget_reconciled_after_a_crash_is_physically_purged(tmp_path):
    root, key = tmp_path / "root", secrets.token_bytes(32)
    record_id, blob = _seed(root, key)
    _crash_forget(tmp_path, root, key, record_id)
    engine = MemoryEngine(root, StaticKeyProvider({"k1": key}))  # open -> reconcile applies the forget
    try:
        partition = engine.partition_context(USER.partition).partition
        assert partition.last_reconcile.get("reapplied") == 1
        assert _alive(engine, USER, record_id) is None
        assert not partition.pending_purge_checkpoint
        assert _files_containing(partition_dir(root, USER), blob) == []  # gone from every file
    finally:
        engine.close()


def test_cd2_a_failed_apply_reconciled_in_process_is_physically_purged(tmp_path, monkeypatch):
    root, key = tmp_path / "root", secrets.token_bytes(32)
    record_id, blob = _seed(root, key)
    original = ForgettingService.apply_tombstone
    failed = []

    def flaky(self, conn, kind, token, generation, forget_policy=None, *, access=None):
        if access is not None and not failed:
            failed.append(1)
            raise sqlite3.OperationalError("database or disk is full")
        return original(self, conn, kind, token, generation, forget_policy, access=access)

    monkeypatch.setattr(ForgettingService, "apply_tombstone", flaky)
    engine = MemoryEngine(root, StaticKeyProvider({"k1": key}))
    try:
        with pytest.raises(StorageFull):  # typed (R2-CD-5), never a raw sqlite3 error
            engine.forget(USER, ForgetTarget("memory", record_id))
        assert _alive(engine, USER, record_id) is None  # the next call reconciles
        partition = engine.partition_context(USER.partition).partition
        assert not partition.pending_purge_checkpoint
        assert _files_containing(partition_dir(root, USER), blob) == []
    finally:
        engine.close()


def test_cd2_an_idempotent_retry_after_reconcile_reports_the_real_purge_state(tmp_path):
    root, key = tmp_path / "root", secrets.token_bytes(32)
    record_id, blob = _seed(root, key)
    _crash_forget(tmp_path, root, key, record_id, "k-1")
    reader = _reader(root)  # a concurrent reader: the reconcile's checkpoint cannot complete
    engine = MemoryEngine(root, StaticKeyProvider({"k1": key}))
    try:
        partition = engine.partition_context(USER.partition).partition
        assert partition.last_reconcile.get("reapplied") == 1
        assert partition.pending_purge_checkpoint  # recorded, so later calls retry it
        assert blob in db_path(root, USER).read_bytes()
        replay = engine.forget(USER, ForgetTarget("memory", record_id), idempotency_key="k-1")
        assert replay.receipt.status == "ok" and replay.receipt.idempotent_replay
        assert replay.physical_purge_pending is True
        assert _PURGE_PENDING in replay.receipt.limitations
        reader.execute("COMMIT")
        reader.close()
        reader = None
        again = engine.forget(USER, ForgetTarget("memory", record_id), idempotency_key="k-1")
        assert again.physical_purge_pending is False and _PURGE_PENDING not in again.receipt.limitations
        assert not partition.pending_purge_checkpoint
        assert _files_containing(partition_dir(root, USER), blob) == []
    finally:
        if reader is not None:
            reader.close()
        engine.close()


def test_cd2_a_replay_while_the_checkpoint_is_still_blocked_stays_pending(tmp_path):
    root, key = tmp_path / "root", secrets.token_bytes(32)
    record_id, blob = _seed(root, key)
    engine = MemoryEngine(root, StaticKeyProvider({"k1": key}), config=EngineConfig(busy_timeout_ms=100))
    reader = _reader(root)
    try:
        first = engine.forget(USER, ForgetTarget("memory", record_id), idempotency_key="k-2")
        assert first.physical_purge_pending is True and _PURGE_PENDING in first.receipt.limitations
        again = engine.forget(USER, ForgetTarget("memory", record_id), idempotency_key="k-2")
        assert again.physical_purge_pending is True and _PURGE_PENDING in again.receipt.limitations
        assert again.receipt.limitations.count(_PURGE_PENDING) == 1
        assert blob in db_path(root, USER).read_bytes()
    finally:
        reader.execute("COMMIT")
        reader.close()
    try:
        done = engine.forget(USER, ForgetTarget("memory", record_id), idempotency_key="k-2")
        assert done.physical_purge_pending is False
        assert _files_containing(partition_dir(root, USER), blob) == []
    finally:
        engine.close()


def test_cd2_an_unflushed_purge_is_finished_on_the_next_open(tmp_path, monkeypatch):
    """A process that died between its purge commit and its checkpoint: the next open flushes."""
    root, key = tmp_path / "root", secrets.token_bytes(32)
    record_id, blob = _seed(root, key)
    engine = MemoryEngine(root, StaticKeyProvider({"k1": key}))
    monkeypatch.setattr(Partition, "flush_purged", lambda self, **kwargs: True)  # "dies" before it
    engine.forget(USER, ForgetTarget("memory", record_id))
    monkeypatch.undo()
    partition = engine.partition_context(USER.partition).partition
    assert partition.purge_checkpointed_generation() < partition.deletion_generation()
    other = MemoryEngine(root, StaticKeyProvider({"k1": key}))  # another process opens meanwhile
    try:
        other_partition = other.partition_context(USER.partition).partition
        assert other_partition.purge_checkpointed_generation() == other_partition.deletion_generation()
        assert not other_partition.pending_purge_checkpoint
        assert blob not in db_path(root, USER).read_bytes()
    finally:
        other.close()
        engine.close()


# =========================================================================== R2-CD-3
def _race_first_open(root: Path, monkeypatch, b_provider, *, pause: str, forget: bool):
    """Opener B decides the vault does not exist and pauses; engine A creates the vault and writes
    (and forgets); B then resumes and fails. Returns (A's provider, kept id, B's error)."""
    reached, go = threading.Event(), threading.Event()
    b_thread: dict[str, threading.Thread] = {}
    if pause == "existence_check":
        original = partition_mod._ledger_has_entries
        calls = []

        def paused(path):
            if threading.current_thread() is b_thread.get("t") and not calls:
                calls.append(1)
                reached.set()
                assert go.wait(30)
            return original(path)

        monkeypatch.setattr(partition_mod, "_ledger_has_entries", paused)
    else:
        original_db = partition_mod.Database

        def paused_db(*args, **kwargs):
            if threading.current_thread() is b_thread.get("t") and not reached.is_set():
                reached.set()
                assert go.wait(30)
            return original_db(*args, **kwargs)

        monkeypatch.setattr(partition_mod, "Database", paused_db)
    errors: list[BaseException] = []

    def open_b():
        try:
            Partition(root, PartitionRef("standard", "default"), b_provider).close()
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertions
            errors.append(exc)

    b = threading.Thread(target=open_b)
    b_thread["t"] = b
    b.start()
    assert reached.wait(30)
    a_provider = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    engine_a = MemoryEngine(root, a_provider)
    keep = engine_a.remember(USER, RememberRequest(content="written by A", scope=PROJ_A)).record.id
    if forget:
        doomed = engine_a.remember(USER, RememberRequest(content="forgotten by A", scope=PROJ_A)).record.id
        engine_a.forget(USER, ForgetTarget("memory", doomed))
    go.set()
    b.join(30)
    assert not b.is_alive()
    assert db_path(root, USER).is_file()  # A's database survived B's failure
    engine_a.close()
    return a_provider, keep, errors


@pytest.mark.parametrize("variant", ["locked", "wrong_key"])
@pytest.mark.parametrize("pause", ["existence_check", "database_open"])
def test_cd3_a_failed_first_open_never_deletes_another_openers_vault(tmp_path, monkeypatch, variant, pause):
    root = tmp_path / "root"
    b_provider = StaticKeyProvider({"k1": secrets.token_bytes(32)})  # same key id, other bytes
    if variant == "locked":
        b_provider.locked = True
    a_provider, keep, errors = _race_first_open(root, monkeypatch, b_provider, pause=pause,
                                                forget=pause == "database_open")
    assert errors and isinstance(errors[0], VaultLocked if variant == "locked" else WrongKey), errors
    monkeypatch.undo()
    reopened = MemoryEngine(root, a_provider)
    try:
        assert [r.id for r in reopened.list(USER)] == [keep]
    finally:
        reopened.close()
    assert not list(partition_dir(root, USER).glob(".memory.sqlite3.*"))  # no staging file left


def test_cd3_a_failed_first_open_leaves_no_database_and_a_later_open_works(tmp_path):
    root = tmp_path / "root"
    locked = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    locked.locked = True
    with pytest.raises(VaultLocked):
        MemoryEngine(root, locked).list(USER)
    assert not db_path(root, USER).exists()
    assert not list(partition_dir(root, USER).glob(".memory.sqlite3.*"))
    locked.locked = False
    engine = MemoryEngine(root, locked)
    try:
        record = engine.remember(USER, RememberRequest(content="first write", scope=PROJ_A)).record
        assert [r.id for r in engine.list(USER)] == [record.id]
    finally:
        engine.close()


# =========================================================================== R2-CD-4
SECRET_PROJECT = "acquisition-of-initech"


@pytest.fixture
def sealed_requests(monkeypatch):
    """(payload, inserted forget_requests row) of every forget request, captured at insert time."""
    captured = []
    original = Partition.record_forget_request

    def spy(self, kind, token, policy, key_token, payload):
        marker = original(self, kind, token, policy, key_token, payload)
        row = self.ledger.db.conn.execute("SELECT ciphertext FROM forget_requests WHERE marker_id=?",
                                          (marker,)).fetchone()
        captured.append((payload, bytes(row[0])))
        return marker

    monkeypatch.setattr(Partition, "record_forget_request", spy)
    return captured


def test_cd4_a_completed_forget_leaves_no_sealed_request_on_disk(make_engine, root, sealed_requests):
    access = access_for(projects=("proj-a", SECRET_PROJECT))
    engine = make_engine()
    engine.remember(access, RememberRequest(content="board approved the deal",
                                            scope=Scope.of(project=SECRET_PROJECT)))
    receipt = engine.forget(access, ForgetTarget("project", SECRET_PROJECT))
    assert receipt.physical_purge_pending is False
    (payload, ciphertext), = sealed_requests
    # The request never names the target (the store keeps it only as a keyed token) ...
    assert payload["target"] == {"kind": "project"}
    assert SECRET_PROJECT not in json.dumps(payload["target"])
    # ... and its sealed bytes are gone from every partition file, the ledger WAL included.
    assert _files_containing(partition_dir(root, access), ciphertext) == []


def test_cd4_the_ledger_is_scrubbed_while_another_engine_keeps_it_open(make_engine, root, sealed_requests):
    access = access_for(projects=(SECRET_PROJECT,))
    a, b = make_engine(), make_engine()
    b.partition_context(access.partition)  # a second holder of the ledger file
    a.remember(access, RememberRequest(content="secret", scope=Scope.of(project=SECRET_PROJECT)))
    assert a.forget(access, ForgetTarget("project", SECRET_PROJECT)).physical_purge_pending is False
    ciphertext = sealed_requests[0][1]
    assert _files_containing(partition_dir(root, access), ciphertext) == []
    a.close()
    assert _files_containing(partition_dir(root, access), ciphertext) == []


# =========================================================================== R2-CD-5
DISK_FULL_CHILD = textwrap.dedent(r'''
    import json, resource, secrets, signal, sys
    sys.path.insert(0, %(tests)r)
    from conftest import access_for
    from locus_memory import MemoryEngine, StaticKeyProvider
    from locus_memory.models import ForgetTarget, RememberRequest, Scope

    access = access_for(projects=("proj-a",))
    scope = Scope.of(project="proj-a")
    engine = MemoryEngine(sys.argv[1], StaticKeyProvider({"k1": secrets.token_bytes(32)}))
    ids = [engine.remember(access, RememberRequest(content=f"fact {i} " + "x" * 50, scope=scope)).record.id
           for i in range(5)]
    ctx = engine.partition_context(access.partition)
    ctx.partition.db.checkpoint(); ctx.partition.ledger.db.checkpoint()
    # A full disk: any write growing a file past 40000 bytes fails (EFBIG).
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (40000, resource.RLIM_INFINITY))
    out = {}

    def attempt(label, call):
        try:
            call()
            out[label] = {"ok": True}
        except BaseException as exc:
            out[label] = {"ok": False, "mro": [k.__name__ for k in type(exc).__mro__],
                          "code": getattr(exc, "code", None)}

    attempt("remember", lambda: engine.remember(access, RememberRequest(content="y" * 30000, scope=scope)))
    attempt("forget", lambda: engine.forget(access, ForgetTarget("memory", ids[0])))
    attempt("get", lambda: engine.get(access, ids[1]))
    resource.setrlimit(resource.RLIMIT_FSIZE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    attempt("get_after_space_freed", lambda: engine.get(access, ids[1]))
    attempt("forgotten_after_space_freed", lambda: engine.get(access, ids[0]))
    engine.close()
    print("RESULT " + json.dumps(out))
''') % {"tests": str(TESTS)}


@pytest.mark.skipif(sys.platform.startswith("win"), reason="RLIMIT_FSIZE is POSIX-only")
def test_cd5_a_full_disk_is_a_typed_storage_error_not_contention(tmp_path):
    done = subprocess.run([sys.executable, "-c", DISK_FULL_CHILD, str(tmp_path / "vault")],
                          capture_output=True, text=True, timeout=180)
    lines = [line for line in done.stdout.splitlines() if line.startswith("RESULT ")]
    assert lines, done.stdout + done.stderr
    out = json.loads(lines[0][len("RESULT "):])
    for label in ("remember", "forget", "get"):
        result = out[label]
        assert not result["ok"], (label, result)
        assert "StorageUnavailable" in result["mro"] and "MemoryEngineError" in result["mro"], (label, result)
        assert "Contention" not in result["mro"], (label, result)
        assert result["code"] in ("storage_unavailable", "storage_full"), (label, result)
    assert out["get_after_space_freed"]["ok"], out
    assert not out["forgotten_after_space_freed"]["ok"]  # the forget was applied once it could be


def test_cd5_sqlite_full_is_storage_full(make_engine):
    engine = make_engine()
    engine.remember(USER, RememberRequest(content="first", scope=PROJ_A))
    partition = engine.partition_context(USER.partition).partition
    conn = partition.db.conn
    pages = int(conn.execute("PRAGMA page_count").fetchone()[0])
    conn.execute(f"PRAGMA max_page_count={pages}")
    with pytest.raises(StorageFull) as info:
        engine.remember(USER, RememberRequest(content="z" * 30_000, scope=PROJ_A))
    assert info.value.code == "storage_full" and not isinstance(info.value, Contention)
    assert isinstance(info.value.__cause__, sqlite3.Error)
    conn.execute("PRAGMA max_page_count=1073741823")
    engine.remember(USER, RememberRequest(content="fits again", scope=PROJ_A))


def _chmod_tree(path: Path, *, readonly: bool) -> None:
    for item in [path, *path.rglob("*")]:
        if item.is_dir():
            os.chmod(item, 0o500 if readonly else 0o700)
        else:
            os.chmod(item, 0o400 if readonly else 0o600)


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs POSIX permissions (not root)")
def test_cd5_a_read_only_vault_raises_a_typed_error(tmp_path):
    root, key = tmp_path / "vault", secrets.token_bytes(32)
    engine = MemoryEngine(root, StaticKeyProvider({"k1": key}))
    engine.remember(USER, RememberRequest(content="fact one", scope=PROJ_A))
    engine.close()
    _chmod_tree(root, readonly=True)
    try:
        engine = MemoryEngine(root, StaticKeyProvider({"k1": key}))
        try:
            with pytest.raises(MemoryEngineError) as info:
                engine.remember(USER, RememberRequest(content="fact two", scope=PROJ_A))
        finally:
            engine.close()
    finally:
        _chmod_tree(root, readonly=False)
    assert isinstance(info.value, StorageReadOnly) and info.value.code == "storage_read_only"
    assert isinstance(info.value, StorageUnavailable) and not isinstance(info.value, Contention)


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs POSIX permissions (not root)")
def test_cd5_the_cli_maps_storage_errors_to_their_own_exit_code(tmp_path, capsys):
    root = tmp_path / "cli-root"
    assert main(["--root", str(root), "--json", "init"]) == 0
    assert main(["--root", str(root), "--json", "remember", "first fact"]) == 0
    capsys.readouterr()
    vaults = [p for p in root.iterdir() if p.is_dir() and (p / Partition.DB_NAME).exists()]
    assert vaults
    for vault in vaults:
        _chmod_tree(vault, readonly=True)
    try:
        code = main(["--root", str(root), "--json", "remember", "second fact"])
        document = json.loads(capsys.readouterr().out)
    finally:
        for vault in vaults:
            _chmod_tree(vault, readonly=False)
    assert code == EXIT_STORAGE == 4
    assert document["error"] == "storage_read_only"


# =========================================================================== R2-HC-1
PATCH = REPO / "handoff" / "locus" / "0002-stage2-memory-adapter.patch"
HEADER = "Approved memory results (local user-controlled context):"
LEGACY_KEY = bytes(range(32))


def _new_file_from_patch(patch: str, path: str) -> str:
    """The content of a file the patch adds (``--- /dev/null``-style hunk ``@@ -0,0 +1,N @@``)."""
    lines = patch.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith(f"+++ b/{path}"))
    hunk = lines[start + 1]
    assert hunk.startswith("@@ -0,0 +1,"), hunk
    count = int(hunk.split("+1,")[1].split()[0])
    body = lines[start + 2:start + 2 + count]
    assert all(line.startswith("+") for line in body)
    return "".join(line[1:] for line in body)


@pytest.fixture
def host_adapter(tmp_path):
    """The Stage-2 ``memory_adapter`` module exactly as handoff patch 0002 adds it, in a stub host
    package (``sessions.strip_prompt_decoration`` and the Stage-1 ``memory._master_key`` custody)."""
    name = "stage2host_" + uuid.uuid4().hex[:8]
    package = tmp_path / "hostpkg" / name
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "sessions.py").write_text("def strip_prompt_decoration(text):\n    return text\n")
    (package / "memory.py").write_text(
        "class MemoryError(Exception):\n    pass\n\n\n"
        f"def _master_key(_explicit, _path, *, vault_path=None):\n    return {LEGACY_KEY!r}\n")
    (package / "memory_adapter.py").write_text(
        _new_file_from_patch(PATCH.read_text(), "agent/ollama_code/memory_adapter.py"))
    sys.path.insert(0, str(package.parent))
    try:
        yield importlib.import_module(f"{name}.memory_adapter")
    finally:
        sys.path.remove(str(package.parent))
        for module in [m for m in sys.modules if m == name or m.startswith(name + ".")]:
            del sys.modules[module]


@dataclass
class _Policy:
    recall_enabled: bool = True
    scopes: tuple = ("personal", "workspace", "agent")
    max_automatic_memories: int = 8
    max_automatic_tokens: int = 1200


@pytest.fixture
def host(tmp_path, host_adapter):
    app, workspace = tmp_path / "app", tmp_path / "ws"
    workspace.mkdir()
    vault = LegacyMemoryVault(app / "memory" / "memory.sqlite3", key=LEGACY_KEY)
    adapter = host_adapter.MemoryAdapter(app_dir=app, edition="Locus", mode="enabled")
    core = types.SimpleNamespace(workspace_root=str(workspace), cwd=str(workspace), identity_mode=False,
                                 memory_context="", session=types.SimpleNamespace(session_id="s1"),
                                 reset_system_message=lambda: None)
    yield types.SimpleNamespace(module=host_adapter, adapter=adapter, vault=vault, core=core, ws=str(workspace))
    adapter.close()


def _recall(host, query="what is the weather in Paris", **kwargs):
    return host.adapter.recall(host.core, query, _Policy(), just_chat=kwargs.get("just_chat", False),
                               agent_id="primary", legacy=lambda: host.module.LegacyRecall(""))


def test_hc1_the_adapter_checks_the_header_the_model_tool_returns(host_adapter):
    assert host_adapter.LEGACY_RESULTS_HEADER == HEADER


@pytest.mark.parametrize("where", ["content", "title"])
def test_hc1_an_approved_memory_quoting_the_legacy_header_is_recalled(host, where):
    value = {"scope": "personal", "kind": "preference", "title": "Recall notes",
             "content": "Copied from chat: prefer tabs"}
    value[where] = HEADER + " " + value[where]
    candidate = host.vault.save(value, workspace=host.ws, default_status="candidate")
    assert host.vault.approve(candidate["id"], workspace=host.ws)["status"] == "approved"
    for query in ("which indentation do I prefer?", "what is the weather in Paris", "hello"):
        text = _recall(host, query)  # never raises; the preference is served inside the packet
        assert text.count(CONTEXT_WRAPPER_OPEN) == 1 and HEADER in text and "prefer tabs" in text
    assert CONTEXT_WRAPPER_OPEN in _recall(host, "hi", just_chat=True)
    host.core.memory_context = _recall(host)
    host.adapter.revalidate_before_use(host.core)
    assert "prefer tabs" in host.core.memory_context
    assert "adapter.layer_violation" not in host.adapter.engine.metrics.snapshot()["counters"]


def test_hc1_revalidation_of_a_memory_edited_to_quote_the_header_does_not_fail(host):
    record = host.vault.save({"scope": "personal", "kind": "preference", "title": "Indentation",
                              "content": "prefer tabs"}, workspace=host.ws)
    host.core.memory_context = _recall(host, "tabs")
    host.vault.save({"scope": "personal", "kind": "preference", "title": "Indentation",
                     "content": HEADER + " prefer spaces"}, record["id"], workspace=host.ws)
    host.adapter.revalidate_before_use(host.core)  # recompiled, never raises
    assert "prefer spaces" in host.core.memory_context and "prefer tabs" not in host.core.memory_context


def test_hc1_a_genuine_double_layer_is_detected_but_never_fails_the_turn(host, monkeypatch):
    host.vault.save({"scope": "personal", "kind": "preference", "title": "Style",
                     "content": "prefer concise answers"}, workspace=host.ws)
    packet = _recall(host)
    check = host.module.assert_single_memory_layer
    check(packet)
    with pytest.raises(AssertionError):
        check(HEADER + "\n- a legacy item\n\n" + packet)  # a legacy layer outside the packet
    with pytest.raises(AssertionError):
        check(packet + "\n" + packet)  # two packets
    with pytest.raises(AssertionError):
        check(HEADER + "\n" + packet[:60])  # a legacy layer before a packet the host truncated
    check(packet[:60])  # a truncated packet alone (its tail, close tag included, cut off) is fine

    def tripped(_text):
        raise AssertionError("memory was injected twice (engine packet and legacy layer)")

    monkeypatch.setattr(host.module, "assert_single_memory_layer", tripped)
    assert _recall(host) == ""  # fail closed: no engine memory, and the turn goes on
    host.core.memory_context = HEADER + "\n" + packet
    host.adapter.revalidate_before_use(host.core)  # nothing pending: no-op, no raise
    counters = host.adapter.engine.metrics.snapshot()["counters"]
    assert counters["adapter.layer_violation"]["value"] >= 1


# =========================================================================== R2-ROB-2
OTHERS = [access_for(projects=("proj-a",), agents=(f"x{i}",)) for i in range(4)]


def _event(i: int, session: str = "s1") -> IngestionEvent:
    return IngestionEvent(event_id=f"{session}-e{i}", session_ref=session, sequence=i, role="user",
                          text=f"hello world {i}", occurred_at=1_700_000_000.0 + i, scope=PROJ_A)


def test_rob2_an_evicting_search_never_blocks_a_forget(make_engine, monkeypatch):
    engine = make_engine(config=EngineConfig(history_hydration_batch=5))
    archive = engine.services(USER).history
    assert isinstance(archive, HistoryArchive)
    archive.ingest_batch(USER, [_event(i) for i in range(60)])
    archive.ingest_batch(USER, [_event(0, "s2")])
    started = threading.Event()
    original = HistoryArchive._hydrate_batch

    def slow(self, proj, grants, batch):
        if grants == USER.grants:
            started.set()
            time.sleep(0.25)  # a decrypt-heavy batch; the projection lock is held
        return original(self, proj, grants, batch)

    monkeypatch.setattr(HistoryArchive, "_hydrate_batch", slow)
    results: dict = {}
    searcher = threading.Thread(target=lambda: results.setdefault("a", engine.search_history(USER, "hello")))
    searcher.start()
    assert started.wait(10)
    time.sleep(0.1)
    # Four new grant sets: the fifth projection evicts the one being hydrated.
    evictor = threading.Thread(target=lambda: [engine.search_history(a, "hello") for a in OTHERS])
    evictor.start()
    time.sleep(0.5)
    # The evicting search never parks inside the archive lock (waiting on the hydrating projection).
    assert archive._lock.acquire(blocking=False), "an evicting search holds the archive lock"
    archive._lock.release()
    started_at = time.monotonic()
    engine.forget(USER, ForgetTarget("session", "s2"))  # its purge needs the archive lock
    assert time.monotonic() - started_at < 1.5
    started_at = time.monotonic()
    archive.ingest_batch(USER, [_event(0, "s3")])  # an unrelated writer is not stalled either
    assert time.monotonic() - started_at < 1.5
    evictor.join(60)
    searcher.join(60)
    assert not evictor.is_alive() and not searcher.is_alive()
    hits = results["a"].hits
    assert hits and all(hit.message.session_ref != "s2" for hit in hits)


def test_rob2_an_evicted_projection_is_closed_once_its_search_answers(make_engine):
    engine = make_engine()
    archive = engine.services(USER).history
    archive.ingest_batch(USER, [_event(i) for i in range(3)])
    engine.search_history(USER, "hello")
    first = archive._projections[USER.grants.fingerprint()]
    for access in OTHERS:
        engine.search_history(access, "hello")
    assert first.evicted and first.closed  # nobody held it: closed right away
    assert USER.grants.fingerprint() not in archive._projections


# =========================================================================== R2-ROB-3
GIT = shutil.which("git")
REPO_ACCESS = access_for(repositories=("repo-a",), projects=("proj-a",))


def _repository_engine(tmp_path: Path, make_engine, files: int, **config):
    from test_repository import PY_MODULE, make_repo

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    sources = {f"pkg/m{i}.py": PY_MODULE.replace("Widget", f"Widget{i}") for i in range(files)}
    repo = make_repo(allowed / "repo", sources)
    engine = make_engine(host=HostCapabilities(allowed_repository_roots=(allowed,)),
                         config=EngineConfig(**config) if config else None)
    engine.register_repository(REPO_ACCESS, repo, repository_id="repo-a")
    return engine


def _on_first_create(monkeypatch, hook):
    original = RepositoryService._create_observation
    calls = []

    def wrapped(self, *args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            hook()
        return original(self, *args, **kwargs)

    monkeypatch.setattr(RepositoryService, "_create_observation", wrapped)
    return calls


@pytest.mark.skipif(GIT is None, reason="git is required")
def test_rob3_a_deadline_passing_during_the_commit_records_a_partial_snapshot(tmp_path, make_engine,
                                                                              monkeypatch):
    files = 1200
    engine = _repository_engine(tmp_path, make_engine, files)
    now = [0.0]
    monkeypatch.setattr(repo_service, "Deadline", lambda ms: Deadline(ms, clock=lambda: now[0]))

    def expire():
        now[0] = 1e9  # the deadline passes inside the first commit batch

    _on_first_create(monkeypatch, expire)
    first = engine.snapshot_repository(REPO_ACCESS, "repo-a", deadline_ms=1000, max_files=files)
    assert first["state"] == "partial"
    assert "deadline" in first["coverage"]["partial_reasons"] and not first["coverage"]["complete"]
    created = first["counts"]["observations_created"]
    assert 0 < created < files
    assert first["coverage"]["not_parsed_stopped"] == files - created
    status = engine.services(REPO_ACCESS).repository.status(REPO_ACCESS, "repo-a")
    assert json.dumps(status).count(first["snapshot_id"]) >= 1
    monkeypatch.undo()
    # The next snapshot resumes: what the stopped one settled is reused, the rest is created.
    second = engine.snapshot_repository(REPO_ACCESS, "repo-a", max_files=files)
    assert second["state"] == "complete"
    assert second["counts"]["observations_reused"] == created
    assert second["counts"]["observations_created"] == files - created


@pytest.mark.skipif(GIT is None, reason="git is required")
def test_rob3_cancellation_during_the_commit_records_a_partial_snapshot(tmp_path, make_engine, monkeypatch):
    files = 1200
    engine = _repository_engine(tmp_path, make_engine, files)
    token = CancellationToken()
    _on_first_create(monkeypatch, lambda: token.cancel("host shutting down"))
    result = engine.snapshot_repository(REPO_ACCESS, "repo-a", cancel=token, max_files=files)
    assert result["state"] == "partial" and "cancelled" in result["coverage"]["partial_reasons"]
    assert result["counts"]["observations_created"] < files


@pytest.mark.skipif(GIT is None, reason="git is required")
def test_rob3_a_forget_during_a_long_snapshot_commit_is_not_starved(tmp_path, make_engine, monkeypatch):
    files = 900
    engine = _repository_engine(tmp_path, make_engine, files, busy_timeout_ms=300)
    doomed = engine.remember(REPO_ACCESS, RememberRequest(content="some fact", scope=PROJ_A)).record
    original = RepositoryService._create_observation
    committing = threading.Event()

    def slow(self, *args, **kwargs):
        committing.set()
        time.sleep(0.004)  # ~3.6 s of commit work in all (the busy budget is ~1.6 s)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(RepositoryService, "_create_observation", slow)
    outcome: dict = {}

    def forget():
        assert committing.wait(30)
        time.sleep(0.2)
        started = time.monotonic()
        try:
            engine.forget(REPO_ACCESS, ForgetTarget("memory", doomed.id))
            outcome["forget"] = ("ok", time.monotonic() - started)
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertions
            outcome["forget"] = (type(exc).__name__, time.monotonic() - started)

    worker = threading.Thread(target=forget)
    worker.start()
    result = engine.snapshot_repository(REPO_ACCESS, "repo-a", max_files=files)
    worker.join(60)
    kind, waited = outcome["forget"]
    assert kind == "ok", outcome
    assert waited < 1.5
    assert result["state"] == "complete" and result["counts"]["observations_created"] == files
    assert _alive(engine, REPO_ACCESS, doomed.id) is None
