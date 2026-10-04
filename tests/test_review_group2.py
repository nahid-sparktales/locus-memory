"""Review group 2: key rotation must remove the replaced key material from the on-disk files.

Defect ``rotation-no-checkpoint``: ``rotate_master_key(drop_old=True)`` and a completed
``rotate_data_key`` deleted the old wraps (and, for data keys, re-sealed every row) only
inside a WAL transaction and never checkpointed. ``memory.sqlite3`` kept the
pre-rotation pages until an auto-checkpoint or close, so a retired master key plus a
file-level copy of the running vault still unwrapped the (unchanged) data and HMAC keys,
and a retired DEK still opened the old ciphertexts.

The tests copy / scan the raw vault files the way a stolen disk or a file-level backup
of a running host would, instead of asking SQLite (which would read through the WAL).
"""
from __future__ import annotations

import secrets
import shutil
import sqlite3
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from conftest import access_for
from foundation_support import db_path, files_containing, partition_dir
from locus_memory import StaticKeyProvider, admin
from locus_memory.errors import AccessDenied
from locus_memory.models import Actor, Correction, Operation, RememberRequest, Scope

FORMAT_TAG = b"locus-memory/v1"
PROJ_A = Scope.of(project="proj-a")


def remember(engine, access, text):
    return engine.remember(access, RememberRequest(content=text, scope=PROJ_A)).record


def wrap_aad(pid: str, dek_id: str, master_id: str, purpose: str) -> bytes:
    return b"|".join([FORMAT_TAG, b"wrap", pid.encode(), dek_id.encode(), master_id.encode(),
                      purpose.encode()])


def read_rows(path: Path, sql: str, params: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        return [tuple(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def main_file_copy(path: Path, dest: Path) -> Path:
    """What a file-level copy of the main database file alone yields (no -wal next to it)."""
    shutil.copyfile(path, dest)
    return dest


def unwrap_with(copy: Path, pid: str, master_id: str, master_key: bytes) -> dict[tuple[str, str], bytes]:
    out = {}
    for dek_id, purpose, nonce, wrapped in read_rows(
            copy, "SELECT dek_id, purpose, nonce, wrapped FROM key_wraps WHERE master_key_id=?", (master_id,)):
        try:
            out[(dek_id, purpose)] = AESGCM(master_key).decrypt(
                bytes(nonce), bytes(wrapped), wrap_aad(pid, dek_id, master_id, purpose))
        except InvalidTag:
            pass
    return out


def files_holding_any(directory: Path, needles: list[bytes]) -> set[str]:
    hits: set[str] = set()
    for needle in needles:
        hits |= {p.name for p in files_containing(directory, needle)}
    return hits


def stored_receipt(ctx, receipt_id: str) -> dict:
    with ctx.partition.db.read() as conn:
        return ctx.partition.load_receipt(conn, receipt_id)


@pytest.fixture
def two_keys():
    return secrets.token_bytes(32), secrets.token_bytes(32)


# ---------------------------------------------------------------------------- master key
@pytest.mark.parametrize("prime", ["close_reopen", "explicit_checkpoint"])
def test_master_rotation_drop_old_removes_old_wraps_from_the_vault_files(
        make_engine, root, user_access, tmp_path, two_keys, prime):
    k_old, k_new = two_keys
    keys = StaticKeyProvider({"old": k_old})
    engine = make_engine(key_provider=keys)
    record = remember(engine, user_access, "secret fact alpha")
    if prime == "close_reopen":
        engine.close()  # an earlier session ended normally: the old wraps sit in the main file
        engine = make_engine(key_provider=keys)
        assert engine.get(user_access, record.id).content == "secret fact alpha"
    else:
        engine.partition_context(user_access.partition).partition.db.checkpoint()
    ctx = engine.partition_context(user_access.partition)
    pid, main = ctx.partition.partition_id, db_path(root, user_access)
    old_wraps = [bytes(r[0]) for r in read_rows(main, "SELECT wrapped FROM key_wraps WHERE master_key_id='old'")]
    assert len(old_wraps) == 2  # the data key and the HMAC key
    assert files_holding_any(partition_dir(root, user_access), old_wraps) == {"memory.sqlite3"}

    keys.add("new", k_new, make_current=True)
    receipt = engine.rotate_master_key(user_access, "new", drop_old=True)

    assert receipt.status == "ok" and receipt.details["master_key_ids"] == ["new"]
    # Neither the main file, nor the WAL, nor anything else in the partition holds an old wrap.
    copy = main_file_copy(main, tmp_path / "copy.sqlite3")
    assert unwrap_with(copy, pid, "old", k_old) == {}, "the retired master key still opens the main file"
    assert read_rows(copy, "SELECT DISTINCT master_key_id FROM key_wraps") == [("new",)]
    assert files_holding_any(partition_dir(root, user_access), old_wraps) == set()
    assert receipt.details["flushed"] is True
    assert admin.UNFLUSHED_LIMITATION not in receipt.limitations
    assert admin.PRE_ROTATION_COPIES_LIMITATION in receipt.limitations
    # The stored receipt matches the returned one.
    stored = stored_receipt(ctx, receipt.receipt_id)
    assert stored["details"]["flushed"] is True
    assert admin.UNFLUSHED_LIMITATION not in stored["limitations"]
    # Data stays readable with the new master key alone.
    engine.close()
    only_new = make_engine(key_provider=StaticKeyProvider({"new": k_new}))
    assert only_new.get(user_access, record.id).content == "secret fact alpha"


def test_master_rotation_keeping_old_wraps_still_flushes(make_engine, root, user_access, two_keys, tmp_path):
    k_old, k_new = two_keys
    keys = StaticKeyProvider({"old": k_old})
    engine = make_engine(key_provider=keys)
    remember(engine, user_access, "fact")
    pid = engine.partition_context(user_access.partition).partition.partition_id
    keys.add("new", k_new)
    receipt = engine.rotate_master_key(user_access, "new", drop_old=False)
    assert receipt.details["flushed"] is True
    assert receipt.details["master_key_ids"] == ["new", "old"]
    # The new wraps were folded into the main file: a copy of it alone opens with either key.
    copy = main_file_copy(db_path(root, user_access), tmp_path / "copy.sqlite3")
    assert set(unwrap_with(copy, pid, "new", k_new)) == set(unwrap_with(copy, pid, "old", k_old))
    assert len(unwrap_with(copy, pid, "new", k_new)) == 2


# ---------------------------------------------------------------------------- data key
def test_completed_data_key_rotation_removes_retired_dek_material_from_the_vault_files(
        make_engine, root, user_access, tmp_path):
    engine = make_engine()
    ids = []
    for i in range(5):
        record = remember(engine, user_access, f"secret fact {i}")
        engine.correct(user_access, record.id, Correction(content=f"corrected secret fact {i}"),
                       expected_revision=1)
        ids.append(record.id)
    ctx = engine.partition_context(user_access.partition)
    ctx.partition.db.checkpoint()  # the old-DEK material is in the main file
    main = db_path(root, user_access)
    old_dek = ctx.partition.keyring.current_dek_id
    conn = sqlite3.connect(main)
    try:
        tables = admin.sealed_tables(conn)
        old_material = [bytes(r[0]) for r in conn.execute(
            "SELECT wrapped FROM key_wraps WHERE dek_id=?", (old_dek,))]
        for table in tables:
            # A 24-byte prefix stays in the b-tree cell even if a payload overflows.
            old_material += [bytes(r[0])[:24] for r in conn.execute(
                f'SELECT ciphertext FROM "{table}" WHERE dek_id=?', (old_dek,))]
    finally:
        conn.close()
    assert len(old_material) >= 1 + 5 + 10  # the wrap, records, revisions (and receipts)
    assert files_holding_any(partition_dir(root, user_access), old_material) == {"memory.sqlite3"}

    in_progress = engine.rotate_data_key(user_access, batch=4)
    assert in_progress["state"] == "in_progress"
    report = engine.rotate_data_key(user_access, batch=1000)

    assert report["state"] == "complete" and report["retired"] == [old_dek]
    copy = main_file_copy(main, tmp_path / "copy.sqlite3")
    assert read_rows(copy, "SELECT COUNT(*) FROM key_wraps WHERE dek_id=?", (old_dek,)) == [(0,)], \
        "the retired DEK is still wrapped in the main file"
    for table in tables:
        assert read_rows(copy, f'SELECT COUNT(*) FROM "{table}" WHERE dek_id=?', (old_dek,)) == [(0,)], \
            f"{table} rows sealed under the retired DEK linger in the main file"
    assert files_holding_any(partition_dir(root, user_access), old_material) == set()
    # Only the completing call removes key material, so only it reports a flush.
    assert in_progress["flushed"] is None and report["flushed"] is True
    stored = stored_receipt(ctx, report["receipt_id"])
    assert stored["status"] == "ok" and stored["details"]["flushed"] is True
    assert all(engine.get(user_access, i).content.startswith("corrected secret fact") for i in ids)


# ---------------------------------------------------------------------------- blocked flush
@pytest.fixture
def pinned_reader(root, user_access):
    """A reader holding a snapshot from before the rotation (blocks a TRUNCATE checkpoint)."""
    holders: list[sqlite3.Connection] = []

    def pin() -> sqlite3.Connection:
        conn = sqlite3.connect(db_path(root, user_access), isolation_level=None)
        conn.execute("BEGIN")
        conn.execute("SELECT COUNT(*) FROM key_wraps").fetchone()
        holders.append(conn)
        return conn

    yield pin
    for conn in holders:
        conn.close()


def _short_busy_timeout(ctx) -> None:
    # Each checkpoint attempt waits up to the busy timeout for the pinned reader.
    ctx.partition.db.conn.execute("PRAGMA busy_timeout=20")


def test_master_rotation_reports_unflushed_when_a_reader_pins_the_old_snapshot(
        make_engine, root, user_access, two_keys, pinned_reader):
    k_old, k_new = two_keys
    keys = StaticKeyProvider({"old": k_old})
    engine = make_engine(key_provider=keys)
    remember(engine, user_access, "secret fact beta")
    ctx = engine.partition_context(user_access.partition)
    ctx.partition.db.checkpoint()
    main = db_path(root, user_access)
    old_wraps = [bytes(r[0]) for r in read_rows(main, "SELECT wrapped FROM key_wraps WHERE master_key_id='old'")]
    _short_busy_timeout(ctx)
    reader = pinned_reader()
    keys.add("new", k_new, make_current=True)

    started = time.monotonic()
    receipt = engine.rotate_master_key(user_access, "new", drop_old=True)
    assert time.monotonic() - started < 5  # bounded retries, not an indefinite wait

    # The rotation committed, but the host is told the old wraps are still on disk.
    assert receipt.status == "ok" and receipt.details["master_key_ids"] == ["new"]
    assert receipt.details["flushed"] is False
    assert admin.UNFLUSHED_LIMITATION in receipt.limitations
    assert stored_receipt(ctx, receipt.receipt_id)["details"]["flushed"] is False
    assert "memory.sqlite3" in files_holding_any(partition_dir(root, user_access), old_wraps)

    # The retry path: once the reader is gone, the flush is confirmed and the wraps are gone.
    reader.execute("COMMIT")
    assert admin.flush_key_material(ctx, user_access) is True
    assert files_holding_any(partition_dir(root, user_access), old_wraps) == set()


def test_completed_data_key_rotation_reports_unflushed_when_a_reader_pins_the_old_snapshot(
        make_engine, root, user_access, pinned_reader):
    engine = make_engine()
    remember(engine, user_access, "secret fact gamma")
    ctx = engine.partition_context(user_access.partition)
    ctx.partition.db.checkpoint()
    main = db_path(root, user_access)
    old_dek = ctx.partition.keyring.current_dek_id
    old_wrap = read_rows(main, "SELECT wrapped FROM key_wraps WHERE dek_id=?", (old_dek,))[0][0]
    _short_busy_timeout(ctx)
    reader = pinned_reader()

    report = engine.rotate_data_key(user_access, batch=1000)
    assert report["state"] == "complete" and report["flushed"] is False
    stored = stored_receipt(ctx, report["receipt_id"])
    assert stored["details"]["flushed"] is False
    assert admin.UNFLUSHED_LIMITATION in stored["limitations"]
    assert files_containing(partition_dir(root, user_access), bytes(old_wrap))

    reader.execute("COMMIT")
    assert admin.flush_key_material(ctx, user_access) is True
    assert files_containing(partition_dir(root, user_access), bytes(old_wrap)) == []


def test_flush_key_material_is_a_user_or_host_admin_action(make_engine, user_access):
    engine = make_engine()
    remember(engine, user_access, "fact")
    ctx = engine.partition_context(user_access.partition)
    no_admin = access_for(projects=("proj-a",), operations=set(Operation) - {Operation.ADMIN})
    agent = access_for(actor=Actor.AGENT, projects=("proj-a",))
    for access in (no_admin, agent):
        with pytest.raises(AccessDenied):
            admin.flush_key_material(ctx, access)
    assert admin.flush_key_material(ctx, user_access) is True
