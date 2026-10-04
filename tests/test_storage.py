"""Persistence, key custody, rotation, tamper detection, plaintext-at-rest guarantees,
open-existing-only mode and the engine's plaintext export document."""
from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import stat
import subprocess
import sys
import textwrap

import pytest

from conftest import CANARY, access_for, scan_for_plaintext
from foundation_support import (
    count,
    db_path,
    files_containing,
    key_wraps_snapshot,
    ledger_path,
    raw_db,
)
from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.errors import (
    AccessDenied,
    IntegrityError,
    MemoryEngineError,
    MigrationError,
    NotFound,
    SensitiveContent,
    ValidationError,
    VaultLocked,
    WrongKey,
)
from locus_memory.models import (
    CandidateProposal,
    Correction,
    ForgetTarget,
    Lifecycle,
    Operation,
    RememberRequest,
    Scope,
    SourceKind,
    SourceRef,
)
from locus_memory.storage import schema
from locus_memory.storage.partition import Partition

PROJ_A = Scope.of(project="proj-a")
DOC = SourceRef(SourceKind.DOCUMENT, "doc-1")


def remember(engine, access, content, scope=PROJ_A, **kw):
    return engine.remember(access, RememberRequest(content=content, scope=scope, **kw)).record


# ---------------------------------------------------------------------------- install / restart / schema
def test_constructing_an_engine_touches_nothing(root, keys):
    MemoryEngine(root, keys).close()
    assert not root.exists()


def test_fresh_install_creates_private_encrypted_store(engine, root, user_access):
    status = engine.status(user_access)
    pdir = root / user_access.partition.partition_id
    assert stat.S_IMODE(pdir.stat().st_mode) == 0o700
    assert stat.S_IMODE(db_path(root, user_access).stat().st_mode) == 0o600
    assert ledger_path(root, user_access).exists()
    assert status.schema_version == schema.SCHEMA_VERSION
    assert status.cipher == "AES-256-GCM" and status.key_id
    assert status.counts == {} and status.generation == 0 and status.deletion_generation == 0
    wraps = key_wraps_snapshot(db_path(root, user_access))
    assert sorted(w[2] for w in wraps) == ["data", "hmac"]
    with raw_db(db_path(root, user_access)) as conn:
        assert conn.execute("SELECT value FROM meta WHERE key='partition_id'").fetchone()[0] == \
            user_access.partition.partition_id
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_restart_preserves_records_generation_and_keys(make_engine, root, user_access):
    first = make_engine()
    record = remember(first, user_access, "persisted fact")
    generation = first.status(user_access).generation
    wraps = key_wraps_snapshot(db_path(root, user_access))
    first.close()
    second = make_engine()
    assert second.get(user_access, record.id).content == "persisted fact"
    assert second.status(user_access).generation == generation
    assert key_wraps_snapshot(db_path(root, user_access)) == wraps


def test_migration_from_an_empty_file(make_engine, root, user_access):
    path = db_path(root, user_access)
    path.parent.mkdir(parents=True)
    path.touch()
    engine = make_engine()
    assert engine.status(user_access).schema_version == schema.SCHEMA_VERSION
    assert remember(engine, user_access, "works").lifecycle == Lifecycle.APPROVED


def test_a_newer_schema_is_refused_without_changes(make_engine, root, user_access):
    make_engine().status(user_access)
    path = db_path(root, user_access)
    with raw_db(path) as conn:
        conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    wraps = key_wraps_snapshot(path)
    engine = make_engine()
    with pytest.raises(MigrationError):
        engine.status(user_access)
    with raw_db(path) as conn:
        assert conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == "99"
    assert key_wraps_snapshot(path) == wraps


def test_a_store_of_another_partition_is_refused(make_engine, root):
    alice, bob = access_for(profile="alice"), access_for(profile="bob")
    engine = make_engine()
    remember(engine, alice, "alice's fact", scope=Scope.global_())
    engine.status(bob)
    engine.close()
    shutil.copy(db_path(root, alice), db_path(root, bob))
    for suffix in ("-wal", "-shm"):
        (db_path(root, bob).parent / f"memory.sqlite3{suffix}").unlink(missing_ok=True)
    with pytest.raises(MigrationError):
        make_engine().status(bob)


def test_failed_open_releases_every_handle(make_engine, root, user_access, monkeypatch):
    make_engine().status(user_access)
    closed = []
    original = Partition.close
    monkeypatch.setattr(Partition, "close", lambda self: (closed.append(self), original(self))[1])
    with pytest.raises(WrongKey):
        make_engine(key_provider=StaticKeyProvider({"k1": secrets.token_bytes(32)})).status(user_access)
    assert len(closed) == 1
    assert closed[0].db.open_connections == 0 and closed[0].db._closed


# ---------------------------------------------------------------------------- open-existing-only mode
def test_open_existing_only_engine_refuses_a_missing_vault_and_creates_nothing(keys, root, user_access):
    engine = MemoryEngine(root, keys, create_partitions=False)
    try:
        with pytest.raises(NotFound):
            engine.status(user_access)
        with pytest.raises(NotFound):
            engine.remember(user_access, RememberRequest(content="never stored", scope=PROJ_A))
        with pytest.raises(NotFound):
            engine.export(user_access)
    finally:
        engine.close()
    assert not root.exists()  # no root, partition directory, database, ledger or key wraps


def test_partition_create_false_is_a_typed_not_found(keys, root, user_access):
    with pytest.raises(NotFound):
        Partition(root, user_access.partition, keys, create=False)
    assert not root.exists()


def test_open_existing_only_engine_opens_a_vault_but_never_creates_a_mistyped_profile(
        make_engine, keys, root, user_access):
    record = remember(make_engine(), user_access, "existing fact")
    wraps = key_wraps_snapshot(db_path(root, user_access))
    engine = MemoryEngine(root, keys, create_partitions=False)
    try:
        assert engine.get(user_access, record.id).content == "existing fact"
        assert remember(engine, user_access, "second fact").lifecycle == Lifecycle.APPROVED
        typo = access_for(profile="defualt", projects=("proj-a",))
        with pytest.raises(NotFound):
            engine.list(typo)
        with pytest.raises(NotFound):  # every call re-checks; nothing was cached or created
            engine.remember(typo, RememberRequest(content="lost write", scope=PROJ_A))
    finally:
        engine.close()
    assert sorted(p.name for p in root.iterdir()) == [user_access.partition.partition_id]
    assert key_wraps_snapshot(db_path(root, user_access)) == wraps  # never re-keyed


def test_open_existing_only_engine_never_initializes_an_empty_database_file(keys, root, user_access, monkeypatch):
    path = db_path(root, user_access)
    path.parent.mkdir(parents=True)
    path.touch()
    closed = []
    original = Partition.close
    monkeypatch.setattr(Partition, "close", lambda self: (closed.append(self), original(self))[1])
    engine = MemoryEngine(root, keys, create_partitions=False)
    try:
        with pytest.raises(NotFound):
            engine.status(user_access)
    finally:
        engine.close()
    assert len(closed) == 1 and closed[0].db.open_connections == 0  # every handle released
    with raw_db(path) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "key_wraps" not in tables and "meta" not in tables  # no schema, no keys
    assert not ledger_path(root, user_access).exists()


# ---------------------------------------------------------------------------- atomicity
def _row_counts(path):
    return {t: count(path, f"SELECT COUNT(*) FROM {t}")
            for t in ("records", "record_revisions", "record_scopes", "record_sources", "receipts",
                      "idempotency", "derivations")}


def test_exception_inside_a_write_leaves_no_partial_record(engine, root, user_access, monkeypatch):
    remember(engine, user_access, "baseline")
    path = db_path(root, user_access)
    before, generation = _row_counts(path), engine.status(user_access).generation

    def explode(*args, **kwargs):
        raise RuntimeError("crash after the record and revision were inserted")

    monkeypatch.setattr(Partition, "make_receipt", explode)
    with pytest.raises(RuntimeError):
        engine.remember(user_access, RememberRequest(content="half written", scope=PROJ_A), idempotency_key="k")
    monkeypatch.undo()
    assert _row_counts(path) == before
    assert engine.status(user_access).generation == generation
    assert [r.content for r in engine.list(user_access)] == ["baseline"]
    # The idempotency key was not consumed by the failed attempt.
    retry = engine.remember(user_access, RememberRequest(content="half written", scope=PROJ_A),
                            idempotency_key="k")
    assert not retry.receipt.idempotent_replay


CRASH_SCRIPT = textwrap.dedent("""
    import os, sys
    from locus_memory import MemoryEngine, StaticKeyProvider
    from locus_memory.models import AccessContext, Operation, PartitionRef, RememberRequest, Scope, ScopeGrants
    from locus_memory.storage.partition import Partition
    root, key = sys.argv[1], bytes.fromhex(sys.argv[2])
    access = AccessContext(principal="u", partition=PartitionRef("standard", "default"),
                           grants=ScopeGrants(projects=frozenset({"proj-a"})), operations=frozenset(Operation))
    engine = MemoryEngine(root, StaticKeyProvider({"k1": key}))
    engine.remember(access, RememberRequest(content="committed before the crash", scope=Scope.of(project="proj-a")))
    Partition.make_receipt = lambda *a, **k: os._exit(17)   # die mid-transaction, no cleanup
    engine.remember(access, RememberRequest(content="never committed", scope=Scope.of(project="proj-a")))
""")


def test_process_killed_mid_transaction_leaves_a_consistent_store(make_engine, root, user_access):
    key = secrets.token_bytes(32)
    result = subprocess.run([sys.executable, "-c", CRASH_SCRIPT, str(root), key.hex()],
                            capture_output=True, timeout=60)
    assert result.returncode == 17, result.stderr.decode()
    engine = make_engine(key_provider=StaticKeyProvider({"k1": key}))
    assert [r.content for r in engine.list(user_access)] == ["committed before the crash"]
    path = db_path(root, user_access)
    with raw_db(path) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert count(path, "SELECT COUNT(*) FROM record_revisions") == 1
    assert count(path, "SELECT COUNT(*) FROM receipts") == 1
    assert remember(engine, user_access, "store still writable").revision == 1


# ---------------------------------------------------------------------------- keys
def test_wrong_key_is_refused_and_never_replaced(make_engine, root, user_access):
    remember(make_engine(), user_access, "secret fact")
    path = db_path(root, user_access)
    wraps = key_wraps_snapshot(path)
    with pytest.raises(WrongKey):
        make_engine(key_provider=StaticKeyProvider({"k1": secrets.token_bytes(32)})).status(user_access)
    assert key_wraps_snapshot(path) == wraps


def test_missing_or_locked_key_is_vault_locked_and_never_replaced(make_engine, root, user_access):
    remember(make_engine(), user_access, "secret fact")
    path = db_path(root, user_access)
    wraps = key_wraps_snapshot(path)
    with pytest.raises(VaultLocked):
        make_engine(key_provider=StaticKeyProvider({"k2": secrets.token_bytes(32)})).status(user_access)
    locked = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    locked.locked = True
    with pytest.raises(VaultLocked):
        make_engine(key_provider=locked).status(user_access)
    assert key_wraps_snapshot(path) == wraps


def test_locked_provider_on_a_fresh_root_creates_no_keys(make_engine, keys, root, user_access):
    keys.locked = True
    with pytest.raises(VaultLocked):
        make_engine().status(user_access)
    path = db_path(root, user_access)
    if path.exists():
        with raw_db(path) as conn:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            assert "key_wraps" not in tables or not conn.execute("SELECT COUNT(*) FROM key_wraps").fetchone()[0]
    keys.locked = False
    engine = make_engine()
    remember(engine, user_access, "first write after unlock")
    assert len(key_wraps_snapshot(path)) == 2


def test_master_key_rotation(make_engine, keys, root, user_access):
    engine = make_engine()
    record = remember(engine, user_access, "survives master rotation")
    k2 = secrets.token_bytes(32)
    keys.add("k2", k2)
    no_admin = access_for(projects=("proj-a",), operations=set(Operation) - {Operation.ADMIN})
    with pytest.raises(AccessDenied):
        engine.rotate_master_key(no_admin, "k2")
    agent = access_for(actor="agent", projects=("proj-a",))
    with pytest.raises(AccessDenied):
        engine.rotate_master_key(agent, "k2")
    path = db_path(root, user_access)
    before = key_wraps_snapshot(path)
    with pytest.raises(VaultLocked):
        engine.rotate_master_key(user_access, "k-absent")
    assert key_wraps_snapshot(path) == before
    receipt = engine.rotate_master_key(user_access, "k2", drop_old=True)
    assert receipt.status == "ok" and receipt.details["master_key_ids"] == ["k2"]
    assert {w[1] for w in key_wraps_snapshot(path)} == {"k2"}
    engine.close()
    # The host can now delete the old master key.
    only_new = make_engine(key_provider=StaticKeyProvider({"k2": k2}))
    assert only_new.get(user_access, record.id).content == "survives master rotation"
    remember(only_new, user_access, "new write under rotated master")
    only_new.close()
    with pytest.raises(VaultLocked):
        make_engine(key_provider=StaticKeyProvider({"k1": keys.get_key("k1")})).status(user_access)


def test_master_key_rotation_keeping_old_wraps(make_engine, keys, root, user_access):
    engine = make_engine()
    record = remember(engine, user_access, "both keys open it")
    keys.add("k2", secrets.token_bytes(32))
    engine.rotate_master_key(user_access, "k2", drop_old=False)
    engine.close()
    for key_id in ("k1", "k2"):
        e = make_engine(key_provider=StaticKeyProvider({key_id: keys.get_key(key_id)}))
        assert e.get(user_access, record.id).content == "both keys open it"
        e.close()


def _dek_ids_in_use(path):
    with raw_db(path) as conn:
        ids = set()
        for table in ("records", "record_revisions", "receipts"):
            ids |= {r[0] for r in conn.execute(f"SELECT DISTINCT dek_id FROM {table} WHERE dek_id IS NOT NULL")}
        return ids


def _populate(engine, access, n=6):
    ids = []
    for i in range(n):
        record = remember(engine, access, f"fact number {i}")
        engine.correct(access, record.id, Correction(content=f"corrected fact number {i}"), expected_revision=1)
        ids.append(record.id)
    return ids


def test_data_key_rotation_is_progressive_and_keeps_old_data_readable(make_engine, root, user_access):
    engine = make_engine()
    ids = _populate(engine, user_access)
    path = db_path(root, user_access)
    old_dek = engine.status(user_access).key_id
    with pytest.raises(AccessDenied):
        engine.rotate_data_key(access_for(projects=("proj-a",), operations={Operation.READ, Operation.WRITE}))
    reports, written = [], []
    while True:
        report = engine.rotate_data_key(user_access, batch=4)
        reports.append(report)
        # Old and new data are readable and writable at every step.
        assert {r.id for r in engine.list(user_access)} == set(ids) | set(written)
        for record_id in ids:
            assert engine.get(user_access, record_id).content.startswith("corrected fact")
        if report["state"] == "complete":
            break
        assert report["state"] == "in_progress" and report["migrated"] == 4
        assert old_dek in {w[0] for w in key_wraps_snapshot(path)}  # not retired while rows remain
        written.append(remember(engine, user_access, f"written during rotation {len(reports)}").id)
        assert len(reports) < 50
    new_dek = reports[0]["current_dek_id"]
    assert new_dek != old_dek and reports[0]["started"]
    assert reports[-1]["retired"] == [old_dek] and reports[-1]["remaining"] == {}
    assert _dek_ids_in_use(path) == {new_dek}
    assert old_dek not in {w[0] for w in key_wraps_snapshot(path)}
    assert engine.status(user_access).key_id == new_dek
    # Revisions re-encrypted too: the prior (pre-correction) payload still decrypts.
    ctx = engine.partition_context(user_access.partition)
    with ctx.partition.db.read() as conn:
        assert ctx.records.revision_record(conn, ids[0], 1).content == "fact number 0"
    engine.close()
    reopened = make_engine()
    assert {r.id for r in reopened.list(user_access)} == set(ids) | set(written)
    assert reopened.data_key_rotation_status(user_access)["state"] == "idle"


def test_data_key_rotation_resumes_after_restart(make_engine, root, user_access):
    engine = make_engine()
    ids = _populate(engine, user_access, n=4)
    first = engine.rotate_data_key(user_access, batch=3)
    assert first["state"] == "in_progress"
    engine.close()
    engine = make_engine()
    status = engine.data_key_rotation_status(user_access)
    assert status["state"] == "in_progress" and status["remaining"]
    report = engine.rotate_data_key(user_access, batch=1000)
    assert report["state"] == "complete" and not report["started"]
    assert report["current_dek_id"] == first["current_dek_id"]
    assert all(engine.get(user_access, i) for i in ids)
    assert _dek_ids_in_use(db_path(root, user_access)) == {first["current_dek_id"]}


def test_data_key_rotation_never_strands_rows_nobody_can_reencrypt(make_engine, root, user_access):
    engine = make_engine()
    remember(engine, user_access, "fact")
    ctx = engine.partition_context(user_access.partition)
    with ctx.partition.db.write() as conn:  # a sealed table no service knows how to re-encrypt
        conn.execute("CREATE TABLE opaque_test(id TEXT PRIMARY KEY, dek_id TEXT, nonce BLOB, ciphertext BLOB)")
        dek, nonce, ct = ctx.partition.seal_json("opaque_test", "o1", {"k": "v"}, {"payload": 1})
        conn.execute("INSERT INTO opaque_test VALUES('o1',?,?,?)", (dek, nonce, ct))
    old_dek = dek
    report = engine.rotate_data_key(user_access, batch=100)
    assert report["state"] == "blocked" and report["blocked_tables"] == ["opaque_test"]
    assert report["retired"] == []
    assert old_dek in {w[0] for w in key_wraps_snapshot(db_path(root, user_access))}
    with ctx.partition.db.read() as conn:
        row = conn.execute("SELECT * FROM opaque_test").fetchone()
        assert ctx.partition.open_json("opaque_test", "o1", {"k": "v"}, row["dek_id"], row["nonce"],
                                       row["ciphertext"]) == {"payload": 1}


def test_data_key_rotation_refuses_to_reseal_a_tampered_row(make_engine, root, user_access):
    engine = make_engine()
    record = remember(engine, user_access, "fact")
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("UPDATE records SET lifecycle='candidate' WHERE id=?", (record.id,))
    with pytest.raises(IntegrityError):
        engine.rotate_data_key(user_access, batch=100)
    # The batch rolled back: the tampered row was not laundered under the new key.
    with pytest.raises(IntegrityError):
        engine.get(user_access, record.id)


def test_a_second_engine_follows_a_data_key_rotation(make_engine, root, user_access):
    a, b = make_engine(), make_engine()
    record = remember(a, user_access, "shared fact")
    assert b.get(user_access, record.id).content == "shared fact"  # b caches the old DEK
    report = a.rotate_data_key(user_access, batch=1000)
    assert report["state"] == "complete"
    assert b.get(user_access, record.id).content == "shared fact"  # b reloads the new DEK
    written = remember(b, user_access, "written by the stale engine")
    with raw_db(db_path(root, user_access)) as conn:
        dek = conn.execute("SELECT dek_id FROM records WHERE id=?", (written.id,)).fetchone()[0]
    assert dek == report["current_dek_id"]
    assert a.get(user_access, written.id).content == "written by the stale engine"


# ---------------------------------------------------------------------------- tampering
@pytest.mark.parametrize("column,value", [
    ("lifecycle", "approved"), ("kind", "constraint"), ("revision", 7), ("scope_token", "f" * 40),
])
def test_relabelled_metadata_is_never_served(make_engine, root, user_access, column, value):
    engine = make_engine()
    candidate = engine.propose(user_access, CandidateProposal(content="unreviewed", sources=(DOC,),
                                                              scope=PROJ_A)).record
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute(f"UPDATE records SET {column}=? WHERE id=?", (value, candidate.id))
    with pytest.raises(IntegrityError):
        engine.get(user_access, candidate.id)
    with pytest.raises(IntegrityError):
        engine.list(user_access, lifecycles=None)


def test_ciphertext_moved_between_rows_fails(make_engine, root, user_access):
    engine = make_engine()
    a = remember(engine, user_access, "first")
    b = remember(engine, user_access, "second")
    with raw_db(db_path(root, user_access)) as conn:
        row = conn.execute("SELECT dek_id, nonce, ciphertext FROM records WHERE id=?", (a.id,)).fetchone()
        conn.execute("UPDATE records SET dek_id=?, nonce=?, ciphertext=? WHERE id=?", (*tuple(row), b.id))
    assert engine.get(user_access, a.id).content == "first"
    with pytest.raises(IntegrityError):
        engine.get(user_access, b.id)


def test_scope_index_tampering_never_leaks_a_record(make_engine, root):
    owner = access_for(projects=("proj-a", "proj-b"))
    only_a = access_for(projects=("proj-a",))
    engine = make_engine()
    a = remember(engine, owner, "project a fact", scope=Scope.of(project="proj-a"))
    b = remember(engine, owner, "project b secret", scope=Scope.of(project="proj-b"))
    path = db_path(root, owner)
    with raw_db(path) as conn:
        token_a = conn.execute("SELECT value_token FROM record_scopes WHERE record_id=?", (a.id,)).fetchone()[0]
        # 1) relabel b's authorization index as project a
        conn.execute("UPDATE record_scopes SET value_token=? WHERE record_id=?", (token_a, b.id))
    with pytest.raises(IntegrityError):
        engine.list(only_a)
    with pytest.raises(NotFound):
        engine.get(only_a, b.id)
    with raw_db(path) as conn:  # 2) drop b's index rows: it now looks profile-global
        conn.execute("DELETE FROM record_scopes WHERE record_id=?", (b.id,))
    with pytest.raises(IntegrityError):
        engine.list(access_for())
    with raw_db(path) as conn:  # 3) garbage token: b simply becomes invisible, never mis-served
        conn.execute("INSERT INTO record_scopes(record_id, dim, value_token) VALUES(?,?,?)",
                     (b.id, "project", "0" * 40))
    assert [r.id for r in engine.list(owner)] == [a.id]
    assert engine.status(owner).counts == {"approved": 1}


def test_tampered_revision_receipt_and_dek_reference(make_engine, root, user_access):
    engine = make_engine()
    record = remember(engine, user_access, "v1 content")
    engine.correct(user_access, record.id, Correction(content="v2 content"), expected_revision=1)
    engine.remember(user_access, RememberRequest(content="idem", scope=PROJ_A), idempotency_key="idem-1")
    path = db_path(root, user_access)
    with raw_db(path) as conn:
        conn.execute("UPDATE record_revisions SET change='approved' WHERE record_id=? AND revision=1", (record.id,))
        conn.execute("UPDATE receipts SET operation='forget'")
    ctx = engine.partition_context(user_access.partition)
    with ctx.partition.db.read() as conn, pytest.raises(IntegrityError):
        ctx.records.revision_record(conn, record.id, 1)
    with pytest.raises(IntegrityError):
        engine.remember(user_access, RememberRequest(content="idem", scope=PROJ_A), idempotency_key="idem-1")
    with raw_db(path) as conn:
        conn.execute("UPDATE records SET dek_id='d-forged' WHERE id=?", (record.id,))
    with pytest.raises(IntegrityError):
        engine.get(user_access, record.id)


def test_tampered_key_wrap_or_partition_label_refuses_to_open(make_engine, root, user_access):
    remember(make_engine(), user_access, "x")
    path = db_path(root, user_access)
    with raw_db(path) as conn:
        wrapped = conn.execute("SELECT wrapped FROM key_wraps WHERE purpose='data'").fetchone()[0]
        conn.execute("UPDATE key_wraps SET wrapped=? WHERE purpose='data'",
                     (bytes([wrapped[0] ^ 1]) + wrapped[1:],))
    with pytest.raises(WrongKey):
        make_engine().status(user_access)
    with raw_db(path) as conn:
        conn.execute("UPDATE key_wraps SET wrapped=? WHERE purpose='data'", (wrapped,))
        conn.execute("UPDATE meta SET value='pdeadbeef' WHERE key='partition_id'")
    with pytest.raises(MigrationError):
        make_engine().status(user_access)


# ---------------------------------------------------------------------------- plaintext at rest
def test_canary_never_reaches_disk_logs_or_errors(make_engine, root, user_access, caplog):
    caplog.set_level(logging.DEBUG)
    engine = make_engine()
    checkpoints = []

    def assert_clean(stage):
        checkpoints.append(stage)
        assert scan_for_plaintext(root, CANARY) == [], stage

    record = engine.remember(user_access, RememberRequest(
        content=f"remember {CANARY}", title=f"title {CANARY}", tags=["canary"], scope=PROJ_A,
        subject="user", predicate="canary")).record
    assert_clean("remember")
    candidate = engine.propose(user_access, CandidateProposal(content=f"candidate {CANARY}", sources=(DOC,),
                                                              scope=PROJ_A)).record
    assert_clean("propose")
    engine.correct(user_access, record.id, Correction(content=f"corrected {CANARY} v2"), expected_revision=1)
    assert_clean("correct")
    engine.approve(user_access, candidate.id, expected_revision=1)
    other = engine.propose(user_access, CandidateProposal(content=f"rejected {CANARY}", sources=(DOC,),
                                                          scope=PROJ_A)).record
    engine.reject(user_access, other.id, expected_revision=1, reason=f"no {CANARY}")
    engine.explain(user_access, record.id)
    engine.status(user_access)
    assert_clean("approve/reject/explain")
    engine.forget(user_access, ForgetTarget("memory", record.id))
    assert_clean("forget")
    engine.close()
    assert_clean("closed")
    assert {p.name for p in (root / user_access.partition.partition_id).iterdir()} >= {
        "memory.sqlite3", "deletion-ledger.sqlite3"}
    for message in caplog.messages:
        assert CANARY not in message
    # Errors describe the problem, never the content.
    engine = make_engine()
    for bad in (f"{CANARY} password=hunter2hunter2", f"{CANARY} " + "x" * 40_000):
        with pytest.raises((SensitiveContent, ValidationError)) as exc:
            engine.remember(user_access, RememberRequest(content=bad, scope=PROJ_A))
        assert CANARY not in str(exc.value) and CANARY not in repr(exc.value.to_dict())


def test_forget_removes_the_ciphertext_itself(make_engine, root, user_access):
    engine = make_engine()
    record = remember(engine, user_access, "to be forgotten")
    engine.correct(user_access, record.id, Correction(content="to be forgotten, corrected"), expected_revision=1)
    keep = remember(engine, user_access, "unrelated")
    path = db_path(root, user_access)
    with raw_db(path) as conn:
        blobs = [bytes(r[0]) for r in conn.execute("SELECT ciphertext FROM records WHERE id=?", (record.id,))]
        blobs += [bytes(r[0]) for r in conn.execute(
            "SELECT ciphertext FROM record_revisions WHERE record_id=?", (record.id,))]
    assert len(blobs) == 3
    engine.forget(user_access, ForgetTarget("memory", record.id))
    for table, column in (("records", "id"), ("record_revisions", "record_id"), ("record_scopes", "record_id"),
                          ("record_sources", "record_id"), ("derivations", "derived_id")):
        assert count(path, f"SELECT COUNT(*) FROM {table} WHERE {column}=?", (record.id,)) == 0, table
    engine.close()
    for blob in blobs:
        assert files_containing(root, blob[:48]) == []
    assert make_engine().get(user_access, keep.id).content == "unrelated"


def test_sqlite_side_files_are_not_world_readable(make_engine, root, user_access):
    engine = make_engine()
    remember(engine, user_access, "x")
    pdir = root / user_access.partition.partition_id
    assert stat.S_IMODE(pdir.stat().st_mode) == 0o700
    files = sorted(p.name for p in pdir.iterdir())
    assert {"memory.sqlite3-wal", "deletion-ledger.sqlite3-wal"} <= set(files)
    for path in pdir.iterdir():  # database, ledger, WAL and SHM files
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name
    assert os.access(pdir, os.R_OK)


def test_data_key_rotation_never_retires_a_key_history_still_uses(make_engine, root, user_access, clock):
    from locus_memory.models import IngestionEvent

    engine = make_engine()
    remember(engine, user_access, "fact")
    engine.ingest_event(user_access, IngestionEvent(event_id="e1", session_ref="s1", sequence=0, role="user",
                                                    text="archived line", occurred_at=clock(), scope=PROJ_A))
    old_dek = engine.status(user_access).key_id
    report = engine.rotate_data_key(user_access, batch=10_000)
    path = db_path(root, user_access)
    with raw_db(path) as conn:
        history_deks = {r[0] for r in conn.execute("SELECT dek_id FROM history_messages")}
    if report["state"] == "complete":  # the archive takes part in rotation (implements reencrypt)
        assert history_deks == {report["current_dek_id"]}
    else:  # it does not (yet): rotation is blocked and the old key is kept
        assert report["state"] == "blocked" and "history_messages" in report["blocked_tables"]
        assert history_deks == {old_dek}
        assert old_dek in {w[0] for w in key_wraps_snapshot(path)}
    page = engine.browse_history(user_access, "s1")
    assert "archived line" in repr(page)


# ---------------------------------------------------------------------------- export
PROJ_B = Scope.of(project="proj-b")


def _ingest(engine, access, session, seq, text, scope, clock):
    from locus_memory.models import IngestionEvent

    return engine.ingest_event(access, IngestionEvent(
        event_id=f"{session}-e{seq}", session_ref=session, sequence=seq, role="user", text=text,
        occurred_at=clock(), scope=scope))


def test_export_returns_every_authorized_record_of_every_lifecycle_and_nothing_else(make_engine, clock):
    writer = access_for(projects=("proj-a", "proj-b"), agents=("agent-9",))
    both = access_for(projects=("proj-a", "proj-b"))
    only_a = access_for(projects=("proj-a",))
    engine = make_engine()
    a_fact = remember(engine, writer, "fact in a")
    b_fact = remember(engine, writer, "fact in b", scope=PROJ_B)
    global_fact = remember(engine, writer, "global fact", scope=Scope.global_())
    a_and_agent = remember(engine, writer, "a with agent", scope=Scope.of(project="proj-a", agent="agent-9"))
    candidate = engine.propose(writer, CandidateProposal(content="candidate in a", sources=(DOC,),
                                                         scope=PROJ_A)).record
    rejected = engine.propose(writer, CandidateProposal(content="rejected in a", sources=(DOC,),
                                                        scope=PROJ_A)).record
    engine.reject(writer, rejected.id, expected_revision=1)
    forgotten = remember(engine, writer, "forgotten in a")
    engine.forget(writer, ForgetTarget("memory", forgotten.id))

    document = engine.export(only_a)
    assert document["format"] == "locus-memory.export" and document["version"] == 1
    assert document["partition_id"] == only_a.partition.partition_id
    assert document["exported_at"] == clock()
    assert "history" not in document  # history is excluded by default
    assert json.loads(json.dumps(document)) == document  # a plain JSON-compatible document
    by_id = {r["id"]: r for r in document["records"]}
    assert set(by_id) == {a_fact.id, global_fact.id, candidate.id, rejected.id}
    assert by_id[a_fact.id]["content"] == "fact in a"
    assert by_id[candidate.id]["lifecycle"] == "candidate" and by_id[rejected.id]["lifecycle"] == "rejected"
    text = json.dumps(document)
    for hidden in (b_fact, a_and_agent, forgotten):  # other scopes, intersecting scopes, deleted records
        assert hidden.id not in text and hidden.content not in text
    # A caller with wider grants exports more; one with every grant exports everything left.
    assert {r["id"] for r in engine.export(both)["records"]} == set(by_id) | {b_fact.id}
    assert {r["id"] for r in engine.export(writer)["records"]} == set(by_id) | {b_fact.id, a_and_agent.id}
    # Ungranted callers get only global records, never an error that reveals what exists.
    assert {r["id"] for r in engine.export(access_for())["records"]} == {global_fact.id}


def test_export_requires_the_export_operation_before_opening_anything(make_engine, root, agent_access):
    engine = make_engine()
    reader = access_for(projects=("proj-a",), operations={Operation.READ})
    with pytest.raises(AccessDenied):
        engine.export(reader)
    with pytest.raises(AccessDenied):
        engine.export(agent_access, include_history=True)
    assert not root.exists()  # refused before the partition was opened (or created)
    writer = access_for(projects=("proj-a",))
    remember(engine, writer, "exportable")
    _ingest(engine, writer, "sess-a", 0, "archived line", PROJ_A, clock=lambda: 1_800_000_000.0)
    exporter = access_for(projects=("proj-a",), operations={Operation.EXPORT})
    assert [r["content"] for r in engine.export(exporter)["records"]] == ["exportable"]
    with pytest.raises(AccessDenied):  # history additionally needs READ for its sessions
        engine.export(exporter, include_history=True)
    with pytest.raises(AccessDenied):
        engine.export(reader)
    with pytest.raises(ValidationError):
        engine.export(writer, include_history="yes")
    with pytest.raises(MemoryEngineError):
        engine.export(None)


def test_export_includes_history_only_when_asked_and_only_authorized_sessions(make_engine, clock):
    writer = access_for(projects=("proj-a", "proj-b"))
    only_a = access_for(projects=("proj-a",))
    engine = make_engine()
    remember(engine, writer, "a fact")
    for seq, text in ((0, "first line in a"), (1, "second line in a"), (3, "fourth line in a")):
        _ingest(engine, writer, "sess-a", seq, text, PROJ_A, clock)
    _ingest(engine, writer, "sess-b", 0, "secret line in b", PROJ_B, clock)
    _ingest(engine, writer, "sess-g", 0, "global line", Scope.global_(), clock)

    default = engine.export(only_a)
    assert "history" not in default
    assert "line" not in json.dumps(default["records"])
    with_history = engine.export(only_a, include_history=True)
    assert with_history["records"] == default["records"]
    sessions = {s["session_ref"]: s for s in with_history["history"]}
    assert set(sessions) == {"sess-a", "sess-g"}
    sess_a = sessions["sess-a"]
    assert sess_a["scope"] == {"project": "proj-a"} and sess_a["message_count"] == 3
    assert [(m["sequence"], m["text"]) for m in sess_a["messages"]] == [
        (0, "first line in a"), (1, "second line in a"), (3, "fourth line in a")]
    # The missing sequence is reported as a gap, never silently closed.
    assert sess_a["gaps"] == [{"from_seq": 2, "to_seq": 2, "reason": "not_received"}]
    assert [m["text"] for m in sessions["sess-g"]["messages"]] == ["global line"]
    text = json.dumps(with_history)
    assert "secret line in b" not in text and "sess-b" not in text
    assert {s["session_ref"] for s in engine.export(writer, include_history=True)["history"]} == {
        "sess-a", "sess-b", "sess-g"}


def test_export_writes_nothing_to_disk(make_engine, root, tmp_path, user_access, clock):
    engine = make_engine()
    remember(engine, user_access, f"exported {CANARY}")
    _ingest(engine, user_access, "sess-a", 0, f"history {CANARY}", PROJ_A, clock)
    engine.status(user_access)
    before = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    document = engine.export(user_access, include_history=True)
    assert CANARY in json.dumps(document)
    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == before
    assert not scan_for_plaintext(tmp_path, CANARY)
