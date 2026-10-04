"""Round-4 review, batch 3: regression tests for the reproduced defects.

R4-RG-2      after a rollback, a legacy edit restoring a statement a package correction had replaced was
             skipped as suppressed on every import (the correction suppressed it against the record's
             own legacy identity); the package kept serving what the authoritative store no longer
             said and every re-migration failed validation for good
R4-PERF-1    process_outbox (and so maintain) and reconcile_external decrypted every externally synced
             summary, observation and derived record inside the store's write transaction, whatever
             the outbox budget
R4-TAMPER-4  scope/profile forgets of legacy rows the package never held were decided by the plaintext
             rollback watermark in package meta and by the legacy created_at column (also after the
             importer had found the row covered)
R4-TAMPER-6  expiry and external withdrawal were pre-filtered on the plaintext expires_at / pinned /
             valid_until / lifecycle columns: one edit kept an expired or superseded record's
             external replica forever, and reconcile reported it in sync
"""
from __future__ import annotations

import math
import sqlite3
from pathlib import Path

import pytest

import test_review_group1 as group1
from conftest import access_for
from foundation_support import db_path, raw_db
from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.errors import IntegrityError
from locus_memory.migrations import legacy as legacy_mod
from locus_memory.models import (
    Correction,
    ForgetTarget,
    MemoryKind,
    RememberRequest,
    Retention,
    Scope,
    SourceKind,
    SourceRef,
    Validity,
)
from locus_memory.providers import hub as hub_mod
from locus_memory.providers.fake import FakeExternalMemory
from locus_memory.storage.records import RecordStore
from test_providers import _external_setup, hub_of
from test_review_group1 import AGENT, IDS, KEY, WS, _cut_over, _legacy_ids, _migrator, _proj_a

admin = group1.admin
control = group1.control
legacy_db = group1.legacy_db
mapping = group1.mapping
menv = group1.menv

PROJ_A = Scope.of(project="proj-a")
P = Scope.of(project="p")


# =========================================================================== R4-RG-2
OLD = "This project uses unittest."
NEW = "This project uses nose."
THIRD = "This project uses pytest-xdist."
RID = IDS["candidate_approved"]


def _legacy_row(legacy_db: Path, record_id: str) -> dict:
    return next(m for m in LegacyMemoryVault(legacy_db, key=KEY).list(workspace=WS) if m["id"] == record_id)


def _edit_legacy(legacy_db: Path, clock, record_id: str, content: str) -> None:
    """The user edits the row in the (authoritative) legacy store, as Locus does."""
    clock.advance(60)
    vault = LegacyMemoryVault(legacy_db, key=KEY, clock=clock)
    row = next(m for m in vault.list(workspace=WS) if m["id"] == record_id)
    vault.save({**row, "content": content}, record_id, workspace=WS)
    assert _legacy_row(legacy_db, record_id)["content"] == content


def _import(engine, admin, legacy_db, mapping):
    return legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()


def _remigrate(engine, control, admin, legacy_db, mapping, tmp_path):
    again = _migrator(engine, control, admin, legacy_db, mapping, tmp_path / "again")
    again.prepare_shadow()
    result = again.validate()
    assert result["validated"], result["verify"]["mismatches"]
    assert again.cutover()["state"] == "package_authoritative"


def test_rg2_a_legacy_edit_back_to_the_corrected_away_statement_is_imported(menv, control, admin, legacy_db,
                                                                           mapping, tmp_path, clock):
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    record = menv.get(admin, RID)
    assert record.content == OLD
    menv.correct(admin, RID, Correction(content=NEW), expected_revision=record.revision)  # suppresses OLD
    assert migrator.rollback()["state"] == "legacy_authoritative"
    assert _legacy_row(legacy_db, RID)["content"] == NEW
    _edit_legacy(legacy_db, clock, RID, OLD)
    # Every import - the Stage-2 adapter runs one per turn while legacy is authoritative.
    reports = [_import(menv, admin, legacy_db, mapping) for _ in range(3)]
    assert not any(r.get("skipped_suppressed") for r in reports)
    assert reports[0].get("updated") == 1
    assert all(r.get("unchanged") == r["rows"] for r in reports[1:])
    assert menv.get(admin, RID).content == OLD
    # Re-migration is not blocked: validate agrees with the import, and the cutover keeps the edit.
    _remigrate(menv, control, admin, legacy_db, mapping, tmp_path)
    assert menv.get(admin, RID).content == OLD


def test_rg2_a_chain_of_corrections_then_an_edit_back_is_imported(menv, control, admin, legacy_db, mapping,
                                                                  tmp_path, clock):
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    record = menv.get(admin, RID)
    record = menv.correct(admin, RID, Correction(content=NEW), expected_revision=record.revision).record
    menv.correct(admin, RID, Correction(content=THIRD), expected_revision=record.revision)  # suppresses NEW too
    assert migrator.rollback()["state"] == "legacy_authoritative"
    _edit_legacy(legacy_db, clock, RID, NEW)
    report = _import(menv, admin, legacy_db, mapping)
    assert report.get("updated") == 1 and not report.get("skipped_suppressed")
    assert menv.get(admin, RID).content == NEW
    _remigrate(menv, control, admin, legacy_db, mapping, tmp_path)


def test_rg2_a_written_back_package_record_with_evidence_edited_back_is_imported(menv, control, admin, legacy_db,
                                                                                mapping, tmp_path, clock):
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    note = menv.remember(admin, RememberRequest(content="The release train leaves on Tuesdays", scope=PROJ_A,
                                                sources=(SourceRef(SourceKind.DOCUMENT, "release-doc"),))).record
    menv.correct(admin, note.id, Correction(content="The release train leaves on Thursdays"),
                 expected_revision=note.revision)  # suppresses the Tuesday statement against its sources
    assert migrator.rollback()["state"] == "legacy_authoritative"
    assert menv.get(admin, note.id).extra.get("legacy_round_trip")
    _edit_legacy(legacy_db, clock, note.id, "The release train leaves on Tuesdays")
    report = _import(menv, admin, legacy_db, mapping)
    assert report.get("updated") == 1 and not report.get("skipped_suppressed")
    stored = menv.get(admin, note.id)
    assert stored.content == "The release train leaves on Tuesdays"
    assert SourceRef(SourceKind.DOCUMENT, "release-doc").identity() in {s.identity() for s in stored.sources}
    _remigrate(menv, control, admin, legacy_db, mapping, tmp_path)


def test_rg2_a_stale_pre_correction_legacy_row_is_still_refused(menv, control, admin, legacy_db, mapping,
                                                                tmp_path):
    before = tmp_path / "legacy-before-rollback.sqlite3"
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    with sqlite3.connect(legacy_db) as src, sqlite3.connect(before) as dst:
        src.backup(dst)
    record = menv.get(admin, RID)
    menv.correct(admin, RID, Correction(content=NEW), expected_revision=record.revision)
    assert migrator.rollback()["counts"].get("written_back") == 1
    # The pre-correction row comes back (a restored backup): not newer than what the package holds.
    with sqlite3.connect(before) as src:
        row = src.execute("SELECT * FROM memories WHERE id=?", (RID,)).fetchone()
        columns = [d[0] for d in src.execute("SELECT * FROM memories LIMIT 0").description]
    with sqlite3.connect(legacy_db) as dst:
        dst.execute("DELETE FROM memories WHERE id=?", (RID,))
        dst.execute(f"INSERT INTO memories({','.join(columns)}) VALUES({','.join('?' * len(columns))})", row)
    for _ in range(2):
        assert _import(menv, admin, legacy_db, mapping).get("skipped_suppressed") == 1
    assert menv.get(admin, RID).content == NEW


def test_rg2_a_relearning_suppression_of_another_records_statement_still_refuses(menv, control, admin,
                                                                                 legacy_db, mapping, tmp_path,
                                                                                 clock):
    """The waiver is the record's own: a statement it never made, suppressed against its evidence by
    the forget of another record, is not brought in by a legacy edit."""
    doc = SourceRef(SourceKind.DOCUMENT, "release-doc")
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    note = menv.remember(admin, RememberRequest(content="The release train leaves on Tuesdays", scope=PROJ_A,
                                                sources=(doc,))).record
    other = menv.remember(admin, RememberRequest(content="Payroll runs on the 25th", scope=PROJ_A,
                                                 sources=(doc,))).record
    assert menv.forget(admin, ForgetTarget("memory", other.id)).deleted.get("memories")  # do not relearn it
    assert migrator.rollback()["state"] == "legacy_authoritative"
    _edit_legacy(legacy_db, clock, note.id, "Payroll runs on the 25th")
    assert _import(menv, admin, legacy_db, mapping).get("skipped_suppressed") == 1
    assert menv.get(admin, note.id).content == "The release train leaves on Tuesdays"


# =========================================================================== R4-PERF-1
N_SYNCED = 150


def _synced_summaries(make_engine, clock, n=N_SYNCED, *, transient: int = 0):
    ext = FakeExternalMemory("ext", clock=clock)
    engine = _external_setup(make_engine, clock, ext)
    access = access_for(projects=("p",))
    for i in range(n):
        engine.remember(access, RememberRequest(content=f"summary {i} of the deployment notes", scope=P,
                                                kind=MemoryKind.SUMMARY))
    for i in range(transient):
        engine.remember(access, RememberRequest(content=f"transient note {i}", scope=P,
                                                retention=Retention("transient", clock() + 60)))
    hub = hub_of(engine, access)
    synced = 0
    while True:
        report = hub.sync_external(access, "ext", limit=hub.MAX_SYNC_BATCH)
        synced += report["confirmed"]
        if not report["sent"]:
            break
    assert synced == n + transient
    return engine, access, hub, ext


class _DecryptProbe:
    """Counts record decryptions and checks, at each one, whether another connection could take the
    store's write lock right now (BEGIN IMMEDIATE with a zero busy timeout)."""

    def __init__(self, monkeypatch, db: Path) -> None:
        self.calls = 0
        self.under_write_lock = 0
        original = RecordStore.get
        probe = self

        def counting_get(store, conn, record_id):
            probe.calls += 1
            other = sqlite3.connect(str(db), timeout=0, isolation_level=None)
            try:
                other.execute("BEGIN IMMEDIATE")
                other.execute("ROLLBACK")
            except sqlite3.OperationalError:
                probe.under_write_lock += 1
            finally:
                other.close()
            return original(store, conn, record_id)

        monkeypatch.setattr(RecordStore, "get", counting_get)


def test_perf1_process_outbox_decrypts_a_bounded_batch_outside_the_write_lock(make_engine, clock, monkeypatch):
    engine, access, hub, ext = _synced_summaries(make_engine, clock)
    probe = _DecryptProbe(monkeypatch, Path(hub.p.db.path))
    report = hub.process_outbox(access, budget=1)
    assert report["attempted"] == 0 and report["remaining"] == 0
    assert 0 < probe.calls <= hub_mod.SWEEP_BATCH < N_SYNCED  # bounded by the batch, not by N
    assert probe.under_write_lock == 0
    assert len(ext.items) == N_SYNCED  # nothing current was withdrawn


def test_perf1_the_round_robin_reaches_every_replica(make_engine, clock, monkeypatch):
    engine, access, hub, _ext = _synced_summaries(make_engine, clock)
    judged: set[str] = set()
    original = hub_mod.ProviderHub._judge

    def recording(self, conn, record_ids, now):
        ids = list(record_ids)
        judged.update(ids)
        return original(self, conn, ids, now)

    monkeypatch.setattr(hub_mod.ProviderHub, "_judge", recording)
    for _ in range(math.ceil(N_SYNCED / hub_mod.SWEEP_BATCH)):
        hub.process_outbox(access, budget=1)
    assert len(judged) == N_SYNCED


def test_perf1_maintain_and_reconcile_never_decrypt_under_the_write_lock(make_engine, clock, monkeypatch):
    engine, access, hub, ext = _synced_summaries(make_engine, clock)
    probe = _DecryptProbe(monkeypatch, Path(hub.p.db.path))
    sweep = {"calls": 0}
    original = hub_mod.ProviderHub._judge

    def counting(self, conn, record_ids, now):
        ids = list(record_ids)
        sweep["calls"] += len(ids)
        return original(self, conn, ids, now)

    monkeypatch.setattr(hub_mod.ProviderHub, "_judge", counting)
    engine.maintain(access)
    assert 0 < sweep["calls"] <= 3 * hub_mod.SWEEP_BATCH
    report = hub.reconcile_external(access, "ext")
    assert report.get("in_sync") == N_SYNCED
    assert probe.under_write_lock == 0
    assert len(ext.items) == N_SYNCED


def test_perf1_a_replica_expired_at_read_time_is_still_withdrawn_promptly(make_engine, clock):
    engine, access, hub, ext = _synced_summaries(make_engine, clock, transient=2)
    clock.advance(3600)  # retention ended; maintenance has not persisted it
    report = hub.process_outbox(access)
    assert report["attempted"] == 2
    assert len(ext.items) == N_SYNCED
    assert not any(item["content"].startswith("transient note") for item in ext.items.values())


# =========================================================================== R4-TAMPER-4
MARK = "TAMPER4 project-a fact saved before the project forget"


def _served(engine, admin) -> list[str]:
    return [rid for rid in _proj_a(engine, admin) if MARK in engine.get(admin, rid).content]


def _never_imported_row_then_forget(engine, admin, legacy_db, mapping, clock) -> tuple[dict, float]:
    _import(engine, admin, legacy_db, mapping)
    clock.advance(5)
    row = LegacyMemoryVault(legacy_db, key=KEY, clock=clock).save({"content": MARK, "scope": "workspace"},
                                                                  workspace=WS, agent_id=AGENT)
    clock.advance(5)
    forget_time = clock()
    assert engine.forget(admin, ForgetTarget("project", "proj-a")).deleted.get("memories")
    clock.advance(3600)
    assert row["id"] not in {r.id for r in engine.list(admin, lifecycles=None)}
    return row, forget_time


@pytest.mark.parametrize("tamper", ["none", "package_watermark", "delete_tombstone_row"])
def test_tamper4_package_side_edits_never_undo_a_scope_forget(tamper, engine, admin, legacy_db, mapping, clock,
                                                              root):
    _never_imported_row_then_forget(engine, admin, legacy_db, mapping, clock)
    with raw_db(db_path(root, admin)) as conn:
        if tamper == "package_watermark":
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('migration_rollback_generation', '999999')")
        elif tamper == "delete_tombstone_row":
            conn.execute("DELETE FROM tombstones WHERE target_kind='scope:project'")
    report = _import(engine, admin, legacy_db, mapping)
    assert report.get("imported", 0) == 0 and report.get("skipped_forgotten", 0) >= 1
    assert _served(engine, admin) == []


def test_tamper4_an_offline_watermark_edit_survives_no_reopen(make_engine, admin, legacy_db, mapping, clock, root):
    first = make_engine()
    _never_imported_row_then_forget(first, admin, legacy_db, mapping, clock)
    first.close()
    with raw_db(db_path(root, admin)) as conn:
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('migration_rollback_generation', '999999')")
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('migration_rollback_generation_mac', 'x')")
    reopened = make_engine()
    report = _import(reopened, admin, legacy_db, mapping)
    assert report.get("imported", 0) == 0
    assert _served(reopened, admin) == []


def test_tamper4_a_forged_watermark_is_never_laundered_by_a_rollback(menv, control, admin, legacy_db, mapping,
                                                                     tmp_path, root):
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    victim = sorted(_legacy_ids(legacy_db))[0]
    assert menv.forget(admin, ForgetTarget("memory", victim)).deleted
    with raw_db(db_path(root, admin)) as conn:  # planted before the rollback records its own
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('migration_rollback_generation', '999999')")
    assert migrator.rollback()["state"] == "legacy_authoritative"
    ctx = menv.partition_context(admin.partition)
    with ctx.partition.db.read() as conn:
        generation = ctx.partition.deletion_generation(conn)
        assert legacy_mod.rollback_watermark(conn) == generation  # the forged value is gone
        assert legacy_mod.rollback_watermark(conn, ctx) == generation


def test_tamper4_a_created_at_edit_after_the_importer_found_the_row_covered_changes_nothing(
        engine, admin, legacy_db, mapping, clock):
    row, forget_time = _never_imported_row_then_forget(engine, admin, legacy_db, mapping, clock)
    report = _import(engine, admin, legacy_db, mapping)  # the honest created_at: covered
    assert report.get("imported", 0) == 0 and report.get("skipped_forgotten", 0) >= 1
    conn = sqlite3.connect(legacy_db)  # keyless edit of the unauthenticated column
    try:
        with conn:
            conn.execute("UPDATE memories SET created_at=? WHERE id=?", (forget_time + 100, row["id"]))
    finally:
        conn.close()
    for _ in range(2):
        report = _import(engine, admin, legacy_db, mapping)
        assert report.get("imported", 0) == 0
    assert _served(engine, admin) == []
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["missing"] == 0


# =========================================================================== R4-TAMPER-6
def _stored(root, access, record_id):
    with raw_db(db_path(root, access)) as conn:
        row = conn.execute("SELECT lifecycle FROM records WHERE id=?", (record_id,)).fetchone()
        return None if row is None else row[0]


def _transient_synced(make_engine, clock, user_access, **remember):
    ext = FakeExternalMemory("ext", clock=clock)
    engine = _external_setup(make_engine, clock, ext)
    record = engine.remember(user_access, RememberRequest(content="TRANSIENT secret", scope=PROJ_A,
                                                          **remember)).record
    assert hub_of(engine, user_access).sync_external(user_access, "ext")["confirmed"] == 1
    engine.close()
    return ext, record


@pytest.mark.parametrize("tamper_sql", [
    "UPDATE records SET expires_at=NULL WHERE id=?",
    "UPDATE records SET pinned=1 WHERE id=?",
    "UPDATE records SET expires_at=9e15 WHERE id=?",
])
def test_tamper6_an_expiry_column_edit_never_keeps_an_expired_replica(make_engine, clock, root, user_access,
                                                                       tamper_sql):
    ext, record = _transient_synced(make_engine, clock, user_access,
                                    retention=Retention("transient", clock() + 60, False))
    with raw_db(db_path(root, user_access)) as conn:
        assert conn.execute(tamper_sql, (record.id,)).rowcount == 1
    clock.advance(3600)
    engine = _external_setup(make_engine, clock, ext)
    with pytest.raises(IntegrityError):  # never served as current: the row fails closed
        engine.get(user_access, record.id)
    engine.maintain(user_access)
    hub = hub_of(engine, user_access)
    hub.process_outbox(user_access)
    assert ext.items == {}
    assert hub.reconcile_external(user_access, "ext").get("in_sync", 0) == 0


def test_tamper6_a_validity_column_edit_never_keeps_a_stale_replica(make_engine, clock, root, user_access):
    ext, record = _transient_synced(make_engine, clock, user_access, validity=Validity(valid_until=clock() + 60))
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("UPDATE records SET valid_until=NULL WHERE id=?", (record.id,))
    clock.advance(3600)
    engine = _external_setup(make_engine, clock, ext)
    hub_of(engine, user_access).process_outbox(user_access)
    assert ext.items == {}


def test_tamper6_a_superseded_record_relabelled_approved_is_withdrawn(make_engine, clock, root, user_access):
    ext = FakeExternalMemory("ext", clock=clock)
    engine = _external_setup(make_engine, clock, ext)
    old = engine.remember(user_access, RememberRequest(content="OLD statement", scope=PROJ_A)).record
    assert hub_of(engine, user_access).sync_external(user_access, "ext")["confirmed"] == 1
    new = engine.remember(user_access, RememberRequest(content="NEW statement", scope=PROJ_A)).record
    engine.supersede(user_access, old.id, new.id, expected_revision=old.revision)
    engine.close()
    assert _stored(root, user_access, old.id) == "superseded"
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("UPDATE records SET lifecycle='approved' WHERE id=?", (old.id,))
    engine = _external_setup(make_engine, clock, ext)
    hub = hub_of(engine, user_access)
    report = hub.reconcile_external(user_access, "ext")
    assert report.get("in_sync", 0) == 0 and report["queued_deletions"]
    hub.process_outbox(user_access)
    assert ext.items == {}


def test_tamper6_reconcile_judges_the_authenticated_record(make_engine, clock, root, user_access, monkeypatch):
    """Without the sweep, reconcile alone withdraws a replica whose local row no longer authenticates."""
    ext, record = _transient_synced(make_engine, clock, user_access,
                                    retention=Retention("transient", clock() + 60, False))
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("UPDATE records SET expires_at=NULL WHERE id=?", (record.id,))
    engine = _external_setup(make_engine, clock, ext)
    hub = hub_of(engine, user_access)
    monkeypatch.setattr(hub_mod.ProviderHub, "_sweep_plan", lambda self: hub_mod._SweepPlan({}, {}))
    report = hub.reconcile_external(user_access, "ext")
    assert report.get("locally_unreadable_refused") == 1 and report.get("in_sync", 0) == 0
    hub.process_outbox(user_access)
    assert ext.items == {}


@pytest.mark.parametrize("column,value", [("expires_at", 1.0), ("pinned", 1), ("valid_from", 5.0),
                                          ("valid_until", 9e15)])
def test_tamper6_relabelled_time_columns_are_never_served(engine, root, user_access, column, value):
    record = engine.remember(user_access, RememberRequest(content="durable fact", scope=PROJ_A)).record
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute(f"UPDATE records SET {column}=? WHERE id=?", (value, record.id))
    with pytest.raises(IntegrityError):
        engine.get(user_access, record.id)
    with pytest.raises(IntegrityError):
        engine.list(user_access, lifecycles=None)
