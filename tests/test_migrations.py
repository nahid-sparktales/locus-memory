"""Legacy -> package migration, cutover state machine, crash recovery and rollback.

Uses a disposable copy of the fixture produced by the real Locus code. Never touches
real app data.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from conftest import CANARY, access_for, scan_for_plaintext
from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.errors import (
    MigrationError,
    NotFound,
    OwnershipFenced,
    RevisionConflict,
    ValidationError,
)
from locus_memory.migrations import legacy as legacy_mod
from locus_memory.migrations.cutover import Migrator, SimulatedCrash
from locus_memory.migrations.state import OwnershipControl
from locus_memory.models import (
    Correction,
    EpisodeReport,
    ForgetTarget,
    Lifecycle,
    Operation,
    Scope,
)

FIXTURE = Path(__file__).parent / "fixtures" / "locus_legacy"
EXPECTED = json.loads((FIXTURE / "expected.json").read_text())
KEY = bytes.fromhex(EXPECTED["key_hex"])
WS, OTHER, AGENT = EXPECTED["workspace"], EXPECTED["other_workspace"], EXPECTED["agent_id"]
IDS = EXPECTED["ids"]


@pytest.fixture
def legacy_db(tmp_path: Path) -> Path:
    target = tmp_path / "legacy" / "memory.sqlite3"
    target.parent.mkdir()
    shutil.copy(FIXTURE / "memory.sqlite3", target)
    return target


@pytest.fixture
def mapping() -> legacy_mod.LegacyMapping:
    return legacy_mod.LegacyMapping.from_known({WS: "proj-a", OTHER: "proj-b"}, [AGENT])


@pytest.fixture
def admin():
    return access_for(projects=("proj-a", "proj-b"), agents=(AGENT,), operations=set(Operation))


@pytest.fixture
def control(root):
    ctl = OwnershipControl(root)
    yield ctl
    ctl.close()


def make_migrator(engine, control, admin, legacy_db, mapping, tmp_path):
    return Migrator(engine, control, admin, legacy_db, KEY, mapping, work_dir=tmp_path / "migration",
                    project_workspaces={"proj-a": WS, "proj-b": OTHER})


def test_inventory_is_read_only_and_content_free(legacy_db, mapping):
    before = legacy_db.read_bytes()
    report = legacy_mod.inventory(legacy_db, KEY, mapping)
    assert legacy_db.read_bytes() == before
    assert report["rows"] == len(EXPECTED["memories"]) and report["decrypt_failures"] == 0
    assert report["not_migrated_tables"]["context_snapshots"]["rows"] == 1
    assert report["unsupported_fields"]["feedback"]["records"] >= 1
    text = json.dumps(report)
    for item in EXPECTED["memories"].values():
        assert item["content"] not in text


def test_inventory_reports_unmapped_scopes_and_wrong_key(legacy_db):
    report = legacy_mod.inventory(legacy_db, KEY, legacy_mod.LegacyMapping())
    assert report["unmapped_scopes"].get("workspace", 0) >= 1
    bad = legacy_mod.inventory(legacy_db, b"\x02" * 32)
    assert bad["decrypt_failures"] == bad["rows"]


def test_snapshot_manifest_integrity_and_no_plaintext(legacy_db, tmp_path):
    manifest = legacy_mod.snapshot(legacy_db, tmp_path / "snap")
    assert manifest["rows"] == len(EXPECTED["memories"])
    assert legacy_mod.verify_snapshot(tmp_path / "snap")["ok"]
    for item in EXPECTED["memories"].values():
        assert not scan_for_plaintext(tmp_path / "snap", item["content"])
    with pytest.raises(MigrationError):
        legacy_mod.snapshot(legacy_db, tmp_path / "snap")


def test_import_preserves_identity_lifecycle_scope_and_is_idempotent(engine, admin, legacy_db, mapping):
    first = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    assert first["imported"] == len(EXPECTED["memories"])
    again = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    assert again["unchanged"] == len(EXPECTED["memories"]) and again.get("imported", 0) == 0
    rec = engine.get(admin, IDS["candidate_approved"])
    assert rec.lifecycle == Lifecycle.APPROVED and rec.scope == Scope.of(project="proj-a")
    old = engine.get(admin, IDS["ws_fact"])
    assert old.lifecycle == Lifecycle.SUPERSEDED and old.links.superseded_by == IDS["candidate_approved"]
    assert engine.get(admin, IDS["agent"]).lifecycle == Lifecycle.STALE  # feedback 'incorrect'
    assert engine.get(admin, IDS["personal"]).scope.is_global
    pending = engine.get(admin, IDS["pending"])
    assert pending.lifecycle in (Lifecycle.CANDIDATE, Lifecycle.EXPIRED)  # never approved by migration
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]


def test_unmapped_scope_needs_legacy_target_grant(engine, legacy_db):
    admin_unmapped = access_for(operations=set(Operation))
    legacy_mod.LegacyImporter(engine, admin_unmapped, legacy_db, KEY, legacy_mod.LegacyMapping()).run()
    visible = {r.id for r in engine.list(admin_unmapped, lifecycles=None)}
    assert IDS["personal"] in visible and IDS["ws_fact"] not in visible
    from locus_memory.compat.legacy_vault import legacy_target

    granted = access_for(legacy_targets=(legacy_target("workspace", workspace=WS),), operations=set(Operation))
    assert IDS["ws_fact"] in {r.id for r in engine.list(granted, lifecycles=None)}


def test_delta_import_applies_legacy_edits_and_deletions(engine, admin, legacy_db, mapping):
    legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    vault = LegacyMemoryVault(legacy_db, key=KEY)
    current = next(r for r in vault.list() if r["id"] == IDS["personal"])
    vault.save({**current, "content": "Prefer tabs everywhere."}, IDS["personal"])
    vault.delete(IDS["expired_validity"])
    delta = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    assert delta["updated"] == 1 and delta["deleted_in_legacy"] == 1
    assert engine.get(admin, IDS["personal"]).content == "Prefer tabs everywhere."
    with pytest.raises(NotFound):
        engine.get(admin, IDS["expired_validity"])
    # A deleted legacy record is tombstoned: re-importing an old snapshot cannot resurrect it.
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]


def test_import_interrupted_mid_batch_resumes(engine, admin, legacy_db, mapping):
    importer = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping, batch=2)

    def crash(done: int) -> None:
        if done >= 2:
            raise SimulatedCrash("mid-import")

    importer.after_batch = crash
    with pytest.raises(SimulatedCrash):
        importer.run()
    report = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping, batch=2).run()
    assert report["imported"] + report["unchanged"] == len(EXPECTED["memories"])
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]


def test_full_cutover_fences_legacy_writer(engine, control, admin, legacy_db, mapping, tmp_path):
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    guard = control.writer_guard(admin.partition.partition_id, "memories", "legacy")
    legacy_writer = LegacyMemoryVault(legacy_db, key=KEY, write_guard=guard)
    legacy_writer.save({"content": "written before shadow", "scope": "personal"}, "pre_shadow")
    assert migrator.prepare_shadow()["state"] == "shadow_prepared"
    legacy_writer.save({"content": "written during shadow", "scope": "personal"}, "during_shadow")
    validated = migrator.validate(queries=["tabs", "pytest"])
    assert validated["validated"], validated
    assert engine.get(admin, "during_shadow").content == "written during shadow"
    result = migrator.cutover(queries=["tabs"])
    assert result["state"] == "package_authoritative" and result["cutover"]
    with pytest.raises(OwnershipFenced):
        legacy_writer.save({"content": "late legacy write", "scope": "personal"}, "late")
    assert legacy_writer.list()  # reads still work
    history = control.history(admin.partition.partition_id)
    assert [h["to_state"] for h in history] == ["shadow_prepared", "validated", "cutover_in_progress",
                                                 "package_authoritative"]


@pytest.mark.parametrize("point", ["after_fence", "after_final_delta", "before_authoritative"])
def test_crash_during_cutover_resumes_without_losing_writes(engine, control, admin, legacy_db, mapping,
                                                            tmp_path, point):
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    migrator.validate()
    migrator.crash_at = point
    with pytest.raises(SimulatedCrash):
        migrator.cutover()
    state = control.get(admin.partition.partition_id)
    assert state.state == "cutover_in_progress" and state.writers == frozenset()
    with pytest.raises(OwnershipFenced):
        control.assert_writer(admin.partition.partition_id, "memories", "legacy")
    with pytest.raises(OwnershipFenced):
        control.assert_writer(admin.partition.partition_id, "memories", "package")
    migrator.crash_at = None
    assert migrator.resume()["state"] == "package_authoritative"


@pytest.mark.parametrize("point", ["after_snapshot", "after_shadow_import"])
def test_crash_during_shadow_leaves_legacy_authoritative(engine, control, admin, legacy_db, mapping, tmp_path, point):
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.crash_at = point
    with pytest.raises(SimulatedCrash):
        migrator.prepare_shadow()
    assert control.get(admin.partition.partition_id).state == "legacy_authoritative"
    control.assert_writer(admin.partition.partition_id, "memories", "legacy")
    migrator.crash_at = None
    assert migrator.prepare_shadow()["state"] == "shadow_prepared"


def test_cutover_aborts_to_legacy_when_verification_fails(engine, control, admin, legacy_db, mapping, tmp_path,
                                                          monkeypatch):
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    migrator.validate()
    monkeypatch.setattr(legacy_mod, "verify", lambda *a, **k: {"ok": False, "checked": 0, "missing": 1,
                                                                "mismatches": [{"id": "x", "field": "content"}],
                                                                "behaviour": []})
    result = migrator.cutover()
    assert result["state"] == "legacy_authoritative" and not result["cutover"]
    control.assert_writer(admin.partition.partition_id, "memories", "legacy")


def test_illegal_transitions_and_concurrent_migrators(control, admin):
    pid = admin.partition.partition_id
    with pytest.raises(ValidationError):
        control.transition(pid, "memories", "package_authoritative", expected_generation=0, reason="skip")
    control.transition(pid, "memories", "shadow_prepared", expected_generation=0, reason="a")
    with pytest.raises(RevisionConflict):
        control.transition(pid, "memories", "validated", expected_generation=0, reason="stale migrator")


def test_rollback_preserves_post_cutover_corrections_and_deletions(engine, control, admin, legacy_db, mapping,
                                                                   tmp_path):
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    migrator.validate()
    migrator.cutover()
    rec = engine.get(admin, IDS["personal"])
    engine.correct(admin, rec.id, Correction(content="Prefer spaces, actually."), expected_revision=rec.revision)
    engine.forget(admin, ForgetTarget("memory", IDS["agent"]))
    new = engine.remember(admin, __import__("locus_memory.models", fromlist=["x"]).RememberRequest(
        "Uses ruff for lint", scope=Scope.of(project="proj-a")))
    plan = migrator.plan_rollback()
    assert plan["safe"], plan
    result = migrator.rollback()
    assert result["state"] == "legacy_authoritative"
    vault = LegacyMemoryVault(legacy_db, key=KEY)
    by_id = {r["id"]: r for r in vault.list(workspace=WS, agent_id=AGENT)}
    assert by_id[IDS["personal"]]["content"] == "Prefer spaces, actually."
    assert IDS["agent"] not in by_id
    assert by_id[new.record.id]["content"] == "Uses ruff for lint"
    assert by_id[new.record.id]["scope"] == "workspace"


def test_rollback_refuses_unrepresentable_records_unless_partial(engine, control, admin, legacy_db, mapping,
                                                                 tmp_path):
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    migrator.validate()
    migrator.cutover()
    engine.record_episode(admin, EpisodeReport(episode_id="ep1", task_ref="task-1", attempt_ref="a1",
                                               objective="Fix flaky test", scope=Scope.of(project="proj-a")))
    with pytest.raises(MigrationError):
        migrator.rollback()
    assert control.get(admin.partition.partition_id).state == "package_authoritative"
    result = migrator.rollback(allow_partial=True)
    assert result["state"] == "legacy_authoritative" and result["package_readonly_recovery"]
    assert engine.get_episode(admin, "ep1")  # still recoverable from the package store


def test_crash_during_rollback_resumes(engine, control, admin, legacy_db, mapping, tmp_path):
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    migrator.validate()
    migrator.cutover()
    migrator.crash_at = "before_rollback_complete"
    with pytest.raises(SimulatedCrash):
        migrator.rollback()
    assert control.get(admin.partition.partition_id).state == "rollback_in_progress"
    migrator.crash_at = None
    assert migrator.resume()["state"] == "legacy_authoritative"


def test_migration_artifacts_contain_no_plaintext(engine, control, admin, legacy_db, mapping, tmp_path):
    vault = LegacyMemoryVault(legacy_db, key=KEY)
    vault.save({"content": CANARY, "scope": "personal"}, "canary_row")
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    migrator.validate()
    assert engine.get(admin, "canary_row").content == CANARY
    assert not scan_for_plaintext(tmp_path / "migration", CANARY)
    engine.close()
    assert not scan_for_plaintext(engine.root, CANARY)


def test_engine_canonical_writes_are_fenced_until_package_is_authoritative(make_engine, control, admin, legacy_db,
                                                                          mapping, tmp_path):
    from locus_memory.host import HostCapabilities
    from locus_memory.models import RememberRequest

    engine = make_engine(host=HostCapabilities(ownership=control))
    with pytest.raises(OwnershipFenced):
        engine.remember(admin, RememberRequest("not yet authoritative"))
    assert engine.ownership_state(admin)["state"] == "legacy_authoritative"
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()  # migration imports are not canonical user writes and are allowed
    migrator.validate()
    with pytest.raises(OwnershipFenced):
        engine.remember(admin, RememberRequest("still legacy authoritative"))
    migrator.cutover()
    assert engine.remember(admin, RememberRequest("now the package owns writes")).receipt.status == "ok"
    # Deletion is never fenced: forgetting must always be possible.
    assert engine.ownership_state(admin)["permitted_writers"] == ["package"]
