"""Legacy -> package migration, cutover state machine, crash recovery and rollback.

Uses a disposable copy of the fixture produced by the real Locus code. Never touches
real app data.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from conftest import CANARY, access_for, scan_for_plaintext
from locus_memory.compat.legacy_vault import LegacyMemoryVault, legacy_target
from locus_memory.errors import (
    AccessDenied,
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
    Actor,
    Correction,
    EpisodeReport,
    ForgetTarget,
    Lifecycle,
    Operation,
    Scope,
    ScopeGrants,
)

FIXTURE = Path(__file__).parent / "fixtures" / "locus_legacy"
EXPECTED = json.loads((FIXTURE / "expected.json").read_text())
KEY = bytes.fromhex(EXPECTED["key_hex"])
WS, OTHER, AGENT = EXPECTED["workspace"], EXPECTED["other_workspace"], EXPECTED["agent_id"]
IDS = EXPECTED["ids"]


def _fixture_now() -> float:
    conn = sqlite3.connect(f"file:{FIXTURE / 'memory.sqlite3'}?mode=ro", uri=True)
    try:
        return float(conn.execute("SELECT MAX(updated_at) FROM memories").fetchone()[0]) + 60.0
    finally:
        conn.close()


# The legacy vault expires candidates on read (list/approve) against its clock; pin it near the
# fixture's creation so the fixture's pending candidate does not silently expire as real time passes.
LEGACY_NOW = _fixture_now()


def legacy_vault(path: Path, **kwargs) -> LegacyMemoryVault:
    return LegacyMemoryVault(path, key=KEY, clock=lambda: LEGACY_NOW, **kwargs)


def legacy_column(path: Path, record_id: str, column: str):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(f"SELECT {column} FROM memories WHERE id=?", (record_id,)).fetchone()[0]
    finally:
        conn.close()


def importer(engine, access, legacy_db, mapping=None):
    return legacy_mod.LegacyImporter(engine, access, legacy_db, KEY, mapping)


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
    vault = legacy_vault(legacy_db)
    current = next(r for r in vault.list() if r["id"] == IDS["personal"])
    vault.save({**current, "content": "Prefer tabs everywhere."}, IDS["personal"])
    vault.delete(IDS["expired_validity"])
    delta = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    assert delta["updated"] == 1 and delta["deleted_in_legacy"] == 1
    assert delta["deletion_propagation"] == {"propagated": 1, "failed": 0, "failed_by_code": {}}
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


# --------------------------------------------------------- deltas the legacy revision does not show
def test_legacy_feedback_incorrect_is_a_delta_marking_stale(engine, admin, legacy_db, mapping):
    importer(engine, admin, legacy_db, mapping).run()
    before = engine.get(admin, IDS["personal"])
    assert before.lifecycle == Lifecycle.APPROVED
    revision = legacy_column(legacy_db, IDS["personal"], "revision")
    legacy_vault(legacy_db).feedback(IDS["personal"], "incorrect")
    assert legacy_column(legacy_db, IDS["personal"], "revision") == revision  # the vault did not bump it
    delta = importer(engine, admin, legacy_db, mapping).run()
    assert delta["updated"] == 1 and delta["metadata_deltas"] == 1 and delta["deleted_in_legacy"] == 0
    after = engine.get(admin, IDS["personal"])
    assert after.lifecycle == Lifecycle.STALE and after.revision == before.revision + 1
    assert after.extra["legacy_feedback"]["incorrect"] == 1
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]
    again = importer(engine, admin, legacy_db, mapping).run()
    assert again["unchanged"] == len(EXPECTED["memories"]) and again.get("updated", 0) == 0


def test_legacy_approve_replace_is_a_delta_superseding_with_link(engine, admin, legacy_db, mapping):
    importer(engine, admin, legacy_db, mapping).run()
    old_id = IDS["candidate_approved"]
    assert engine.get(admin, old_id).lifecycle == Lifecycle.APPROVED
    revision = legacy_column(legacy_db, old_id, "revision")
    vault = legacy_vault(legacy_db)
    new = vault.save({"title": "Test runner", "content": "This project uses nose2.", "tags": ["testing"],
                      "scope": "workspace", "status": "candidate"}, workspace=WS)
    vault.approve(new["id"], workspace=WS, resolution="replace")
    assert legacy_column(legacy_db, old_id, "superseded_by") == new["id"]
    assert legacy_column(legacy_db, old_id, "revision") == revision  # superseded in place, no revision bump
    delta = importer(engine, admin, legacy_db, mapping).run()
    assert delta["imported"] == 1 and delta["updated"] == 1 and delta["metadata_deltas"] == 1
    old = engine.get(admin, old_id)
    assert old.lifecycle == Lifecycle.SUPERSEDED and old.links.superseded_by == new["id"]
    replacement = engine.get(admin, new["id"])
    assert replacement.lifecycle == Lifecycle.APPROVED and old_id in replacement.links.supersedes
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]


def test_mapping_change_rescopes_legacy_target_to_project(engine, admin, legacy_db, mapping):
    target = legacy_target("workspace", workspace=WS)
    by_target = access_for(legacy_targets=(target,), operations={Operation.READ})
    importer(engine, admin, legacy_db, legacy_mod.LegacyMapping()).run()  # host had no mapping yet
    before = engine.get(by_target, IDS["ws_fact"])
    assert before.scope == Scope.of(legacy_target=target)
    delta = importer(engine, admin, legacy_db, mapping).run()
    scoped = sum(1 for item in EXPECTED["memories"].values() if item["scope"] != "personal")
    assert delta["rescoped"] == delta["updated"] == scoped and delta["unchanged"] == 1
    assert delta.get("metadata_deltas", 0) == 0
    after = engine.get(admin, IDS["ws_fact"])
    assert after.scope == Scope.of(project="proj-a") and after.revision == before.revision + 1
    assert engine.get(admin, IDS["other"]).scope == Scope.of(project="proj-b")
    assert engine.get(admin, IDS["agent"]).scope == Scope.of(agent=AGENT)
    with pytest.raises(NotFound):  # the authorization index moved with the scope
        engine.get(by_target, IDS["ws_fact"])
    assert IDS["ws_fact"] not in {r.id for r in engine.list(by_target, lifecycles=None)}
    assert IDS["ws_fact"] in {r.id for r in engine.list(access_for(projects=("proj-a",)), lifecycles=None)}
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]
    assert importer(engine, admin, legacy_db, mapping).run()["unchanged"] == len(EXPECTED["memories"])


def test_records_imported_without_fingerprint_are_reimported_once(engine, admin, legacy_db, mapping):
    importer(engine, admin, legacy_db, mapping).run()
    ctx = engine.partition_context(admin.partition)
    with ctx.partition.db.write() as conn:  # as written by an importer that predates fingerprints
        rec = ctx.records.get(conn, IDS["personal"])
        extra = {k: v for k, v in rec.extra.items() if k != "legacy_fingerprint"}
        ctx.services.core.write_internal(conn, __import__("dataclasses").replace(
            rec, revision=rec.revision + 1, extra=extra), change="legacy_delta", actor=Actor.SYSTEM,
            expected=rec.revision)
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]  # unknown is not a mismatch
    delta = importer(engine, admin, legacy_db, mapping).run()
    assert delta["updated"] == delta["metadata_deltas"] == 1
    assert engine.get(admin, IDS["personal"]).extra["legacy_fingerprint"]
    assert importer(engine, admin, legacy_db, mapping).run()["unchanged"] == len(EXPECTED["memories"])


def test_verify_compares_metadata_changed_without_revision_bump(engine, admin, legacy_db, mapping):
    importer(engine, admin, legacy_db, mapping).run()
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]
    conn = sqlite3.connect(legacy_db)  # columns outside the AAD, edited in place by the legacy store
    with conn:
        conn.execute("UPDATE memories SET pinned=1 WHERE id=?", (IDS["personal"],))
        conn.execute("UPDATE memories SET superseded_by=? WHERE id=?", (IDS["personal"], IDS["other"]))
        conn.execute("UPDATE memories SET expires_at=expires_at+60 WHERE id=?", (IDS["pending"],))
    conn.close()
    result = legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)
    fields = {(m["id"], m["field"]) for m in result["mismatches"]}
    assert not result["ok"]
    assert (IDS["personal"], "pinned") in fields
    assert (IDS["other"], "superseded_by") in fields and (IDS["other"], "lifecycle") in fields
    assert (IDS["pending"], "expires_at") in fields
    assert not any(field == "legacy_revision" for _, field in fields)  # the legacy revision never moved
    delta = importer(engine, admin, legacy_db, mapping).run()
    assert delta["updated"] == delta["metadata_deltas"] == 3
    assert engine.get(admin, IDS["personal"]).retention.pinned
    assert engine.get(admin, IDS["other"]).links.superseded_by == IDS["personal"]
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]
    # Package-side drift is caught as well (and is not mistaken for a legacy delta).
    rec = engine.get(admin, IDS["candidate_approved"])
    engine.set_pinned(admin, rec.id, True, expected_revision=rec.revision)
    drift = legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)
    assert not drift["ok"] and {"id": rec.id, "field": "pinned"} in drift["mismatches"]


# --------------------------------------------------------------------------- deletion propagation
def test_out_of_grant_legacy_deletion_propagates_without_aborting_others(engine, legacy_db, mapping, monkeypatch):
    narrow = access_for(projects=("proj-a",), operations=set(Operation))  # admin actor, proj-a grant only
    importer(engine, narrow, legacy_db, mapping).run()
    ctx = engine.partition_context(narrow.partition)
    original = ctx.services.forgetting.forget
    used: dict[str, object] = {}

    def spy(access, target, forget_policy, **kwargs):
        used[target.ref] = access
        return original(access, target, forget_policy, **kwargs)

    monkeypatch.setattr(ctx.services.forgetting, "forget", spy)
    vault = legacy_vault(legacy_db)
    deleted = ("other", "agent", "personal", "expired_validity")  # proj-b and agent are outside the grants
    for name in deleted:
        assert vault.delete(IDS[name])
    delta = importer(engine, narrow, legacy_db, mapping).run()
    assert delta["deleted_in_legacy"] == len(deleted)
    assert delta["deletion_propagation"] == {"propagated": len(deleted), "failed": 0, "failed_by_code": {}}
    # Each forget is authorized for exactly that record's own scope - never wider.
    assert used[IDS["other"]].grants == ScopeGrants(projects=frozenset({"proj-b"}))
    assert used[IDS["agent"]].grants == ScopeGrants(agents=frozenset({AGENT}))
    assert used[IDS["expired_validity"]].grants == ScopeGrants(projects=frozenset({"proj-a"}))
    assert used[IDS["personal"]].grants == ScopeGrants()
    for access in used.values():
        assert access.actor == Actor.HOST and access.operations == frozenset({Operation.FORGET, Operation.ADMIN})
        assert access.principal == narrow.principal and access.partition == narrow.partition
    everyone = access_for(projects=("proj-a", "proj-b"), agents=(AGENT,), operations=set(Operation))
    with ctx.partition.db.read() as conn:
        for name in deleted:
            assert ctx.services.forgetting.tombstone_generation(conn, "memory", IDS[name]) is not None
    for name in deleted:
        with pytest.raises(NotFound):
            engine.get(everyone, IDS[name])
    assert legacy_mod.verify(engine, everyone, legacy_db, KEY, mapping)["ok"]


def test_failed_deletion_propagation_continues_and_blocks_verification(engine, admin, legacy_db, mapping,
                                                                      monkeypatch):
    importer(engine, admin, legacy_db, mapping).run()
    ctx = engine.partition_context(admin.partition)
    original = ctx.services.forgetting.forget

    def flaky(access, target, forget_policy, **kwargs):
        if target.ref == IDS["agent"]:
            raise AccessDenied("simulated failure")
        return original(access, target, forget_policy, **kwargs)

    monkeypatch.setattr(ctx.services.forgetting, "forget", flaky)
    vault = legacy_vault(legacy_db)
    for name in ("agent", "other", "expired_validity"):
        assert vault.delete(IDS[name])
    delta = importer(engine, admin, legacy_db, mapping).run()
    assert delta["deletion_propagation"] == {"propagated": 2, "failed": 1, "failed_by_code": {"access_denied": 1}}
    assert delta["deleted_in_legacy"] == 2
    for name in ("other", "expired_validity"):
        with pytest.raises(NotFound):
            engine.get(admin, IDS[name])
    assert engine.get(admin, IDS["agent"])  # the failed one stays, and verification says so
    result = legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)
    assert not result["ok"] and result["mismatches"] == [{"id": IDS["agent"], "field": "deleted_in_legacy"}]
    monkeypatch.setattr(ctx.services.forgetting, "forget", original)
    retry = importer(engine, admin, legacy_db, mapping).run()
    assert retry["deletion_propagation"] == {"propagated": 1, "failed": 0, "failed_by_code": {}}
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]


def test_unpropagated_legacy_deletion_aborts_cutover(engine, control, admin, legacy_db, mapping, tmp_path,
                                                     monkeypatch):
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    assert migrator.validate()["validated"]
    ctx = engine.partition_context(admin.partition)

    def refuse(access, target, forget_policy, **kwargs):
        raise AccessDenied("simulated failure")

    monkeypatch.setattr(ctx.services.forgetting, "forget", refuse)
    assert legacy_vault(legacy_db).delete(IDS["other"])
    result = migrator.cutover()
    assert result["state"] == "legacy_authoritative" and not result["cutover"]
    assert result["delta"]["deletion_propagation"]["failed_by_code"] == {"access_denied": 1}
    assert {"id": IDS["other"], "field": "deleted_in_legacy"} in result["verify"]["mismatches"]
    control.assert_writer(admin.partition.partition_id, "memories", "legacy")


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


def test_rollback_writes_back_a_post_cutover_pin(engine, control, admin, legacy_db, mapping, tmp_path):
    migrator = make_migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    migrator.validate()
    migrator.cutover()
    rec = engine.get(admin, IDS["candidate_approved"])
    assert not rec.retention.pinned and legacy_column(legacy_db, rec.id, "pinned") == 0
    engine.set_pinned(admin, rec.id, True, expected_revision=rec.revision)
    result = migrator.rollback()
    assert result["state"] == "legacy_authoritative"
    assert legacy_column(legacy_db, rec.id, "pinned") == 1


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
