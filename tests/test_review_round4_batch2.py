"""Round-4 review, batch 2: regression tests for the reproduced defects.

R4-TAMPER-7  a plaintext meta.legacy_residue_generation marker disabled purging forgotten rows from
             the live legacy vault after cutover, while receipts reported a complete forget
R4-TAMPER-8  the procedure evidence gate mapped episode ids to records through the plaintext episodes
             index without checking the decrypted episode id (failed episodes counted as verified)
R4-TAMPER-9  evidence revocation was driven by the plaintext procedure_evidence index
R4-MF-3      a snapshot from a failed or crashed prepare_shadow was never recorded or removed; after
             an abort the recorded snapshot outlived a legacy-side delete
R4-EG-2      a record citing a memory only as SourceRef(MEMORY) escaped retention inheritance, expiry,
             staling on correction and the excluded-observation hide/purge
R4-EG-3      repository observations left under memory_text consent (extraction via the observation,
             external sync, embedding, summarization)
R4-EG-4      derived-record invalidation was one level deep
R4-EG-5      a READ-only caller could poison a stored embedding with a forged title
"""
from __future__ import annotations

import dataclasses
import json
import secrets
import shutil
import sqlite3
from pathlib import Path

import pytest

import test_learning as learning
import test_review_group1 as group1
from conftest import FakeClock, access_for
from foundation_support import db_path, raw_db
from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.errors import (
    ConsentRequired,
    Contention,
    IntegrityError,
    InvalidTransition,
    MigrationError,
    NotFound,
)
from locus_memory.forgetting import _LEGACY_AUTHORITY, _MIGRATION_RESIDUE
from locus_memory.host import EngineConfig, HostCapabilities
from locus_memory.migrations import legacy as legacy_mod
from locus_memory.migrations.cutover import RESIDUE_KEY, Migrator, SimulatedCrash
from locus_memory.models import (
    Actor,
    CandidateProposal,
    ContextRequest,
    Correction,
    EpisodeOutcome,
    ForgetTarget,
    Lifecycle,
    MemoryKind,
    Operation,
    ProcedureState,
    Query,
    RememberRequest,
    Retention,
    Scope,
    SourceKind,
    SourceRef,
    Validity,
)
from locus_memory.providers.base import (
    DATA_MEMORY_TEXT,
    DATA_REPOSITORY_SOURCE,
    ConsentGrant,
    StaticConsentPolicy,
)
from test_learning import draft, report, two_independent
from test_repository import GIT, make_repo
from test_review_group1 import AGENT, IDS, KEY, OTHER, WS, _cut_over

# Shared fixtures (registered here under the same names).
admin = group1.admin
control = group1.control
legacy_db = group1.legacy_db
mapping = group1.mapping
menv = group1.menv
authority = learning.authority
runner = learning.runner
eng = learning.eng
needs_git = pytest.mark.skipif(GIT is None, reason="git is required for repository memory tests")


def _legacy_rows(path: Path) -> dict[str, dict]:
    return {row["id"]: row for row in LegacyMemoryVault(path, key=KEY).raw_rows()}


def _meta(root: Path, access, key: str) -> str | None:
    with raw_db(db_path(root, access)) as conn:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


# =========================================================================== R4-TAMPER-7
@pytest.mark.parametrize("marker", ["999999", "garbage", "0", "current-forged"])
def test_tamper7_a_forged_residue_marker_never_skips_the_legacy_purge(marker, menv, control, admin, legacy_db,
                                                                       mapping, tmp_path, root, make_engine):
    _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    menv.close()
    with raw_db(db_path(root, admin)) as conn:
        generation = int(conn.execute("SELECT value FROM meta WHERE key='deletion_generation'").fetchone()[0])
        # An offline tamperer (no keys) writes a marker at or "ahead of" the next deletion generation.
        value = {"999999": "999999", "garbage": "garbage", "0": str(generation + 1),
                 "current-forged": f"{generation + 1}:{'0' * 64}"}[marker]
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (RESIDUE_KEY, value))
    engine = make_engine(host=HostCapabilities(ownership=control))
    target = IDS["personal"]
    assert target in _legacy_rows(legacy_db)
    receipt = engine.forget(admin, ForgetTarget("memory", target))
    assert receipt.deleted.get("memories")
    # The forget reached the live legacy vault, so the receipt's claim of a complete forget is true.
    assert target not in _legacy_rows(legacy_db)
    assert receipt.physical_purge_pending is False
    assert _MIGRATION_RESIDUE not in receipt.receipt.limitations
    assert _meta(root, admin, RESIDUE_KEY) != value  # replaced by an authenticated marker


def test_tamper7_reopening_purges_whatever_the_marker_says(menv, control, admin, legacy_db, mapping, tmp_path,
                                                           root, make_engine):
    _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    target = IDS["personal"]
    receipt = menv.forget(admin, ForgetTarget("memory", target))
    assert target not in _legacy_rows(legacy_db) and not receipt.physical_purge_pending
    authentic = _meta(root, admin, RESIDUE_KEY)
    assert authentic and ":" in authentic  # a keyed marker, not a plaintext counter
    menv.close()
    # The row comes back in the legacy file (e.g. an older copy restored) while the marker still says
    # "done": the open re-checks anyway.
    shutil.copy(group1.FIXTURE / "memory.sqlite3", legacy_db)
    for suffix in ("-wal", "-shm"):
        Path(str(legacy_db) + suffix).unlink(missing_ok=True)
    assert target in _legacy_rows(legacy_db)
    engine = make_engine(host=HostCapabilities(ownership=control))
    engine.list(admin)
    assert target not in _legacy_rows(legacy_db)
    assert _meta(root, admin, RESIDUE_KEY) == authentic


def test_tamper7_a_stripped_cutover_set_still_purges_ledger_forgotten_rows(menv, control, admin, legacy_db,
                                                                          mapping, tmp_path, root, make_engine):
    _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    menv.close()
    with raw_db(db_path(root, admin)) as conn:
        conn.execute("DELETE FROM migration_cutover_ids")  # plaintext table, editable offline
    engine = make_engine(host=HostCapabilities(ownership=control))
    target = IDS["personal"]
    receipt = engine.forget(admin, ForgetTarget("memory", target))
    assert receipt.deleted.get("memories")
    # The authenticated ledger proves the forget: the legacy copy goes regardless of the plaintext set.
    assert target not in _legacy_rows(legacy_db)
    assert not receipt.physical_purge_pending


# =========================================================================== R4-TAMPER-8
def _failed_and_verified(engine, user, agent, auth):
    two_independent(engine, user, auth)
    f1, _ = engine.record_episode(agent, report("ep-f1", "task-x", claimed="failure"))
    f2, _ = engine.record_episode(agent, report("ep-f2", "task-y", claimed="failure"))
    assert f1.outcome == EpisodeOutcome.FAILURE and f2.outcome == EpisodeOutcome.FAILURE


def _alias_failed_to_verified(root, access) -> None:
    with raw_db(db_path(root, access)) as conn:
        records = {r[0]: r[1] for r in conn.execute("SELECT episode_id, record_id FROM episodes")}
        conn.execute("UPDATE episodes SET record_id=? WHERE episode_id='ep-f1'", (records["ep-one"],))
        conn.execute("UPDATE episodes SET record_id=? WHERE episode_id='ep-f2'", (records["ep-two"],))


def _learning_engine(make_engine, clock, auth, run):
    return make_engine(host=HostCapabilities(clock=clock, verification=auth, evaluation_runner=run))


def test_tamper8_an_aliased_episode_index_never_counts_as_verified_evidence(make_engine, clock, authority, runner,
                                                                          user_access, agent_access, root):
    engine = _learning_engine(make_engine, clock, authority, runner)
    _failed_and_verified(engine, user_access, agent_access, authority)
    engine.close()
    _alias_failed_to_verified(root, user_access)
    engine = _learning_engine(make_engine, clock, authority, runner)
    procedure, _ = engine.nominate_procedure(agent_access, draft(evidence=("ep-f1", "ep-f2"), name="shortcut-b"))
    assert procedure.state == ProcedureState.INSUFFICIENT_EVIDENCE
    assert procedure.independent_evidence == 0
    # The aliased ids lead nowhere: the index row does not name the record's own episode.
    with pytest.raises(NotFound):
        engine.get_episode(user_access, "ep-f1")
    assert [e.episode_id for e in engine.list_episodes(user_access, outcome="verified_success")] in (
        ["ep-one", "ep-two"], ["ep-two", "ep-one"])
    with raw_db(db_path(root, user_access)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM events WHERE reason_code='episode_index_mismatch'").fetchone()[0]


def test_tamper8_an_aliased_nomination_is_never_evaluated_approved_or_injected(make_engine, clock, authority,
                                                                              runner, user_access, agent_access,
                                                                              root):
    engine = _learning_engine(make_engine, clock, authority, runner)
    _failed_and_verified(engine, user_access, agent_access, authority)
    engine.close()
    _alias_failed_to_verified(root, user_access)
    engine = _learning_engine(make_engine, clock, authority, runner)
    procedure, _ = engine.nominate_procedure(agent_access, draft(evidence=("ep-f1", "ep-f2"), name="shortcut-c"))
    with pytest.raises(InvalidTransition):
        engine.evaluate_procedure(user_access, procedure.procedure_id)
    with pytest.raises(InvalidTransition):
        engine.approve_procedure(user_access, procedure.procedure_id, expected_version=procedure.version)
    packet = engine.build_context(user_access, ContextRequest(token_allowance=4000, query="shortcut-c procedure"))
    assert procedure.record_id not in {item.record_id for item in packet.items}


def test_tamper8_a_repointed_index_row_never_resumes_another_episode(make_engine, clock, authority, runner,
                                                                    user_access, agent_access, root):
    engine = _learning_engine(make_engine, clock, authority, runner)
    _failed_and_verified(engine, user_access, agent_access, authority)
    engine.close()
    _alias_failed_to_verified(root, user_access)
    engine = _learning_engine(make_engine, clock, authority, runner)
    with pytest.raises(IntegrityError):
        engine.record_episode(agent_access, report("ep-f1", "task-x", attempt="a2", claimed="failure"))


def test_tamper8_a_repointed_procedure_index_serves_nothing(eng, user_access, authority, root, make_engine, clock,
                                                           runner):
    first = learning.approved_procedure(eng, user_access, authority)
    second, _ = eng.nominate_procedure(user_access, draft(evidence=("ep-one", "ep-two"), name="another-procedure"))
    eng.close()
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("UPDATE procedures SET record_id=? WHERE procedure_id=?", (second.record_id, first.procedure_id))
    engine = _learning_engine(make_engine, clock, authority, runner)
    with pytest.raises(NotFound):
        engine.services(user_access).procedures.get(user_access, first.procedure_id)


# =========================================================================== R4-TAMPER-9
def _strip_evidence_index(root, access) -> None:
    with raw_db(db_path(root, access)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM procedure_evidence").fetchone()[0]
        conn.execute("DELETE FROM procedure_evidence")


def _assert_revoked(engine, access, procedure_id: str, dest: Path) -> None:
    after = engine.services(access).procedures.get(access, procedure_id)
    assert after.state == ProcedureState.REVOKED_EVIDENCE
    assert after.evidence_episode_ids == ("ep-two",) and after.independent_evidence == 1
    assert engine.get(access, after.record_id).lifecycle == Lifecycle.STALE
    packet = engine.build_context(access, ContextRequest(token_allowance=8000))
    assert after.record_id not in {item.record_id for item in packet.items}
    dest.mkdir(exist_ok=True)
    with pytest.raises(InvalidTransition):
        engine.export_procedure(access, procedure_id, dest)


def test_tamper9_forgetting_evidence_revokes_without_the_plaintext_evidence_index(eng, user_access, authority,
                                                                                 root, make_engine, clock, runner,
                                                                                 tmp_path):
    approved = learning.approved_procedure(eng, user_access, authority)
    episode_record = eng.get_episode(user_access, "ep-one").record_id
    eng.close()
    _strip_evidence_index(root, user_access)
    engine = _learning_engine(make_engine, clock, authority, runner)
    receipt = engine.forget(user_access, ForgetTarget("memory", episode_record))
    assert receipt.deleted.get("procedures_revoked") == 1
    _assert_revoked(engine, user_access, approved.procedure_id, tmp_path / "skills")


def test_tamper9_read_paths_and_maintenance_catch_an_unrevoked_procedure(eng, user_access, authority, root,
                                                                        make_engine, clock, runner, tmp_path):
    """The state an earlier build left: the evidence episode is gone, the procedure still approved."""
    approved = learning.approved_procedure(eng, user_access, authority)
    eng.close()
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("DELETE FROM episodes WHERE episode_id='ep-one'")  # gone, never re-assessed
    engine = _learning_engine(make_engine, clock, authority, runner)
    packet = engine.build_context(user_access, ContextRequest(token_allowance=8000))
    assert approved.record_id not in {item.record_id for item in packet.items}
    assert engine.services(user_access).procedures.get(user_access, approved.procedure_id).state == \
        ProcedureState.APPROVED  # not re-assessed yet
    engine.maintain(user_access)
    _assert_revoked(engine, user_access, approved.procedure_id, tmp_path / "skills")


def test_tamper9_export_reassesses_before_writing(eng, user_access, authority, root, make_engine, clock, runner,
                                                 tmp_path):
    approved = learning.approved_procedure(eng, user_access, authority)
    eng.close()
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("DELETE FROM episodes WHERE episode_id='ep-one'")
    engine = _learning_engine(make_engine, clock, authority, runner)
    dest = tmp_path / "skills"
    dest.mkdir()
    with pytest.raises(InvalidTransition):
        engine.export_procedure(user_access, approved.procedure_id, dest)
    assert not any(dest.rglob("*.md"))
    _assert_revoked(engine, user_access, approved.procedure_id, dest)


# =========================================================================== R4-MF-3
FIXTURE = group1.FIXTURE
VICTIM = IDS["ws_fact"]


class _Env:
    def __init__(self, tmp: Path, *, busy_ms: int = 5_000) -> None:
        from locus_memory.migrations.state import OwnershipControl

        self._control_type = OwnershipControl
        self.root = tmp / "root"
        self.work = tmp / "migration"
        self.legacy = tmp / "legacy" / "memory.sqlite3"
        self.legacy.parent.mkdir(parents=True)
        shutil.copy(FIXTURE / "memory.sqlite3", self.legacy)
        self.busy_ms = busy_ms
        self.keys = StaticKeyProvider({"k1": secrets.token_bytes(32)})
        self.admin = access_for(projects=("proj-a", "proj-b"), agents=(AGENT,), operations=set(Operation))
        self.mapping = legacy_mod.LegacyMapping.from_known({WS: "proj-a", OTHER: "proj-b"}, [AGENT])
        self.open()

    def open(self) -> None:
        self.control = self._control_type(self.root)
        self.engine = MemoryEngine(self.root, self.keys, host=HostCapabilities(ownership=self.control,
                                                                              clock=FakeClock()),
                                   config=EngineConfig(busy_timeout_ms=self.busy_ms))

    def close(self) -> None:
        self.engine.close()
        self.control.close()

    def restart(self) -> None:
        self.close()
        self.open()

    def migrator(self) -> Migrator:
        return Migrator(self.engine, self.control, self.admin, self.legacy, KEY, self.mapping, work_dir=self.work,
                        project_workspaces={"proj-a": WS, "proj-b": OTHER})

    def snapshots(self) -> list[Path]:
        return sorted(self.work.glob("snapshot-*/legacy-snapshot.sqlite3"))


def _finish_and_forget(env: _Env):
    m = env.migrator()
    assert m.prepare_shadow()["state"] == "shadow_prepared"
    assert m.validate()["validated"]
    cut = m.cutover()
    assert cut["state"] == "package_authoritative" and cut["legacy_residue"]["complete"] is True
    return env.engine.forget(env.admin, ForgetTarget("memory", VICTIM))


@pytest.mark.parametrize("point", ["after_snapshot", "after_shadow_import"])
def test_mf3_a_crashed_prepare_shadow_leaves_no_snapshot_after_cutover(tmp_path, point):
    env = _Env(tmp_path)
    try:
        m = env.migrator()
        m.crash_at = point
        with pytest.raises(SimulatedCrash):
            m.prepare_shadow()
        assert len(env.snapshots()) == 1
        recorded = env.control.get(env.admin.partition.partition_id, "memories").details["snapshot_dirs"]
        assert [Path(p).name for p in recorded] == [env.snapshots()[0].parent.name]  # recorded before writing
        env.restart()
        receipt = _finish_and_forget(env)
        assert receipt.deleted.get("memories")
        assert env.snapshots() == []
        assert receipt.physical_purge_pending is False and _MIGRATION_RESIDUE not in receipt.receipt.limitations
    finally:
        env.close()


def test_mf3_a_failed_prepare_shadow_removes_its_snapshot(tmp_path):
    env = _Env(tmp_path, busy_ms=100)
    try:
        ctx = env.engine.partition_context(env.admin.partition)
        blocker = sqlite3.connect(ctx.partition.db.path, isolation_level=None)
        blocker.execute("BEGIN IMMEDIATE")
        try:
            with pytest.raises(Contention):
                env.migrator().prepare_shadow()
        finally:
            blocker.execute("ROLLBACK")
            blocker.close()
        assert env.control.get(env.admin.partition.partition_id, "memories").state == "legacy_authoritative"
        assert env.snapshots() == []  # removed when the attempt failed
        receipt = _finish_and_forget(env)
        assert env.snapshots() == [] and not receipt.physical_purge_pending
    finally:
        env.close()


def test_mf3_an_unrecorded_owned_snapshot_is_found_and_reported_until_removed(tmp_path):
    """A snapshot an earlier build left unrecorded but marked with this partition's manifest owner
    (or one whose recording was lost) is swept from the recorded work directory."""
    env = _Env(tmp_path)
    try:
        receipt = _finish_and_forget(env)
        assert env.snapshots() == [] and not receipt.physical_purge_pending
        stray = env.work / "snapshot-1"
        legacy_mod.snapshot(env.legacy, stray, owner=env.admin.partition.partition_id)
        foreign = env.work / "snapshot-2"
        legacy_mod.snapshot(env.legacy, foreign, owner="another-partition")
        operator = env.work / "snapshot-3"
        operator.mkdir()
        (operator / "notes.txt").write_text("mine")
        again = env.engine.forget(env.admin, ForgetTarget("memory", IDS["personal"]))
        assert not again.physical_purge_pending
        assert not stray.exists()
        assert (foreign / "legacy-snapshot.sqlite3").exists()  # another partition's: never touched
        assert (operator / "notes.txt").read_text() == "mine"
    finally:
        env.close()


def test_mf3_abort_removes_the_recorded_snapshot(tmp_path):
    env = _Env(tmp_path)
    try:
        m = env.migrator()
        m.prepare_shadow()
        assert m.validate()["validated"]
        receipt = env.engine.forget(env.admin, ForgetTarget("memory", VICTIM))
        assert _LEGACY_AUTHORITY in receipt.receipt.limitations
        assert len(env.snapshots()) == 1
        result = m.abort_cutover("operator changed mind")
        assert result["state"] == "legacy_authoritative" and result["snapshots_removed"] == 1
        assert env.snapshots() == []
        guard = env.control.writer_guard(env.admin.partition.partition_id, "memories", "legacy")
        assert LegacyMemoryVault(env.legacy, key=KEY, write_guard=guard).delete(VICTIM, workspace=WS)
        assert VICTIM not in _legacy_rows(env.legacy)  # forgotten there: no copy anywhere
    finally:
        env.close()


def test_mf3_a_retried_prepare_shadow_removes_the_earlier_attempts_copy(tmp_path):
    env = _Env(tmp_path)
    try:
        m = env.migrator()
        m.crash_at = "after_shadow_import"
        with pytest.raises(SimulatedCrash):
            m.prepare_shadow()
        first = env.snapshots()
        env.restart()
        env.migrator().prepare_shadow()
        now = env.snapshots()
        assert len(now) == 1 and now != first
        manifest = json.loads((now[0].parent / "manifest.json").read_text())
        assert manifest["owner"] == env.admin.partition.partition_id
    finally:
        env.close()


def test_mf3_update_details_never_changes_state_or_generation(tmp_path):
    from locus_memory.errors import RevisionConflict
    from locus_memory.migrations.state import OwnershipControl

    control = OwnershipControl(tmp_path)
    try:
        before = control.get("p1", "memories")
        after = control.update_details("p1", "memories", expected_generation=before.generation,
                                       details={"work_dir": "/w"}, append={"snapshot_dirs": ["a", "b"]})
        after = control.update_details("p1", "memories", expected_generation=before.generation,
                                       append={"snapshot_dirs": ["b", "c"]})
        assert after.state == before.state and after.generation == before.generation
        assert after.details == {"work_dir": "/w", "snapshot_dirs": ["a", "b", "c"]}
        moved = control.transition("p1", "memories", "shadow_prepared", expected_generation=after.generation,
                                   reason="t")
        assert moved.details["snapshot_dirs"] == ["a", "b", "c"]
        with pytest.raises(RevisionConflict):
            control.update_details("p1", "memories", expected_generation=before.generation, details={})
    finally:
        control.close()


def test_mf3_migration_error_import_leaves_no_snapshot(tmp_path, monkeypatch):
    env = _Env(tmp_path)
    try:
        m = env.migrator()

        def refuse(self):
            raise MigrationError("the legacy store holds a row the package cannot import")

        monkeypatch.setattr(legacy_mod.LegacyImporter, "run", refuse)
        with pytest.raises(MigrationError):
            m.prepare_shadow()
        assert env.snapshots() == []
        assert env.control.get(env.admin.partition.partition_id, "memories").state == "legacy_authoritative"
    finally:
        env.close()




# =========================================================================== R4-EG-2
P = Scope.of(project="p")


def _p_actors():
    user = access_for(projects=("p",))
    agent = access_for(actor=Actor.AGENT, projects=("p",), operations={Operation.READ, Operation.PROPOSE})
    return user, agent


def _approved_citer(engine, user, agent, content, scope, cited_id, *, derived=False, extra_sources=()):
    candidate = engine.propose(agent, CandidateProposal(
        content=content, scope=scope, sources=(SourceRef(SourceKind.MEMORY, cited_id), *extra_sources),
        derived_from=(cited_id,) if derived else (), proposer="agent-x")).record
    return engine.approve(user, candidate.id, expected_revision=candidate.revision).record


def _in_context(engine, access, needle: str, query: str) -> bool:
    return needle in engine.build_context(access, ContextRequest(token_allowance=800, query=query)).text


def _gone(engine, access, record_id: str) -> bool:
    try:
        engine.get(access, record_id)
    except NotFound:
        return True
    return False


def test_eg2_a_citer_inherits_its_inputs_retention_and_expires_with_it(engine, clock):
    user, agent = _p_actors()
    m = engine.remember(user, RememberRequest(content="This week the lab door code is 4471", scope=P,
                                              retention=Retention("transient", clock() + 3600))).record
    control = _approved_citer(engine, user, agent, "Lab door code (derived): 4471", P, m.id, derived=True)
    citer = _approved_citer(engine, user, agent, "Lab door code: 4471", P, m.id)
    assert control.retention.expires_at == m.retention.expires_at
    assert citer.retention.policy == "transient" and citer.retention.expires_at == m.retention.expires_at
    clock.advance(7200)
    engine.maintain(user)
    assert engine.get(user, m.id).lifecycle == Lifecycle.EXPIRED
    assert engine.get(user, control.id).lifecycle == Lifecycle.EXPIRED
    assert engine.get(user, citer.id).lifecycle == Lifecycle.EXPIRED
    assert not _in_context(engine, user, "Lab door code: 4471", "lab door code")


def test_eg2_a_citer_candidate_inherits_the_capped_ttl(engine, clock):
    user, agent = _p_actors()
    m = engine.remember(user, RememberRequest(content="Visitor badge pin is 8812 today", scope=P,
                                              retention=Retention("transient", clock() + 600))).record
    candidate = engine.propose(agent, CandidateProposal(content="Visitor badge pin: 8812", scope=P,
                                                        sources=(SourceRef(SourceKind.MEMORY, m.id),))).record
    assert candidate.retention.expires_at == m.retention.expires_at
    clock.advance(1200)
    with pytest.raises(InvalidTransition):
        engine.approve(user, candidate.id, expected_revision=candidate.revision)


def test_eg2_a_citer_goes_stale_when_its_input_is_corrected(engine):
    user, agent = _p_actors()
    m = engine.remember(user, RememberRequest(content="Deploy window is Tuesday 9am", scope=P)).record
    control = _approved_citer(engine, user, agent, "Derived note: deploy slot Tuesday 9am", P, m.id, derived=True)
    citer = _approved_citer(engine, user, agent, "Team deploys Tuesday 9am", P, m.id)
    pending = engine.propose(agent, CandidateProposal(content="Deploys happen on Tuesday mornings", scope=P,
                                                      sources=(SourceRef(SourceKind.MEMORY, m.id),))).record
    receipt = engine.correct(user, m.id, Correction(content="Deploy window is Thursday 2pm"),
                             expected_revision=None).receipt
    assert receipt.details["derived_marked_stale"] == 3
    assert engine.get(user, control.id).lifecycle == Lifecycle.STALE
    assert engine.get(user, citer.id).lifecycle == Lifecycle.STALE
    assert engine.get(user, pending.id).lifecycle == Lifecycle.EXPIRED
    assert not _in_context(engine, user, "Team deploys Tuesday 9am", "deploy window")


def test_eg2_an_attested_citer_with_independent_evidence_keeps_its_statement(engine, clock):
    user, _agent = _p_actors()
    m = engine.remember(user, RememberRequest(content="Standup moved to 10am this sprint", scope=P,
                                              retention=Retention("transient", clock() + 3600))).record
    other = engine.remember(user, RememberRequest(content="The team calendar lists standup at 10am", scope=P)).record
    mine = engine.remember(user, RememberRequest(
        content="Standup is at 10am", scope=P,
        sources=(SourceRef(SourceKind.MEMORY, m.id), SourceRef(SourceKind.MEMORY, other.id)))).record
    engine.correct(user, m.id, Correction(content="Standup moved to 11am this sprint"), expected_revision=None)
    assert engine.get(user, mine.id).lifecycle == Lifecycle.APPROVED
    clock.advance(7200)
    engine.maintain(user)
    assert engine.get(user, m.id).lifecycle == Lifecycle.EXPIRED
    kept = engine.get(user, mine.id)
    assert kept.lifecycle == Lifecycle.APPROVED and kept.retention.expires_at is None
    # The same attested statement citing only that memory follows it.
    only = engine.remember(user, RememberRequest(
        content="Retro happens after standup", scope=P, sources=(SourceRef(SourceKind.MEMORY, other.id),))).record
    engine.correct(user, other.id, Correction(content="The team calendar lists standup at 9am"),
                   expected_revision=None)
    assert engine.get(user, only.id).lifecycle == Lifecycle.STALE


def _payroll_repo(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    repo = make_repo(allowed / "repo", {"payroll/rates.py":
                                        '"""Payroll override rates for ACME execs: CEO 3x."""\nimport os\n',
                                        "app.py": '"""Application entry point."""\nimport os\n'})
    return allowed, repo


@needs_git
def test_eg2_citers_of_an_excluded_observation_are_hidden_then_purged(tmp_path, keys, clock):
    allowed, repo = _payroll_repo(tmp_path)
    root = tmp_path / "root"

    def open_engine(patterns=()):
        return MemoryEngine(root, keys, host=HostCapabilities(
            clock=clock, allowed_repository_roots=(allowed,), repository_exclude_patterns=patterns))

    user = access_for(repositories=("r",))
    agent = access_for(actor=Actor.AGENT, repositories=("r",), operations={Operation.READ, Operation.PROPOSE})
    r_scope = Scope.of(repository="r")
    engine = open_engine()
    try:
        engine.register_repository(user, repo, repository_id="r")
        engine.snapshot_repository(user, "r")
        observations = {r.extra.get("path"): r for r in engine.list(user) if r.kind == MemoryKind.REPOSITORY_OBSERVATION}
        obs, app = observations["payroll/rates.py"], observations["app.py"]
        citer = _approved_citer(engine, user, agent, "ACME exec payroll override: CEO gets 3x", r_scope, obs.id)
        second = _approved_citer(engine, user, agent, "Executive pay multiplier noted: 3x", r_scope, citer.id)
        attested = engine.remember(user, RememberRequest(
            content="Payroll rules live next to the app entry point", scope=r_scope,
            sources=(SourceRef(SourceKind.MEMORY, obs.id), SourceRef(SourceKind.MEMORY, app.id)))).record
    finally:
        engine.close()
    engine = open_engine(("payroll/**",))
    try:
        for hidden in (obs.id, citer.id, second.id):
            assert _gone(engine, user, hidden)
        assert engine.get(user, attested.id).lifecycle == Lifecycle.APPROVED  # other live evidence
        assert not _in_context(engine, user, "CEO gets 3x", "CEO override")
        engine.snapshot_repository(user, "r")  # purges the observation and what follows it
        ctx = engine.partition_context(user.partition)
        with ctx.partition.db.read() as conn:
            assert ctx.records.get(conn, citer.id) is None and ctx.records.get(conn, second.id) is None
        kept = engine.get(user, attested.id)
        assert {s.ref for s in kept.sources} == {app.id}  # the purged citation is dropped
    finally:
        engine.close()


# =========================================================================== R4-EG-4
def _extract_from(engine, access, parent, text):
    hub = engine.services(access).providers
    return hub.extract_candidates(access, [{"id": "e1", "text": text, "source": SourceRef(SourceKind.MEMORY, parent.id),
                                            "scope": parent.scope}], provider="fake-extract")[0].record


def _approve(engine, access, record_id):
    return engine.approve(access, record_id, expected_revision=engine.get(access, record_id).revision).record


def _plain_chain(engine, user, agent, **kw):
    i1 = engine.remember(user, RememberRequest(content="Deploy window is Tuesday 14:00 UTC", scope=P, **kw)).record
    e1 = _approve(engine, user, _extract_from(engine, user, i1, "Deploy window is Tuesday 14:00 UTC").id)
    l2 = engine.propose(agent, CandidateProposal(content="Release train departs Tuesdays at 14:00 UTC", scope=P,
                                                 sources=(SourceRef(SourceKind.MEMORY, e1.id),),
                                                 derived_from=(e1.id,))).record
    l2 = _approve(engine, user, l2.id)
    l3 = engine.propose(agent, CandidateProposal(content="Freeze code before the Tuesday train", scope=P,
                                                 sources=(SourceRef(SourceKind.MEMORY, l2.id),),
                                                 derived_from=(l2.id,))).record
    l3 = _approve(engine, user, l3.id)
    return i1, e1, l2, l3


@pytest.fixture
def chain_engine(make_engine, clock):
    from locus_memory.providers.fake import FakeExtractor

    return make_engine(host=HostCapabilities(clock=clock, providers={"fake-extract": FakeExtractor()}))


def test_eg4_correction_invalidates_every_level(chain_engine):
    user, agent = _p_actors()
    i1, e1, l2, l3 = _plain_chain(chain_engine, user, agent)
    receipt = chain_engine.correct(user, i1.id, Correction(content="Deploy window is Thursday 09:00 UTC"),
                                   expected_revision=None).receipt
    assert receipt.details["derived_marked_stale"] == 3
    for record in (e1, l2, l3):
        assert chain_engine.get(user, record.id).lifecycle == Lifecycle.STALE
    assert not _in_context(chain_engine, user, "Tuesdays at 14:00", "deploy release Tuesday")


def test_eg4_supersede_invalidates_every_level(chain_engine):
    user, agent = _p_actors()
    i1, e1, l2, l3 = _plain_chain(chain_engine, user, agent)
    new = chain_engine.remember(user, RememberRequest(content="Deploy window is Thursday 09:00 UTC", scope=P)).record
    chain_engine.supersede(user, i1.id, new.id, expected_revision=i1.revision)
    for record in (e1, l2, l3):
        assert chain_engine.get(user, record.id).lifecycle == Lifecycle.STALE
    assert chain_engine.get(user, new.id).lifecycle == Lifecycle.APPROVED


def test_eg4_validity_and_retention_end_reach_every_level(chain_engine, clock):
    user, agent = _p_actors()
    i1, e1, l2, l3 = _plain_chain(chain_engine, user, agent, validity=Validity(valid_until=clock() + 100))
    clock.advance(500)
    chain_engine.maintain(user)
    for record in (i1, e1, l2, l3):
        assert chain_engine.get(user, record.id).lifecycle == Lifecycle.STALE
    j1, f1, m2, m3 = _plain_chain(chain_engine, user, agent, retention=Retention("transient", clock() + 100))
    assert m3.retention.expires_at == j1.retention.expires_at  # inherited through every level
    clock.advance(500)
    chain_engine.maintain(user)
    for record in (j1, f1, m2, m3):
        assert chain_engine.get(user, record.id).lifecycle == Lifecycle.EXPIRED


def test_eg4_a_second_level_replica_is_withdrawn(make_engine, clock):
    from locus_memory.providers.fake import FakeExternalMemory, FakeExtractor

    ext = FakeExternalMemory("ext", clock=clock)
    consent = StaticConsentPolicy([ConsentGrant(provider="ext", granted_at=clock() - 1)])
    engine = make_engine(host=HostCapabilities(clock=clock, consent=consent,
                                               providers={"fake-extract": FakeExtractor(), "ext": ext}))
    user, agent = _p_actors()
    i1, _e1, _l2, _l3 = _plain_chain(engine, user, agent)
    hub = engine.services(user).providers
    hub.sync_external(user, "ext")
    assert any("Release train departs" in item["content"] for item in ext.items.values())
    engine.correct(user, i1.id, Correction(content="Deploy window is Thursday 09:00 UTC"), expected_revision=None)
    hub.process_outbox(user)
    contents = [item["content"] for item in ext.items.values()]
    assert not any("Release train departs" in c or "Freeze code" in c for c in contents)


@needs_git
def test_eg4_a_deeper_derivation_of_an_excluded_observation_is_hidden_everywhere(tmp_path, keys, clock):
    from locus_memory.providers.fake import FakeExtractor

    allowed, repo = _payroll_repo(tmp_path)
    extractor = FakeExtractor(data_classes=("memory_text", "repository_source"))

    def open_engine(patterns=()):
        return MemoryEngine(tmp_path / "root", keys, host=HostCapabilities(
            clock=clock, providers={"fake-extract": extractor}, allowed_repository_roots=(allowed,),
            repository_exclude_patterns=patterns))

    user = access_for(repositories=("r",))
    agent = access_for(actor=Actor.AGENT, repositories=("r",), operations={Operation.READ, Operation.PROPOSE})
    r_scope = Scope.of(repository="r")
    engine = open_engine()
    try:
        engine.register_repository(user, repo, repository_id="r")
        engine.snapshot_repository(user, "r")
        obs = next(r for r in engine.list(user) if r.extra.get("path") == "payroll/rates.py")
        ext = _approve(engine, user, _extract_from(engine, user, obs, "Payroll override rates for ACME execs: CEO 3x.").id)
        level2 = engine.propose(agent, CandidateProposal(content="Exec comp policy: CEO override is 3x base",
                                                         sources=(SourceRef(SourceKind.MEMORY, ext.id),),
                                                         derived_from=(ext.id,), scope=r_scope)).record
        level2 = _approve(engine, user, level2.id)
    finally:
        engine.close()
    engine = open_engine(("payroll/**",))
    try:
        for hidden in (obs.id, ext.id, level2.id):
            assert _gone(engine, user, hidden)
        with pytest.raises(NotFound):
            engine.explain(user, level2.id)
        assert level2.id not in [h.record.id for h in engine.search(user, "policy base").hits]
    finally:
        engine.close()


# =========================================================================== R4-EG-3
SECRET_DOC = "Fraud rules: auto-approve refunds under 500 for VIP tier; skip KYC."
QUOTE = "auto-approve refunds under 500 for VIP tier; skip KYC"


@pytest.fixture
def source_env(tmp_path):
    from locus_memory.providers.fake import (
        FakeEmbeddingProvider,
        FakeExternalMemory,
        FakeExtractor,
        FakeSummarizer,
    )

    clock = FakeClock()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    repo = make_repo(allowed / "repo", {
        "billing/fraud.py": f'"""{SECRET_DOC}"""\nimport os\nclass FraudGate:\n    pass\n',
        "billing/ledger.py": '"""Ledger internals: hidden reserve account 77."""\nclass Ledger:\n    pass\n',
        "billing/limits.py": '"""Limit tables: VIP override threshold."""\nclass Limits:\n    pass\n',
    })
    both = frozenset({DATA_MEMORY_TEXT, DATA_REPOSITORY_SOURCE})
    providers = {p.descriptor.name: p for p in (
        FakeExternalMemory(clock=clock), FakeExtractor("cloud-extract", egress=True),
        FakeEmbeddingProvider("cloud-embed", egress=True), FakeSummarizer("cloud-sum", egress=True))}
    for provider in providers.values():  # every provider would accept repository source (with consent)
        provider.descriptor = dataclasses.replace(provider.descriptor, data_classes_accepted=both)
    r_scope = Scope.of(repository="r")
    consent = StaticConsentPolicy([ConsentGrant(provider=name, scope=r_scope, granted_at=clock() - 1,
                                                data_classes=frozenset({DATA_MEMORY_TEXT})) for name in providers])
    engine = MemoryEngine(tmp_path / "root", StaticKeyProvider({"k1": secrets.token_bytes(32)}),
                          host=HostCapabilities(clock=clock, providers=providers, consent=consent,
                                                allowed_repository_roots=(allowed,)))
    user = access_for(repositories=("r",))
    engine.register_repository(user, repo, repository_id="r")
    engine.snapshot_repository(user, "r")
    fraud = next(r for r in engine.list(user) if r.kind == MemoryKind.REPOSITORY_OBSERVATION
                 and r.extra.get("path") == "billing/fraud.py")
    yield dict(engine=engine, user=user, providers=providers, consent=consent, fraud=fraud, clock=clock,
               scope=r_scope)
    engine.close()


def _grant_source(env) -> None:
    for name in env["providers"]:
        env["consent"].add(ConsentGrant(provider=name, scope=env["scope"], allow_source=True,
                                        data_classes=frozenset({DATA_REPOSITORY_SOURCE}),
                                        granted_at=env["clock"]() - 1))


@needs_git
def test_eg3_observation_evidence_needs_repository_source_consent(source_env):
    engine, user, fraud = source_env["engine"], source_env["user"], source_env["fraud"]
    extractor = source_env["providers"]["cloud-extract"]
    hub = engine.services(user).providers
    item = {"id": "e1", "text": QUOTE, "scope": source_env["scope"], "source": SourceRef(SourceKind.MEMORY, fraud.id)}
    with pytest.raises(ConsentRequired):
        hub.extract_candidates(user, [item], provider="cloud-extract")
    assert extractor.calls == []
    _grant_source(source_env)
    hub.extract_candidates(user, [item], provider="cloud-extract")
    assert [(i["text"], i["data_class"]) for call in extractor.calls for i in call] == [(QUOTE, DATA_REPOSITORY_SOURCE)]


@needs_git
def test_eg3_a_local_extractor_must_accept_repository_source(tmp_path, keys, clock):
    from locus_memory.errors import UnsupportedCapability
    from locus_memory.providers.fake import FakeExtractor

    allowed, repo = _payroll_repo(tmp_path)
    engine = MemoryEngine(tmp_path / "root", keys, host=HostCapabilities(
        clock=clock, providers={"fake-extract": FakeExtractor()}, allowed_repository_roots=(allowed,)))
    user = access_for(repositories=("r",))
    try:
        engine.register_repository(user, repo, repository_id="r")
        engine.snapshot_repository(user, "r")
        obs = next(r for r in engine.list(user) if r.extra.get("path") == "payroll/rates.py")
        with pytest.raises(UnsupportedCapability):  # the provider declared memory text and transcripts only
            _extract_from(engine, user, obs, "Payroll override rates for ACME execs: CEO 3x.")
    finally:
        engine.close()


@needs_git
def test_eg3_external_sync_never_sends_observations_under_memory_text(source_env):
    engine, user = source_env["engine"], source_env["user"]
    external = source_env["providers"]["fake-external"]
    hub = engine.services(user).providers
    report = hub.sync_external(user, "fake-external")
    assert report["sent"] == 0 and report["skipped"].get("not_consented") == 3
    assert not external.items
    _grant_source(source_env)
    report = hub.sync_external(user, "fake-external")
    assert report["confirmed"] == 3
    assert any(SECRET_DOC in item["content"] for item in external.items.values())


@needs_git
def test_eg3_search_and_summarization_never_send_observations_under_memory_text(source_env):
    engine, user = source_env["engine"], source_env["user"]
    embedder, summarizer = source_env["providers"]["cloud-embed"], source_env["providers"]["cloud-sum"]
    engine.search(user, Query(text="refund KYC fraud"))
    assert not any("billing/" in text for call in embedder.calls for text in call[1:])
    result = engine.consolidate(user, {"summarize": True})
    assert not any(SECRET_DOC in (item.get("content") or "") for call in summarizer.calls for item in call)
    assert result["counts"].get("summary_inputs_skipped_not_consented") == 3
    _grant_source(source_env)
    engine.search(user, Query(text="refund KYC fraud"))
    assert any(SECRET_DOC in text for call in embedder.calls for text in call[1:])


@needs_git
def test_eg3_a_restatement_of_an_observation_is_repository_source_too(source_env):
    engine, user, fraud = source_env["engine"], source_env["user"], source_env["fraud"]
    external = source_env["providers"]["fake-external"]
    agent = access_for(actor=Actor.AGENT, repositories=("r",), operations={Operation.READ, Operation.PROPOSE})
    restated = _approved_citer(engine, user, agent, "VIP refunds under 500 skip KYC", source_env["scope"], fraud.id,
                               derived=True)
    hub = engine.services(user).providers
    report = hub.sync_external(user, "fake-external")
    assert report["sent"] == 0 and report["skipped"].get("not_consented") == 4  # 3 observations + the restatement
    assert not external.items
    with pytest.raises(ConsentRequired):
        hub.summarize(user, [{"id": restated.id, "content": restated.content}], scope=source_env["scope"],
                      provider="cloud-sum")


# =========================================================================== R4-EG-5
FORGED_TITLE = "kubernetes cluster outage database password rotation"


@pytest.fixture
def embed_env(make_engine, clock):
    from locus_memory.providers.fake import FakeEmbeddingProvider

    embedder = FakeEmbeddingProvider()
    engine = make_engine(host=HostCapabilities(clock=clock, providers={embedder.descriptor.name: embedder}))
    user = access_for(projects=("p",))
    record = engine.remember(user, RememberRequest(content="release train leaves every tuesday",
                                                   title="Release cadence", scope=P)).record
    return engine, embedder, user, record


def test_eg5_a_forged_title_never_reaches_the_provider_or_the_cache(embed_env):
    from locus_memory.providers.embeddings import cosine
    from locus_memory.providers.hub import _record_text

    engine, embedder, user, record = embed_env
    agent = access_for(actor=Actor.AGENT, projects=("p",), operations={Operation.READ})
    hub = engine.services(agent).providers
    forged = dataclasses.replace(record, title=FORGED_TITLE)
    scores = hub.semantic_scores(agent, "database password", [forged])
    assert not any(FORGED_TITLE in text for call in embedder.calls for text in call)
    assert scores.coverage.get("embedded_now") == 1  # the stored record's own text was embedded
    true_vector = embedder.vector(_record_text(engine.get(user, record.id)))
    honest = hub.semantic_scores(user, "database password", [engine.get(user, record.id)])
    assert honest[record.id] == pytest.approx(cosine(embedder.vector("database password"), true_vector), abs=1e-6)
    related = hub.semantic_scores(user, "release train", [engine.get(user, record.id)])
    assert related[record.id] == pytest.approx(cosine(embedder.vector("release train"), true_vector), abs=1e-6)
    assert record.id not in [h.record.id for h in engine.search(user, "database password").hits]


def test_eg5_a_forged_title_never_steers_a_rebase(embed_env):
    from locus_memory.providers.hub import _record_text

    engine, embedder, user, record = embed_env
    hub = engine.services(user).providers
    hub.semantic_scores(user, "release", [record])  # an honest vector at revision 1
    renamed = engine.correct(user, record.id, Correction(title="Train schedule"), expected_revision=None).record
    agent = access_for(actor=Actor.AGENT, projects=("p",), operations={Operation.READ})
    # The old title with the current revision: the old vector's text, but not the record's text now.
    stale_title = dataclasses.replace(renamed, title="Release cadence")
    engine.services(agent).providers.semantic_scores(agent, "train", [stale_title])
    ctx = engine.partition_context(user.partition)
    store = ctx.services.providers.embeddings
    model_key = ctx.services.providers.model_key(embedder.descriptor.name)
    with ctx.partition.db.read() as conn:
        vector = store.load(conn, model_key, [record.id], dimensions=embedder.descriptor.dimensions)[record.id]
    assert vector.revision == renamed.revision
    assert vector.text_token == store.text_token(_record_text(engine.get(user, record.id)))


def test_eg5_a_forged_title_is_never_sent_to_a_reranker(make_engine, clock):
    from locus_memory.providers.fake import FakeReranker

    reranker = FakeReranker()
    engine = make_engine(host=HostCapabilities(clock=clock, providers={reranker.descriptor.name: reranker}))
    user = access_for(projects=("p",))
    record = engine.remember(user, RememberRequest(content="release train leaves every tuesday",
                                                   title="Release cadence", scope=P)).record
    agent = access_for(actor=Actor.AGENT, projects=("p",), operations={Operation.READ})
    engine.services(agent).providers.rerank(agent, "database password",
                                            [dataclasses.replace(record, title=FORGED_TITLE)])
    assert reranker.calls and not any(FORGED_TITLE in text for _query, texts in reranker.calls for text in texts)
