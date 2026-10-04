"""Regression tests for review round 3, batch 2 (reproduced defects).

R3-MF-5  a forget made while a cutover was in progress was applied to the package only and got a
         receipt without any legacy limitation; when the cutover was then aborted, the
         authoritative legacy store kept serving the forgotten memory.
R3-MF-6  an idempotent replay (or a receipt recorded by a reconcile) skipped the migration-copy
         propagation and the legacy-authority limitation; the already-open reconcile path never
         propagated deletions to the legacy vault.
R3-MF-7  forgotten_check re-imported a legacy candidate whose session evidence was forgotten,
         though forgetting removes such evidence-dependent rows.
R3-MF-8  a partial rollback left the pre-correction legacy row of a record that became
         unrepresentable; a re-migration then reverted the user's correction and made it durable.
R3-EG-3  records derived from a memory (extractions, proposals with derived_from) never followed
         their input's expiry or correction; approving them made transient content durable.
R3-EG-4  extract_candidates sent expired, rejected and excluded memory evidence to egress
         extractors.
R3-EG-5  approved summaries stayed approved and injected when their inputs went stale through a
         repository snapshot or validity end, or were purged as excluded observations.
R3-EG-6  external replicas of superseded, stale (also at read time) or excluded records were
         never withdrawn.

Each test reproduces the report's scenario and asserts the correct outcome. All data lives in
pytest tmp dirs (the legacy vault is a copy of tests/fixtures/locus_legacy).
"""
from __future__ import annotations

import secrets
import sqlite3

import pytest

import test_review_group1 as group1
from conftest import FakeClock, access_for
from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.errors import Contention, NotFound, StaleDerivation
from locus_memory.forgetting import _CUTOVER_PENDING, _LEGACY_AUTHORITY, _MIGRATION_RESIDUE
from locus_memory.host import EngineConfig, HostCapabilities
from locus_memory.migrations import legacy as legacy_mod
from locus_memory.migrations.cutover import Migrator, SimulatedCrash, abort_cutover
from locus_memory.models import (
    Actor,
    CandidateProposal,
    ContextRequest,
    Correction,
    ForgetPolicy,
    ForgetTarget,
    Lifecycle,
    MemoryKind,
    Operation,
    RememberRequest,
    Retention,
    Scope,
    SourceKind,
    SourceRef,
    Validity,
)
from locus_memory.providers.base import ConsentGrant, StaticConsentPolicy
from locus_memory.providers.fake import FakeExternalMemory, FakeExtractor
from locus_memory.providers.hub import evidence_from_memories
from test_repository import GIT, commit_all, make_repo
from test_review_group1 import IDS, KEY, OTHER, WS, _cut_over, _legacy_ids, _migrator

# Shared migration fixtures (a copy of the legacy fixture vault, its mapping, an admin context, the
# ownership control and an engine wired to it), registered here under the same names.
admin = group1.admin
control = group1.control
legacy_db = group1.legacy_db
mapping = group1.mapping
menv = group1.menv

P = Scope.of(project="p")
needs_git = pytest.mark.skipif(GIT is None, reason="git is required for repository memory tests")


def _gone(engine, access, record_id: str) -> bool:
    try:
        engine.get(access, record_id)
    except NotFound:
        return True
    return False


def _legacy_serves(legacy_db, record_id: str, query: str = "pytest") -> bool:
    vault = LegacyMemoryVault(legacy_db, key=KEY)
    return (record_id in {m["id"] for m in vault.list(workspace=WS)}
            or record_id in {m["id"] for m in vault.search(query, workspace=WS)})


# =========================================================================== R3-MF-5
def _interrupted_cutover(menv, control, admin, legacy_db, mapping, tmp_path):
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    assert migrator.validate()["validated"]
    migrator.crash_at = "after_fence"
    with pytest.raises(SimulatedCrash):
        migrator.cutover()
    migrator.crash_at = None
    assert migrator.state().state == "cutover_in_progress"
    return migrator


def _abort(migrator, how):
    if how == "operator_abort":
        return migrator.abort_cutover()
    if how == "failing_quiesce":
        def failing_quiesce():
            raise RuntimeError("the host could not drain its writers")
        with pytest.raises(RuntimeError):
            migrator.resume(quiesce=failing_quiesce)
        return None
    # verify fails: another legacy row no longer authenticates
    with sqlite3.connect(migrator.legacy_db) as conn:
        conn.execute("UPDATE memories SET revision=revision+1 WHERE id=?", (IDS["personal"],))
    result = migrator.resume()
    assert result["cutover"] is False
    assert result["legacy_deletions"] == {"deleted": 1, "complete": True}
    with sqlite3.connect(migrator.legacy_db) as conn:  # repaired by the operator afterwards
        conn.execute("UPDATE memories SET revision=revision-1 WHERE id=?", (IDS["personal"],))
    return result


@pytest.mark.parametrize("how", ["operator_abort", "failing_quiesce", "verify_failure"])
def test_mf5_a_forget_during_cutover_reaches_the_legacy_store_when_the_cutover_aborts(
        menv, control, admin, legacy_db, mapping, tmp_path, how):
    migrator = _interrupted_cutover(menv, control, admin, legacy_db, mapping, tmp_path)
    rid = IDS["ws_fact"]
    assert _legacy_serves(legacy_db, rid)
    receipt = menv.forget(admin, ForgetTarget("memory", rid))  # forgetting is never fenced
    assert _gone(menv, admin, rid)
    # The receipt says what happens to the legacy copy (no store is the authority right now).
    assert _CUTOVER_PENDING in receipt.receipt.limitations
    result = _abort(migrator, how)
    assert control.get(migrator.partition_id, "memories").state == "legacy_authoritative"
    # The now authoritative legacy store no longer serves the forgotten memory.
    assert rid not in _legacy_ids(legacy_db)
    assert not _legacy_serves(legacy_db, rid)
    if how == "operator_abort":
        assert result["legacy_deletions"] == {"deleted": 1, "complete": True}
    # Live legacy data is untouched by the abort.
    assert IDS["candidate_approved"] in _legacy_ids(legacy_db)
    # The next migration neither re-imports it nor treats it as missing.
    again = _migrator(menv, control, admin, legacy_db, mapping, tmp_path / "again")
    again.prepare_shadow()
    validated = again.validate()
    assert _gone(menv, admin, rid)
    assert not any(m["id"] == rid for m in validated["verify"]["mismatches"])


def test_mf5_cutover_forgets_by_scope_or_evidence_reach_the_legacy_store_too(
        menv, control, admin, legacy_db, mapping, tmp_path):
    migrator = _interrupted_cutover(menv, control, admin, legacy_db, mapping, tmp_path)
    ws_rows = {i for i in _legacy_ids(legacy_db) if i in {IDS["ws_fact"], IDS["candidate_approved"]}}
    assert ws_rows
    menv.forget(admin, ForgetTarget("project", "proj-a"))
    migrator.abort_cutover()
    assert not ws_rows & _legacy_ids(legacy_db)


def test_mf5_an_abort_without_the_partition_context_still_happens_and_the_receipt_said_so(
        menv, control, admin, legacy_db, mapping, tmp_path):
    migrator = _interrupted_cutover(menv, control, admin, legacy_db, mapping, tmp_path)
    rid = IDS["ws_fact"]
    receipt = menv.forget(admin, ForgetTarget("memory", rid))
    # The plain escape hatch (no engine, e.g. an unopenable vault) never applies deletions ...
    assert abort_cutover(control, migrator.partition_id)["state"] == "legacy_authoritative"
    assert _legacy_serves(legacy_db, rid)
    # ... and the receipt of the forget made in that window said the legacy copy may stay.
    assert _CUTOVER_PENDING in receipt.receipt.limitations
    assert "served from there until it is forgotten there" in _CUTOVER_PENDING


def test_mf5_a_completed_cutover_still_removes_the_legacy_copy(menv, control, admin, legacy_db, mapping, tmp_path):
    migrator = _interrupted_cutover(menv, control, admin, legacy_db, mapping, tmp_path)
    rid = IDS["ws_fact"]
    menv.forget(admin, ForgetTarget("memory", rid))
    assert migrator.resume()["state"] == "package_authoritative"
    assert rid not in _legacy_ids(legacy_db)


# =========================================================================== R3-MF-6
@pytest.fixture
def slow_menv(make_engine, control):
    # A short busy timeout, so a held write lock makes a forget fail with Contention quickly.
    return make_engine(host=HostCapabilities(ownership=control), config=EngineConfig(busy_timeout_ms=50))


def _forget_fails_after_its_ledger_append(engine, access, record_id, key):
    path = engine.partition_context(access.partition).partition.db.path
    blocker = sqlite3.connect(path, isolation_level=None, timeout=0.1)
    blocker.execute("BEGIN IMMEDIATE")  # another writer holds the main database
    try:
        with pytest.raises(Contention):
            engine.forget(access, ForgetTarget("memory", record_id), idempotency_key=key)
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()


def test_mf6_a_retry_applied_by_reconcile_reaches_the_legacy_vault(slow_menv, control, admin, legacy_db, mapping,
                                                                   tmp_path):
    _cut_over(slow_menv, control, admin, legacy_db, mapping, tmp_path)
    rid = IDS["personal"]
    assert rid in _legacy_ids(legacy_db)
    _forget_fails_after_its_ledger_append(slow_menv, admin, rid, "k-retry")
    retry = slow_menv.forget(admin, ForgetTarget("memory", rid), idempotency_key="k-retry")
    assert retry.receipt.idempotent_replay and _gone(slow_menv, admin, rid)
    # The reconcile that applied the entry propagated it: the receipt's completeness is true.
    assert rid not in _legacy_ids(legacy_db)
    assert retry.physical_purge_pending is False
    assert _MIGRATION_RESIDUE not in retry.receipt.limitations


def test_mf6_a_reconcile_on_an_open_engine_propagates_without_a_retry(slow_menv, control, admin, legacy_db, mapping,
                                                                      tmp_path):
    _cut_over(slow_menv, control, admin, legacy_db, mapping, tmp_path)
    rid = IDS["personal"]
    _forget_fails_after_its_ledger_append(slow_menv, admin, rid, "k-other")
    slow_menv.list(admin, lifecycles=None)  # any call reconciles the open partition
    assert rid not in _legacy_ids(legacy_db)


def test_mf6_a_replay_under_legacy_authority_keeps_the_legacy_limitation(menv, control, admin, legacy_db, mapping,
                                                                         tmp_path):
    _migrator(menv, control, admin, legacy_db, mapping, tmp_path).prepare_shadow()  # legacy stays authoritative
    rid = IDS["personal"]
    first = menv.forget(admin, ForgetTarget("memory", rid), idempotency_key="k1")
    again = menv.forget(admin, ForgetTarget("memory", rid), idempotency_key="k1")
    assert again.receipt.idempotent_replay
    assert _LEGACY_AUTHORITY in first.receipt.limitations
    assert _LEGACY_AUTHORITY in again.receipt.limitations
    assert again.receipt.limitations.count(_LEGACY_AUTHORITY) == 1


def test_mf6_a_reconcile_applied_receipt_under_legacy_authority_has_the_limitation(
        slow_menv, control, admin, legacy_db, mapping, tmp_path):
    _migrator(slow_menv, control, admin, legacy_db, mapping, tmp_path).prepare_shadow()
    rid = IDS["personal"]
    _forget_fails_after_its_ledger_append(slow_menv, admin, rid, "k2")
    retry = slow_menv.forget(admin, ForgetTarget("memory", rid), idempotency_key="k2")
    assert retry.receipt.idempotent_replay
    assert _LEGACY_AUTHORITY in retry.receipt.limitations
    assert rid in _legacy_ids(legacy_db)  # what the limitation says: legacy keeps serving it


# =========================================================================== R3-MF-7
def _legacy_candidate(legacy_db, clock, session="sess-7"):
    vault = LegacyMemoryVault(legacy_db, key=KEY, clock=clock)
    return vault.save({"content": "Deploy freeze starts Friday", "scope": "workspace", "status": "candidate",
                       "source_session_id": session}, workspace=WS, default_status="candidate")["id"]


def test_mf7_a_session_forget_after_the_shadow_import_is_never_undone_by_validate(
        menv, control, admin, legacy_db, mapping, tmp_path, clock):
    cid = _legacy_candidate(legacy_db, clock)
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    assert menv.get(admin, cid).lifecycle == Lifecycle.CANDIDATE
    menv.forget(admin, ForgetTarget("session", "sess-7"), policy=ForgetPolicy(suppress_relearning=False))
    assert _gone(menv, admin, cid)
    result = migrator.validate()
    assert result["validated"] and result["delta"].get("imported", 0) == 0
    assert _gone(menv, admin, cid)


def test_mf7_a_candidate_citing_a_session_forgotten_before_the_first_import_is_skipped(
        menv, control, admin, legacy_db, mapping, tmp_path, clock):
    cid = _legacy_candidate(legacy_db, clock)
    menv.forget(admin, ForgetTarget("session", "sess-7"))
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    report = migrator.prepare_shadow()["import"]
    assert report.get("skipped_forgotten") == 1
    assert _gone(menv, admin, cid)
    result = migrator.validate()
    assert result["validated"], result["verify"]  # covered, never "missing"
    assert _gone(menv, admin, cid)


def test_mf7_forgotten_check_covers_an_evidence_dependent_row_and_keeps_an_approved_one(
        menv, admin, legacy_db, mapping, clock):
    cid = _legacy_candidate(legacy_db, clock)
    vault = LegacyMemoryVault(legacy_db, key=KEY, clock=clock)
    mid = vault.save({"content": "Release train is weekly", "scope": "workspace", "status": "approved",
                      "source_session_id": "sess-7"}, workspace=WS, default_status="approved")["id"]
    menv.forget(admin, ForgetTarget("session", "sess-7"))
    codec = LegacyMemoryVault.codec(KEY)
    conn = legacy_mod._connect_ro(legacy_db)
    try:
        rows = {row["id"]: row for row in conn.execute("SELECT * FROM memories")}
    finally:
        conn.close()
    ctx = menv.partition_context(admin.partition)
    with ctx.partition.db.read() as c:
        candidate, _ = legacy_mod.map_record(codec.open_row(rows[cid], include_private=True), mapping, now=clock())
        assert legacy_mod.forgotten_check(ctx, c, candidate) == (None, "source")
        approved, _ = legacy_mod.map_record(codec.open_row(rows[mid], include_private=True), mapping, now=clock())
        kept, reason = legacy_mod.forgotten_check(ctx, c, approved)
    # Forgetting keeps an approved memory with its other evidence: imported with the citation dropped.
    assert reason is None
    assert [s.kind for s in kept.sources] == [SourceKind.LEGACY_IMPORT]


# =========================================================================== R3-MF-8
OLD = "This project uses unittest."
NEW = "This project uses nose2 now."


def _corrected_then_partially_rolled_back(menv, control, admin, legacy_db, mapping, tmp_path, clock):
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    rid = IDS["candidate_approved"]
    record = menv.get(admin, rid)
    assert record.content == OLD and record.extra.get("legacy")
    corrected = menv.correct(admin, rid, Correction(content=NEW, retention=Retention("transient", clock() + 86_400)),
                             expected_revision=record.revision).record
    assert corrected.retention.policy == "transient"
    plan = migrator.plan_rollback()
    assert "retention:transient" in plan["unrepresentable"]
    result = migrator.rollback(allow_partial=True)
    assert result["state"] == "legacy_authoritative"
    return migrator, rid, result, plan


def test_mf8_a_partial_rollback_never_leaves_the_corrected_away_row_served(
        menv, control, admin, legacy_db, mapping, tmp_path, clock):
    _migrator_, rid, result, plan = _corrected_then_partially_rolled_back(menv, control, admin, legacy_db,
                                                                          mapping, tmp_path, clock)
    # The authoritative legacy store does not serve the corrected-away statement.
    assert rid not in _legacy_ids(legacy_db)
    assert not _legacy_serves(legacy_db, rid, "unittest")
    clock.advance(30 * 86_400)
    assert not _legacy_serves(legacy_db, rid, "unittest")
    # The plan announced it and the report names what stayed in the package.
    assert plan["stale_legacy_rows_to_delete"] == 1
    assert result["counts"]["kept_in_package_only"] == 1
    assert result["counts"]["deleted_stale_unrepresentable"] == 1
    assert rid in result["package_only_ids"]
    assert "earlier legacy copies" in result["limitations"][0]


def test_mf8_a_re_migration_keeps_the_correction_and_its_expiry(
        menv, control, admin, legacy_db, mapping, tmp_path, clock):
    _m, rid, _result, _plan = _corrected_then_partially_rolled_back(menv, control, admin, legacy_db, mapping,
                                                                    tmp_path, clock)
    clock.advance(10)
    again = _migrator(menv, control, admin, legacy_db, mapping, tmp_path / "again")
    report = again.prepare_shadow()["import"]
    # The deleted legacy row is not a legacy deletion of the record the rollback kept for recovery.
    assert not _gone(menv, admin, rid)
    assert report.get("drift_repaired", 0) == 0
    record = menv.get(admin, rid)
    assert record.content == NEW and record.retention.policy == "transient"
    assert again.validate()["validated"]
    assert again.cutover()["state"] == "package_authoritative"
    record = menv.get(admin, rid)
    assert record.content == NEW and record.retention.policy == "transient"
    clock.advance(30 * 86_400)
    menv.maintain(admin)
    assert menv.get(admin, rid).lifecycle == Lifecycle.EXPIRED  # the user's expiry still holds


def test_mf8_an_unchanged_earlier_legacy_row_never_wins_over_the_recovery_record(
        menv, control, admin, legacy_db, mapping, tmp_path, clock):
    before = tmp_path / "legacy-before-rollback.sqlite3"
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    with sqlite3.connect(legacy_db) as src, sqlite3.connect(before) as dst:
        src.backup(dst)
    rid = IDS["candidate_approved"]
    record = menv.get(admin, rid)
    menv.correct(admin, rid, Correction(content=NEW, retention=Retention("transient", clock() + 86_400)),
                 expected_revision=record.revision)
    migrator.rollback(allow_partial=True)
    # The earlier legacy row comes back unchanged (a restored backup, a delete that did not happen).
    with sqlite3.connect(before) as src:
        row = src.execute("SELECT * FROM memories WHERE id=?", (rid,)).fetchone()
        columns = [d[0] for d in src.execute("SELECT * FROM memories LIMIT 0").description]
    with sqlite3.connect(legacy_db) as dst:
        dst.execute(f"INSERT INTO memories({','.join(columns)}) VALUES({','.join('?' * len(columns))})", row)
    again = _migrator(menv, control, admin, legacy_db, mapping, tmp_path / "again")
    report = again.prepare_shadow()["import"]
    assert report.get("recovery_kept") == 1 and not report.get("drift_repaired")
    record = menv.get(admin, rid)
    assert record.content == NEW and record.retention.policy == "transient"
    assert again.validate()["validated"]


def test_mf8_a_delta_never_brings_back_a_suppressed_statement(menv, control, admin, legacy_db, mapping, tmp_path,
                                                             clock):
    # Edited in round 4 (R4-RG-2): this test used to make a *newer* legacy edit restate OLD after the
    # rollback and expected it to be refused - that is the user's authoritative edit and is now
    # imported (tests/test_review_round4_batch3.py). What stays refused is a *stale* legacy row: the
    # pre-correction version coming back (a restored backup), not newer than what the package holds.
    before = tmp_path / "legacy-before-rollback.sqlite3"
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    with sqlite3.connect(legacy_db) as src, sqlite3.connect(before) as dst:
        src.backup(dst)
    rid = IDS["candidate_approved"]
    record = menv.get(admin, rid)
    menv.correct(admin, rid, Correction(content=NEW), expected_revision=record.revision)  # suppresses OLD
    assert migrator.rollback()["counts"].get("written_back") == 1
    with sqlite3.connect(before) as src:
        row = src.execute("SELECT * FROM memories WHERE id=?", (rid,)).fetchone()
        columns = [d[0] for d in src.execute("SELECT * FROM memories LIMIT 0").description]
    with sqlite3.connect(legacy_db) as dst:  # the legacy row restates OLD again: the stale version
        dst.execute("DELETE FROM memories WHERE id=?", (rid,))
        dst.execute(f"INSERT INTO memories({','.join(columns)}) VALUES({','.join('?' * len(columns))})", row)
    again = _migrator(menv, control, admin, legacy_db, mapping, tmp_path / "again")
    report = again.prepare_shadow()["import"]
    assert report.get("skipped_suppressed") == 1
    assert menv.get(admin, rid).content == NEW


# =========================================================================== R3-EG-3
TRANSIENT = "Meeting room B is booked for the Friday offsite"


@pytest.fixture
def extract_env(make_engine, clock):
    extractor = FakeExtractor(egress=True)
    consent = StaticConsentPolicy([ConsentGrant(provider=extractor.descriptor.name, granted_at=clock() - 1)])
    engine = make_engine(host=HostCapabilities(clock=clock, providers={extractor.descriptor.name: extractor},
                                               consent=consent))
    return engine, access_for(projects=("p",)), extractor


def _transient(engine, user, clock, text=TRANSIENT, seconds=3600):
    return engine.remember(user, RememberRequest(content=text, scope=P,
                                                 retention=Retention("transient", clock() + seconds))).record


def test_eg3_an_extraction_from_a_transient_memory_never_outlives_it(extract_env, clock):
    engine, user, extractor = extract_env
    m = _transient(engine, user, clock)
    c = engine.services(user).providers.extract_candidates(
        user, evidence_from_memories([m]), provider=extractor.descriptor.name)[0].record
    assert c.links.derived_from == (m.id,)
    assert c.retention.expires_at == m.retention.expires_at  # the candidate TTL is capped at the input's end
    clock.advance(7200)
    # Read-time expiry, before maintenance: neither the input nor what restates it is approvable.
    with pytest.raises(Exception) as refused:
        engine.approve(user, c.id, expected_revision=None)
    assert refused.value.code in ("invalid_transition", "stale_derivation")
    engine.maintain(user)
    assert engine.get(user, c.id).lifecycle == Lifecycle.EXPIRED


def test_eg3_an_approved_derivation_keeps_its_inputs_expiry(make_engine, clock):
    engine = make_engine()
    user = access_for(projects=("p",))
    agent = access_for(projects=("p",), actor=Actor.AGENT, operations=(Operation.READ, Operation.PROPOSE))
    m = _transient(engine, user, clock)
    c = engine.propose(agent, CandidateProposal(content="Restated: " + TRANSIENT, scope=P,
                                                sources=(SourceRef(SourceKind.MEMORY, m.id),),
                                                derived_from=(m.id,))).record
    approved = engine.approve(user, c.id, expected_revision=None).record
    assert approved.retention.policy == "transient"
    assert approved.retention.expires_at == m.retention.expires_at
    clock.advance(7200)
    assert engine.get(user, c.id).lifecycle == Lifecycle.EXPIRED  # read time
    engine.maintain(user)
    assert engine.get(user, c.id).lifecycle == Lifecycle.EXPIRED
    clock.advance(365 * 86_400)
    engine.maintain(user)
    assert engine.get(user, c.id).lifecycle == Lifecycle.EXPIRED


def test_eg3_an_agent_proposal_expires_with_its_input(make_engine, clock):
    engine = make_engine()
    user = access_for(projects=("p",))
    agent = access_for(projects=("p",), actor=Actor.AGENT, operations=(Operation.READ, Operation.PROPOSE))
    m = _transient(engine, user, clock)
    c = engine.propose(agent, CandidateProposal(content="Restated: " + TRANSIENT, scope=P,
                                                sources=(SourceRef(SourceKind.MEMORY, m.id),),
                                                derived_from=(m.id,))).record
    clock.advance(7200)
    engine.maintain(user)
    assert engine.get(user, m.id).lifecycle == Lifecycle.EXPIRED
    assert engine.get(user, c.id).lifecycle == Lifecycle.EXPIRED
    with pytest.raises(Exception):  # noqa: B017 - expired: never approvable
        engine.approve(user, c.id, expected_revision=None)


def test_eg3_correcting_an_input_stales_approved_and_expires_pending_derivations(engine):
    user = access_for(projects=("p",))
    m = engine.remember(user, RememberRequest(content="Deploy window is Tuesday 9am", scope=P)).record
    src = (SourceRef(SourceKind.MEMORY, m.id),)
    pending = engine.propose(user, CandidateProposal(content="Noted: deploy window is Tuesday 9am", scope=P,
                                                     sources=src, derived_from=(m.id,))).record
    approved = engine.propose(user, CandidateProposal(content="Team deploys on Tuesday 9am", scope=P,
                                                      sources=src, derived_from=(m.id,))).record
    engine.approve(user, approved.id, expected_revision=None)
    receipt = engine.correct(user, m.id, Correction(content="Deploy window is Thursday 2pm"),
                             expected_revision=None).receipt
    assert receipt.details["derived_marked_stale"] == 2
    assert engine.get(user, pending.id).lifecycle == Lifecycle.EXPIRED
    assert engine.get(user, approved.id).lifecycle == Lifecycle.STALE
    with pytest.raises(Exception):  # noqa: B017 - the corrected-away statement is not approvable
        engine.approve(user, pending.id, expected_revision=None)


def test_eg3_a_derivation_the_user_restated_no_longer_follows_its_input(engine, clock):
    user = access_for(projects=("p",))
    m = _transient(engine, user, clock)
    c = engine.propose(user, CandidateProposal(content="Restated: " + TRANSIENT, scope=P,
                                               sources=(SourceRef(SourceKind.MEMORY, m.id),),
                                               derived_from=(m.id,))).record
    engine.approve(user, c.id, expected_revision=None)
    restated = engine.correct(user, c.id, Correction(content="The offsite is in room B (my own note)",
                                                     retention=Retention("durable", None)),
                              expected_revision=None).record
    assert restated.extra.get("inputs_detached") and "inherited_retention" not in restated.extra
    engine.correct(user, m.id, Correction(content="Meeting room C is booked for the offsite"),
                   expected_revision=None)
    clock.advance(7200)
    engine.maintain(user)
    assert engine.get(user, c.id).lifecycle == Lifecycle.APPROVED


# =========================================================================== R3-EG-4
def test_eg4_expired_memory_evidence_never_leaves_the_store(extract_env, clock):
    engine, user, extractor = extract_env
    m = _transient(engine, user, clock, text="Another short-lived note about the Friday standup", seconds=10)
    clock.advance(20)  # retention ended; maintenance has not run
    with pytest.raises(StaleDerivation):
        engine.services(user).providers.extract_candidates(user, evidence_from_memories([m]),
                                                           provider=extractor.descriptor.name)
    assert extractor.calls == []
    assert engine.list(user, lifecycles=(Lifecycle.CANDIDATE,)) == []


@pytest.mark.parametrize("state", ["rejected", "superseded"])
def test_eg4_rejected_or_superseded_memory_evidence_is_refused_before_egress(extract_env, state):
    engine, user, extractor = extract_env
    if state == "rejected":
        cand = engine.propose(user, CandidateProposal(content="The user secretly prefers tabs over spaces",
                                                      scope=P, sources=(SourceRef(SourceKind.USER_ACTION, "ua"),)
                                                      )).record
        record = engine.reject(user, cand.id, expected_revision=cand.revision).record
    else:
        old = engine.remember(user, RememberRequest(content="Alice's desk is on floor 2", scope=P)).record
        new = engine.remember(user, RememberRequest(content="Alice's desk is on floor 5", scope=P)).record
        record = engine.supersede(user, old.id, new.id, expected_revision=old.revision).record
    with pytest.raises(StaleDerivation):
        engine.services(user).providers.extract_candidates(user, evidence_from_memories([record]),
                                                           provider=extractor.descriptor.name)
    assert extractor.calls == []


def test_eg4_a_proposal_is_never_derived_from_a_rejected_memory(engine):
    user = access_for(projects=("p",))
    cand = engine.propose(user, CandidateProposal(content="The user secretly prefers tabs", scope=P,
                                                  sources=(SourceRef(SourceKind.USER_ACTION, "ua"),))).record
    engine.reject(user, cand.id, expected_revision=cand.revision)
    with pytest.raises(StaleDerivation):
        engine.propose(user, CandidateProposal(content="Prefers tab indentation", scope=P,
                                               sources=(SourceRef(SourceKind.MEMORY, cand.id),),
                                               derived_from=(cand.id,)))


@needs_git
def test_eg4_an_observation_of_a_now_excluded_path_is_not_sent(tmp_path):
    allowed = (tmp_path / "allowed").resolve()
    repo = make_repo(allowed / "repo", {"settings_prod.py": '"""prod db host ZEPHYR-DB-7 user=svc_payments"""\nX = 1\n'})
    clock = FakeClock()
    keys = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    access = access_for(repositories=("r1",))
    first = MemoryEngine(tmp_path / "root", keys, host=HostCapabilities(clock=clock, allowed_repository_roots=(allowed,)))
    first.register_repository(access, repo, repository_id="r1")
    first.snapshot_repository(access, "r1")
    observations = [r for r in first.list(access, kinds=(MemoryKind.REPOSITORY_OBSERVATION,))
                    if r.extra.get("path") == "settings_prod.py"]
    first.close()
    assert len(observations) == 1
    extractor = FakeExtractor(egress=True)
    consent = StaticConsentPolicy([ConsentGrant(provider=extractor.descriptor.name, granted_at=clock.now - 1)])
    engine = MemoryEngine(tmp_path / "root", keys, host=HostCapabilities(
        clock=clock, allowed_repository_roots=(allowed,), repository_exclude_patterns=["settings_prod.py"],
        providers={extractor.descriptor.name: extractor}, consent=consent))
    try:
        with pytest.raises(NotFound):
            engine.services(access).providers.extract_candidates(access, evidence_from_memories(observations),
                                                                 provider=extractor.descriptor.name)
        assert extractor.calls == []
    finally:
        engine.close()


# =========================================================================== R3-EG-5
class _StubSummarizer:
    def summarize(self, items, *, scope, deadline_s=None):
        return "Summary: " + " | ".join(i["content"].replace("\n", " ")[-200:] for i in items)


class _StubHub:
    def summarizer(self, access):
        return _StubSummarizer()


def _summarize_and_approve(engine, user):
    providers = engine.services(user).providers
    engine.services(user).providers = _StubHub()
    try:
        summaries = engine.consolidate(user, {"summarize": True})["summaries"]
    finally:
        engine.services(user).providers = providers
    assert summaries
    summary_id = summaries[0]
    engine.approve(user, summary_id, expected_revision=None)
    return summary_id


def _not_served(engine, user, summary_id, query):
    packet = engine.build_context(user, ContextRequest(token_allowance=4000, query=query))
    assert summary_id not in [i.record_id for i in packet.items]
    assert summary_id not in [h.record.id for h in engine.search(user, query).hits]
    exported = {r["id"]: r["lifecycle"] for r in engine.export(user)["records"]}
    assert exported.get(summary_id) in (None, "stale", "expired")


def _plans_repo(tmp_path, make_engine, clock, **host):
    allowed = (tmp_path / "allowed").resolve()
    repo = make_repo(allowed / "repo", {
        f"plans/{name}.py": f'"""Project ZEPHYR {name} acquisition plan."""\nimport os\n\n'
                            f"def {name}_plan():\n    return 1\n" for name in ("alpha", "beta", "gamma")})
    engine = make_engine(host=HostCapabilities(clock=clock, allowed_repository_roots=(allowed,), **host))
    user = access_for(repositories=("repo-a",))
    service = engine.services(user).repository
    service.register(user, repo, repository_id="repo-a")
    assert service.snapshot(user, "repo-a")["state"] == "complete"
    observations = [o.id for o in service.observations(user, "repo-a")]
    assert len(observations) == 3
    return engine, user, repo, allowed, observations


@needs_git
def test_eg5_a_snapshot_that_stales_the_inputs_stales_their_summary(tmp_path, make_engine, clock):
    engine, user, repo, _allowed, observations = _plans_repo(tmp_path, make_engine, clock)
    summary_id = _summarize_and_approve(engine, user)
    assert "ZEPHYR" in engine.get(user, summary_id).content
    for name in ("alpha", "beta", "gamma"):
        (repo / "plans" / f"{name}.py").write_text(f'"""Renamed module {name}."""\n')
    commit_all(repo, "rewrite")
    counts = engine.services(user).repository.snapshot(user, "repo-a")["counts"]
    assert counts.get("observations_stale") == 3
    assert engine.get(user, summary_id).lifecycle == Lifecycle.STALE
    _not_served(engine, user, summary_id, "ZEPHYR acquisition")


@needs_git
def test_eg5_a_summary_of_excluded_observations_is_hidden_then_removed(tmp_path, make_engine, clock):
    engine, user, _repo, allowed, observations = _plans_repo(tmp_path, make_engine, clock)
    summary_id = _summarize_and_approve(engine, user)
    engine.close()
    engine = make_engine(host=HostCapabilities(clock=clock, allowed_repository_roots=(allowed,),
                                               repository_exclude_patterns=("plans/**",)))
    # Hidden from the moment the exclusion applies (before any snapshot purges anything) ...
    assert _gone(engine, user, summary_id)
    assert summary_id not in {r["id"] for r in engine.export(user)["records"]}
    _not_served(engine, user, summary_id, "ZEPHYR acquisition")
    # ... and removed with the observations it restates.
    counts = engine.services(user).repository.snapshot(user, "repo-a")["counts"]
    assert counts.get("observations_excluded_removed") == 3
    ctx = engine.partition_context(user.partition)
    with ctx.partition.db.read() as conn:
        assert conn.execute("SELECT 1 FROM records WHERE id=?", (summary_id,)).fetchone() is None
    _not_served(engine, user, summary_id, "ZEPHYR acquisition")


@needs_git
def test_eg5_a_pending_summary_of_excluded_observations_is_not_approvable(tmp_path, make_engine, clock):
    engine, user, _repo, allowed, observations = _plans_repo(tmp_path, make_engine, clock)
    providers = engine.services(user).providers
    engine.services(user).providers = _StubHub()
    summary_id = engine.consolidate(user, {"summarize": True})["summaries"][0]
    engine.services(user).providers = providers
    engine.close()
    engine = make_engine(host=HostCapabilities(clock=clock, allowed_repository_roots=(allowed,),
                                               repository_exclude_patterns=("plans/**",)))
    with pytest.raises((NotFound, StaleDerivation)):
        engine.approve(user, summary_id, expected_revision=None)


def test_eg5_validity_end_stales_the_summary_of_its_inputs(make_engine, clock):
    engine = make_engine()
    user = access_for(projects=("p",))
    for text in ("Sprint goal is the PHOENIX launch", "PHOENIX launch owner is Bob", "PHOENIX launch date is May 3"):
        engine.remember(user, RememberRequest(content=text, kind="fact", scope=P,
                                              validity=Validity(valid_until=clock() + 100)))
    summary_id = _summarize_and_approve(engine, user)
    clock.advance(200)
    out = engine.maintain(user)
    assert out["marked_stale"] == 4  # three inputs and their summary
    assert engine.get(user, summary_id).lifecycle == Lifecycle.STALE
    _not_served(engine, user, summary_id, "PHOENIX launch")


# =========================================================================== R3-EG-6
@pytest.fixture
def sync_env(make_engine, clock):
    external = FakeExternalMemory("ext", clock=clock)
    consent = StaticConsentPolicy([ConsentGrant(provider="ext", granted_at=clock.now - 1)])
    engine = make_engine(host=HostCapabilities(clock=clock, providers={"ext": external}, consent=consent))
    access = access_for(projects=("p",))
    return engine, access, engine.services(access).providers, external


def _external(external):
    return sorted(item["content"] for item in external.items.values())


def test_eg6_superseded_and_stale_replicas_are_withdrawn(sync_env, clock):
    engine, access, hub, external = sync_env
    m1 = engine.remember(access, RememberRequest(content="Alice's phone number is 555-0100 (old)", scope=P)).record
    m3 = engine.remember(access, RememberRequest(content="Office address is Main St 1", scope=P,
                                                 validity=Validity(valid_until=clock.now + 100))).record
    assert hub.sync_external(access, "ext")["confirmed"] == 2
    m2 = engine.remember(access, RememberRequest(content="Alice's phone number is 555-0199", scope=P)).record
    engine.supersede(access, m1.id, m2.id, expected_revision=engine.get(access, m1.id).revision)
    clock.advance(200)
    engine.maintain(access)  # marks m3 stale and drains the outbox
    assert engine.get(access, m3.id).lifecycle == Lifecycle.STALE
    assert hub.sync_external(access, "ext")["sent"] == 1  # only m2
    hub.process_outbox(access)
    assert _external(external) == ["Alice's phone number is 555-0199"]
    assert hub.reconcile_external(access, "ext")["in_sync"] == 1


def test_eg6_a_replica_stale_at_read_time_is_withdrawn_before_maintenance(sync_env, clock):
    engine, access, hub, external = sync_env
    engine.remember(access, RememberRequest(content="Office address is Main St 1", scope=P,
                                            validity=Validity(valid_until=clock.now + 100)))
    assert hub.sync_external(access, "ext")["confirmed"] == 1
    clock.advance(200)  # validity ended; maintenance has not run
    assert hub.sync_external(access, "ext")["sent"] == 0
    assert hub.process_outbox(access)["attempted"] == 1
    assert _external(external) == []


def test_eg6_reconcile_queues_the_withdrawal_of_a_superseded_replica(sync_env, clock):
    engine, access, hub, external = sync_env
    old = engine.remember(access, RememberRequest(content="Bob's team is Platform", scope=P)).record
    hub.sync_external(access, "ext")
    new = engine.remember(access, RememberRequest(content="Bob's team is Payments", scope=P)).record
    engine.supersede(access, old.id, new.id, expected_revision=old.revision)
    report = hub.reconcile_external(access, "ext")
    assert report["queued_deletions"]
    hub.process_outbox(access)
    assert _external(external) == []


def test_eg6_a_summary_staled_by_an_input_correction_is_withdrawn(sync_env, clock):
    engine, access, hub, external = sync_env
    texts = ("Sprint goal is the PHOENIX launch", "PHOENIX launch owner is Bob", "PHOENIX launch date is May 3")
    first = [engine.remember(access, RememberRequest(content=t, kind="fact", scope=P)).record for t in texts][0]
    summary_id = _summarize_and_approve(engine, access)
    hub.sync_external(access, "ext")
    assert any(c.startswith("Summary:") for c in _external(external))
    engine.correct(access, first.id, Correction(content="Sprint goal is the ORION launch"),
                   expected_revision=first.revision)
    assert engine.get(access, summary_id).lifecycle == Lifecycle.STALE
    hub.sync_external(access, "ext")
    hub.process_outbox(access)
    assert not any(c.startswith("Summary:") for c in _external(external))


def test_eg6_a_reverted_record_is_sent_again(sync_env, clock):
    engine, access, hub, external = sync_env
    old = engine.remember(access, RememberRequest(content="Carol leads the design review", scope=P)).record
    hub.sync_external(access, "ext")
    new = engine.remember(access, RememberRequest(content="Dave leads the design review", scope=P)).record
    engine.supersede(access, old.id, new.id, expected_revision=old.revision)
    hub.sync_external(access, "ext")
    hub.process_outbox(access)
    assert _external(external) == ["Dave leads the design review"]
    engine.approve(access, old.id, expected_revision=None)  # explicit revert: current again
    assert hub.sync_external(access, "ext")["confirmed"] >= 1  # (the former superseder changed too)
    assert _external(external) == ["Carol leads the design review", "Dave leads the design review"]


@needs_git
def test_eg6_an_excluded_observation_is_withdrawn_without_a_new_snapshot(tmp_path):
    allowed = (tmp_path / "allowed").resolve()
    repo = make_repo(allowed / "repo", {"plans/zephyr.py": '"""Project ZEPHYR acquisition."""\nX = 1\n'})
    clock = FakeClock()
    keys = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    # Observations are repository source (R4-EG-3): consent and the provider cover it.
    external = FakeExternalMemory("ext", clock=clock, data_classes=("memory_text", "repository_source"))
    consent = StaticConsentPolicy([ConsentGrant(provider="ext", granted_at=clock.now - 1, allow_source=True,
                                                data_classes=frozenset({"memory_text", "repository_source"}))])
    access = access_for(repositories=("r1",))

    def host(**kw):
        return HostCapabilities(clock=clock, allowed_repository_roots=(allowed,), providers={"ext": external},
                                consent=consent, **kw)

    first = MemoryEngine(tmp_path / "root", keys, host=host())
    first.register_repository(access, repo, repository_id="r1")
    first.snapshot_repository(access, "r1")
    assert first.services(access).providers.sync_external(access, "ext")["confirmed"] >= 1
    first.close()
    assert any("ZEPHYR" in c for c in _external(external))
    engine = MemoryEngine(tmp_path / "root", keys, host=host(repository_exclude_patterns=("plans/**",)))
    try:
        engine.services(access).providers.process_outbox(access)
        assert not any("ZEPHYR" in c for c in _external(external))
    finally:
        engine.close()


def test_eg6_queue_deletion_of_an_unrelated_forget_does_not_claim_superseded_replicas(sync_env):
    engine, access, hub, _external_ = sync_env
    old = engine.remember(access, RememberRequest(content="Erin works remotely", scope=P)).record
    other = engine.remember(access, RememberRequest(content="Unrelated note", scope=P)).record
    hub.sync_external(access, "ext")
    new = engine.remember(access, RememberRequest(content="Erin works in the office", scope=P)).record
    engine.supersede(access, old.id, new.id, expected_revision=old.revision)
    receipt = engine.forget(access, ForgetTarget("memory", other.id))
    # The forget's receipt names only the external deletion it caused (the superseded replica is
    # withdrawn by the outbox sweep, under its own cause).
    assert len(receipt.pending_external) == 1


# Unused-import guards for helpers shared with the other review modules.
assert OTHER and Migrator
