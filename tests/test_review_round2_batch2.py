"""Regression tests for review round 2, batch 2 (reproduced defects).

R2-FG-5  a forget whose ledger append landed after rollback's last pending-deletion check (during
         the final legacy checkpoint) was applied to the package only, while its receipt reported
         a deletion and the memory stayed live in the now-authoritative legacy store.
R2-FG-6  a memory an agent proposed (basis source_attributed) and the user then corrected in their
         own words kept ``basis_attested_by='agent'``, so forgetting one of its cited sources
         purged (and suppressed) the user's corrected statement.
R2-FG-7  a rollback interrupted after its reverse sync never adopted package-native records as
         legacy round trips on resume, so every later migration was refused.
R2-SL-2  revalidate_context, explain and export still served observations of paths the host had
         excluded since they were ingested.
R2-SL-3  ProcedureService.revoke_evidence was not partition-bound: a context of another
         partition could revoke procedure evidence here (and probe episode ids).
R2-SL-4  same root cause as R2-FG-6, through a forgotten message source.
R2-SL-5  approved summaries of transient inputs became durable and kept the inputs' content after
         their retention ended (and could be approved after the inputs expired at read time).
R2-SL-6  PARTIAL packets caused by a transient semantic-provider failure or a deadline inside the
         ranker were cached and revalidated as valid.

Each test reproduces the report's scenario and asserts the correct outcome. All data lives in
pytest tmp dirs (the legacy vault is a copy of tests/fixtures/locus_legacy).
"""
from __future__ import annotations

import dataclasses
import inspect
import json
import os
import secrets
import shutil
import subprocess
import threading
import time

import pytest

import test_learning as learning
import test_review_group1 as group1
from conftest import FakeClock, access_for
from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.context.compiler import (
    R_RANK_PARTIAL,
    R_RANK_PARTIAL_TRANSIENT,
)
from locus_memory.errors import (
    AccessDenied,
    InvalidTransition,
    MigrationError,
    NotFound,
    StaleDerivation,
)
from locus_memory.forgetting import _LEGACY_AUTHORITY
from locus_memory.host import HostCapabilities
from locus_memory.migrations import legacy as legacy_mod
from locus_memory.migrations.cutover import Migrator, SimulatedCrash
from locus_memory.models import (
    Actor,
    CandidateProposal,
    ContextRequest,
    Correction,
    ForgetTarget,
    IngestionEvent,
    Lifecycle,
    MemoryKind,
    Operation,
    ProcedureState,
    RememberRequest,
    ResultStatus,
    Retention,
    Scope,
    SliceSpec,
    SourceKind,
    SourceRef,
    StatementBasis,
)
from locus_memory.storage.partition import PARTITION_BOUND_CLASSES
from test_review_group1 import KEY, _cut_over, _legacy_ids, _migrator

# Shared migration fixtures (a copy of the legacy fixture vault, its mapping, an admin context, the
# ownership control and an engine wired to it), registered in this module under the same names.
admin = group1.admin
control = group1.control
legacy_db = group1.legacy_db
mapping = group1.mapping
menv = group1.menv
# Procedure fixtures (a verification authority, an evaluation runner and an engine wired to them).
authority = learning.authority
runner = learning.runner
eng = learning.eng
candidate = learning.candidate

PROJ_A = Scope.of(project="proj-a")
USER = access_for(projects=("proj-a",))
AGENT = access_for(actor=Actor.AGENT, projects=("proj-a",), operations={Operation.READ, Operation.PROPOSE})


def _alive(engine, access, record_id):
    try:
        return engine.get(access, record_id)
    except NotFound:
        return None


# =========================================================================== R2-FG-5
def _rollback_with_a_forget_injected(engine, control, admin, legacy_db, mapping, tmp_path, monkeypatch, *,
                                     pause_in, wait_for_append):
    """Cut over, remember a package-native memory, roll back on a worker thread, pause it at
    ``pause_in`` (a predicate on (method name, args)), forget the memory from another thread while
    it is paused, then let the rollback finish. Returns (migrator, doomed, results, appended)."""
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    doomed = engine.remember(admin, RememberRequest(content="my doctor appointment is friday",
                                                    scope=PROJ_A)).record
    partition = engine.partition_context(admin.partition).partition
    reached, go = threading.Event(), threading.Event()
    fired: list[int] = []

    def hook(name):
        original = getattr(Migrator, name)

        def hooked(self, *args, **kwargs):
            if not fired and pause_in(name, args):
                fired.append(1)
                reached.set()
                go.wait(20)
            return original(self, *args, **kwargs)
        monkeypatch.setattr(Migrator, name, hooked)

    hook("_checkpoint_legacy")
    hook("_move")
    out: dict = {}
    rollback = threading.Thread(target=lambda: out.setdefault("rollback", migrator.rollback()))
    rollback.start()
    assert reached.wait(20), "the rollback never reached the pause point"
    head = partition.ledger.head()[0]
    forget = threading.Thread(target=lambda: out.setdefault(
        "receipt", engine.forget(admin, ForgetTarget("memory", doomed.id))))
    forget.start()
    if wait_for_append:
        deadline = time.monotonic() + 10
        while partition.ledger.head()[0] == head and time.monotonic() < deadline:
            time.sleep(0.01)
    else:
        time.sleep(0.5)
    appended = partition.ledger.head()[0] > head
    go.set()
    rollback.join(60)
    forget.join(60)
    assert not rollback.is_alive() and not forget.is_alive()
    return migrator, doomed, out, appended


def test_fg5_a_forget_appended_during_the_final_checkpoint_reaches_the_legacy_store(
        menv, control, admin, legacy_db, mapping, tmp_path, monkeypatch):
    migrator, doomed, out, appended = _rollback_with_a_forget_injected(
        menv, control, admin, legacy_db, mapping, tmp_path, monkeypatch,
        pause_in=lambda name, args: name == "_checkpoint_legacy", wait_for_append=True)
    assert appended  # the forget's durable decision precedes the transition ...
    assert migrator.state().state == "legacy_authoritative"
    receipt = out["receipt"]
    assert receipt.deleted.get("memories") == 1
    assert _alive(menv, admin, doomed.id) is None
    assert doomed.id not in _legacy_ids(legacy_db)  # ... so the rollback applied it to legacy too
    assert _LEGACY_AUTHORITY not in receipt.receipt.limitations


def test_fg5_no_forget_appends_between_the_final_check_and_the_transition(
        menv, control, admin, legacy_db, mapping, tmp_path, monkeypatch):
    # Paused inside the final transition: the forget cannot append until it has committed.
    migrator, doomed, out, appended = _rollback_with_a_forget_injected(
        menv, control, admin, legacy_db, mapping, tmp_path, monkeypatch,
        pause_in=lambda name, args: name == "_move" and args and args[0] == "legacy_authoritative",
        wait_for_append=False)
    assert not appended, "a ledger append slipped between the final deletion check and the transition"
    assert migrator.state().state == "legacy_authoritative"
    receipt = out["receipt"]
    # The forget came after the rollback: a forget while legacy is the authority. Its receipt says
    # the legacy store keeps serving its copy (it never claims the memory is gone everywhere) ...
    assert _alive(menv, admin, doomed.id) is None
    ctx = menv.partition_context(admin.partition)
    with ctx.partition.db.read() as conn:
        assert receipt.deletion_generation > legacy_mod.rollback_watermark(conn)
    assert _LEGACY_AUTHORITY in receipt.receipt.limitations
    assert doomed.id in _legacy_ids(legacy_db)
    # ... and the next migration never brings it back, and its cutover deletes the legacy copy.
    again = _migrator(menv, control, admin, legacy_db, mapping, tmp_path / "again")
    again.prepare_shadow()
    assert _alive(menv, admin, doomed.id) is None
    assert again.validate()["validated"]
    assert again.cutover()["state"] == "package_authoritative"
    assert doomed.id not in _legacy_ids(legacy_db)


def test_fg5_receipts_say_whether_the_legacy_store_still_holds_the_memory(menv, control, admin, legacy_db,
                                                                        mapping, tmp_path):
    # Legacy authoritative (no cutover yet): the package forget does not reach the legacy store.
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    imported = group1._proj_a(menv, admin)
    first = sorted(imported)[0]
    receipt = menv.forget(admin, ForgetTarget("memory", first))
    assert _LEGACY_AUTHORITY in receipt.receipt.limitations
    assert first in _legacy_ids(legacy_db)
    # Package authoritative: the forget reaches the legacy copy, and the receipt says nothing else.
    assert migrator.validate()["validated"]
    migrator.cutover()
    second = sorted(group1._proj_a(menv, admin))[0]
    receipt = menv.forget(admin, ForgetTarget("memory", second))
    assert _LEGACY_AUTHORITY not in receipt.receipt.limitations
    assert second not in _legacy_ids(legacy_db) and first not in _legacy_ids(legacy_db)


# =========================================================================== R2-FG-6 / R2-SL-4
def _agent_proposal_approved(engine, *, sources, content, basis=StatementBasis.SOURCE_ATTRIBUTED, agent=AGENT):
    proposed = engine.propose(agent, CandidateProposal(content=content, scope=PROJ_A, sources=sources,
                                                       basis=basis)).record
    assert proposed.extra.get("basis_attested_by") == "agent"
    return engine.approve(USER, proposed.id, expected_revision=proposed.revision).record


def _two_memories(engine, label):
    return [engine.remember(USER, RememberRequest(content=f"evidence {i} for {label}", scope=PROJ_A)).record
            for i in (1, 2)]


def test_fg6_a_user_correction_reattests_the_basis_so_other_evidence_keeps_the_memory(engine):
    m1, m2 = _two_memories(engine, "postgres")
    approved = _agent_proposal_approved(engine, sources=(SourceRef(SourceKind.MEMORY, m1.id),
                                                         SourceRef(SourceKind.MEMORY, m2.id)),
                                        content="The build uses Postgres 15")
    corrected = engine.correct(USER, approved.id, Correction(content="The build uses Postgres 16"),
                               expected_revision=approved.revision).record
    assert corrected.basis == StatementBasis.USER_STATED
    assert corrected.extra.get("basis_attested_by") == "user"
    receipt = engine.forget(USER, ForgetTarget("memory", m1.id))
    kept = _alive(engine, USER, corrected.id)
    assert kept is not None, "the user's corrected statement was purged with one of its sources"
    assert receipt.retained_by_policy.get("memories_with_other_evidence") == 1
    assert receipt.deleted.get("memories") == 1  # only m1
    assert all(s.ref != m1.id for s in kept.sources)
    assert any(s.kind == SourceKind.USER_ACTION for s in kept.sources)
    services = engine.services(USER)
    with services.core.p.db.read() as conn:  # the corrected content is not suppressed
        assert services.forgetting.blocked_reason(conn, kept) is None


def test_sl4_a_corrected_agent_proposal_survives_forgetting_its_message_source(engine, user_access, agent_access,
                                                                             clock):
    event = engine.ingest_event(user_access, IngestionEvent(
        event_id="ev-1", session_ref="sess-1", sequence=0, role="user",
        text="we run postgres 14 for the team database", occurred_at=clock.now, scope=PROJ_A))
    message = SourceRef(SourceKind.MESSAGE, event.message_id)
    proposed = engine.propose(agent_access, CandidateProposal(content="team uses postgres 14", sources=(message,),
                                                              scope=PROJ_A)).record
    approved = engine.approve(user_access, proposed.id, expected_revision=proposed.revision).record
    corrected = engine.correct(user_access, proposed.id, Correction(content="Team uses Postgres 16 in production"),
                               expected_revision=approved.revision).record
    receipt = engine.forget(user_access, ForgetTarget("source", message.identity()))
    kept = _alive(engine, user_access, corrected.id)
    assert kept is not None, f"user-corrected memory deleted (receipt.deleted={receipt.deleted})"
    assert message not in kept.sources and any(s.kind == SourceKind.USER_ACTION for s in kept.sources)
    assert receipt.retained_by_policy.get("memories_with_other_evidence") == 1
    assert not receipt.deleted.get("memories")


def test_fg6_approval_alone_does_not_attest_an_agents_basis(engine):
    # Documented decision: a reviewer approves the statement, not the agent's claim about its basis.
    m1, m2 = _two_memories(engine, "mysql")
    approved = _agent_proposal_approved(engine, sources=(SourceRef(SourceKind.MEMORY, m1.id),
                                                         SourceRef(SourceKind.MEMORY, m2.id)),
                                        content="The build uses MySQL 8")
    assert approved.extra.get("basis_attested_by") == "agent"
    engine.forget(USER, ForgetTarget("memory", m1.id))
    assert _alive(engine, USER, approved.id) is None
    # And one with a single source goes with it, approved or not.
    (m3,) = _two_memories(engine, "redis")[:1]
    only = _agent_proposal_approved(engine, sources=(SourceRef(SourceKind.MEMORY, m3.id),),
                                    content="The cache is Redis 7")
    engine.forget(USER, ForgetTarget("memory", m3.id))
    assert _alive(engine, USER, only.id) is None


def test_fg6_a_correction_that_keeps_the_content_keeps_the_attestation(engine):
    m1, m2 = _two_memories(engine, "tags")
    approved = _agent_proposal_approved(engine, sources=(SourceRef(SourceKind.MEMORY, m1.id),
                                                         SourceRef(SourceKind.MEMORY, m2.id)),
                                        content="The build uses Node 20")
    retagged = engine.correct(USER, approved.id, Correction(tags=("build",)),
                              expected_revision=approved.revision).record
    assert retagged.basis == StatementBasis.SOURCE_ATTRIBUTED
    assert retagged.extra.get("basis_attested_by") == "agent"


# =========================================================================== R2-FG-7
def _new_memory(engine, admin):
    return engine.remember(admin, RememberRequest(content="Uses ruff for linting", scope=PROJ_A)).record


@pytest.mark.parametrize("how", ["simulated_crash", "exception_in_final_move"])
def test_fg7_a_resumed_rollback_adopts_package_native_records(engine, control, admin, legacy_db, mapping, tmp_path,
                                                             monkeypatch, how):
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    new = _new_memory(engine, admin)
    if how == "simulated_crash":
        migrator.crash_at = "before_rollback_complete"
        with pytest.raises(SimulatedCrash):
            migrator.rollback()
        migrator.crash_at = None
    else:  # a real failure after the reverse sync (e.g. a transient control-store error)
        real_move = Migrator._move
        calls = {"n": 0}

        def flaky_move(self, target, reason, **details):
            if target == "legacy_authoritative" and calls["n"] == 0:
                calls["n"] += 1
                raise RuntimeError("transient control-store failure")
            return real_move(self, target, reason, **details)

        monkeypatch.setattr(Migrator, "_move", flaky_move)
        with pytest.raises(RuntimeError):
            migrator.rollback()
        monkeypatch.setattr(Migrator, "_move", real_move)
    assert migrator.state().state == "rollback_in_progress"
    assert new.id in _legacy_ids(legacy_db)  # the legacy write committed before the failure
    resumed = migrator.resume()
    assert resumed["state"] == "legacy_authoritative"
    assert engine.get(admin, new.id).extra.get("legacy_round_trip") is True
    again = _migrator(engine, control, admin, legacy_db, mapping, tmp_path / "again")
    assert again.prepare_shadow()["state"] == "shadow_prepared"
    assert _alive(engine, admin, new.id).content == "Uses ruff for linting"


def test_fg7_preflight_names_the_conflicting_ids(engine, admin, legacy_db, mapping, tmp_path):
    # A package-native record that uses a legacy id (never a round trip): the refusal says which.
    taken = sorted(_legacy_ids(legacy_db))[0]
    ctx = engine.partition_context(admin.partition)
    native = _new_memory(engine, admin)
    with ctx.partition.db.write() as conn:
        record = dataclasses.replace(ctx.records.get(conn, native.id), id=taken, revision=1)
        ctx.services.core.write_internal(conn, record, change="created", actor=Actor.USER, expected=None)
    with pytest.raises(MigrationError) as raised:
        legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    assert raised.value.details["conflicting_ids"] == 1 and raised.value.details["ids"] == [taken]


# =========================================================================== R2-SL-2
GIT = shutil.which("git")
SECRET = "db-17.internal"


def _git(cwd, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"})
    subprocess.run([GIT, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main",
                    "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                   cwd=cwd, env=env, check=True, capture_output=True)


@pytest.fixture
def excluded_later(tmp_path):
    """A packet (and an observation) compiled while settings_prod.py was not excluded, then the
    host restarted with that path excluded. Yields (engine, access, request, packet, obs_id)."""
    if GIT is None:
        pytest.skip("git is required")
    allowed = (tmp_path / "allowed").resolve()
    repo = allowed / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", ".")
    (repo / "settings_prod.py").write_text(f'"""prod db host {SECRET} user=svc_payments"""\nX = 1\n')
    (repo / "app.py").write_text('"""application entry point"""\nY = 2\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    clock = FakeClock()
    keys = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    root = tmp_path / "root"
    access = access_for(repositories=("r1",), projects=("proj-a",))
    first = MemoryEngine(root, keys, host=HostCapabilities(clock=clock, allowed_repository_roots=(allowed,)))
    first.register_repository(access, repo, repository_id="r1")
    first.snapshot_repository(access, "r1")
    request = ContextRequest(token_allowance=4000, query="prod db host", repository="r1")
    packet = first.build_context(access, request)
    observation = [r for r in first.list(access, kinds=(MemoryKind.REPOSITORY_OBSERVATION,))
                   if r.extra.get("path") == "settings_prod.py"]
    first.close()
    assert SECRET in packet.text and len(observation) == 1
    engine = MemoryEngine(root, keys, host=HostCapabilities(clock=clock, allowed_repository_roots=(allowed,),
                                                            repository_exclude_patterns=["settings_prod.py"]))
    yield engine, access, request, packet, observation[0].id
    engine.close()


@pytest.mark.parametrize("invalidated", [False, True])
def test_sl2_revalidation_never_passes_a_now_excluded_observation(excluded_later, invalidated):
    engine, access, _request, packet, obs_id = excluded_later
    if invalidated:
        engine.invalidate(access, "exclusions changed")
    fresh = engine.revalidate_context(access, packet)
    assert fresh is not packet
    assert SECRET not in fresh.text and obs_id not in {item.record_id for item in fresh.items}


def test_sl2_a_packet_compiled_under_the_exclusion_revalidates_unchanged(excluded_later):
    engine, access, request, _packet, obs_id = excluded_later
    packet = engine.build_context(access, request)
    assert SECRET not in packet.text and obs_id not in {item.record_id for item in packet.items}
    assert engine.revalidate_context(access, packet) is packet  # nothing it relies on changed


def test_sl2_explain_and_export_hide_a_now_excluded_observation(excluded_later):
    engine, access, _request, packet, obs_id = excluded_later
    with pytest.raises(NotFound):
        engine.get(access, obs_id)
    with pytest.raises(NotFound):
        engine.explain(access, obs_id)
    document = engine.export(access)
    assert SECRET not in json.dumps(document)
    assert obs_id not in {record["id"] for record in document["records"]}
    assert document["records"]  # the other observations are still exported
    explained = engine.explain_context(access, packet.receipt_id)
    assert obs_id not in {item["record_id"] for item in explained["items"]}
    assert explained["unavailable_items"] >= 1


# =========================================================================== R2-SL-3
def _two_partitions():
    personal = access_for(profile="personal", projects=("proj-a",), agents=("agent-1",), repositories=("repo-a",))
    work = access_for(profile="work", projects=("proj-a",), operations={Operation.READ, Operation.MAINTAIN})
    assert personal.partition.partition_id != work.partition.partition_id
    return personal, work


def _receipt_count(services):
    with services.core.p.db.read() as conn:
        return conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]


def test_sl3_revoke_evidence_refuses_a_context_of_another_partition(eng, authority):
    personal, work = _two_partitions()
    procedure = candidate(eng, personal, authority)
    services = eng.services(personal)
    receipts = _receipt_count(services)
    for episode in ("ep-one", "ep-does-not-exist"):  # same refusal: no existence oracle
        with pytest.raises(AccessDenied, match="different partition"):
            services.procedures.revoke_evidence(work, episode)
        with pytest.raises(AccessDenied, match="different partition"):
            services.procedures.revoke_evidence(work, [episode], report_to=work)
    assert services.procedures.get(personal, procedure.procedure_id).state == ProcedureState.CANDIDATE
    assert _receipt_count(services) == receipts
    # The partition's own context still works.
    outcome = services.procedures.revoke_evidence(personal, "ep-one")
    assert outcome["procedures_revoked"] == 1


def test_sl3_every_public_method_that_can_take_an_access_context_is_partition_bound():
    import locus_memory.services as services_mod

    services_mod.build_services  # noqa: B018  (imports every service module)
    assert len(PARTITION_BOUND_CLASSES) >= 10
    unbound = []
    for cls in PARTITION_BOUND_CLASSES:
        for name, func in vars(cls).items():
            if name.startswith("_") or not inspect.isfunction(func):
                continue
            target = inspect.unwrap(func)
            params = inspect.signature(target).parameters.values()
            if any("access" in p.name.lower() or "AccessContext" in str(p.annotation) for p in params):
                if getattr(func, "__partition_check__", None) is None:
                    unbound.append(f"{cls.__name__}.{name}")
    assert not unbound, f"public methods taking an AccessContext without the partition check: {unbound}"


# =========================================================================== R2-SL-5
SECRETISH = "deploy key is on the blue usb stick today"
TRANSIENT_TEXTS = (SECRETISH, "standup moved to 10am this week only", "oncall is dana until friday")


class _Summarizer:
    def summarize(self, items, *, scope, deadline_s=None):
        return "Summary: " + " | ".join(item["content"] for item in items)


class _Hub:
    def summarizer(self, access):
        return _Summarizer()


def _transient_inputs(make_engine, clock, *, policy="session", ttl=3600):
    engine = make_engine()
    user = access_for(projects=("p",))
    now = clock()
    ids = [engine.remember(user, RememberRequest(content=text, kind="fact", scope=Scope.of(project="p"),
                                                 retention=Retention(policy, now + ttl, False))).record.id
           for text in TRANSIENT_TEXTS]
    engine.services(user).providers = _Hub()
    return engine, user, ids


def _context_text(engine, user):
    return engine.build_context(user, ContextRequest(token_allowance=4000)).text


def test_sl5_an_approved_summary_expires_with_its_transient_inputs(make_engine, clock):
    engine, user, ids = _transient_inputs(make_engine, clock)
    inputs_end = clock() + 3600
    summary_id = engine.consolidate(user, {"summarize": True})["summaries"][0]
    candidate_summary = engine.get(user, summary_id)
    assert SECRETISH in candidate_summary.content
    assert candidate_summary.retention.expires_at <= inputs_end  # a candidate never outlives them
    approved = engine.approve(user, summary_id, expected_revision=None).record
    assert approved.retention.policy == "session" and approved.retention.expires_at == inputs_end
    assert "blue usb stick" in _context_text(engine, user)
    clock.advance(7200)  # the inputs' retention has ended; maintenance has not run
    assert [engine.get(user, i).lifecycle for i in ids] == [Lifecycle.EXPIRED] * 3
    assert engine.get(user, summary_id).lifecycle == Lifecycle.EXPIRED
    assert "blue usb stick" not in _context_text(engine, user)
    result = engine.maintain(user)
    assert summary_id in engine.services(user).core.p.load_receipt(
        engine.services(user).core.p.db.conn, result["receipt_id"])["record_ids"]
    clock.advance(365 * 86400)
    engine.maintain(user)
    assert engine.get(user, summary_id).lifecycle == Lifecycle.EXPIRED
    assert "blue usb stick" not in _context_text(engine, user)


def test_sl5_a_summary_cannot_be_approved_once_its_inputs_expired(make_engine, clock):
    engine, user, ids = _transient_inputs(make_engine, clock)
    summary_id = engine.consolidate(user, {"summarize": True})["summaries"][0]
    clock.advance(7200)  # expired at read time; maintenance has not run
    with pytest.raises((StaleDerivation, InvalidTransition)):
        engine.approve(user, summary_id, expected_revision=None)
    assert engine.get(user, summary_id).lifecycle == Lifecycle.EXPIRED
    assert "blue usb stick" not in _context_text(engine, user)


def test_sl5_inputs_expired_at_read_time_block_approval_even_with_a_long_candidate_ttl(engine, clock):
    # A summary written without an inherited retention (e.g. by an earlier build): the inputs are
    # checked as they read now, not by their stored lifecycle.
    inputs = [engine.remember(USER, RememberRequest(content=text, scope=PROJ_A,
                                                    retention=Retention("transient", clock() + 60))).record
              for text in TRANSIENT_TEXTS[:2]]
    summary = group1._summary(engine, inputs)
    clock.advance(120)
    with pytest.raises(StaleDerivation):
        engine.approve(USER, summary.id, expected_revision=1)


def test_sl5_maintenance_expires_summaries_whose_input_retention_ended(engine, clock):
    # Approved summaries without an inherited retention (written by an earlier build) still go when
    # maintenance expires an input: they restate content whose retention is over.
    inputs = [engine.remember(USER, RememberRequest(content=text, scope=PROJ_A,
                                                    retention=Retention("transient", clock() + 60))).record
              for text in TRANSIENT_TEXTS[:2]]
    summary = group1._summary(engine, inputs)
    engine.approve(USER, summary.id, expected_revision=1)
    ctx = engine.partition_context(USER.partition)
    with ctx.partition.db.write() as conn:  # as an earlier build stored it: durable, no expiry
        stored = ctx.records.get(conn, summary.id)
        legacy_shape = dataclasses.replace(stored, revision=stored.revision + 1,
                                           retention=Retention("durable", None, False),
                                           extra={k: v for k, v in stored.extra.items() if k != "inherited_retention"})
        ctx.services.core.write_internal(conn, legacy_shape, change="test_fixture", actor=Actor.SYSTEM,
                                         expected=stored.revision)
    clock.advance(120)
    out = engine.maintain(USER)
    assert engine.get(USER, summary.id).lifecycle == Lifecycle.EXPIRED
    assert out["expired"] == 3  # two inputs and the summary
    with ctx.partition.db.read() as conn:
        assert summary.id in ctx.partition.load_receipt(conn, out["receipt_id"])["record_ids"]


def test_sl5_summaries_of_durable_inputs_stay_durable(make_engine, clock):
    engine = make_engine()
    user = access_for(projects=("p",))
    for text in TRANSIENT_TEXTS:
        engine.remember(user, RememberRequest(content=text, kind="fact", scope=Scope.of(project="p")))
    engine.services(user).providers = _Hub()
    summary_id = engine.consolidate(user, {"summarize": True})["summaries"][0]
    assert "inherited_retention" not in engine.get(user, summary_id).extra
    approved = engine.approve(user, summary_id, expected_revision=None).record
    assert approved.retention == Retention("durable", None, False)


# =========================================================================== R2-SL-6
def _ranked_engine(make_engine):
    engine = make_engine()
    user = access_for()
    for i in range(3):
        engine.remember(user, RememberRequest(content=f"alpha fact number {i} about deploys", kind="fact",
                                              scope=Scope.of()))
    request = ContextRequest(token_allowance=2000, query="deploys", deadline_ms=60_000,
                             slices=(SliceSpec("facts", 1000, (), None, True),))
    return engine, user, request


def _healthy(calls):
    def scores(access, text, records, **kwargs):
        calls.append("ok")
        return {r.id: 1.0 - 0.1 * i for i, r in enumerate(sorted(records, key=lambda r: r.created_at))}
    return scores


def test_sl6_a_semantic_provider_failure_is_neither_cached_nor_revalidated(make_engine):
    engine, user, request = _ranked_engine(make_engine)
    hub = engine.services(user).providers
    calls: list[str] = []

    def broken(access, text, records, **kwargs):
        calls.append("broken")
        raise TimeoutError("provider down")

    hub.semantic_scores = broken
    degraded = engine.build_context(user, request)
    assert degraded.status == ResultStatus.PARTIAL
    assert degraded.coverage.partial_reasons == (R_RANK_PARTIAL_TRANSIENT,)
    hub.semantic_scores = _healthy(calls)  # the provider recovers; nothing was written
    again = engine.build_context(user, request)
    assert again.costs["cache"] == "miss" and again.status == ResultStatus.COMPLETE
    assert calls == ["broken", "ok"]
    fresh = engine.revalidate_context(user, degraded)
    assert fresh is not degraded and fresh.status == ResultStatus.COMPLETE
    assert engine.build_context(user, request).costs["cache"] == "hit"  # a complete packet still caches


def test_sl6_a_deadline_inside_the_ranker_is_neither_cached_nor_revalidated(make_engine):
    engine, user, request = _ranked_engine(make_engine)
    services = engine.services(user)
    fake = {"t": 1000.0}
    services.retrieval.monotonic = lambda: fake["t"]  # only the ranker's deadline clock
    calls: list[str] = []

    def slow(access, text, records, **kwargs):
        calls.append("slow")
        fake["t"] += 3600.0  # longer than the remaining budget
        return None

    services.providers.semantic_scores = slow
    degraded = engine.build_context(user, request)
    assert degraded.coverage.partial_reasons == (R_RANK_PARTIAL_TRANSIENT,)
    services.providers.semantic_scores = _healthy(calls)
    again = engine.build_context(user, request)
    assert again.costs["cache"] == "miss" and again.status == ResultStatus.COMPLETE and calls[-1] == "ok"
    assert engine.revalidate_context(user, degraded) is not degraded


def test_sl6_a_recovered_provider_brings_back_semantic_only_matches(make_engine):
    engine, user, request = _ranked_engine(make_engine)
    engine.remember(user, RememberRequest(content="rollout pipeline for production releases", kind="fact",
                                          scope=Scope.of()))
    hub = engine.services(user).providers

    def broken(access, text, records, **kwargs):
        raise TimeoutError("provider down")

    hub.semantic_scores = broken
    assert len(engine.build_context(user, request).items) == 3
    hub.semantic_scores = lambda access, text, records, **kw: {r.id: (0.9 if "rollout" in r.content else 0.1)
                                                               for r in records}
    recovered = engine.build_context(user, request)
    assert recovered.costs["cache"] == "miss" and len(recovered.items) == 4


def test_sl6_a_deterministic_partial_ranking_is_still_cached(make_engine):
    engine, user, _request = _ranked_engine(make_engine)
    words = " ".join(f"term{i}" for i in range(40)) + " deploys"  # more than the query term limit
    request = ContextRequest(token_allowance=2000, query=words, slices=(SliceSpec("facts", 1000, (), None, True),))
    first = engine.build_context(user, request)
    assert first.coverage.partial_reasons == (R_RANK_PARTIAL,)
    second = engine.build_context(user, request)
    assert second.costs["cache"] == "hit"
    assert engine.revalidate_context(user, first) is first


def test_sl6_rank_reason_classification():
    from locus_memory.context.compiler import _rank_partial_reason
    from locus_memory.models import Coverage

    class Result:
        def __init__(self, reasons, status="partial", missing=()):
            self.coverage = Coverage(total=3, searched=3, index_ready=True, missing=tuple(missing),
                                     partial_reasons=tuple(reasons))
            self.status = ResultStatus(status)

    assert _rank_partial_reason(Result([], status="complete")) is None
    assert _rank_partial_reason(Result(["query_terms_truncated:max_24"])) == R_RANK_PARTIAL
    assert _rank_partial_reason(Result(["lexical_fallback:bm25_python (fts5 unavailable)"])) == R_RANK_PARTIAL
    assert _rank_partial_reason(Result([], missing=["1 authorized record(s) failed authentication"])) == R_RANK_PARTIAL
    for reason in ("semantic_unavailable:error", "semantic_unavailable:timeout", "deadline_exceeded:semantic",
                   "cancelled:text", "ranker_unavailable:text", "concurrent_change:1_results_dropped",
                   "something a host ranker invented"):
        assert _rank_partial_reason(Result(["query_terms_truncated:max_24", reason])) == R_RANK_PARTIAL_TRANSIENT
