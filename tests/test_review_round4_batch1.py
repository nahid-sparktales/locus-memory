"""Round-4 review, batch 1: regression tests for the reproduced defects.

R4-TAMPER-1  ledger replay driven by the plaintext deletion_generation counter
R4-TAMPER-2  scope/source/session/derivation forgets find victims only through index tables
R4-TAMPER-3  an inserted migration_forgets row voids a user's memory forget at the next import
R4-TAMPER-5  deleted provider_sync rows silently cancel external deletion of forgotten memories
R4-MF-1      re-migration wedged by a kept derived_from that points at a forgotten parent
R4-MF-2      rollback writes back records of unmapped agents; re-import rescopes them
R4-EG-1      derived-record scope ignores derived_from parents and episode/attempt/repository evidence
R4-RG-1      superseding a memory with an update derived from it fails or leaves it stale
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from conftest import FakeClock, access_for
from foundation_support import count, db_path, ledger_path, raw_db
from locus_memory.errors import NotFound, SuppressedError
from locus_memory.host import HostCapabilities
from locus_memory.models import (
    Actor,
    CandidateProposal,
    ForgetPolicy,
    ForgetTarget,
    Lifecycle,
    Operation,
    RememberRequest,
    Scope,
    SourceKind,
    SourceRef,
)
from locus_memory.storage.ledger import MemoryLedgerMirror

PROJ_A = Scope.of(project="proj-a")


def _restore(backup: Path, path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    shutil.copy(backup, path)


# =========================================================================== R4-RG-1
ALPHA = Scope.of(project="alpha")


def _rg1_actors():
    user = access_for(projects=("alpha",))
    agent = access_for(actor=Actor.AGENT, projects=("alpha",), operations={Operation.READ, Operation.PROPOSE})
    return user, agent


def test_rg1_approve_supersede_with_an_update_derived_from_the_superseded_memory(engine):
    user, agent = _rg1_actors()
    x = engine.remember(user, RememberRequest(content="Build server is in Frankfurt", scope=ALPHA,
                                              subject="build server", predicate="location")).record
    other = engine.propose(agent, CandidateProposal(
        content="Build server rack is labelled F7", scope=ALPHA, derived_from=(x.id,),
        sources=(SourceRef(SourceKind.MEMORY, x.id),))).record
    r = engine.propose(agent, CandidateProposal(
        content="Build server moved to Dublin", scope=ALPHA, subject="build server", predicate="location",
        sources=(SourceRef(SourceKind.MEMORY, x.id),), derived_from=(x.id,))).record
    assert x.id in r.links.conflicts_with
    result = engine.approve(user, r.id, expected_revision=r.revision, resolution="supersede")
    assert result.receipt.details["superseded"] == [x.id]
    assert engine.get(user, r.id).lifecycle == Lifecycle.APPROVED
    assert engine.get(user, x.id).lifecycle == Lifecycle.SUPERSEDED
    # Another record derived from the superseded memory still follows it (a pending one expires).
    assert engine.get(user, other.id).lifecycle == Lifecycle.EXPIRED


def test_rg1_keep_both_then_supersede_keeps_the_superseder_current(engine):
    user, agent = _rg1_actors()
    x = engine.remember(user, RememberRequest(content="Standup is at 9am", scope=ALPHA)).record
    r = engine.propose(agent, CandidateProposal(
        content="Standup is now at 10am", scope=ALPHA,
        sources=(SourceRef(SourceKind.MEMORY, x.id),), derived_from=(x.id,))).record
    restated = engine.propose(agent, CandidateProposal(
        content="Standup happens every morning at 9", scope=ALPHA, derived_from=(x.id,),
        sources=(SourceRef(SourceKind.MEMORY, x.id),))).record
    r = engine.approve(user, r.id, expected_revision=r.revision).record
    restated = engine.approve(user, restated.id, expected_revision=restated.revision).record
    x = engine.get(user, x.id)
    engine.supersede(user, x.id, r.id, expected_revision=x.revision)
    assert engine.get(user, r.id).lifecycle == Lifecycle.APPROVED
    hits = engine.search(user, "standup 10am").hits
    assert any(r.id in repr(hit) for hit in hits)
    # A restatement of the superseded memory still goes stale.
    assert engine.get(user, restated.id).lifecycle == Lifecycle.STALE


# =========================================================================== legacy migration helpers
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "locus_legacy"
EXPECTED = json.loads((FIXTURE / "expected.json").read_text())
LEGACY_KEY = bytes.fromhex(EXPECTED["key_hex"])
WS, OTHER, AGENT = EXPECTED["workspace"], EXPECTED["other_workspace"], EXPECTED["agent_id"]
NEW_AGENT = "agent-new"


class LegacyEnv:
    """A package engine with ownership control over a private copy of the legacy fixture."""

    def __init__(self, tmp: Path, *, agents=(AGENT,), mirror=None) -> None:
        from locus_memory import MemoryEngine, StaticKeyProvider
        from locus_memory.migrations import legacy as legacy_mod
        from locus_memory.migrations.state import OwnershipControl

        self.tmp = tmp
        self.root = tmp / "root"
        self.legacy = tmp / "legacy" / "memory.sqlite3"
        self.legacy.parent.mkdir(parents=True)
        shutil.copy(FIXTURE / "memory.sqlite3", self.legacy)  # a copy; the fixture is never touched
        self.clock = FakeClock()
        self.keys = StaticKeyProvider({"k1": bytes(range(32))})
        self.admin = access_for(projects=("proj-a", "proj-b"), agents=(AGENT, NEW_AGENT), operations=set(Operation))
        self.mapping = legacy_mod.LegacyMapping.from_known({WS: "proj-a", OTHER: "proj-b"}, list(agents))
        self.control = OwnershipControl(self.root)
        self.mirror = mirror
        self.engine = MemoryEngine(self.root, self.keys, host=self.host())

    def host(self) -> HostCapabilities:
        return HostCapabilities(ownership=self.control, clock=self.clock, ledger_mirror=self.mirror)

    def reopen(self) -> None:
        from locus_memory import MemoryEngine

        self.engine.close()
        self.engine = MemoryEngine(self.root, self.keys, host=self.host())

    def close(self) -> None:
        for fn in (self.engine.close, self.control.close):
            try:
                fn()
            except Exception:
                pass

    def migrator(self, name: str, mapping=None):
        from locus_memory.migrations.cutover import Migrator

        return Migrator(self.engine, self.control, self.admin, self.legacy, LEGACY_KEY, mapping or self.mapping,
                        work_dir=self.tmp / name, project_workspaces={"proj-a": WS, "proj-b": OTHER})

    def state(self) -> str:
        return self.control.get(self.admin.partition.partition_id, "memories").state

    def legacy_ids(self) -> set[str]:
        from locus_memory.compat.legacy_vault import LegacyMemoryVault

        return {row["id"] for row in LegacyMemoryVault(self.legacy, key=LEGACY_KEY).raw_rows()}

    def stored(self, record_id: str):
        ctx = self.engine.partition_context(self.admin.partition)
        with ctx.partition.db.read() as conn:
            return ctx.records.get(conn, record_id)

    def cut_over(self, name: str = "m1"):
        migrator = self.migrator(name)
        migrator.prepare_shadow()
        assert migrator.validate()["validated"]
        assert migrator.cutover()["state"] == "package_authoritative"
        return migrator


@pytest.fixture
def legacy_env(tmp_path):
    env = LegacyEnv(tmp_path)
    yield env
    env.close()


# =========================================================================== R4-MF-2
def test_mf2_rollback_refuses_records_of_an_agent_the_mapping_does_not_know(legacy_env):
    from locus_memory.errors import MigrationError

    env = legacy_env
    m1 = env.cut_over()
    n = env.engine.remember(env.admin, RememberRequest(content="agent-new prefers verbose logs",
                                                       scope=Scope.of(agent=NEW_AGENT))).record
    plan = m1.plan_rollback()
    assert plan["safe"] is False and plan["unrepresentable"] == {"fact:agent": 1}
    with pytest.raises(MigrationError):
        m1.rollback()
    assert env.state() == "package_authoritative"
    rb = m1.rollback(allow_partial=True)
    assert rb["state"] == "legacy_authoritative"
    assert n.id not in env.legacy_ids()  # kept in the package recovery store, never rescoped by an import
    m2 = env.cut_over("m2")
    assert m2.state().state == "package_authoritative"
    assert env.stored(n.id).scope.as_dict() == {"agent": NEW_AGENT}
    agent_only = access_for(agents=(NEW_AGENT,), operations=set(Operation))
    assert n.id in {r.id for r in env.engine.list(agent_only, lifecycles=None)}
    env.engine.forget(env.admin, ForgetTarget("agent", NEW_AGENT))
    assert env.stored(n.id) is None


def test_mf2_reimport_never_rescopes_a_written_back_agent_record_to_legacy_target(legacy_env):
    """A legacy row of an agent the import mapping does not know (written back by a rollback whose
    mapping knew it, or by an earlier build) keeps the package record's concrete agent scope."""
    from locus_memory.migrations import legacy as legacy_mod

    env = legacy_env
    full = legacy_mod.LegacyMapping.from_known({WS: "proj-a", OTHER: "proj-b"}, [AGENT, NEW_AGENT])
    m1 = env.migrator("m1", full)
    m1.prepare_shadow()
    assert m1.validate()["validated"]
    m1.cutover()
    n = env.engine.remember(env.admin, RememberRequest(content="agent-new prefers verbose logs",
                                                       scope=Scope.of(agent=NEW_AGENT))).record
    assert m1.rollback()["state"] == "legacy_authoritative"
    assert n.id in env.legacy_ids()
    # The next migration runs with a mapping that knows only the original agent (Stage-2 adapter).
    m2 = env.migrator("m2")
    shadow = m2.prepare_shadow()
    assert not shadow["import"].get("rescoped")
    assert m2.validate()["validated"]
    assert m2.cutover()["state"] == "package_authoritative"
    assert env.stored(n.id).scope.as_dict() == {"agent": NEW_AGENT}
    env.engine.forget(env.admin, ForgetTarget("agent", NEW_AGENT))
    assert env.stored(n.id) is None
    assert n.id not in env.legacy_ids()  # the forget reaches the legacy copy kept for rollback


# =========================================================================== R4-MF-1
def _mf1_setup(env):
    from locus_memory.models import StatementBasis

    m1 = env.cut_over()
    x = env.engine.remember(env.admin, RememberRequest(content="Parent fact about the build", scope=PROJ_A)).record
    z = env.engine.remember(env.admin, RememberRequest(content="Another fact about the build", scope=PROJ_A)).record
    prop = env.engine.propose(env.admin, CandidateProposal(
        content="The user's own summary derived from the parent", sources=(SourceRef(SourceKind.MEMORY, z.id),),
        derived_from=(x.id,), basis=StatementBasis.USER_STATED, scope=PROJ_A)).record
    y = env.engine.approve(env.admin, prop.id, expected_revision=prop.revision).record
    return m1, x, y


@pytest.mark.parametrize("legacy_edit", [False, True], ids=["no_legacy_edit", "legacy_feedback_edit"])
def test_mf1_kept_derivation_of_a_forgotten_parent_does_not_wedge_remigration(legacy_env, legacy_edit):
    from locus_memory.compat.legacy_vault import LegacyMemoryVault

    env = legacy_env
    m1, x, y = _mf1_setup(env)
    receipt = env.engine.forget(env.admin, ForgetTarget("memory", x.id))
    assert receipt.retained_by_policy.get("user_confirmed_derivations") == 1
    kept = env.stored(y.id)
    assert kept.links.derived_from == ()  # storage matches the receipt: the parent link is severed
    parent_token = env.engine.partition_context(env.admin.partition).partition.token("memory", x.id)
    assert count(db_path(env.root, env.admin), "SELECT COUNT(*) FROM derivations WHERE derived_id=?"
                 " AND input_token=?", (y.id, parent_token)) == 0
    assert m1.rollback()["state"] == "legacy_authoritative"
    assert y.id in env.legacy_ids()
    if legacy_edit:
        guard = env.control.writer_guard(env.admin.partition.partition_id, "memories", "legacy")
        LegacyMemoryVault(env.legacy, key=LEGACY_KEY, write_guard=guard).feedback(y.id, "incorrect", workspace=WS)
    m2 = env.migrator("m2")
    shadow = m2.prepare_shadow()
    assert not shadow["import"].get("skipped_suppressed")
    result = m2.validate()
    assert result["validated"], result["verify"]["mismatches"]
    assert m2.cutover()["state"] == "package_authoritative"
    stored = env.stored(y.id)
    assert stored.content == y.content and stored.basis == y.basis
    assert x.id not in stored.links.derived_from


def test_mf1_delta_drops_a_stale_parent_edge_left_by_an_earlier_build(legacy_env):
    """A record already holding a derived_from edge to a forgotten parent (stored before the cascade
    severed such edges) is still re-migrated: the dangling parent is dropped, not a refusal."""
    import dataclasses

    from locus_memory.models import Actor as _Actor

    env = legacy_env
    m1, x, y = _mf1_setup(env)
    env.engine.forget(env.admin, ForgetTarget("memory", x.id))
    ctx = env.engine.partition_context(env.admin.partition)
    current = env.stored(y.id)
    stale = dataclasses.replace(current, revision=current.revision + 1,
                                links=dataclasses.replace(current.links, derived_from=(x.id,)))
    with ctx.partition.db.write() as conn:  # what an earlier build left behind
        ctx.services.core.write_internal(conn, stale, change="source_forgotten", actor=_Actor.SYSTEM,
                                         expected=current.revision)
    assert m1.rollback()["state"] == "legacy_authoritative"
    m2 = env.migrator("m2")
    m2.prepare_shadow()
    result = m2.validate()
    assert result["validated"], result["verify"]["mismatches"]
    assert m2.cutover()["state"] == "package_authoritative"
    assert x.id not in env.stored(y.id).links.derived_from


def test_mf1_a_migration_that_cannot_validate_can_be_aborted_back_to_legacy(legacy_env):
    from locus_memory.migrations.cutover import abort_cutover

    env = legacy_env
    migrator = env.migrator("m1")
    migrator.prepare_shadow()
    assert env.state() == "shadow_prepared"
    assert migrator.abort_cutover("operator gave up")["state"] == "legacy_authoritative"
    assert migrator.prepare_shadow()["state"] == "shadow_prepared"
    assert migrator.validate()["validated"]
    assert abort_cutover(env.control, env.admin.partition.partition_id)["state"] == "legacy_authoritative"


# =========================================================================== R4-EG-1
SECRET_LINE = "API_HOST = 'internal.corp.example'"
OPEN = Scope.of(project="open")
REPO = Scope.of(repository="repo-a")


def _contents(engine, access):
    return {r.content for r in engine.list(access, lifecycles=None)}


@pytest.fixture
def eg1_repo(tmp_path):
    """repo-a registered with its default scope {repository: repo-a}; an egress extractor whose
    only consent covers repository source (allow_source) for {project: open}."""
    from locus_memory import MemoryEngine, StaticKeyProvider
    from locus_memory.providers.base import (
        DATA_MEMORY_TEXT,
        DATA_REPOSITORY_SOURCE,
        ConsentGrant,
        StaticConsentPolicy,
    )
    from locus_memory.providers.fake import FakeExtractor
    from test_repository import git, make_repo

    if shutil.which("git") is None:
        pytest.skip("git is required")
    clock = FakeClock()
    allowed = (tmp_path / "allowed").resolve()
    allowed.mkdir()
    repo = make_repo(allowed / "repo", {"settings.py": SECRET_LINE + "\n"})
    ext = FakeExtractor("cloud-extract", egress=True, data_classes=(DATA_MEMORY_TEXT, DATA_REPOSITORY_SOURCE))
    consent = StaticConsentPolicy([ConsentGrant(
        provider="cloud-extract", scope=OPEN, data_classes=frozenset({DATA_MEMORY_TEXT, DATA_REPOSITORY_SOURCE}),
        allow_source=True, granted_at=clock.now - 1)])
    host = HostCapabilities(clock=clock, providers={"cloud-extract": ext}, consent=consent,
                            allowed_repository_roots=(allowed,))
    engine = MemoryEngine(tmp_path / "root", StaticKeyProvider({"k1": bytes(range(32))}), host=host)
    user = access_for(repositories=("repo-a",), projects=("open",))
    engine.register_repository(user, repo, repository_id="repo-a")
    engine.snapshot_repository(user, "repo-a")
    blob = git(repo, "rev-parse", "HEAD:settings.py")
    head = git(repo, "rev-parse", "HEAD")
    teammate = access_for(projects=("open",), principal="teammate")  # no repo-a grant
    yield engine, ext, user, teammate, blob, head
    engine.close()


def test_eg1_repository_evidence_needs_consent_for_the_repository_scope(eg1_repo):
    from locus_memory.errors import ConsentRequired

    engine, ext, user, teammate, blob, _ = eg1_repo
    hub = engine.services(user).providers
    src = SourceRef(SourceKind.BLOB_RANGE, f"repo-a:{blob}")
    with pytest.raises(ConsentRequired):
        hub.extract_candidates(user, [{"id": "e1", "text": SECRET_LINE, "source": src, "scope": OPEN}],
                               provider="cloud-extract")
    assert ext.calls == []  # nothing left the process
    assert not any("internal.corp.example" in c for c in _contents(engine, teammate))


def test_eg1_repository_evidence_is_narrowed_to_the_repository_scope(eg1_repo):
    engine, _, user, teammate, blob, head = eg1_repo
    agent = access_for(repositories=("repo-a",), projects=("open",), actor=Actor.AGENT)
    w_blob = engine.propose(agent, CandidateProposal(
        content="The internal API host is internal.corp.example",
        sources=(SourceRef(SourceKind.BLOB_RANGE, f"repo-a:{blob}"),), scope=OPEN, proposer="agent-x")).record
    w_commit = engine.propose(agent, CandidateProposal(
        content="The initial commit configured internal.corp.example",
        sources=(SourceRef(SourceKind.COMMIT, f"repo-a:{head}"),), scope=OPEN, proposer="agent-x")).record
    assert w_blob.scope.as_dict() == {"project": "open", "repository": "repo-a"}
    assert w_commit.scope.as_dict() == {"project": "open", "repository": "repo-a"}
    assert not any("internal.corp.example" in c for c in _contents(engine, teammate))


def test_eg1_repository_forget_removes_restatements_cited_from_other_scopes(eg1_repo):
    """Records written before scopes were reconciled (declared {project: open}, citing repo-a's blob)
    are removed by a forget of the repository, like those of a forgotten source."""
    import dataclasses

    from locus_memory.models import Actor as _Actor

    engine, _, user, teammate, blob, _ = eg1_repo
    agent = access_for(repositories=("repo-a",), projects=("open",), actor=Actor.AGENT)
    src = SourceRef(SourceKind.BLOB_RANGE, f"repo-a:{blob}")
    leaked = engine.propose(agent, CandidateProposal(content="The internal API host is internal.corp.example",
                                                     sources=(src,), scope=OPEN, proposer="agent-x")).record
    ctx = engine.partition_context(user.partition)
    with ctx.partition.db.write() as conn:  # what an earlier build stored: the declared scope only
        legacy_shape = dataclasses.replace(leaked, revision=leaked.revision + 1, scope=OPEN)
        ctx.services.core.write_internal(conn, legacy_shape, change="source_forgotten", actor=_Actor.SYSTEM,
                                         expected=leaked.revision)
    assert "The internal API host is internal.corp.example" in _contents(engine, teammate)
    receipt = engine.forget(user, ForgetTarget("repository", "repo-a"))
    assert receipt.deleted.get("repositories") == 1
    with ctx.partition.db.read() as conn:
        assert ctx.records.get(conn, leaked.id) is None
    assert not any("internal.corp.example" in c for c in _contents(engine, teammate))


def test_eg1_derived_from_parent_scope_narrows_the_proposal(engine):
    user_a = access_for(projects=("A",))
    agent_a = access_for(projects=("A",), actor=Actor.AGENT)
    reader_b = access_for(projects=("B",), principal="other")
    m = engine.remember(user_a, RememberRequest(content="Project A acquisition target is Globex, closing in Q3",
                                                scope=Scope.of(project="A"))).record
    g = engine.remember(user_a, RememberRequest(content="I prefer short status updates", scope=Scope())).record
    w = engine.propose(agent_a, CandidateProposal(content="Acquisition target: Globex (Q3)", derived_from=(m.id,),
                                                  sources=(SourceRef(SourceKind.MEMORY, g.id),), scope=Scope(),
                                                  proposer="agent")).record
    assert w.scope.as_dict() == {"project": "A"}
    assert "Acquisition target: Globex (Q3)" not in _contents(engine, reader_b)
    from locus_memory.errors import ValidationError

    agent_ab = access_for(projects=("A", "B"), actor=Actor.AGENT)
    with pytest.raises(ValidationError):  # a declaration that conflicts with the parent's scope
        engine.propose(agent_ab, CandidateProposal(content="Globex elsewhere", derived_from=(m.id,),
                                                   sources=(SourceRef(SourceKind.MEMORY, g.id),),
                                                   scope=Scope.of(project="B"), proposer="agent"))


def test_eg1_episode_and_task_attempt_evidence_narrow_the_proposal(engine):
    from locus_memory.models import EpisodeReport

    agent_a = access_for(projects=("A",), actor=Actor.AGENT)
    reader_b = access_for(projects=("B",), principal="other-user")
    ep, _ = engine.record_episode(agent_a, EpisodeReport(
        episode_id="ep1", task_ref="t1", attempt_ref="a1", objective="Migrate ACME payroll DB credentials vault",
        scope=Scope.of(project="A"), approach="rotated payroll vault on host db-7.acme.internal"))
    w_ep = engine.propose(agent_a, CandidateProposal(content="Payroll vault lives on host db-7.acme.internal",
                                                     sources=(SourceRef(SourceKind.EPISODE, "ep1"),),
                                                     proposer="agent-x")).record
    w_att = engine.propose(agent_a, CandidateProposal(
        content="Payroll vault rotation ran on db-7.acme.internal",
        sources=(SourceRef(SourceKind.TASK_ATTEMPT, "a1", locator={"task_ref": "t1"}),), proposer="agent-x")).record
    assert w_ep.scope.as_dict() == {"project": "A"} and w_att.scope.as_dict() == {"project": "A"}
    seen_b = _contents(engine, reader_b)
    assert not any("db-7.acme.internal" in c for c in seen_b)


# =========================================================================== R4-TAMPER-2
def _strip(root, access, sql, params=()):
    with raw_db(db_path(root, access)) as conn:
        return conn.execute(sql, params).rowcount


def test_tamper2_scope_forget_finds_a_record_whose_scope_index_was_stripped(make_engine, root, user_access):
    engine = make_engine()
    rec = engine.remember(user_access, RememberRequest(content="PROJA-SECRET alpha", scope=PROJ_A)).record
    engine.close()
    assert _strip(root, user_access, "DELETE FROM record_scopes WHERE record_id=?", (rec.id,)) >= 1
    engine = make_engine()
    receipt = engine.forget(user_access, ForgetTarget("project", "proj-a"))
    assert receipt.deleted.get("memories") == 1
    with pytest.raises(NotFound):
        engine.get(user_access, rec.id)
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM records WHERE id=?", (rec.id,)) == 0


def test_tamper2_replayed_scope_forget_after_restore_ignores_a_stripped_index(make_engine, root, user_access,
                                                                            tmp_path):
    engine = make_engine()
    rec = engine.remember(user_access, RememberRequest(content="PROJA-SECRET beta", scope=PROJ_A)).record
    engine.close()
    backup = tmp_path / "pre-forget.sqlite3"
    shutil.copy(db_path(root, user_access), backup)
    engine = make_engine()
    engine.forget(user_access, ForgetTarget("project", "proj-a"))
    engine.close()
    _restore(backup, db_path(root, user_access))
    _strip(root, user_access, "DELETE FROM record_scopes WHERE record_id=?", (rec.id,))
    engine = make_engine()
    with pytest.raises(NotFound):
        engine.get(user_access, rec.id)
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM records WHERE id=?", (rec.id,)) == 0


def test_tamper2_source_forget_finds_a_citer_whose_source_index_was_stripped(make_engine, root):
    acc = access_for(projects=("proj-a",))
    engine = make_engine()
    rec = engine.propose(acc, CandidateProposal(content="DOC1-SECRET gamma", scope=PROJ_A,
                                                sources=(SourceRef(SourceKind.DOCUMENT, "doc-1"),))).record
    engine.close()
    _strip(root, acc, "DELETE FROM record_sources WHERE record_id=?", (rec.id,))
    _strip(root, acc, "DELETE FROM derivations WHERE derived_id=?", (rec.id,))
    engine = make_engine()
    engine.forget(acc, ForgetTarget("source", "document:doc-1"))
    with pytest.raises(NotFound):
        engine.get(acc, rec.id)


def test_tamper2_cascade_finds_a_derived_record_whose_derivation_edge_was_stripped(make_engine, root):
    acc = access_for(projects=("proj-a",))
    engine = make_engine()
    parent = engine.remember(acc, RememberRequest(content="PARENT fact delta", scope=PROJ_A)).record
    child = engine.propose(acc, CandidateProposal(content="CHILD derived from parent delta", scope=PROJ_A,
                                                  sources=(SourceRef(SourceKind.DOCUMENT, "doc-9"),),
                                                  derived_from=(parent.id,))).record
    engine.close()
    assert _strip(root, acc, "DELETE FROM derivations WHERE derived_id=? AND input_kind='memory'", (child.id,)) >= 1
    engine = make_engine()
    receipt = engine.forget(acc, ForgetTarget("memory", parent.id))
    assert receipt.deleted.get("derived_memories") == 1
    with pytest.raises(NotFound):
        engine.get(acc, child.id)
    assert count(db_path(root, acc), "SELECT COUNT(*) FROM records WHERE id=?", (child.id,)) == 0


def test_tamper2_scope_forget_finds_a_session_whose_scope_index_was_stripped(make_engine, root, user_access,
                                                                           clock):
    from locus_memory.models import IngestionEvent

    engine = make_engine()
    engine.ingest_event(user_access, IngestionEvent(event_id="ev-1", session_ref="sess-a", sequence=0, role="user",
                                                    text="HISTSECRET zeta transcript", occurred_at=clock(),
                                                    scope=PROJ_A))
    engine.close()
    assert _strip(root, user_access, "DELETE FROM history_session_scopes") >= 1
    engine = make_engine()
    engine.forget(user_access, ForgetTarget("project", "proj-a"))
    engine.close()
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM history_messages") == 0
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM history_sessions") == 0


# =========================================================================== R4-TAMPER-1
SECRET = "SECRET-R4T1 forgotten after backup"


def _set_counter(path: Path, value: int) -> None:
    with raw_db(path) as conn:
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('deletion_generation', ?)", (str(value),))


def _forget_after_backup(make_engine, root, access, tmp_path, host, *, scope=PROJ_A, target=None):
    """Remember SECRET, back up the main database, forget it (memory target unless ``target``);
    returns (record, backup path, ledger head)."""
    engine = make_engine(host=host())
    record = engine.remember(access, RememberRequest(content=SECRET, scope=scope)).record
    engine.close()
    backup = tmp_path / "old-main.sqlite3"
    shutil.copy(db_path(root, access), backup)
    engine = make_engine(host=host())
    engine.forget(access, target or ForgetTarget("memory", record.id))
    with pytest.raises(NotFound):
        engine.get(access, record.id)
    engine.close()
    head = count(ledger_path(root, access), "SELECT MAX(generation) FROM ledger")
    return record, backup, head


@pytest.mark.parametrize("with_mirror", [False, True], ids=["no_mirror", "mirror"])
def test_tamper1_restored_old_database_with_an_edited_counter_still_replays(make_engine, root, user_access,
                                                                            tmp_path, clock, with_mirror):
    mirror = MemoryLedgerMirror() if with_mirror else None
    host = lambda: HostCapabilities(clock=clock, ledger_mirror=mirror)  # noqa: E731
    record, backup, head = _forget_after_backup(make_engine, root, user_access, tmp_path, host)
    _restore(backup, db_path(root, user_access))
    _set_counter(db_path(root, user_access), head)  # keyless edit of the plaintext counter
    engine = make_engine(host=host())
    with pytest.raises(NotFound):
        engine.get(user_access, record.id)
    assert SECRET not in {r.content for r in engine.list(user_access)}
    engine.close()
    engine = make_engine(host=host())  # and it stays forgotten
    with pytest.raises(NotFound):
        engine.get(user_access, record.id)
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM records WHERE id=?", (record.id,)) == 0


def test_tamper1_restored_old_database_without_its_checkpoint_still_replays(make_engine, root, user_access,
                                                                            tmp_path, clock):
    host = lambda: HostCapabilities(clock=clock)  # noqa: E731
    record, backup, head = _forget_after_backup(make_engine, root, user_access, tmp_path, host)
    _restore(backup, db_path(root, user_access))
    with raw_db(db_path(root, user_access)) as conn:  # looks like a store written before checkpoints
        conn.execute("DELETE FROM meta WHERE key='deletion_checkpoint'")
    _set_counter(db_path(root, user_access), head)
    engine = make_engine(host=host())
    with pytest.raises(NotFound):
        engine.get(user_access, record.id)


@pytest.mark.parametrize("target", ["memory", "project"])
def test_tamper1_old_database_with_the_current_deletion_state_transplanted_is_repaired(
        make_engine, root, user_access, tmp_path, clock, target):
    """An older backup given the *current* database's authenticated checkpoint and deletion-state
    tables (copied row by row, no key needed) still loses every record a forget removed."""
    mirror = MemoryLedgerMirror()
    host = lambda: HostCapabilities(clock=clock, ledger_mirror=mirror)  # noqa: E731
    forget_target = ForgetTarget("project", "proj-a") if target == "project" else None
    record, backup, _head = _forget_after_backup(make_engine, root, user_access, tmp_path, host,
                                                 target=forget_target)
    current = tmp_path / "current-main.sqlite3"
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    shutil.copy(db_path(root, user_access), current)
    _restore(backup, db_path(root, user_access))
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("ATTACH DATABASE ? AS cur", (str(current),))
        conn.execute("INSERT OR REPLACE INTO meta SELECT * FROM cur.meta WHERE key IN"
                     " ('deletion_generation', 'deletion_checkpoint')")
        for table in ("tombstones", "suppressions", "tombstone_aliases"):
            conn.execute(f"DELETE FROM {table}")
            conn.execute(f"INSERT INTO {table} SELECT * FROM cur.{table}")
        conn.execute("DELETE FROM tombstones WHERE target_kind='memory'")  # and drop the removed ids
        conn.execute("DETACH DATABASE cur")
    engine = make_engine(host=host())
    with pytest.raises(NotFound):
        engine.get(user_access, record.id)
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM records WHERE id=?", (record.id,)) == 0


def test_tamper1_deleted_suppression_rows_are_restored_from_the_ledger(make_engine, root, user_access):
    engine = make_engine()
    src = (SourceRef(SourceKind.DOCUMENT, "doc-r4t1"),)
    record = engine.propose(user_access, CandidateProposal(content=SECRET, sources=src, scope=PROJ_A)).record
    engine.forget(user_access, ForgetTarget("memory", record.id))
    engine.close()
    with raw_db(db_path(root, user_access)) as conn:
        assert conn.execute("DELETE FROM suppressions").rowcount >= 1
    engine = make_engine()
    with pytest.raises(SuppressedError):
        engine.propose(user_access, CandidateProposal(content=SECRET, sources=src, scope=PROJ_A))


def test_tamper1_deleted_tombstone_rows_are_restored_from_the_ledger(make_engine, root, user_access):
    from locus_memory.errors import ValidationError

    engine = make_engine()
    parent = engine.remember(user_access, RememberRequest(content="Launch codename is NIGHTJAR", scope=PROJ_A,
                                                          memory_id="mstable0001")).record
    child = engine.propose(user_access, CandidateProposal(content="NIGHTJAR summary", scope=PROJ_A,
                                                          sources=(SourceRef(SourceKind.MEMORY, parent.id),),
                                                          derived_from=(parent.id,))).record
    engine.forget(user_access, ForgetTarget("memory", parent.id))
    engine.close()
    with raw_db(db_path(root, user_access)) as conn:
        assert conn.execute("DELETE FROM tombstones").rowcount >= 2
    engine = make_engine()
    with pytest.raises(ValidationError):  # the forgotten id is never re-created
        engine.remember(user_access, RememberRequest(content="the project is public now", scope=PROJ_A,
                                                     memory_id="mstable0001"))
    ctx = engine.partition_context(user_access.partition)
    forgetting = ctx.services.forgetting
    with ctx.partition.db.read() as conn:  # the cascade's removal is a tombstone again too
        assert forgetting.tombstone_generation(conn, "memory", child.id) is not None


def test_tamper1_an_unaltered_store_reopens_without_repairs(make_engine, user_access):
    engine = make_engine()
    a = engine.remember(user_access, RememberRequest(content="kept fact", scope=PROJ_A)).record
    b = engine.remember(user_access, RememberRequest(content="forgotten fact", scope=PROJ_A)).record
    engine.forget(user_access, ForgetTarget("memory", b.id))
    engine.close()
    engine = make_engine()
    assert engine.get(user_access, a.id).content == "kept fact"
    report = engine.reconcile(user_access)
    assert report["reapplied"] == 0 and not report.get("resurrected_removed")
    assert engine.status(user_access).deletion_generation == 1


# =========================================================================== R4-TAMPER-3
TARGET = EXPECTED["ids"]["personal"]


def _tamper3(env, *, policy, mark=False, drop_suppressions=False, drop_tombstone=False, offline=False):
    migrator = env.migrator("m1")
    migrator.prepare_shadow()
    original = env.engine.get(env.admin, TARGET)
    env.engine.forget(env.admin, ForgetTarget("memory", TARGET), policy=policy)
    if offline:
        env.engine.close()
    with raw_db(db_path(env.root, env.admin)) as conn:
        tomb = conn.execute("SELECT generation, created_at FROM tombstones WHERE target_kind='memory'"
                            " AND target_token=?", (TARGET,)).fetchone()
        if mark:
            conn.execute("INSERT INTO migration_forgets(record_id, generation, created_at) VALUES(?, NULL, 0)",
                         (TARGET,))
        if drop_suppressions:
            conn.execute("DELETE FROM suppressions WHERE created_at=? AND generation=?",
                         (tomb["created_at"], tomb["generation"] - 1))
        if drop_tombstone:
            conn.execute("DELETE FROM tombstones WHERE target_kind='memory' AND target_token=?", (TARGET,))
    if offline:
        env.reopen()
    from locus_memory.migrations import legacy as legacy_mod

    imported = legacy_mod.LegacyImporter(env.engine, env.admin, env.legacy, LEGACY_KEY, env.mapping).run()
    migrator = env.migrator("m1")
    assert migrator.validate()["validated"]
    assert migrator.cutover()["state"] == "package_authoritative"
    return original, imported


@pytest.mark.parametrize("case", ["mark_and_suppressions", "mark_only_no_suppression", "tombstone_row",
                                  "offline_mark_and_suppressions"])
def test_tamper3_plaintext_rows_never_void_a_users_memory_forget(legacy_env, case):
    env = legacy_env
    kwargs = {
        "mark_and_suppressions": dict(policy=ForgetPolicy(), mark=True, drop_suppressions=True),
        "mark_only_no_suppression": dict(policy=ForgetPolicy(suppress_relearning=False), mark=True),
        "tombstone_row": dict(policy=ForgetPolicy(suppress_relearning=False), drop_tombstone=True),
        "offline_mark_and_suppressions": dict(policy=ForgetPolicy(), mark=True, drop_suppressions=True,
                                              offline=True),
    }[case]
    _original, imported = _tamper3(env, **kwargs)
    assert imported.get("skipped_forgotten") == 1 and not imported.get("imported")
    with pytest.raises(NotFound):
        env.engine.get(env.admin, TARGET)


def test_tamper3_a_propagated_legacy_deletion_still_lets_a_recreated_row_back(legacy_env):
    """The authenticated migration origin keeps what the plaintext mark did: a legacy row deleted in
    legacy (the importer propagates it) and later re-created under the same id is new legacy data."""
    from locus_memory.compat.legacy_vault import LegacyMemoryVault
    from locus_memory.migrations import legacy as legacy_mod

    env = legacy_env
    migrator = env.migrator("m1")
    migrator.prepare_shadow()
    guard = env.control.writer_guard(env.admin.partition.partition_id, "memories", "legacy")
    vault = LegacyMemoryVault(env.legacy, key=LEGACY_KEY, write_guard=guard)
    row = next(r for r in vault.raw_rows() if r["id"] == TARGET)
    snapshot = {k: row[k] for k in row.keys()}
    with raw_db(env.legacy) as conn:
        conn.execute("DELETE FROM memories WHERE id=?", (TARGET,))
    report = legacy_mod.LegacyImporter(env.engine, env.admin, env.legacy, LEGACY_KEY, env.mapping).run()
    assert report["deleted_in_legacy"] == 1
    with pytest.raises(NotFound):
        env.engine.get(env.admin, TARGET)
    with raw_db(env.legacy) as conn:  # the same id written again in the legacy store
        columns = ",".join(snapshot)
        conn.execute(f"INSERT INTO memories({columns}) VALUES({','.join('?' * len(snapshot))})",
                     tuple(snapshot.values()))
    again = legacy_mod.LegacyImporter(env.engine, env.admin, env.legacy, LEGACY_KEY, env.mapping).run()
    assert again.get("imported") == 1
    assert env.engine.get(env.admin, TARGET).id == TARGET
    env.reopen()  # reconcile does not mistake it for a resurrected forgotten record
    assert env.engine.get(env.admin, TARGET).id == TARGET


# =========================================================================== R4-TAMPER-5
def _ext_engine(make_engine, clock, ext):
    from test_providers import _external_setup

    return _external_setup(make_engine, clock, ext)


def _synced(make_engine, clock, ext, access, text):
    from test_providers import hub_of

    engine = _ext_engine(make_engine, clock, ext)
    record = engine.remember(access, RememberRequest(content=text, scope=PROJ_A)).record
    assert hub_of(engine, access).sync_external(access, "ext")["confirmed"] == 1
    return engine, record


def test_tamper5_deleted_replica_mapping_never_cancels_the_external_deletion(make_engine, clock, root,
                                                                            user_access):
    from locus_memory.providers.fake import FakeExternalMemory
    from test_providers import hub_of

    ext = FakeExternalMemory("ext", clock=clock)
    engine, record = _synced(make_engine, clock, ext, user_access, "SECRET replicated externally")
    engine.close()
    with raw_db(db_path(root, user_access)) as conn:
        assert conn.execute("DELETE FROM provider_sync").rowcount == 1
    engine = _ext_engine(make_engine, clock, ext)
    receipt = engine.forget(user_access, ForgetTarget("memory", record.id))
    assert len(receipt.pending_external) == 1
    assert hub_of(engine, user_access).process_outbox(user_access)["confirmed"]
    assert ext.items == {}


def test_tamper5_reconcile_deletes_unmapped_replicas_of_forgotten_records(make_engine, clock, root, user_access):
    from locus_memory.providers.fake import FakeExternalMemory
    from test_providers import hub_of

    ext = FakeExternalMemory("ext", clock=clock)
    engine, record = _synced(make_engine, clock, ext, user_access, "SECRET after-forget both tables")
    engine.forget(user_access, ForgetTarget("memory", record.id))
    engine.close()
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("DELETE FROM provider_sync")
        conn.execute("DELETE FROM provider_outbox")
    ext.items["x-not-ours"] = {"content": "another partition's replica"}
    engine = _ext_engine(make_engine, clock, ext)
    hub = hub_of(engine, user_access)
    report = hub.reconcile_external(user_access, "ext")
    assert report.get("forgotten_refused") == 1 and report.get("unknown_ignored") == 1
    assert hub.process_outbox(user_access)["confirmed"]
    assert list(ext.items) == ["x-not-ours"]  # refs matching nothing local are never deleted


def test_tamper5_forget_after_restoring_a_pre_sync_backup_deletes_the_replica(make_engine, clock, root,
                                                                             user_access, tmp_path):
    from locus_memory.providers.fake import FakeExternalMemory
    from test_providers import hub_of

    ext = FakeExternalMemory("ext", clock=clock)
    engine = _ext_engine(make_engine, clock, ext)
    record = engine.remember(user_access, RememberRequest(content="SECRET restored-backup case", scope=PROJ_A)).record
    engine.close()
    backup = tmp_path / "pre-sync.sqlite3"
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    shutil.copy(db_path(root, user_access), backup)
    engine = _ext_engine(make_engine, clock, ext)
    assert hub_of(engine, user_access).sync_external(user_access, "ext")["confirmed"] == 1
    engine.close()
    _restore(backup, db_path(root, user_access))
    engine = _ext_engine(make_engine, clock, ext)
    receipt = engine.forget(user_access, ForgetTarget("memory", record.id))
    assert receipt.pending_external
    hub_of(engine, user_access).process_outbox(user_access)
    assert ext.items == {}


def test_tamper5_never_approved_records_queue_no_external_deletion(make_engine, clock, user_access):
    from locus_memory.providers.fake import FakeExternalMemory

    ext = FakeExternalMemory("ext", clock=clock)
    engine = _ext_engine(make_engine, clock, ext)
    candidate = engine.propose(user_access, CandidateProposal(
        content="never approved", scope=PROJ_A, sources=(SourceRef(SourceKind.DOCUMENT, "doc-n"),))).record
    receipt = engine.forget(user_access, ForgetTarget("memory", candidate.id))
    assert receipt.pending_external == ()


def test_tamper2_a_stripped_scope_index_fails_closed_instead_of_serving(make_engine, root, user_access, clock):
    from locus_memory.errors import IntegrityError
    from locus_memory.models import IngestionEvent

    engine = make_engine()
    rec = engine.remember(user_access, RememberRequest(content="PROJA-SECRET eta", scope=PROJ_A)).record
    engine.ingest_event(user_access, IngestionEvent(event_id="ev-2", session_ref="sess-b", sequence=0, role="user",
                                                    text="HISTSECRET theta", occurred_at=clock(), scope=PROJ_A))
    _strip(root, user_access, "DELETE FROM record_scopes WHERE record_id=?", (rec.id,))
    with pytest.raises(IntegrityError):  # the index no longer says what the authenticated scope says
        engine.list(user_access)
    _strip(root, user_access, "DELETE FROM history_session_scopes")
    with pytest.raises(IntegrityError):
        engine.search_history(user_access, "HISTSECRET")


def test_eg1_a_repository_forget_reaching_hidden_citers_needs_admin(eg1_repo):
    import dataclasses

    from locus_memory.errors import AccessDenied
    from locus_memory.models import Actor as _Actor

    engine, _, user, _teammate, blob, _ = eg1_repo
    owner = access_for(repositories=("repo-a",), projects=("open", "secret"))
    citer = engine.propose(owner, CandidateProposal(content="secret project restates internal.corp.example",
                                                    sources=(SourceRef(SourceKind.BLOB_RANGE, f"repo-a:{blob}"),),
                                                    scope=Scope.of(project="secret"), proposer="agent-x")).record
    ctx = engine.partition_context(user.partition)
    with ctx.partition.db.write() as conn:  # stored by an earlier build: outside the repository scope
        ctx.services.core.write_internal(conn, dataclasses.replace(citer, revision=citer.revision + 1,
                                                                   scope=Scope.of(project="secret")),
                                         change="source_forgotten", actor=_Actor.SYSTEM, expected=citer.revision)
    no_admin = access_for(repositories=("repo-a",), projects=("open",),
                          operations={Operation.READ, Operation.FORGET, Operation.WRITE})
    with pytest.raises(AccessDenied):
        engine.forget(no_admin, ForgetTarget("repository", "repo-a"))
    engine.forget(owner, ForgetTarget("repository", "repo-a"))  # the owner (admin) may
    with ctx.partition.db.read() as conn:
        assert ctx.records.get(conn, citer.id) is None
