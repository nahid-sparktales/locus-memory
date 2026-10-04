"""Forgetting: targets, derived cascades, suppression, crash/replay, restore and ledger integrity."""
from __future__ import annotations

import shutil

import pytest

from conftest import access_for
from foundation_support import count, db_path, ledger_path, raw_db
from locus_memory.errors import (
    AccessDenied,
    IntegrityError,
    NotFound,
    ReconciliationRequired,
    StaleDerivation,
    SuppressedError,
    ValidationError,
)
from locus_memory.forgetting import ForgettingService
from locus_memory.host import HostCapabilities
from locus_memory.models import (
    CandidateProposal,
    Correction,
    ForgetPolicy,
    ForgetTarget,
    IngestionEvent,
    Lifecycle,
    MemoryKind,
    Operation,
    RememberRequest,
    Scope,
    SourceKind,
    SourceRef,
    StatementBasis,
)
from locus_memory.storage.ledger import MemoryLedgerMirror

PROJ_A, PROJ_B = Scope.of(project="proj-a"), Scope.of(project="proj-b")
DOC1, DOC2 = SourceRef(SourceKind.DOCUMENT, "doc-1"), SourceRef(SourceKind.DOCUMENT, "doc-2")
NO_ADMIN = frozenset(Operation) - {Operation.ADMIN}


def remember(engine, access, content, scope=PROJ_A, **kw):
    return engine.remember(access, RememberRequest(content=content, scope=scope, **kw)).record


def propose(engine, access, content, scope=PROJ_A, sources=(DOC1,), **kw):
    return engine.propose(access, CandidateProposal(content=content, sources=sources, scope=scope, **kw)).record


def gone(engine, access, record_id) -> bool:
    try:
        engine.get(access, record_id)
    except NotFound:
        return True
    return False


class _Crash(RuntimeError):
    pass


def crash_apply(monkeypatch):
    """Simulate a crash after the ledger append, before the main database applies the tombstone."""
    def boom(self, *args, **kwargs):
        raise _Crash("power lost")

    monkeypatch.setattr(ForgettingService, "apply_tombstone", boom)


def restore_file(backup, path):
    for suffix in ("-wal", "-shm"):
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    shutil.copy(backup, path)


# ============================================================================ targets
def test_forget_memory_purges_payloads_and_records_a_tombstone(engine, root, user_access):
    record = remember(engine, user_access, "forget me", sources=(DOC1,))
    engine.correct(user_access, record.id, Correction(content="forget me too"), expected_revision=1)
    keep = remember(engine, user_access, "keep me")
    receipt = engine.forget(user_access, ForgetTarget("memory", record.id))
    assert receipt.deleted == {"memories": 1, "revisions": 2}
    assert receipt.deletion_generation == 1 and receipt.receipt.status == "ok"
    assert receipt.suppressed_sources >= 1
    assert gone(engine, user_access, record.id)
    assert [r.id for r in engine.list(user_access)] == [keep.id]
    path = db_path(root, user_access)
    assert count(path, "SELECT COUNT(*) FROM record_revisions WHERE record_id=?", (record.id,)) == 0
    assert count(path, "SELECT COUNT(*) FROM tombstones WHERE target_kind='memory' AND target_token=?",
                 (record.id,)) == 1
    with raw_db(ledger_path(root, user_access)) as conn:
        rows = conn.execute("SELECT generation, target_kind, target_token FROM ledger").fetchall()
    assert [tuple(r) for r in rows] == [(1, "memory", record.id)]
    assert engine.status(user_access).deletion_generation == 1
    with pytest.raises(NotFound):  # forgetting again is indistinguishable from a missing id
        engine.forget(user_access, ForgetTarget("memory", record.id))


def test_retrying_a_successful_forget_returns_its_receipt(engine, user_access):
    record = remember(engine, user_access, "forget once")
    first = engine.forget(user_access, ForgetTarget("memory", record.id), idempotency_key="f-1")
    again = engine.forget(user_access, ForgetTarget("memory", record.id), idempotency_key="f-1")
    assert again.receipt.idempotent_replay and again.receipt.receipt_id == first.receipt.receipt_id
    assert again.deleted == first.deleted and again.deletion_generation == first.deletion_generation
    assert engine.status(user_access).deletion_generation == 1  # no second deletion happened
    with pytest.raises(AccessDenied):  # the replay path still requires a forget-capable user
        engine.forget(access_for(actor="agent", projects=("proj-a",)), ForgetTarget("memory", record.id),
                      idempotency_key="f-1")


def test_forget_source_keeps_independently_evidenced_memories(engine, root, user_access):
    only = remember(engine, user_access, "only from doc 1", sources=(DOC1,))
    both = remember(engine, user_access, "from doc 1 and doc 2", sources=(DOC1, DOC2))
    engine.correct(user_access, both.id, Correction(title="retitled"), expected_revision=1)
    candidate = propose(engine, user_access, "candidate from doc 1 and 2", sources=(DOC1, DOC2))
    receipt = engine.forget(user_access, ForgetTarget("source", DOC1.identity()))
    assert gone(engine, user_access, only.id) and gone(engine, user_access, candidate.id)
    kept = engine.get(user_access, both.id)
    assert DOC1 not in kept.sources and DOC2 in kept.sources
    assert receipt.retained_by_policy == {"memories_with_other_evidence": 1}
    # History of the kept memory no longer holds payloads that cite the forgotten source.
    path = db_path(root, user_access)
    with raw_db(path) as conn:
        rows = conn.execute("SELECT revision, purged, ciphertext FROM record_revisions WHERE record_id=?"
                            " ORDER BY revision", (both.id,)).fetchall()
    assert [(r[0], r[1], r[2] is None) for r in rows] == [(1, 1, True), (2, 1, True), (3, 0, False)]
    assert engine.explain(user_access, both.id)["revisions"][0]["purged"] is True
    # Relearning the purged statement from the forgotten source is refused.
    with pytest.raises(SuppressedError):
        propose(engine, user_access, "only from doc 1", sources=(DOC1,))


def test_forget_session_removes_memories_citing_the_session(engine, user_access, clock):
    engine.ingest_event(user_access, IngestionEvent(event_id="e1", session_ref="sess-1", sequence=0, role="user",
                                                    text="I drink tea", occurred_at=clock(), scope=PROJ_A))
    cited = remember(engine, user_access, "drinks tea", sources=(SourceRef(SourceKind.SESSION, "sess-1"),))
    unrelated = remember(engine, user_access, "unrelated")
    receipt = engine.forget(user_access, ForgetTarget("session", "sess-1"))
    assert receipt.deleted.get("memories") == 1
    assert gone(engine, user_access, cited.id) and not gone(engine, user_access, unrelated.id)
    with pytest.raises((SuppressedError, ValidationError)):  # a forgotten session cannot be cited again
        propose(engine, user_access, "drinks tea again", sources=(SourceRef(SourceKind.SESSION, "sess-1"),))


@pytest.mark.parametrize("kind,ref,scope", [
    ("project", "proj-a", PROJ_A),
    ("agent", "agent-1", Scope.of(agent="agent-1")),
    ("repository", "repo-a", Scope.of(repository="repo-a")),
])
def test_forget_scope_value_removes_everything_in_it(engine, kind, ref, scope):
    owner = access_for(projects=("proj-a",), agents=("agent-1",), repositories=("repo-a",), teams=("t1",))
    inside = remember(engine, owner, "inside", scope=scope)
    nested = remember(engine, owner, "nested", scope=Scope((*scope.constraints, ("team", "t1"))))
    outside = remember(engine, owner, "outside", scope=Scope.of(team="t1"))
    with pytest.raises(AccessDenied):  # nested record is outside user_access's grants: admin needed
        engine.forget(access_for(projects=("proj-a",), agents=("agent-1",), repositories=("repo-a",),
                                 operations=NO_ADMIN), ForgetTarget(kind, ref))
    receipt = engine.forget(owner, ForgetTarget(kind, ref))
    assert receipt.deleted["memories"] == 2
    assert gone(engine, owner, inside.id) and gone(engine, owner, nested.id)
    assert not gone(engine, owner, outside.id)


def test_broad_forget_counts_only_what_the_caller_may_see(engine, user_access):
    """With ADMIN everything is deleted; without it, hidden items make the request fail closed."""
    remember(engine, user_access, "visible")
    secret = remember(engine, access_for(projects=("proj-a",), teams=("hidden",)), "hidden",
                      scope=Scope.of(project="proj-a", team="hidden"))
    narrow = access_for(projects=("proj-a",), operations=NO_ADMIN)
    with pytest.raises(AccessDenied) as exc:
        engine.forget(narrow, ForgetTarget("project", "proj-a"))
    assert "1" not in str(exc.value)  # no counts leak through the refusal
    admin = access_for(projects=("proj-a",))
    assert engine.forget(admin, ForgetTarget("project", "proj-a")).deleted["memories"] == 2
    assert gone(engine, access_for(projects=("proj-a",), teams=("hidden",)), secret.id)


def test_forget_requires_grants_actor_and_admin_for_profiles(engine, user_access):
    record = remember(engine, user_access, "x")
    with pytest.raises(AccessDenied):
        engine.forget(user_access, ForgetTarget("project", "proj-z"))
    with pytest.raises(AccessDenied):
        engine.forget(access_for(projects=("proj-a",), operations={Operation.READ}), ForgetTarget("memory", record.id))
    with pytest.raises(AccessDenied):
        engine.forget(access_for(projects=("proj-a",), operations=NO_ADMIN), ForgetTarget("profile", "default"))
    with pytest.raises(AccessDenied):
        engine.forget(user_access, ForgetTarget("profile", "someone-else"))
    host = access_for(actor="host", projects=("proj-a",))
    assert engine.forget(host, ForgetTarget("memory", record.id)).deleted["memories"] == 1


def test_forget_profile_wipes_only_that_partition(engine, root, user_access):
    remember(engine, user_access, "a")
    propose(engine, user_access, "b")
    other = access_for(profile="other")
    survivor = remember(engine, other, "other profile", scope=Scope.global_())
    receipt = engine.forget(user_access, ForgetTarget("profile", "default"))
    assert receipt.deleted["memories"] == 2
    assert engine.status(user_access).counts == {}
    path = db_path(root, user_access)
    for table in ("records", "record_revisions", "record_scopes", "suppressions", "derivations"):
        assert count(path, f"SELECT COUNT(*) FROM {table}") == 0, table
    assert engine.get(other, survivor.id).content == "other profile"
    # Work that observed the pre-wipe state cannot commit afterwards.
    with pytest.raises(SuppressedError):
        propose(engine, user_access, "late derived write", observed_generation=0)


# ============================================================================ derived state
def test_derived_records_follow_their_inputs(engine, user_access):
    a = remember(engine, user_access, "input a")
    b = remember(engine, user_access, "input b")
    candidate = propose(engine, user_access, "candidate from a", derived_from=(a.id,))
    summary = propose(engine, user_access, "summary of a and b", kind=MemoryKind.SUMMARY, derived_from=(a.id, b.id))
    engine.approve(user_access, summary.id, expected_revision=1)
    confirmed = propose(engine, user_access, "user confirmed from a", derived_from=(a.id,),
                        basis=StatementBasis.USER_STATED, sources=(DOC2,))
    engine.approve(user_access, confirmed.id, expected_revision=1)
    receipt = engine.forget(user_access, ForgetTarget("memory", a.id))
    assert gone(engine, user_access, candidate.id)
    assert gone(engine, user_access, summary.id)
    assert summary.id in receipt.regenerate_required  # mixed inputs: b remains, regenerate
    assert not gone(engine, user_access, confirmed.id)
    assert receipt.retained_by_policy == {"user_confirmed_derivations": 1}
    assert receipt.deleted["derived_memories"] == 2
    assert not gone(engine, user_access, b.id)
    # New work derived from the forgotten memory is refused.
    with pytest.raises((SuppressedError, NotFound)):
        propose(engine, user_access, "another from a", derived_from=(a.id,))


def test_memory_cited_as_evidence_is_cascaded(engine, user_access, agent_access):
    parent = remember(engine, user_access, "parent")
    child = propose(engine, agent_access, "child from parent", sources=(SourceRef(SourceKind.MEMORY, parent.id),))
    grandchild = propose(engine, user_access, "grandchild", sources=(SourceRef(SourceKind.MEMORY, child.id), DOC2),
                         derived_from=(child.id,))
    engine.forget(user_access, ForgetTarget("memory", parent.id))
    assert gone(engine, user_access, child.id) and gone(engine, user_access, grandchild.id)


def test_include_derived_false_keeps_derivations(engine, user_access):
    a = remember(engine, user_access, "input")
    candidate = propose(engine, user_access, "derived", derived_from=(a.id,))
    engine.forget(user_access, ForgetTarget("memory", a.id), policy=ForgetPolicy(include_derived=False))
    assert engine.get(user_access, candidate.id).lifecycle == Lifecycle.CANDIDATE
    with pytest.raises(SuppressedError):  # but it can never be approved now
        engine.approve(user_access, candidate.id, expected_revision=1)


def test_receipts_do_not_count_derived_items_outside_the_callers_scope(engine):
    owner = access_for(projects=("proj-a", "proj-b"))
    only_a = access_for(projects=("proj-a",), operations=NO_ADMIN)
    a = remember(engine, owner, "a fact")
    hidden = propose(engine, owner, "b candidate derived from a", scope=PROJ_B, derived_from=(a.id,))
    visible = propose(engine, owner, "a candidate derived from a", derived_from=(a.id,))
    receipt = engine.forget(only_a, ForgetTarget("memory", a.id))
    assert receipt.deleted == {"memories": 1, "revisions": 1, "derived_memories": 1, "derived_revisions": 1}
    assert gone(engine, owner, hidden.id) and gone(engine, owner, visible.id)  # still deleted


# ============================================================================ suppression & staleness
def test_suppression_prevents_relearning_from_the_same_source(engine, user_access):
    record = remember(engine, user_access, "lives in Lisbon", sources=(DOC1,))
    engine.forget(user_access, ForgetTarget("memory", record.id))
    for content in ("lives in Lisbon", "  Lives in LISBON. "):
        with pytest.raises(SuppressedError):
            propose(engine, user_access, content, sources=(DOC1,))
    assert propose(engine, user_access, "lives in Porto", sources=(DOC1,)).lifecycle == Lifecycle.CANDIDATE
    # Explicit suppression opt-out.
    other = remember(engine, user_access, "likes jazz", sources=(DOC2,))
    engine.forget(user_access, ForgetTarget("memory", other.id), policy=ForgetPolicy(suppress_relearning=False))
    assert propose(engine, user_access, "likes jazz", sources=(DOC2,)).lifecycle == Lifecycle.CANDIDATE


def test_work_that_observed_state_before_a_project_forget_is_refused(engine, user_access):
    remember(engine, user_access, "project fact")
    observed = engine.status(user_access).deletion_generation
    engine.forget(user_access, ForgetTarget("project", "proj-a"))
    with pytest.raises(SuppressedError):
        propose(engine, user_access, "derived before the forget", observed_generation=observed)
    after = engine.status(user_access).deletion_generation
    assert propose(engine, user_access, "derived after the forget", observed_generation=after)
    assert propose(engine, user_access, "fresh work")  # no observation: nothing to be stale against
    other_scope = propose(engine, user_access, "other scope", scope=Scope.of(agent="agent-1"),
                          observed_generation=observed)
    assert other_scope.lifecycle == Lifecycle.CANDIDATE


def test_commit_guard_refuses_stale_derived_commits(engine, user_access):
    record = remember(engine, user_access, "input")
    ctx = engine.partition_context(user_access.partition)
    forgetting = ctx.services.forgetting
    observed = engine.status(user_access).deletion_generation
    engine.forget(user_access, ForgetTarget("memory", record.id))
    with ctx.partition.db.write() as conn:
        with pytest.raises(StaleDerivation):
            forgetting.commit_guard(conn, inputs=[("memory", record.id)], observed_deletion_generation=observed)
        forgetting.commit_guard(conn, inputs=[("memory", record.id)],
                                observed_deletion_generation=observed + 1)


# ============================================================================ crash / replay / restore
def test_crash_between_ledger_and_apply_is_repaired_before_serving(make_engine, root, user_access, monkeypatch):
    engine = make_engine()
    record = remember(engine, user_access, "half forgotten")
    crash_apply(monkeypatch)
    with pytest.raises(_Crash):
        engine.forget(user_access, ForgetTarget("memory", record.id))
    monkeypatch.undo()
    assert count(ledger_path(root, user_access), "SELECT COUNT(*) FROM ledger") == 1
    # Same process, no restart: the next call reconciles before serving.
    assert gone(engine, user_access, record.id)
    assert engine.status(user_access).deletion_generation == 1
    engine.close()
    assert gone(make_engine(), user_access, record.id)


def test_crash_then_reopen_applies_the_tombstone_before_serving(make_engine, root, user_access, monkeypatch):
    engine = make_engine()
    record = remember(engine, user_access, "half forgotten")
    crash_apply(monkeypatch)
    with pytest.raises(_Crash):
        engine.forget(user_access, ForgetTarget("memory", record.id))
    monkeypatch.undo()
    engine.close()  # "process exits" without any reconciliation
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM records WHERE id=?", (record.id,)) == 1
    reopened = make_engine()
    assert gone(reopened, user_access, record.id)
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM records WHERE id=?", (record.id,)) == 0


def test_a_crashed_entry_is_not_lost_when_a_later_forget_succeeds(make_engine, root, user_access, monkeypatch):
    engine = make_engine()
    first = remember(engine, user_access, "first")
    second = remember(engine, user_access, "second")
    other = make_engine()  # another process, opened (and reconciled) before the crash
    ctx = other.partition_context(user_access.partition)
    crash_apply(monkeypatch)
    with pytest.raises(_Crash):
        engine.forget(user_access, ForgetTarget("memory", first.id))
    monkeypatch.undo()
    with raw_db(db_path(root, user_access)) as conn:
        assert conn.execute("SELECT value FROM meta WHERE key='deletion_generation'").fetchone()[0] == "0"
    # Its forget runs before anyone reconciles (service call: no engine-level pre-check).
    ctx.services.forgetting.forget(user_access, ForgetTarget("memory", second.id), ForgetPolicy())
    with raw_db(db_path(root, user_access)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM records WHERE id=?", (first.id,)).fetchone()[0] == 0
    other.close()
    engine.close()
    final = make_engine()
    assert gone(final, user_access, first.id) and gone(final, user_access, second.id)
    assert final.status(user_access).deletion_generation == 2


def test_an_unfinished_forget_in_another_process_is_applied_before_serving(make_engine, user_access, monkeypatch):
    reader, writer = make_engine(), make_engine()
    record = remember(writer, user_access, "shared")
    assert reader.get(user_access, record.id)  # reader is open and reconciled
    crash_apply(monkeypatch)
    with pytest.raises(_Crash):
        writer.forget(user_access, ForgetTarget("memory", record.id))
    monkeypatch.undo()
    assert gone(reader, user_access, record.id)


def test_restoring_an_old_database_cannot_resurrect_forgotten_memories(make_engine, root, user_access, tmp_path):
    engine = make_engine()
    record = remember(engine, user_access, "forgotten after the backup")
    survivor = remember(engine, user_access, "kept")
    engine.close()
    backup = tmp_path / "backup.sqlite3"
    shutil.copy(db_path(root, user_access), backup)
    engine = make_engine()
    engine.forget(user_access, ForgetTarget("memory", record.id))
    engine.close()
    restore_file(backup, db_path(root, user_access))
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM records WHERE id=?", (record.id,)) == 1
    restored = make_engine()
    assert gone(restored, user_access, record.id)
    assert [r.id for r in restored.list(user_access)] == [survivor.id]
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM record_revisions WHERE record_id=?",
                 (record.id,)) == 0
    with pytest.raises(SuppressedError):
        propose(restored, user_access, "forgotten after the backup",
                sources=engine_sources(record))


def engine_sources(record):
    return record.sources


def test_restoring_database_and_ledger_against_a_newer_mirror(make_engine, root, user_access, tmp_path, clock):
    mirror = MemoryLedgerMirror()
    host = lambda: HostCapabilities(clock=clock, ledger_mirror=mirror)  # noqa: E731
    engine = make_engine(host=host())
    record = remember(engine, user_access, "forgotten after the backup")
    engine.close()
    backups = {name: tmp_path / name for name in ("db", "ledger")}
    shutil.copy(db_path(root, user_access), backups["db"])
    shutil.copy(ledger_path(root, user_access), backups["ledger"])
    engine = make_engine(host=host())
    engine.forget(user_access, ForgetTarget("memory", record.id))
    engine.close()
    assert mirror.read(user_access.partition.partition_id)[0] == 1
    restore_file(backups["db"], db_path(root, user_access))
    restore_file(backups["ledger"], ledger_path(root, user_access))
    with pytest.raises(ReconciliationRequired) as exc:
        make_engine(host=host()).get(user_access, record.id)
    assert exc.value.details == {"known_generation": 1, "local_generation": 0}
    with pytest.raises(AccessDenied):
        make_engine(host=host()).reconcile(access_for(projects=("proj-a",), operations=NO_ADMIN),
                                           acknowledge_mirror_gap=True)
    # An operator explicitly accepts the gap; the decision is durable.
    engine = make_engine(host=host())
    report = engine.reconcile(user_access, acknowledge_mirror_gap=True)
    assert report["acknowledged_gap"] == {"known_generation": 1, "local_generation": 0}
    engine.close()
    reopened = make_engine(host=host())
    assert reopened.status(user_access).deletion_generation >= 1
    assert reopened.reconcile(user_access)["reapplied"] == 0


@pytest.mark.parametrize("tamper", [
    "UPDATE ledger SET target_token='m-other' WHERE generation=1",
    "UPDATE ledger SET target_kind='source' WHERE generation=1",
    "UPDATE ledger SET created_at=created_at+1 WHERE generation=1",
    "UPDATE ledger SET policy='{}' WHERE generation=2",
    "DELETE FROM ledger WHERE generation=1",
    "UPDATE ledger SET mac=(SELECT mac FROM ledger WHERE generation=1) WHERE generation=2",
])
def test_ledger_tampering_is_detected_on_open(make_engine, root, user_access, tamper):
    engine = make_engine()
    first = remember(engine, user_access, "one")
    second = remember(engine, user_access, "two")
    engine.forget(user_access, ForgetTarget("memory", first.id))
    engine.forget(user_access, ForgetTarget("memory", second.id), policy=ForgetPolicy(include_derived=False))
    engine.close()
    with raw_db(ledger_path(root, user_access)) as conn:
        conn.execute(tamper)
    with pytest.raises(IntegrityError):
        make_engine().status(user_access)


def test_a_rolled_back_ledger_is_rebuilt_from_the_store(make_engine, root, user_access, tmp_path):
    engine = make_engine()
    record = remember(engine, user_access, "x")
    engine.close()
    backup = tmp_path / "ledger"
    shutil.copy(ledger_path(root, user_access), backup)
    engine = make_engine()
    engine.forget(user_access, ForgetTarget("memory", record.id), policy=ForgetPolicy(delete_source_archive=True))
    engine.close()
    restore_file(backup, ledger_path(root, user_access))
    engine = make_engine()
    assert gone(engine, user_access, record.id)
    with raw_db(ledger_path(root, user_access)) as conn:
        rows = conn.execute("SELECT generation, target_kind, target_token, policy FROM ledger").fetchall()
    assert [(r[0], r[1], r[2]) for r in rows] == [(1, "memory", record.id)]
    assert '"delete_source_archive":true' in rows[0][3]


def test_replay_applies_the_policy_the_user_chose(make_engine, root, user_access, monkeypatch, clock):
    engine = make_engine()
    a = remember(engine, user_access, "input")
    derived = propose(engine, user_access, "derived", derived_from=(a.id,))
    receipt = engine.ingest_event(user_access, IngestionEvent(
        event_id="e1", session_ref="s1", sequence=0, role="user", text="transcript line",
        occurred_at=clock(), scope=PROJ_A))
    message_source = f"message:{receipt.message_id}"
    path = db_path(root, user_access)
    assert count(path, "SELECT COUNT(*) FROM history_messages") == 1
    crash_apply(monkeypatch)
    with pytest.raises(_Crash):
        engine.forget(user_access, ForgetTarget("memory", a.id), policy=ForgetPolicy(include_derived=False))
    monkeypatch.undo()
    engine.close()
    replayed = make_engine()
    assert gone(replayed, user_access, a.id)
    assert replayed.get(user_access, derived.id).lifecycle == Lifecycle.CANDIDATE  # include_derived=False
    crash_apply(monkeypatch)
    with pytest.raises(_Crash):
        replayed.forget(user_access, ForgetTarget("source", message_source),
                        policy=ForgetPolicy(delete_source_archive=True))
    monkeypatch.undo()
    replayed.close()
    assert count(path, "SELECT COUNT(*) FROM history_messages") == 1
    final = make_engine()
    assert final.status(user_access).deletion_generation == 2
    assert count(path, "SELECT COUNT(*) FROM history_messages") == 0  # delete_source_archive=True


def test_deletion_generation_never_moves_backwards(engine, root, user_access):
    records = [remember(engine, user_access, f"r{i}") for i in range(3)]
    ctx = engine.partition_context(user_access.partition)
    # Another writer appended (and will apply) a later generation first.
    ctx.partition.ledger.append([("memory", "m-elsewhere")])
    for record in records:
        engine.forget(user_access, ForgetTarget("memory", record.id))
    with raw_db(ledger_path(root, user_access)) as conn:
        head = conn.execute("SELECT MAX(generation) FROM ledger").fetchone()[0]
    assert engine.status(user_access).deletion_generation == head == 4
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM tombstones") == 4


# ============================================================================ damaged rows & grants
def test_damaged_records_can_still_be_forgotten(engine, root, user_access):
    damaged = remember(engine, user_access, "tampered later")
    intact = remember(engine, user_access, "intact")
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("UPDATE records SET lifecycle='stale' WHERE id=?", (damaged.id,))
    with pytest.raises(IntegrityError):
        engine.get(user_access, damaged.id)  # never served ...
    receipt = engine.forget(user_access, ForgetTarget("memory", damaged.id))  # ... but always deletable
    assert receipt.deleted["unreadable_memories"] == 1 and receipt.deleted["memories"] == 1
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM records WHERE id=?", (damaged.id,)) == 0
    assert [r.id for r in engine.list(user_access)] == [intact.id]
    hidden = remember(engine, access_for(projects=("proj-b",)), "b", scope=PROJ_B)
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("UPDATE records SET lifecycle='stale' WHERE id=?", (hidden.id,))
    with pytest.raises(NotFound):  # out-of-scope damaged rows stay hidden (SQL scope index)
        engine.forget(user_access, ForgetTarget("memory", hidden.id))
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM records WHERE id=?", (hidden.id,)) == 1


def test_profile_wipe_is_not_blocked_by_a_damaged_row(engine, root, user_access):
    remember(engine, user_access, "fine")
    bad = remember(engine, user_access, "damaged")
    with raw_db(db_path(root, user_access)) as conn:
        conn.execute("UPDATE records SET ciphertext=zeroblob(64) WHERE id=?", (bad.id,))
    receipt = engine.forget(user_access, ForgetTarget("profile", "default"))
    assert receipt.deleted["memories"] == 2 and receipt.deleted["unreadable_memories"] == 1
    assert count(db_path(root, user_access), "SELECT COUNT(*) FROM records") == 0


def test_admin_does_not_widen_grants_for_source_forgets(engine, user_access):
    remember(engine, user_access, "cited", sources=(DOC1,))
    outsider_admin = access_for(projects=("proj-b",))  # every operation, including ADMIN
    assert Operation.ADMIN in outsider_admin.operations
    with pytest.raises(AccessDenied):
        engine.forget(outsider_admin, ForgetTarget("source", DOC1.identity()))
    assert len(engine.list(user_access)) == 1
