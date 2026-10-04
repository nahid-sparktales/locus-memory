"""Regression tests for review round 3, batch 1 (reproduced defects).

R3-MF-1  a rollback kept, in the authoritative legacy store, a record it had just written back when a
         late or post-crash forget removed it by cascade or with its (session/source) evidence.
R3-MF-2  removing a record by cascade, or by a session/source forget, never processed the records
         citing it, so their derived statements of forgotten content stayed served.
R3-MF-3  a re-migration re-imported a written-back record that a cascade had removed while legacy was
         authoritative, as a fresh "legacy" record without provenance.
R3-EG-1  interchange-imported observations and summaries were never hidden, purged or staled when
         their path was excluded or the file changed (they kept reaching context and egress).
R3-EG-2  extract_candidates trusted the caller's data_class label: transcript and repository-source
         evidence reached egress extractors under a memory_text grant, and invented text could be
         cited to a real message.
R3-RG-1  scope and profile forgets could be undone by editing the legacy row's unauthenticated
         created_at column.
R3-API-1 a forget whose policy was not a ForgetPolicy wrote an undecodable ledger entry and made
         the partition permanently unusable.
R3-MF-4  a crash or commit failure between the rollback's ownership transition and its package commit
         left legacy authoritative with no adoption and no watermark (resume was a no-op, every
         re-migration was refused).

Each test reproduces the report's scenario and asserts the correct outcome. All data lives in
pytest tmp dirs (the legacy vault is a copy of tests/fixtures/locus_legacy).
"""
from __future__ import annotations

import dataclasses
import secrets
import shutil
import sqlite3
import threading
import time
from pathlib import Path

import pytest

import test_review_group1 as group1
from conftest import FakeClock, access_for
from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.errors import (
    ConsentRequired,
    MigrationError,
    NotFound,
    StorageFull,
    ValidationError,
)
from locus_memory.forgetting import _LEGACY_AUTHORITY, _ROLLBACK_PENDING
from locus_memory.host import HostCapabilities
from locus_memory.migrations import legacy as legacy_mod
from locus_memory.migrations.cutover import Migrator, SimulatedCrash
from locus_memory.migrations.state import OwnershipControl
from locus_memory.models import (
    Actor,
    CandidateProposal,
    ContextRequest,
    Correction,
    ForgetPolicy,
    ForgetTarget,
    IngestionEvent,
    Lifecycle,
    MemoryKind,
    Operation,
    Query,
    RememberRequest,
    Scope,
    SourceKind,
    SourceRef,
)
from locus_memory.providers.base import (
    DATA_MEMORY_TEXT,
    DATA_REPOSITORY_SOURCE,
    DATA_TRANSCRIPTS,
    ConsentGrant,
    StaticConsentPolicy,
)
from locus_memory.providers.fake import FakeExternalMemory, FakeExtractor
from locus_memory.repository import interchange as ix
from test_repository import GIT, commit_all, git, make_repo
from test_review_group1 import AGENT, IDS, KEY, OTHER, WS, _cut_over, _legacy_ids, _migrator

# Shared migration fixtures (a copy of the legacy fixture vault, its mapping, an admin context, the
# ownership control and an engine wired to it), registered here under the same names.
admin = group1.admin
control = group1.control
legacy_db = group1.legacy_db
mapping = group1.mapping
menv = group1.menv

PROJ_A = Scope.of(project="proj-a")
AGENT_A = access_for(actor=Actor.AGENT, projects=("proj-a",), operations={Operation.READ, Operation.PROPOSE})
needs_git = pytest.mark.skipif(GIT is None, reason="git is required for repository memory tests")


def _gone(engine, access, record_id: str) -> bool:
    try:
        engine.get(access, record_id)
    except NotFound:
        return True
    return False


def _approved_proposal(engine, access, content, sources, derived_from=(), *, scope=PROJ_A, proposer=AGENT_A):
    proposed = engine.propose(proposer, CandidateProposal(content=content, scope=scope, sources=tuple(sources),
                                                          derived_from=tuple(derived_from))).record
    return engine.approve(access, proposed.id, expected_revision=proposed.revision).record


def _ingest(engine, access, session, seq, text, scope, clock):
    return engine.ingest_event(access, IngestionEvent(
        event_id=f"{session}-e{seq}", session_ref=session, sequence=seq, role="user", text=text,
        occurred_at=clock(), scope=scope))


def _tombstoned(engine, access, record_id: str) -> bool:
    ctx = engine.partition_context(access.partition)
    with ctx.partition.db.read() as conn:
        return ctx.services.forgetting.tombstone_generation(conn, "memory", record_id) is not None


# =========================================================================== R3-MF-1
def _derived_pair(engine, admin):
    m1 = engine.remember(admin, RememberRequest(content="Alice's salary review is on the 3rd", scope=PROJ_A)).record
    derived = _approved_proposal(engine, admin, "Alice's salary review derivation",
                                 (SourceRef(SourceKind.MEMORY, m1.id),), (m1.id,))
    assert derived.links.derived_from == (m1.id,)
    return m1, derived


def _session_record(engine, admin, clock):
    _ingest(engine, admin, "sess-x", 0, "Bob asked for a raise", PROJ_A, clock)
    return _approved_proposal(engine, admin, "Bob is negotiating a raise", (SourceRef(SourceKind.SESSION, "sess-x"),))


@pytest.mark.parametrize("crash_point", ["after_reverse_sync", "before_rollback_complete"])
@pytest.mark.parametrize("forget", ["memory_cascade", "session_evidence"])
def test_mf1_a_forget_between_a_crashed_rollback_and_resume_reaches_the_legacy_copy(
        menv, control, admin, legacy_db, mapping, tmp_path, clock, crash_point, forget):
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    if forget == "memory_cascade":
        m1, victim = _derived_pair(menv, admin)
        target = ForgetTarget("memory", m1.id)
    else:
        m1, victim = None, _session_record(menv, admin, clock)
        target = ForgetTarget("session", "sess-x")  # the default ForgetPolicy
    migrator.crash_at = crash_point
    with pytest.raises(SimulatedCrash):
        migrator.rollback(allow_partial=True)  # archived history is not representable in legacy
    assert migrator.state().state == "rollback_in_progress"
    assert victim.id in _legacy_ids(legacy_db)  # the legacy write committed on its own

    receipt = menv.forget(admin, target)
    assert _gone(menv, admin, victim.id)

    migrator.crash_at = None
    result = migrator.resume()
    assert result["state"] == "legacy_authoritative"
    assert victim.id not in _legacy_ids(legacy_db)
    assert not result["counts"].get("legacy_only_kept")
    if m1 is not None:
        assert m1.id not in _legacy_ids(legacy_db)
    assert not [item for item in LegacyMemoryVault(legacy_db, key=KEY).list(workspace=WS)
                if item.get("id") == victim.id]
    # A later re-migration finds nothing to import for it.
    again = _migrator(menv, control, admin, legacy_db, mapping, tmp_path / "again")
    assert again.prepare_shadow()["state"] == "shadow_prepared"
    assert _gone(menv, admin, victim.id)
    # Honest receipt: until the rollback was resumed the legacy file still held the copy.
    assert _ROLLBACK_PENDING in receipt.receipt.limitations
    assert _LEGACY_AUTHORITY not in receipt.receipt.limitations


def test_mf1_a_late_forget_applied_by_the_final_pass_removes_the_written_back_derivation(
        menv, control, admin, legacy_db, mapping, tmp_path, monkeypatch):
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    m1, derived = _derived_pair(menv, admin)
    partition = menv.partition_context(admin.partition).partition
    original = Migrator._checkpoint_legacy
    box: dict = {}

    def checkpoint_with_concurrent_forget(self):
        if "thread" not in box:
            head = partition.ledger.head()[0]
            thread = threading.Thread(target=lambda: box.setdefault(
                "receipt", menv.forget(admin, ForgetTarget("memory", m1.id))))
            box["thread"] = thread
            thread.start()
            deadline = time.monotonic() + 10
            while partition.ledger.head()[0] == head and time.monotonic() < deadline:
                time.sleep(0.01)  # the ledger entry is durable; the forget waits for the store lock
            box["appended"] = partition.ledger.head()[0] != head
        return original(self)

    monkeypatch.setattr(Migrator, "_checkpoint_legacy", checkpoint_with_concurrent_forget)
    result = migrator.rollback()
    box["thread"].join(30)
    assert box.get("appended")
    assert result["state"] == "legacy_authoritative"
    assert _gone(menv, admin, m1.id) and _gone(menv, admin, derived.id)
    assert not {m1.id, derived.id} & _legacy_ids(legacy_db)
    assert not result["counts"].get("legacy_only_kept")
    limitations = box["receipt"].receipt.limitations
    assert _LEGACY_AUTHORITY not in limitations and _ROLLBACK_PENDING not in limitations  # really applied


# =========================================================================== R3-MF-2
USER_P = access_for(projects=("p", "q"), operations=set(Operation))
AGENT_PQ = access_for(actor=Actor.AGENT, projects=("p", "q"), operations={Operation.READ, Operation.PROPOSE})
P = Scope.of(project="p")


def _served(engine, record_id, text):
    """Every read path that could still serve ``record_id``."""
    where = {"get": not _gone(engine, USER_P, record_id)}
    where["search"] = record_id in [h.record.id for h in engine.search(USER_P, Query(text=text)).hits]
    where["list"] = record_id in [r.id for r in engine.list(USER_P)]
    packet = engine.build_context(USER_P, ContextRequest(token_allowance=4000, query=text))
    where["context"] = record_id in [i.record_id for i in packet.items]
    return {k: v for k, v in where.items() if v}


def _p_proposal(engine, content, sources, derived_from=(), scope=P):
    return _approved_proposal(engine, USER_P, content, sources, derived_from, scope=scope, proposer=AGENT_PQ)


def _cites(record_id):
    return (SourceRef(SourceKind.MEMORY, record_id),)


def test_mf2_a_citer_of_a_cascade_removed_record_is_removed(engine):
    y = engine.remember(USER_P, RememberRequest(content="Carol's divorce hearing is on May 9", scope=P)).record
    a = _p_proposal(engine, "Carol has a court date in May", _cites(y.id), (y.id,))
    b = _p_proposal(engine, "Carol may be unavailable mid May", _cites(a.id))
    assert b.extra.get("basis_attested_by") == "agent"
    receipt = engine.forget(USER_P, ForgetTarget("memory", y.id))
    assert _gone(engine, USER_P, a.id)
    assert _served(engine, b.id, "unavailable mid May") == {}
    assert receipt.deleted.get("memories", 0) + receipt.deleted.get("derived_memories", 0) == 3
    # Both removed records are remembered as forgotten (later citations and imports are refused).
    assert _tombstoned(engine, USER_P, a.id) and _tombstoned(engine, USER_P, b.id)


def test_mf2_a_citation_chain_of_any_depth_is_followed(engine):
    y = engine.remember(USER_P, RememberRequest(content="Carol's divorce hearing is on May 9", scope=P)).record
    chain = [y]
    for i in range(6):
        chain.append(_p_proposal(engine, f"Carol inference level {i} about May", _cites(chain[-1].id)))
    engine.forget(USER_P, ForgetTarget("memory", y.id))
    for record in chain:
        assert _gone(engine, USER_P, record.id)


@pytest.mark.parametrize("how", ["session", "source", "scope"])
def test_mf2_citers_of_a_record_removed_by_a_session_source_or_scope_forget_go_too(engine, clock, how):
    receipt_in = engine.ingest_event(USER_P, IngestionEvent(
        event_id="e0", session_ref="sess-1", sequence=0, role="user", text="Erin is moving to Berlin in July",
        occurred_at=clock(), scope=P))
    if how == "session":
        a = _p_proposal(engine, "Erin relocates to Berlin", (SourceRef(SourceKind.SESSION, "sess-1"),))
        target = ForgetTarget("session", "sess-1")
    elif how == "source":
        a = _p_proposal(engine, "Erin relocates to Berlin", (SourceRef(SourceKind.MESSAGE, receipt_in.message_id),))
        target = ForgetTarget("source", f"message:{receipt_in.message_id}")
    else:
        a = _p_proposal(engine, "Erin relocates to Berlin", (SourceRef(SourceKind.SESSION, "sess-1"),))
        target = ForgetTarget("project", "p")
    b = _p_proposal(engine, "Erin will be in the CET timezone", _cites(a.id))
    c = _p_proposal(engine, "Erin's standups move to CET mornings", _cites(b.id))
    engine.forget(USER_P, target)
    assert _gone(engine, USER_P, a.id)
    for record in (b, c):
        assert _served(engine, record.id, "CET") == {}, how


def test_mf2_an_attested_citer_with_independent_evidence_keeps_its_other_source(engine):
    y = engine.remember(USER_P, RememberRequest(content="Carol's divorce hearing is on May 9", scope=P)).record
    other = engine.remember(USER_P, RememberRequest(content="Carol takes leave in mid May", scope=P)).record
    a = _p_proposal(engine, "Carol has a court date in May", _cites(y.id), (y.id,))
    b = _p_proposal(engine, "Carol is away mid May", (*_cites(a.id), *_cites(other.id)))
    # The user restates it in their own words: the basis is now attested by the user.
    b = engine.correct(USER_P, b.id, Correction(content="Carol is away in mid May"),
                       expected_revision=b.revision).record
    receipt = engine.forget(USER_P, ForgetTarget("memory", y.id))
    assert _gone(engine, USER_P, a.id)
    kept = engine.get(USER_P, b.id)
    cited = {s.identity() for s in kept.sources}
    assert f"memory:{other.id}" in cited and f"memory:{a.id}" not in cited  # the forgotten citation is dropped
    assert receipt.retained_by_policy.get("memories_with_other_evidence") == 1


# =========================================================================== R3-MF-3
def test_mf3_remigration_never_reimports_a_cascade_removed_written_back_record(
        menv, control, admin, legacy_db, mapping, tmp_path):
    first = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    m1 = menv.remember(admin, RememberRequest(content="Bob's performance review flagged a layoff risk",
                                              scope=PROJ_A)).record
    derived = _approved_proposal(menv, admin, "Bob is being let go next quarter (inferred)",
                                 _cites(m1.id), (m1.id,))
    assert first.rollback()["state"] == "legacy_authoritative"
    assert {m1.id, derived.id} <= _legacy_ids(legacy_db)
    assert menv.get(admin, derived.id).extra.get("legacy_round_trip")

    receipt = menv.forget(admin, ForgetTarget("memory", m1.id))  # legacy is authoritative again
    assert _LEGACY_AUTHORITY in receipt.receipt.limitations
    assert _gone(menv, admin, derived.id)
    assert _tombstoned(menv, admin, derived.id)  # the cascade is remembered

    second = _migrator(menv, control, admin, legacy_db, mapping, tmp_path / "second")
    imported = second.prepare_shadow()["import"]
    assert imported.get("imported", 0) == 0 and imported.get("skipped_forgotten") == 2
    validated = second.validate()
    assert validated["validated"] and validated["verify"]["missing"] == 0
    assert second.cutover()["state"] == "package_authoritative"
    assert _gone(menv, admin, derived.id) and _gone(menv, admin, m1.id)
    # The receipt's promise holds for the cascade too: the next cutover removed both legacy copies.
    assert not {m1.id, derived.id} & _legacy_ids(legacy_db)


def test_mf3_an_imported_record_removed_with_its_evidence_is_never_reimported(
        menv, control, admin, legacy_db, mapping, tmp_path, clock):
    # The plain-legacy path (no cutover yet): a legacy candidate learned in a session is imported by
    # the shadow sync; forgetting that session (without relearning suppression) removes it as
    # evidence-dependent. Nothing but the removal itself can keep the importer from bringing the
    # still-present legacy row back.
    writer = LegacyMemoryVault(legacy_db, key=KEY, clock=clock)
    row = writer.save({"content": "Deploy freeze starts on Friday", "scope": "workspace", "status": "candidate",
                       "source_session_id": "sess-9"}, workspace=WS, agent_id=AGENT)
    legacy_mod.LegacyImporter(menv, admin, legacy_db, KEY, mapping).run()  # Stage-2 shadow sync
    assert menv.get(admin, row["id"]).lifecycle == Lifecycle.CANDIDATE
    receipt = menv.forget(admin, ForgetTarget("session", "sess-9"), policy=ForgetPolicy(suppress_relearning=False))
    assert _LEGACY_AUTHORITY in receipt.receipt.limitations
    assert _gone(menv, admin, row["id"]) and _tombstoned(menv, admin, row["id"])
    again = legacy_mod.LegacyImporter(menv, admin, legacy_db, KEY, mapping).run()
    assert again.get("imported", 0) == 0 and _gone(menv, admin, row["id"])
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    assert migrator.prepare_shadow()["import"].get("imported", 0) == 0
    validated = migrator.validate()
    assert validated["validated"] and validated["verify"]["missing"] == 0
    assert migrator.cutover()["state"] == "package_authoritative"
    assert _gone(menv, admin, row["id"])
    assert row["id"] not in _legacy_ids(legacy_db)  # the cutover applied the removal to the legacy copy


# =========================================================================== R3-EG-1
SECRET = "ZEPHYR acquisition budget is 40M"


@pytest.fixture
def imported_repo(tmp_path):
    allowed = (tmp_path / "allowed").resolve()
    allowed.mkdir()
    repo = make_repo(allowed / "repo", {"plans/alpha.py": '"""Project ZEPHYR acquisition plan."""\nimport os\n',
                                        "plans/beta.py": '"""Beta plan."""\nimport sys\n',
                                        "src/app.py": '"""App."""\nimport json\n'})
    blobs = {name: git(repo, "rev-parse", f"HEAD:{name}") for name in ("plans/alpha.py", "src/app.py")}
    clock = FakeClock()
    keys = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    ext = FakeExternalMemory(clock=clock)
    consent = StaticConsentPolicy([ConsentGrant(provider="fake-external", granted_at=clock.now - 1)])
    access = access_for(repositories=("repo-a",))
    root = tmp_path / "root"

    def host(**kw):
        return HostCapabilities(clock=clock, allowed_repository_roots=(allowed,), providers={"fake-external": ext},
                                consent=consent, **kw)

    engine = MemoryEngine(root, keys, host=host())
    engine.register_repository(access, repo, repository_id="repo-a")
    engine.snapshot_repository(access, "repo-a")
    native = [r.id for r in engine.list(access, kinds=(MemoryKind.REPOSITORY_OBSERVATION,))
              if r.extra.get("path", "").startswith("plans/")]  # observations of the paths excluded below
    assert len(native) == 2
    document = ix.new_document(
        repository_id="repo-a", hash_algorithm="sha1", producer={"name": "deep-tool", "version": "1", "kind": "tool"},
        records=[
            {"type": "repository", "repository_id": "repo-a", "object_format": "sha1"},
            {"type": "observation", "path": "plans/alpha.py", "blob": blobs["plans/alpha.py"],
             "text": f"plans/alpha.py: {SECRET}", "extraction": "tool", "language": "python"},
            {"type": "summary", "text": f"Summary: plan lives in plans/alpha.py; {SECRET}",
             "source_hashes": [["plans/alpha.py", blobs["plans/alpha.py"]]], "producer": "deep-tool",
             "model": "m1", "basis": "model_interpretation"},
            {"type": "summary", "text": "Summary: the ZEPHYR app reads plans/alpha.py from src/app.py",
             "source_hashes": [["src/app.py", blobs["src/app.py"]], ["plans/alpha.py", blobs["plans/alpha.py"]]],
             "producer": "deep-tool", "model": "m1", "basis": "model_interpretation"},
        ], generated_at=clock.now)
    imported = list(engine.services(access).repository.import_interchange(access, document).record_ids)
    assert len(imported) == 3
    for record_id in imported:
        engine.approve(access, record_id, expected_revision=engine.get(access, record_id).revision)
    engine.close()
    return {"root": root, "keys": keys, "host": host, "access": access, "repo": repo, "ext": ext,
            "native": native, "imported": imported, "blobs": blobs}


@needs_git
def test_eg1_imported_records_of_a_later_excluded_path_are_never_served_or_sent(imported_repo):
    s = imported_repo
    access, imported = s["access"], s["imported"]
    engine = MemoryEngine(s["root"], s["keys"], host=s["host"](repository_exclude_patterns=("plans/**",)))
    try:
        # Before any snapshot: hidden from every read and egress path (one excluded path is enough,
        # including for the summary that also cites the still-included src/app.py).
        for record_id in imported:
            with pytest.raises(NotFound):
                engine.get(access, record_id)
        assert not {h.record.id for h in engine.search(access, "ZEPHYR budget").hits} & set(imported)
        packet = engine.build_context(access, ContextRequest(token_allowance=2000, query="ZEPHYR budget"))
        assert SECRET not in packet.text and not {i.record_id for i in packet.items} & set(imported)
        assert not {r["id"] for r in engine.export(access)["records"]} & set(imported)
        report = engine.services(access).providers.sync_external(access, "fake-external")
        assert report["skipped"].get("excluded") == 3 + len(s["native"])
        assert not any(SECRET in item["content"] for item in s["ext"].items.values())
        # The next snapshot purges them, like the native observation of the same path.
        snapshot = engine.snapshot_repository(access, "repo-a")
        assert snapshot["counts"]["observations_excluded_removed"] == 3 + len(s["native"])
        ctx = engine.partition_context(access.partition)
        with ctx.partition.db.read() as conn:
            assert not [r for r in imported if ctx.records.get_row(conn, r) is not None]
    finally:
        engine.close()


@needs_git
def test_eg1_a_cached_packet_with_an_imported_record_is_revalidated_after_an_exclusion(imported_repo):
    s = imported_repo
    access, imported = s["access"], s["imported"]
    engine = MemoryEngine(s["root"], s["keys"], host=s["host"]())
    try:
        packet = engine.build_context(access, ContextRequest(token_allowance=2000, query="ZEPHYR budget"))
        assert set(imported) & {i.record_id for i in packet.items}
    finally:
        engine.close()
    engine = MemoryEngine(s["root"], s["keys"], host=s["host"](repository_exclude_patterns=("plans/**",)))
    try:
        fresh = engine.revalidate_context(access, packet)
        assert not set(imported) & {i.record_id for i in fresh.items}
        assert SECRET not in fresh.text
    finally:
        engine.close()


@needs_git
def test_eg1_imported_records_go_stale_when_a_cited_file_changes_and_revive_when_it_returns(imported_repo):
    s = imported_repo
    access, imported, repo = s["access"], s["imported"], s["repo"]
    original = (repo / "plans" / "alpha.py").read_text()
    (repo / "plans" / "alpha.py").write_text('"""Project ZEPHYR cancelled."""\nimport sys\n')
    commit_all(repo, "change")
    engine = MemoryEngine(s["root"], s["keys"], host=s["host"]())
    try:
        snapshot = engine.snapshot_repository(access, "repo-a")
        assert snapshot["counts"].get("imported_stale") == 3
        for record_id in imported:
            assert engine.get(access, record_id).lifecycle == Lifecycle.STALE
        packet = engine.build_context(access, ContextRequest(token_allowance=2000, query="ZEPHYR budget"))
        assert not set(imported) & {i.record_id for i in packet.items}
        engine.services(access).providers.sync_external(access, "fake-external")
        assert not any(SECRET in item["content"] for item in s["ext"].items.values())  # stale is never sent
        (repo / "plans" / "alpha.py").write_text(original)
        commit_all(repo, "revert")
        snapshot = engine.snapshot_repository(access, "repo-a")
        assert snapshot["counts"].get("imported_revived") == 3
        for record_id in imported:
            assert engine.get(access, record_id).lifecycle == Lifecycle.APPROVED
    finally:
        engine.close()


@needs_git
def test_eg1_imports_written_before_the_index_existed_are_indexed_on_the_next_snapshot(imported_repo):
    s = imported_repo
    access, imported, repo = s["access"], s["imported"], s["repo"]
    engine = MemoryEngine(s["root"], s["keys"], host=s["host"]())
    try:
        ctx = engine.partition_context(access.partition)
        with ctx.partition.db.write() as conn:  # the store as an earlier build left it
            conn.execute("DELETE FROM repo_derived")
            conn.execute("DELETE FROM meta WHERE key='repo_derived_indexed'")
    finally:
        engine.close()
    (repo / "src" / "app.py").write_text('"""App v2."""\nimport json\n')
    commit_all(repo, "change app")
    engine = MemoryEngine(s["root"], s["keys"], host=s["host"]())
    try:
        snapshot = engine.snapshot_repository(access, "repo-a")
        assert snapshot["counts"].get("imported_stale") == 1
        # Only the summary that also cites src/app.py describes a file that changed.
        stale = [r for r in imported if engine.get(access, r).lifecycle == Lifecycle.STALE]
        assert len(stale) == 1 and "src/app.py" in engine.get(access, stale[0]).content
    finally:
        engine.close()


# =========================================================================== R3-EG-2
TRANSCRIPT = "my therapist appointment is on Tuesday at 4pm, don't tell anyone"


@pytest.fixture
def transcript_hub(tmp_path):
    clock = FakeClock()
    ext = FakeExtractor("cloud-extract", egress=True)
    consent = StaticConsentPolicy([ConsentGrant(provider="cloud-extract", scope=P,
                                                data_classes=frozenset({DATA_MEMORY_TEXT}), granted_at=clock.now - 1)])
    engine = MemoryEngine(tmp_path / "root", StaticKeyProvider({"k1": secrets.token_bytes(32)}),
                          host=HostCapabilities(clock=clock, providers={"cloud-extract": ext}, consent=consent))
    user = access_for(projects=("p",))
    receipt = engine.ingest_event(user, IngestionEvent(event_id="ev-1", session_ref="sess-1", sequence=0,
                                                       role="user", text=TRANSCRIPT, occurred_at=clock.now, scope=P))
    yield engine, ext, user, receipt, consent, clock
    engine.close()


def _evidence(receipt, **kw):
    item = {"id": "e1", "text": "my therapist appointment is on Tuesday at 4pm",
            "source": SourceRef(SourceKind.MESSAGE, receipt.message_id), "scope": P}
    item.update(kw)
    return item


@pytest.mark.parametrize("label", [DATA_MEMORY_TEXT, None])
@pytest.mark.parametrize("caller", ["user", "agent"])
def test_eg2_transcript_evidence_needs_transcript_consent_whatever_its_label(transcript_hub, label, caller):
    engine, ext, user, receipt, _consent, _clock = transcript_hub
    access = user if caller == "user" else access_for(actor=Actor.AGENT, projects=("p",),
                                                      operations=(Operation.READ, Operation.PROPOSE))
    item = _evidence(receipt) if label is None else _evidence(receipt, data_class=label)
    with pytest.raises(ConsentRequired):
        engine.services(access).providers.extract_candidates(access, [item], provider="cloud-extract")
    assert ext.calls == []


def test_eg2_cited_transcript_text_must_be_an_excerpt(transcript_hub):
    engine, ext, user, receipt, consent, clock = transcript_hub
    consent.add(ConsentGrant(provider="cloud-extract", scope=P, data_classes=frozenset({DATA_TRANSCRIPTS}),
                             allow_transcripts=True, granted_at=clock.now - 1))
    hub = engine.services(user).providers
    for invented in (_evidence(receipt, text="completely unrelated text the caller made up"),
                     _evidence(receipt, source=SourceRef(SourceKind.SESSION, "sess-1"), text="a made-up quote")):
        with pytest.raises(ValidationError):
            hub.extract_candidates(user, [invented], provider="cloud-extract")
    assert ext.calls == []
    # Real excerpts of the message, and of a message of the cited session, are accepted.
    hub.extract_candidates(user, [_evidence(receipt)], provider="cloud-extract")
    hub.extract_candidates(user, [_evidence(receipt, id="e2", source=SourceRef(SourceKind.SESSION, "sess-1"),
                                            text="appointment is on Tuesday")], provider="cloud-extract")
    assert [item["data_class"] for call in ext.calls for item in call] == [DATA_TRANSCRIPTS, DATA_TRANSCRIPTS]


def test_eg2_labels_never_loosen_and_unverifiable_kinds_are_refused(transcript_hub):
    engine, ext, user, receipt, _consent, _clock = transcript_hub
    hub = engine.services(user).providers
    with pytest.raises(ValidationError):  # incomparable with what the source is
        hub.extract_candidates(user, [_evidence(receipt, data_class=DATA_REPOSITORY_SOURCE)], provider="cloud-extract")
    with pytest.raises(ValidationError):  # evidence whose text cannot be checked against its source
        hub.extract_candidates(user, [_evidence(receipt, source=SourceRef(SourceKind.EPISODE, "ep-1"))],
                               provider="cloud-extract")
    assert ext.calls == []


@needs_git
def test_eg2_repository_evidence_needs_source_consent_and_must_quote_the_blob(tmp_path):
    clock = FakeClock()
    ext = FakeExtractor("cloud-extract", egress=True, data_classes=(DATA_MEMORY_TEXT, DATA_TRANSCRIPTS,
                                                                    DATA_REPOSITORY_SOURCE))
    repo_scope = Scope.of(repository="repo-a")
    consent = StaticConsentPolicy([ConsentGrant(provider="cloud-extract", scope=repo_scope,
                                                data_classes=frozenset({DATA_MEMORY_TEXT}), granted_at=clock.now - 1)])
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    repo = make_repo(allowed / "repo", {"settings.py": "API_HOST = 'internal.corp.example'\n"})
    engine = MemoryEngine(tmp_path / "root", StaticKeyProvider({"k1": secrets.token_bytes(32)}),
                          host=HostCapabilities(clock=clock, providers={"cloud-extract": ext}, consent=consent,
                                                allowed_repository_roots=(allowed,)))
    try:
        user = access_for(repositories=("repo-a",))
        engine.register_repository(user, repo, repository_id="repo-a")
        engine.snapshot_repository(user, "repo-a")
        source = SourceRef(SourceKind.BLOB_RANGE, f"repo-a:{git(repo, 'rev-parse', 'HEAD:settings.py')}")
        hub = engine.services(user).providers
        quote = {"id": "e1", "text": "API_HOST = 'internal.corp.example'", "source": source, "scope": repo_scope}
        with pytest.raises(ConsentRequired):  # no allow_source: unlabelled source text is not memory text
            hub.extract_candidates(user, [quote], provider="cloud-extract")
        assert ext.calls == []
        consent.add(ConsentGrant(provider="cloud-extract", scope=repo_scope,
                                 data_classes=frozenset({DATA_REPOSITORY_SOURCE}), allow_source=True,
                                 granted_at=clock.now - 1))
        with pytest.raises(ValidationError):
            hub.extract_candidates(user, [dict(quote, text="API_HOST = 'attacker.example'")], provider="cloud-extract")
        assert ext.calls == []
        hub.extract_candidates(user, [quote], provider="cloud-extract")
        assert [item["data_class"] for call in ext.calls for item in call] == [DATA_REPOSITORY_SOURCE]
    finally:
        engine.close()


# =========================================================================== R3-RG-1
RG1_TARGETS = {
    "project": (ForgetTarget("project", "proj-a"), IDS["candidate_approved"]),
    "agent": (ForgetTarget("agent", AGENT), IDS["agent"]),
    "profile": (ForgetTarget("profile", "default"), IDS["personal"]),
}


def _tamper_created_at(legacy_db, record_id, value):
    conn = sqlite3.connect(legacy_db)  # no key: only the unauthenticated plaintext column changes
    try:
        with conn:
            conn.execute("UPDATE memories SET created_at=? WHERE id=?", (value, record_id))
    finally:
        conn.close()


def _ids(engine, access):
    return {r.id for r in engine.list(access, lifecycles=None)}


@pytest.mark.parametrize("name", list(RG1_TARGETS))
@pytest.mark.parametrize("edit", ["future", "after_forget"])
def test_rg1_a_created_at_edit_never_undoes_a_scope_or_profile_forget(menv, control, admin, legacy_db, mapping,
                                                                     tmp_path, clock, name, edit):
    target, victim = RG1_TARGETS[name]
    host = dataclasses.replace(admin, principal="locus-host", actor=Actor.HOST, operations=frozenset({Operation.ADMIN}))
    legacy_mod.LegacyImporter(menv, host, legacy_db, KEY, mapping).run()  # Stage-2 shadow sync
    assert victim in _ids(menv, admin)
    clock.advance(5)
    assert menv.forget(admin, target).deleted.get("memories")
    clock.advance(5)
    _tamper_created_at(legacy_db, victim, clock() + 3600 if edit == "future" else clock() - 1)
    report = legacy_mod.LegacyImporter(menv, host, legacy_db, KEY, mapping).run()
    assert report.get("imported", 0) == 0
    assert victim not in _ids(menv, admin)
    verified = legacy_mod.verify(menv, admin, legacy_db, KEY, mapping)
    assert verified["ok"] and verified["missing"] == 0  # covered by the forget, not missing live data
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    assert migrator.validate()["validated"]
    assert migrator.cutover()["state"] == "package_authoritative"
    assert victim not in _ids(menv, admin)
    assert victim not in _legacy_ids(legacy_db)  # the cutover applied the forget to the legacy copy


def test_rg1_a_never_imported_row_dated_in_the_future_stays_covered(engine, admin, legacy_db, mapping, clock):
    engine.forget(admin, ForgetTarget("project", "proj-a"))  # before any import
    clock.advance(5)
    victim = IDS["candidate_approved"]
    _tamper_created_at(legacy_db, victim, clock() + 3600)
    report = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    assert victim not in _ids(engine, admin)
    assert report.get("skipped_forgotten", 0) >= 1


# =========================================================================== R3-API-1
def _api_engine(tmp_path):
    keys = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    engine = MemoryEngine(tmp_path / "root", keys)
    access = access_for(projects=("p",))
    first = engine.remember(access, RememberRequest(content="hello world", scope=P)).record
    second = engine.remember(access, RememberRequest(content="second memory", scope=P)).record
    return keys, engine, access, first.id, second.id


@pytest.mark.parametrize("bad", ["x", True, [1], 7, 0, "", {"include_derived": False}])
def test_api1_a_non_policy_is_refused_before_anything_is_recorded(tmp_path, bad):
    keys, engine, access, first, second = _api_engine(tmp_path)
    partition = engine.partition_context(access.partition).partition
    head = partition.ledger.head()
    with pytest.raises(ValidationError):
        engine.forget(access, ForgetTarget("memory", first), policy=bad)
    with pytest.raises(ValidationError):
        engine.preview_forget(access, ForgetTarget("memory", first), bad)
    assert partition.ledger.head() == head  # nothing appended
    assert engine.get(access, first).content == "hello world"  # and nothing applied later
    assert engine.get(access, second).content == "second memory"
    assert engine.search(access, Query(text="second")).hits
    engine.close()
    reopened = MemoryEngine(tmp_path / "root", keys)
    try:
        assert reopened.get(access, first).content == "hello world"
        assert reopened.forget(access, ForgetTarget("memory", first)).deleted.get("memories") == 1
    finally:
        reopened.close()


def test_api1_policy_fields_must_be_bools():
    with pytest.raises(ValidationError):
        ForgetPolicy(include_derived="no")
    with pytest.raises(ValidationError):
        ForgetPolicy(suppress_relearning=1)
    assert ForgetPolicy(include_derived=False).include_derived is False


def test_api1_a_bad_policy_recorded_by_an_earlier_build_no_longer_wedges_the_partition(tmp_path):
    keys, engine, access, first, second = _api_engine(tmp_path)
    partition = engine.partition_context(access.partition).partition
    partition.ledger.append([("memory", first, "true")])  # what forget(policy=True) used to record
    partition.reconciled = False
    assert engine.get(access, second).content == "second memory"  # reconciled with the default policy
    with pytest.raises(NotFound):
        engine.get(access, first)
    engine.close()
    reopened = MemoryEngine(tmp_path / "root", keys)
    try:
        assert reopened.reconcile(access, acknowledge_mirror_gap=True) is not None
        assert reopened.get(access, second).content == "second memory"
    finally:
        reopened.close()


# =========================================================================== R3-MF-4
FIXTURE = Path(group1.__file__).parent / "fixtures" / "locus_legacy"


class _Env:
    """An engine and ownership control that can be dropped and reopened from disk (a restart)."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.legacy = tmp / "legacy" / "memory.sqlite3"
        self.legacy.parent.mkdir(parents=True)
        shutil.copy(FIXTURE / "memory.sqlite3", self.legacy)
        self.clock = FakeClock()
        self.keys = StaticKeyProvider({"k1": bytes(range(32))})
        self.admin = access_for(projects=("proj-a", "proj-b"), agents=(AGENT,), operations=set(Operation))
        self.mapping = legacy_mod.LegacyMapping.from_known({WS: "proj-a", OTHER: "proj-b"}, [AGENT])
        self.open()

    def open(self) -> None:
        self.control = OwnershipControl(self.root)
        self.engine = MemoryEngine(self.root, self.keys, host=HostCapabilities(ownership=self.control,
                                                                               clock=self.clock))

    def close(self) -> None:
        for closer in (self.engine.close, self.control.close):
            try:
                closer()
            except Exception:
                pass

    def restart(self) -> None:
        self.close()
        self.open()

    def migrator(self, name: str) -> Migrator:
        return Migrator(self.engine, self.control, self.admin, self.legacy, KEY, self.mapping,
                        work_dir=self.tmp / name, project_workspaces={"proj-a": WS, "proj-b": OTHER})

    def watermark(self) -> int:
        ctx = self.engine.partition_context(self.admin.partition)
        with ctx.partition.db.read() as conn:
            return legacy_mod.rollback_watermark(conn)

    def cut_over_with_note(self, content: str):
        migrator = self.migrator("mig1")
        migrator.prepare_shadow()
        assert migrator.validate()["validated"]
        assert migrator.cutover()["state"] == "package_authoritative"
        note = self.engine.remember(self.admin, RememberRequest(content=content, scope=PROJ_A)).record
        victim = sorted(_legacy_ids(self.legacy))[0]
        assert self.engine.forget(self.admin, ForgetTarget("memory", victim)).deleted  # deletion generation >= 1
        return note


@pytest.fixture
def renv(tmp_path):
    env = _Env(tmp_path)
    yield env
    env.close()


def _assert_completed_rollback(env: _Env, note) -> None:
    assert env.migrator("mig1").state().state == "legacy_authoritative"
    assert note.id in _legacy_ids(env.legacy)
    assert env.engine.get(env.admin, note.id).extra.get("legacy_round_trip") is True
    assert env.watermark() >= 1
    assert env.migrator("mig2").prepare_shadow()["state"] == "shadow_prepared"


@pytest.mark.parametrize("crash", ["before_rollback_complete", "right_after_the_transition_commits"])
def test_mf4_a_crash_around_the_transition_never_loses_the_adoption_or_watermark(renv, monkeypatch, crash):
    note = renv.cut_over_with_note("package-native note written after cutover")
    migrator = renv.migrator("mig1")
    if crash == "before_rollback_complete":
        migrator.crash_at = crash  # package committed, transition not made
    else:
        original = OwnershipControl.transition

        def transition(self, partition_id, family, target, **kw):
            record = original(self, partition_id, family, target, **kw)
            if target == "legacy_authoritative" and kw.get("reason") == "rollback complete":
                raise SimulatedCrash("process died right after the control commit")
            return record

        monkeypatch.setattr(OwnershipControl, "transition", transition)
    with pytest.raises(SimulatedCrash):
        migrator.rollback()
    monkeypatch.undo()
    renv.restart()
    migrator = renv.migrator("mig1")
    if crash == "before_rollback_complete":
        assert migrator.state().state == "rollback_in_progress"  # never legacy without the package commit
        assert migrator.resume()["state"] == "legacy_authoritative"
    else:
        assert migrator.resume() == {"state": "legacy_authoritative", "resumed": False}  # nothing was lost
    _assert_completed_rollback(renv, note)


def test_mf4_a_failed_package_commit_leaves_the_rollback_resumable(renv, monkeypatch):
    note = renv.cut_over_with_note("another package-native note")
    db = renv.engine.partition_context(renv.admin.partition).partition.db
    real = db.conn
    armed = {"on": False}

    class FailingCommit:
        def __init__(self, inner):
            object.__setattr__(self, "_inner", inner)

        def execute(self, sql, *args):
            if armed["on"] and sql.strip().upper() == "COMMIT":
                armed["on"] = False
                raise sqlite3.OperationalError("database or disk is full")
            return self._inner.execute(sql, *args)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    original = legacy_mod.record_rollback_watermark

    def arm_then_record(conn, generation):
        armed["on"] = True  # the rollback's package COMMIT, right after this, fails
        return original(conn, generation)

    monkeypatch.setattr(legacy_mod, "record_rollback_watermark", arm_then_record)
    db._local.conn = FailingCommit(real)
    try:
        with pytest.raises(StorageFull):
            renv.migrator("mig1").rollback()
    finally:
        db._local.conn = real
        monkeypatch.setattr(legacy_mod, "record_rollback_watermark", original)
    migrator = renv.migrator("mig1")
    assert migrator.state().state == "rollback_in_progress"
    assert note.id in _legacy_ids(renv.legacy)  # the legacy write committed on its own
    assert migrator.resume()["state"] == "legacy_authoritative"
    _assert_completed_rollback(renv, note)


def test_mf4_a_legacy_deletion_of_a_written_back_row_is_propagated(renv):
    note = renv.cut_over_with_note("note the user later deletes in the legacy app")
    renv.migrator("mig1").rollback()
    guard = renv.control.writer_guard(renv.admin.partition.partition_id, Migrator.FAMILY, "legacy")
    assert LegacyMemoryVault(renv.legacy, key=KEY, write_guard=guard).delete(note.id)
    again = renv.migrator("mig2")
    shadow = again.prepare_shadow()
    assert shadow["import"]["deletion_propagation"]["propagated"] >= 1
    assert again.validate()["validated"]
    assert again.cutover()["state"] == "package_authoritative"
    assert _gone(renv.engine, renv.admin, note.id)


def test_mf4_resume_repairs_a_rollback_whose_package_commit_an_earlier_build_lost(renv, monkeypatch):
    note = renv.cut_over_with_note("note written back by an earlier build")
    # The earlier build's outcome: legacy authoritative, the note in the legacy file, but neither the
    # adoption nor the watermark committed.
    monkeypatch.setattr(Migrator, "_adopt", staticmethod(lambda *a, **k: False))
    monkeypatch.setattr(legacy_mod, "record_rollback_watermark", lambda conn, generation: None)
    renv.migrator("mig1").rollback()
    monkeypatch.undo()
    assert not renv.engine.get(renv.admin, note.id).extra.get("legacy_round_trip")
    with pytest.raises(MigrationError):
        legacy_mod.LegacyImporter(renv.engine, renv.admin, renv.legacy, KEY, renv.mapping).run()
    resumed = renv.migrator("mig1").resume()
    assert resumed["resumed"] is True and resumed["repaired_rollback"]["adopted"] == 1
    assert renv.migrator("mig1").resume()["resumed"] is False  # idempotent
    _assert_completed_rollback(renv, note)
