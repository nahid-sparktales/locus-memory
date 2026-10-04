"""Regression tests for review round 2, batch 1 (reproduced defects).

R2-FG-1  a scope/profile tombstone swallowed every later legacy row of that workspace, agent or
         profile on re-migration, and a second rollback then deleted the user's only copy.
R2-FG-2  a rollback/re-migration round trip replaced written-back package records with the
         legacy mapping (sources, derived_from, basis lost), so forgetting an input no longer
         cascaded to its approved derivations.
R2-FG-3  forgetting one attempt purged that attempt's lesson with a raw purge: no cascade,
         tombstone or receipt count, so records derived from the lesson stayed served.
R2-FG-4  a legacy deletion of a record a rollback wrote back was never propagated.
R2-SL-1  egress paths (external sync, semantic search embedding, summarization) ignored
         repository exclusions and read-time expiry.
R2-CD-1  after cutover a forgotten memory stayed decryptable in the live legacy vault and in the
         migration snapshot, while the receipt reported a complete forget.
R2-HC-2  the legacy importer ignored ownership: after cutover it reverted user corrections,
         imported writes to the fenced legacy file and forgot authoritative package records.
R2-ROB-1 the derived-record cascade recursed once per chain level: a deep derivation chain made
         forget raise RecursionError and wedged the partition.

Each test reproduces the report's scenario and asserts the correct outcome. All data lives in
pytest tmp dirs (the legacy vault is a copy of tests/fixtures/locus_legacy).
"""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import test_review_group1 as group1
from conftest import access_for
from foundation_support import db_path, ledger_path, raw_db
from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.errors import MemoryEngineError, NotFound, OwnershipFenced
from locus_memory.forgetting import ForgettingService
from locus_memory.host import HostCapabilities
from locus_memory.learning.episodes import attempt_source_ref
from locus_memory.migrations import cutover as cutover_mod
from locus_memory.migrations import legacy as legacy_mod
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
    Retention,
    Scope,
    SourceKind,
    SourceRef,
    StatementBasis,
)
from test_review_group1 import (
    AGENT,
    AGENT_P,
    EXPECTED,
    IDS,
    KEY,
    PROJ_A,
    USER_P,
    WS,
    _Authority,
    _cut_over,
    _legacy_ids,
    _lesson_ids,
    _migrator,
    _proj_a,
    _report,
    _summary,
)

# Shared fixtures (a copy of the legacy fixture vault, its mapping, an admin context, the ownership
# control and an engine wired to it), registered in this module under the same names.
admin = group1.admin
control = group1.control
legacy_db = group1.legacy_db
mapping = group1.mapping
menv = group1.menv

AGENT_A = access_for(actor=Actor.AGENT, projects=("proj-a",), operations={Operation.READ, Operation.PROPOSE})


def _raw_legacy(legacy_db: Path) -> dict[str, sqlite3.Row]:
    """Legacy rows read straight from the file (no vault, no key)."""
    conn = sqlite3.connect(f"file:{legacy_db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return {row["id"]: row for row in conn.execute("SELECT * FROM memories")}
    finally:
        conn.close()


def _file_bytes(path: Path) -> bytes:
    data = b""
    for candidate in (path, path.with_name(path.name + "-wal")):
        if candidate.exists():
            data += candidate.read_bytes()
    return data


def _ingest(engine, access, session, seq, text, scope, clock):
    return engine.ingest_event(access, IngestionEvent(
        event_id=f"{session}-e{seq}", session_ref=session, sequence=seq, role="user", text=text,
        occurred_at=clock(), scope=scope))


# =========================================================================== R2-FG-1
FG1_TARGETS = {
    "project": (ForgetTarget("project", "proj-a"), {"scope": "workspace"}),
    "agent": (ForgetTarget("agent", AGENT), {"scope": "agent"}),
    "profile": (ForgetTarget("profile", "default"), {"scope": "workspace"}),
}


@pytest.mark.parametrize("name", list(FG1_TARGETS))
def test_fg1_legacy_memory_created_after_a_forget_survives_remigration_and_rollback(
        name, engine, control, admin, legacy_db, mapping, tmp_path, clock):
    target, value = FG1_TARGETS[name]
    first = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    before = _legacy_ids(legacy_db)
    assert engine.forget(admin, target).deleted.get("memories")
    first.rollback()
    forgotten = before - _legacy_ids(legacy_db)
    assert forgotten  # the rollback applied the forget to the legacy store

    clock.advance(30 * 86_400)  # a month later Locus (authoritative again) saves a new memory
    vault = LegacyMemoryVault(legacy_db, key=KEY, clock=clock)
    new = vault.save({"content": f"Brand new {name} memory written a month after the wipe", **value},
                     workspace=WS, agent_id=AGENT)

    again = _migrator(engine, control, admin, legacy_db, mapping, tmp_path / "again")
    imported = again.prepare_shadow()["import"]
    assert imported.get("skipped_forgotten", 0) == 0 and imported.get("imported") == 1
    validated = again.validate()
    assert validated["validated"] and validated["verify"]["missing"] == 0
    assert again.cutover()["state"] == "package_authoritative"
    assert engine.get(admin, new["id"]).content.startswith("Brand new")
    # The rows the forget covered stay forgotten.
    assert not (forgotten & {r.id for r in engine.list(admin, lifecycles=None)})

    again.rollback()  # the second rollback keeps the user's (only) copy
    assert new["id"] in _legacy_ids(legacy_db)


def test_fg1_a_scope_forget_covers_only_legacy_rows_written_before_it(engine, admin, legacy_db, mapping, clock):
    legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    covered = _proj_a(engine, admin)
    assert covered
    engine.forget(admin, ForgetTarget("project", "proj-a"))  # legacy is still authoritative (no rollback)
    clock.advance(30 * 86_400)
    vault = LegacyMemoryVault(legacy_db, key=KEY, clock=clock)
    new = vault.save({"content": "created after the forget", "scope": "workspace"}, workspace=WS, agent_id=AGENT)
    ctx = engine.partition_context(admin.partition)
    row = next(r for r in vault.raw_rows() if r["id"] == new["id"])
    mapped, _ = legacy_mod.map_record(vault.open_row(row, include_private=True), mapping, now=clock())
    old_row = next(r for r in vault.raw_rows() if r["id"] in covered)
    old, _ = legacy_mod.map_record(vault.open_row(old_row, include_private=True), mapping, now=clock())
    with ctx.partition.db.read() as conn:
        assert legacy_mod.forgotten_check(ctx, conn, mapped) == (mapped, None)
        assert legacy_mod.forgotten_check(ctx, conn, old)[0] is None  # written before the forget
    report = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    assert report.get("imported") == 1
    assert _proj_a(engine, admin) == {new["id"]}
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]


def test_fg1_rollback_never_deletes_a_legacy_row_the_package_never_held(engine, control, admin, legacy_db,
                                                                       mapping, tmp_path, clock):
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    clock.advance(60)
    writer = LegacyMemoryVault(legacy_db, key=KEY, clock=clock)  # an unguarded writer after cutover
    stray = writer.save({"content": "written to the fenced legacy file", "scope": "personal"})
    covered = writer.save({"content": "a proj-a note the user forgets below", "scope": "workspace"},
                          workspace=WS, agent_id=AGENT)
    clock.advance(60)
    engine.forget(admin, ForgetTarget("project", "proj-a"))
    result = migrator.rollback()
    ids = _legacy_ids(legacy_db)
    assert stray["id"] in ids  # never in the package and not forgotten there: live legacy data
    assert covered["id"] not in ids  # a package forget covers it
    assert result["counts"].get("legacy_only_kept") == 1


# =========================================================================== R2-FG-2
def _derive_from(engine, admin_access, m1_id, content, *, scope=PROJ_A):
    derived = engine.propose(AGENT_A, CandidateProposal(
        content=content, scope=scope, sources=(SourceRef(SourceKind.MEMORY, m1_id),), derived_from=(m1_id,))).record
    return engine.approve(admin_access, derived.id, expected_revision=derived.revision).record


def test_fg2_round_trip_keeps_provenance_so_forgetting_an_input_cascades(menv, control, admin, legacy_db,
                                                                        mapping, tmp_path, clock):
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    m1 = menv.remember(admin, RememberRequest(content="Alice's salary review is on the 3rd", scope=PROJ_A)).record
    from_memory = _derive_from(menv, admin, m1.id, "Alice has a salary review soon")
    _ingest(menv, admin, "sess-raise", 0, "Bob asked for a raise in our one-on-one", PROJ_A, clock)
    proposed = menv.propose(AGENT_A, CandidateProposal(content="Bob is negotiating a raise", scope=PROJ_A,
                                                       sources=(SourceRef(SourceKind.SESSION, "sess-raise"),))).record
    from_session = menv.approve(admin, proposed.id, expected_revision=proposed.revision).record

    # The archived transcript has no legacy representation: a partial rollback keeps it package-only.
    assert migrator.rollback(allow_partial=True)["counts"].get("restored") == 3
    again = _migrator(menv, control, admin, legacy_db, mapping, tmp_path / "again")
    again.prepare_shadow()
    assert again.validate()["validated"]
    assert again.cutover()["state"] == "package_authoritative"

    for record in (from_memory, from_session):
        kept = menv.get(admin, record.id)
        assert kept.basis == StatementBasis.MODEL_INTERPRETATION
        assert kept.extra.get("legacy_round_trip") and not kept.extra.get("legacy")
        assert {s.identity() for s in record.sources} <= {s.identity() for s in kept.sources}
    assert menv.get(admin, from_memory.id).links.derived_from == (m1.id,)

    receipt = menv.forget(admin, ForgetTarget("memory", m1.id))
    assert receipt.deleted.get("derived_memories") == 1
    menv.forget(admin, ForgetTarget("session", "sess-raise"))
    for record in (from_memory, from_session):
        with pytest.raises(NotFound):
            menv.get(admin, record.id)
    assert not menv.search(admin, Query(text="salary review soon")).hits
    assert not menv.search(admin, Query(text="negotiating a raise")).hits
    text = menv.build_context(admin, ContextRequest(token_allowance=4000, query="salary raise")).text
    assert "salary review soon" not in text and "negotiating a raise" not in text


def test_fg2_a_legacy_edit_of_a_written_back_record_keeps_its_provenance(menv, control, admin, legacy_db,
                                                                        mapping, tmp_path, clock):
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    m1 = menv.remember(admin, RememberRequest(content="Alice's salary review is on the 3rd", scope=PROJ_A)).record
    derived = _derive_from(menv, admin, m1.id, "Alice has a salary review soon")
    migrator.rollback()
    adopted = menv.get(admin, derived.id)
    row = _raw_legacy(legacy_db)[derived.id]
    assert adopted.extra["legacy_revision"] == row["revision"]  # an unchanged legacy row is no delta

    clock.advance(3_600)  # Locus (authoritative again) edits the written-back row
    vault = LegacyMemoryVault(legacy_db, key=KEY, clock=clock)
    vault.save({"content": "Alice has a salary review on Friday", "scope": "workspace", "title": adopted.title,
                "kind": adopted.kind.value}, derived.id, workspace=WS)

    again = _migrator(menv, control, admin, legacy_db, mapping, tmp_path / "again")
    assert again.prepare_shadow()["import"].get("updated", 0) >= 1
    assert again.validate()["validated"]
    assert again.cutover()["state"] == "package_authoritative"
    edited = menv.get(admin, derived.id)
    assert edited.content == "Alice has a salary review on Friday"  # the legacy edit wins ...
    assert edited.links.derived_from == (m1.id,)  # ... and the provenance survives the delta
    assert edited.basis == StatementBasis.MODEL_INTERPRETATION
    assert SourceRef(SourceKind.MEMORY, m1.id).identity() in {s.identity() for s in edited.sources}

    menv.forget(admin, ForgetTarget("memory", m1.id))
    with pytest.raises(NotFound):
        menv.get(admin, derived.id)
    assert "salary review on Friday" not in menv.build_context(
        admin, ContextRequest(token_allowance=4000, query="salary review")).text


# =========================================================================== R2-FG-3
@pytest.fixture
def leng(make_engine, clock):
    return make_engine(host=HostCapabilities(clock=clock, verification=_Authority()))


def _a2_lesson_with_derivation(engine):
    engine.record_episode(USER_P, _report("ep-1", "task-1", "a1", proposed_lessons=("keep the a1 lesson",)))
    _, second = engine.record_episode(USER_P, _report("ep-1", "task-1", "a2",
                                                      proposed_lessons=("always pin the ZETA toolchain",)))
    lesson = _lesson_ids(second)[0]
    engine.approve(USER_P, lesson, expected_revision=1)
    derived = engine.propose(AGENT_P, CandidateProposal(
        content="Team rule: ZETA toolchain must be pinned", scope=PROJ_A,
        sources=(SourceRef(SourceKind.MEMORY, lesson),), derived_from=(lesson,))).record
    engine.approve(USER_P, derived.id, expected_revision=derived.revision)
    return lesson, derived.id


A2 = ForgetTarget("source", "task_attempt:" + attempt_source_ref("task-1", "a2"))


def _memory_tombstone(engine, record_id):
    with raw_db(db_path(engine.root, USER_P)) as conn:
        row = conn.execute("SELECT generation FROM tombstones WHERE target_kind='memory' AND target_token=?",
                           (record_id,)).fetchone()
    return None if row is None else row[0]


def test_fg3_forgetting_an_attempt_cascades_through_its_lesson(leng):
    lesson, derived = _a2_lesson_with_derivation(leng)
    receipt = leng.forget(USER_P, A2)
    for record_id in (lesson, derived):
        with pytest.raises(NotFound):
            leng.get(USER_P, record_id)
    assert not leng.search(USER_P, Query(text="ZETA toolchain")).hits
    assert "ZETA" not in leng.build_context(USER_P, ContextRequest(token_allowance=4000)).text
    assert receipt.deleted.get("memories") == 1 and receipt.deleted.get("derived_memories") == 1
    assert _memory_tombstone(leng, lesson) == receipt.deletion_generation
    episode = leng.get_episode(USER_P, "ep-1")
    assert episode.attempts == ("a1",) and episode.proposed_lessons == ("keep the a1 lesson",)
    assert [r.content for r in leng.list(USER_P, lifecycles=(Lifecycle.CANDIDATE,))
            if "a1 lesson" in r.content]  # the remembered attempt's lesson is untouched
    with pytest.raises(MemoryEngineError):  # the forgotten lesson cannot be cited or derived from again
        leng.propose(AGENT_P, CandidateProposal(content="Pin ZETA again", scope=PROJ_A,
                                                sources=(SourceRef(SourceKind.MEMORY, lesson),),
                                                derived_from=(lesson,)))


def test_fg3_a_summary_built_from_the_lesson_goes_with_it(leng):
    lesson, _derived = _a2_lesson_with_derivation(leng)
    other = leng.remember(USER_P, RememberRequest(content="CI runs on every push", scope=PROJ_A)).record
    summary = _summary(leng, [leng.get(USER_P, lesson), other], lifecycle=Lifecycle.APPROVED)
    receipt = leng.forget(USER_P, A2)
    with pytest.raises(NotFound):
        leng.get(USER_P, summary.id)
    assert summary.id in receipt.regenerate_required  # it also had an input that remains
    assert leng.get(USER_P, other.id).content == "CI runs on every push"


def test_fg3_ledger_replay_reaches_the_same_lessons(make_engine, clock, monkeypatch):
    host = lambda: HostCapabilities(clock=clock, verification=_Authority())  # noqa: E731
    engine = make_engine(host=host())
    lesson, derived = _a2_lesson_with_derivation(engine)

    def crash(self, *args, **kwargs):
        raise RuntimeError("process died after the ledger append")

    monkeypatch.setattr(ForgettingService, "apply_tombstone", crash)
    with pytest.raises(RuntimeError):
        engine.forget(USER_P, A2)
    monkeypatch.undo()
    engine.close()
    reopened = make_engine(host=host())  # open-time reconcile applies the entry
    for record_id in (lesson, derived):
        with pytest.raises(NotFound):
            reopened.get(USER_P, record_id)
    assert _memory_tombstone(reopened, lesson) is not None


def test_fg3_a_restored_ledger_adopts_the_forget_not_the_lessons_tombstone(make_engine, root, clock, tmp_path):
    host = lambda: HostCapabilities(clock=clock, verification=_Authority())  # noqa: E731
    engine = make_engine(host=host())
    lesson, derived = _a2_lesson_with_derivation(engine)
    engine.close()
    backup = tmp_path / "before-forget.sqlite3"
    shutil.copy(db_path(root, USER_P), backup)
    engine = make_engine(host=host())
    engine.forget(USER_P, A2)
    engine.close()
    with raw_db(ledger_path(root, USER_P)) as conn:  # the ledger file is restored from before the forget
        conn.execute("DELETE FROM ledger")
    adopting = make_engine(host=host())
    adopting.list(USER_P)  # opening reconciles: the store's tombstones are adopted into the ledger
    adopting.close()
    with raw_db(ledger_path(root, USER_P)) as conn:
        assert [r[0] for r in conn.execute("SELECT target_kind FROM ledger")] == ["source"]
    for suffix in ("-wal", "-shm"):  # ... and later the main database is restored from before it
        db_path(root, USER_P).with_name(db_path(root, USER_P).name + suffix).unlink(missing_ok=True)
    shutil.copy(backup, db_path(root, USER_P))
    restored = make_engine(host=host())
    for record_id in (lesson, derived):
        with pytest.raises(NotFound):
            restored.get(USER_P, record_id)
    assert restored.get_episode(USER_P, "ep-1").attempts == ("a1",)


# =========================================================================== R2-FG-4
def test_fg4_a_legacy_deletion_of_a_written_back_record_is_propagated(engine, control, admin, legacy_db, mapping,
                                                                      tmp_path):
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    new = engine.remember(admin, RememberRequest(content="Uses ruff for linting", scope=PROJ_A)).record
    assert migrator.rollback()["counts"].get("restored") == 1
    assert LegacyMemoryVault(legacy_db, key=KEY).delete(new.id)  # the user deletes it in Locus
    assert {"id": new.id, "field": "deleted_in_legacy"} in legacy_mod.verify(
        engine, admin, legacy_db, KEY, mapping)["mismatches"]  # an unpropagated deletion blocks cutover

    again = _migrator(engine, control, admin, legacy_db, mapping, tmp_path / "again")
    # (the fixture's TTL-expired candidate, absent in legacy since the rollback, is propagated too)
    assert again.prepare_shadow()["import"]["deletion_propagation"]["propagated"] >= 1
    assert again.validate()["validated"]
    assert again.cutover()["state"] == "package_authoritative"
    with pytest.raises(NotFound):
        engine.get(admin, new.id)


def test_fg4_a_package_native_record_absent_from_legacy_is_never_forgotten(engine, admin, legacy_db, mapping):
    legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    native = engine.remember(admin, RememberRequest(content="package-native note", scope=PROJ_A)).record
    report = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    assert report["deletion_propagation"]["propagated"] == 0
    assert engine.get(admin, native.id).content == "package-native note"
    assert all(m["id"] != native.id for m in legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["mismatches"])


# =========================================================================== R2-SL-1
GIT = shutil.which("git")
SECRET_MARK = "db-17.internal"
TRANSIENT_MARK = "wifi-guest-4417"


def _git(cwd, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"})
    subprocess.run([GIT, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main",
                    "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                   cwd=cwd, env=env, check=True, capture_output=True)


@pytest.fixture
def excluded_store(tmp_path, keys, clock):
    """A snapshot taken with no exclusions plus a session-retention memory whose retention has
    ended (maintenance has not run); ``reopen`` opens the store with the host now excluding
    ``settings_prod.py``."""
    if GIT is None:
        pytest.skip("git is required for repository memory tests")
    from locus_memory import MemoryEngine
    from locus_memory.providers.base import DATA_MEMORY_TEXT, ConsentGrant, StaticConsentPolicy

    allowed = (tmp_path / "allowed").resolve()
    repo = allowed / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", ".")
    (repo / "settings_prod.py").write_text(f'"""prod db host {SECRET_MARK} user=svc_payments"""\nX = 1\n')
    for name, doc in (("app.py", "application entry point"), ("util.py", "helper utilities"),
                      ("cli.py", "command line interface"), ("models.py", "data models")):
        (repo / name).write_text(f'"""{doc}"""\nY = 2\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    root = tmp_path / "root"
    access = access_for(repositories=("r1",))
    first = MemoryEngine(root, keys, host=HostCapabilities(clock=clock, allowed_repository_roots=(allowed,)))
    first.register_repository(access, repo, repository_id="r1")
    first.snapshot_repository(access, "r1")
    first.remember(access, RememberRequest(content=f"temp note {TRANSIENT_MARK}", kind="fact", scope=Scope.of(),
                                           retention=Retention("session", clock() + 60, False)))
    first.close()
    clock.advance(120)
    opened = []

    def reopen(providers, consent_names):
        consent = StaticConsentPolicy([ConsentGrant(provider=n, scope=None, data_classes=frozenset({DATA_MEMORY_TEXT}),
                                                    granted_at=clock() - 1) for n in consent_names])
        engine = MemoryEngine(root, keys, host=HostCapabilities(
            clock=clock, allowed_repository_roots=(allowed,), repository_exclude_patterns=["settings_prod.py"],
            providers=providers, consent=consent))
        opened.append(engine)
        # Precondition (round-1 read-path fix): reads hide both already.
        observations = engine.list(access, kinds=(MemoryKind.REPOSITORY_OBSERVATION,))
        assert observations and not any(SECRET_MARK in r.content for r in observations)
        assert [r.lifecycle for r in engine.list(access, lifecycles=None, kinds=(MemoryKind.FACT,))] == [
            Lifecycle.EXPIRED]
        return engine

    yield access, reopen
    for engine in opened:
        engine.close()


def test_sl1_external_sync_never_sends_excluded_or_expired_records(excluded_store, clock):
    from locus_memory.providers.fake import FakeExternalMemory

    access, reopen = excluded_store
    ext = FakeExternalMemory("ext", clock=clock)
    engine = reopen({"ext": ext}, ["ext"])
    report = engine.services(access).providers.sync_external(access, "ext")
    sent = " ".join(item["content"] for call, _ in ext.sync_calls for item in call)
    assert sent and SECRET_MARK not in sent and TRANSIENT_MARK not in sent
    assert report["skipped"].get("excluded") == 1 and report["skipped"].get("expired") == 1


def test_sl1_semantic_search_never_embeds_excluded_observations(excluded_store):
    from locus_memory.providers.fake import FakeEmbeddingProvider

    access, reopen = excluded_store
    embedder = FakeEmbeddingProvider("cloud-embed", egress=True)
    engine = reopen({"cloud-embed": embedder}, ["cloud-embed"])
    result = engine.search(access, Query(text="application entry point"))
    assert not any(SECRET_MARK in hit.record.content for hit in result.hits)
    sent = " ".join(text for call in embedder.calls for text in call)
    assert embedder.calls and SECRET_MARK not in sent and TRANSIENT_MARK not in sent


def test_sl1_provider_hub_drops_unservable_records_whoever_supplies_them(excluded_store):
    from locus_memory.providers.fake import FakeEmbeddingProvider, FakeReranker

    access, reopen = excluded_store
    embedder, reranker = FakeEmbeddingProvider("cloud-embed", egress=True), FakeReranker("cloud-rerank", egress=True)
    engine = reopen({"cloud-embed": embedder, "cloud-rerank": reranker}, ["cloud-embed", "cloud-rerank"])
    ctx = engine.partition_context(access.partition)
    with ctx.partition.db.read() as conn:  # stored records, as a host could pass them
        stored = [ctx.records.get(conn, row[0]) for row in conn.execute("SELECT id FROM records")]
    hub = engine.services(access).providers
    scores = hub.semantic_scores(access, "prod db host", stored, provider="cloud-embed")
    reranked = hub.rerank(access, "prod db host", stored, provider="cloud-rerank")
    assert scores.coverage.get("excluded") == 1 and scores.coverage.get("expired") == 1
    assert reranked.coverage.get("excluded") == 1
    sent = " ".join(t for call in embedder.calls for t in call) + " ".join(
        t for _query, texts in reranker.calls for t in texts)
    assert SECRET_MARK not in sent and TRANSIENT_MARK not in sent


def test_sl1_summarization_never_receives_excluded_observations(excluded_store):
    from locus_memory.providers.fake import FakeSummarizer

    access, reopen = excluded_store
    summarizer = FakeSummarizer("cloud-sum", egress=True, output=lambda items: " | ".join(i["content"] for i in items))
    engine = reopen({"cloud-sum": summarizer}, ["cloud-sum"])
    engine.consolidate(access, {"summarize": True})
    sent = " ".join(item.get("content") or "" for call in summarizer.calls for item in call)
    assert summarizer.calls and SECRET_MARK not in sent
    stored = engine.list(access, lifecycles=None, kinds=(MemoryKind.SUMMARY,))
    assert stored and not any(SECRET_MARK in r.content for r in stored)  # nothing restated it
    ctx = engine.partition_context(access.partition)
    with ctx.partition.db.read() as conn:
        excluded = next(r for r in (ctx.records.get(conn, row[0]) for row in conn.execute("SELECT id FROM records"))
                        if SECRET_MARK in r.content)
    with pytest.raises(NotFound):  # the hub's own summarize API refuses it too
        engine.services(access).providers.summarize(
            access, [{"id": excluded.id, "content": excluded.content}], scope=excluded.scope, provider="cloud-sum")


# =========================================================================== R2-CD-1
def _cd1_target(name: str, admin_access):
    return {"memory": ForgetTarget("memory", IDS["personal"]), "project": ForgetTarget("project", "proj-a"),
            "profile": ForgetTarget("profile", admin_access.partition.profile)}[name]


@pytest.mark.parametrize("name", ["memory", "project", "profile"])
def test_cd1_forget_after_cutover_leaves_no_legacy_or_snapshot_copy(name, menv, control, admin, legacy_db, mapping,
                                                                    tmp_path):
    work = tmp_path / "migration"
    migrator = _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    assert not list(work.glob("snapshot-*/legacy-snapshot.sqlite3"))  # the cutover removed its snapshot
    before = {r.id for r in menv.list(admin, lifecycles=None)}
    rows = _raw_legacy(legacy_db)
    receipt = menv.forget(admin, _cd1_target(name, admin))
    gone = before - {r.id for r in menv.list(admin, lifecycles=None)}
    assert gone and gone <= set(rows)
    assert not (gone & set(_raw_legacy(legacy_db)))  # deleted from the live legacy vault ...
    data = _file_bytes(legacy_db)
    assert not any(bytes(rows[i]["ciphertext"]) in data for i in gone)  # ... and scrubbed from the file
    assert receipt.physical_purge_pending is False
    assert not any("rollback" in item for item in receipt.receipt.limitations)
    rolled = migrator.rollback()  # rollback still works and does not bring anything back
    assert rolled["state"] == "legacy_authoritative" and not (gone & _legacy_ids(legacy_db))


def test_cd1_a_busy_legacy_store_is_reported_and_finished_later(menv, control, admin, legacy_db, mapping, tmp_path,
                                                                make_engine, monkeypatch):
    _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    monkeypatch.setattr(cutover_mod, "LEGACY_BUSY_TIMEOUT_MS", 50, raising=False)
    blocker = sqlite3.connect(legacy_db, isolation_level=None, timeout=5)
    blocker.execute("BEGIN IMMEDIATE")  # e.g. a stale Locus process holds the legacy write lock
    try:
        receipt = menv.forget(admin, ForgetTarget("memory", IDS["personal"]))
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert receipt.physical_purge_pending is True
    assert any("rollback" in item for item in receipt.receipt.limitations)
    assert IDS["personal"] in _raw_legacy(legacy_db)
    menv.close()
    make_engine(host=HostCapabilities(ownership=control)).list(admin)  # the next open finishes it
    assert IDS["personal"] not in _raw_legacy(legacy_db)


def test_cd1_cutover_applies_forgets_made_while_legacy_was_authoritative(engine, control, admin, legacy_db, mapping,
                                                                       tmp_path):
    migrator = _migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    covered = _proj_a(engine, admin)
    engine.forget(admin, ForgetTarget("project", "proj-a"))  # forgetting is never fenced
    assert migrator.validate()["validated"]
    result = migrator.cutover()
    assert result["state"] == "package_authoritative" and result["legacy_residue"]["complete"]
    assert not (covered & set(_raw_legacy(legacy_db)))


# =========================================================================== R2-HC-2
HOST_IMPORT = dataclasses.replace(USER_P, principal="locus-host", actor=Actor.HOST,
                                  operations=frozenset({Operation.ADMIN}), purpose="legacy-shadow-import")


def _importer(engine, legacy_db, mapping, access=None):
    access = access or dataclasses.replace(HOST_IMPORT, grants=access_for(projects=("proj-a", "proj-b"),
                                                                          agents=(AGENT,)).grants)
    return legacy_mod.LegacyImporter(engine, access, legacy_db, KEY, mapping)


def test_hc2_the_importer_refuses_after_cutover_and_a_correction_is_kept(menv, control, admin, legacy_db, mapping,
                                                                        tmp_path):
    _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    record = menv.get(admin, IDS["personal"])
    menv.correct(admin, record.id, Correction(content="Prefer spaces in Go code now"), expected_revision=record.revision)
    with pytest.raises(OwnershipFenced):
        _importer(menv, legacy_db, mapping).run()
    assert menv.get(admin, record.id).content == "Prefer spaces in Go code now"


def test_hc2_a_write_to_the_fenced_legacy_file_is_not_imported(menv, control, admin, legacy_db, mapping, tmp_path):
    _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    stray = LegacyMemoryVault(legacy_db, key=KEY).save({"content": "User writes Rust", "scope": "personal"})
    with pytest.raises(OwnershipFenced):
        _importer(menv, legacy_db, mapping).run()
    with pytest.raises(NotFound):
        menv.get(admin, stray["id"])


def test_hc2_a_deletion_in_the_fenced_legacy_file_is_not_propagated(menv, control, admin, legacy_db, mapping,
                                                                    tmp_path):
    _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    assert LegacyMemoryVault(legacy_db, key=KEY).delete(IDS["personal"])
    importer = _importer(menv, legacy_db, mapping)
    with pytest.raises(OwnershipFenced):
        importer.run()
    with pytest.raises(OwnershipFenced):
        importer._propagate_deletions(set())
    assert menv.get(admin, IDS["personal"]).content == EXPECTED["memories"][IDS["personal"]]["content"]


def test_hc2_migration_writes_are_fenced_inside_the_transaction(menv, control, admin, legacy_db, mapping, tmp_path,
                                                               monkeypatch):
    _cut_over(menv, control, admin, legacy_db, mapping, tmp_path)
    # An importer that passed its up-front check just before the transition (simulated) still
    # cannot commit after it: the check is repeated inside its write transaction.
    with sqlite3.connect(legacy_db) as conn:  # a legacy-side edit, so the stale importer has a delta
        conn.execute("UPDATE memories SET pinned=1 WHERE id=?", (IDS["personal"],))
    importer = _importer(menv, legacy_db, mapping)
    monkeypatch.setattr(importer, "_require_legacy_authority", lambda: None, raising=False)
    before = menv.get(admin, IDS["personal"])
    with pytest.raises(OwnershipFenced):
        importer.run()
    assert menv.get(admin, IDS["personal"]).revision == before.revision
    ctx = menv.partition_context(admin.partition)
    for change in ("imported", "legacy_delta", "legacy_adopted"):
        with ctx.partition.db.write() as conn, pytest.raises(OwnershipFenced):
            current = ctx.records.get(conn, IDS["personal"])
            ctx.services.core.write_internal(conn, dataclasses.replace(current, revision=current.revision + 1),
                                             change=change, actor=Actor.SYSTEM, expected=current.revision)


def test_hc2_only_the_migrators_final_delta_imports_during_cutover(menv, control, admin, legacy_db, mapping,
                                                                   tmp_path, monkeypatch):
    from locus_memory.migrations.cutover import SimulatedCrash

    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    assert migrator.validate()["validated"]
    migrator.crash_at = "after_fence"
    with pytest.raises(SimulatedCrash):
        migrator.cutover()  # left in cutover_in_progress
    migrator.crash_at = None
    with sqlite3.connect(legacy_db) as conn:  # a legacy change the stale importer would write
        conn.execute("UPDATE memories SET pinned=1 WHERE id=?", (IDS["personal"],))
    stale = _importer(menv, legacy_db, mapping)
    with pytest.raises(OwnershipFenced):
        stale.run()
    # Even past its up-front check (read before the barrier), its write is fenced in the transaction.
    monkeypatch.setattr(stale, "_require_legacy_authority", lambda: None, raising=False)
    before = menv.get(admin, IDS["personal"]).revision
    with pytest.raises(OwnershipFenced):
        stale.run()
    assert menv.get(admin, IDS["personal"]).revision == before
    # The Migrator's own final delta imports the change and completes the cutover.
    assert migrator.resume()["state"] == "package_authoritative"
    assert menv.get(admin, IDS["personal"]).retention.pinned is True


def test_hc2_a_failed_forget_precondition_appends_nothing(engine, admin):
    record = engine.remember(admin, RememberRequest(content="kept", scope=PROJ_A)).record
    ctx = engine.partition_context(admin.partition)
    head = ctx.partition.ledger.head()

    def fenced():
        raise OwnershipFenced("the package became authoritative")

    with pytest.raises(OwnershipFenced):
        ctx.services.forgetting.forget(admin, ForgetTarget("memory", record.id), ForgetPolicy(),
                                       precondition=fenced)
    assert ctx.partition.ledger.head() == head
    assert engine.get(admin, record.id).content == "kept"


# =========================================================================== R2-ROB-1
DEPTH = int(sys.getrecursionlimit() * 1.5)


def _chain(engine, depth=DEPTH):
    root = engine.remember(USER_P, RememberRequest(content="root fact", scope=PROJ_A)).record
    previous = root.id
    for step in range(depth):
        previous = engine.propose(AGENT_P, CandidateProposal(
            content=f"derived step {step} alpha", sources=(SourceRef(SourceKind.MEMORY, previous),), scope=PROJ_A,
            derived_from=(previous,))).record.id
    return root


def _records(engine):
    with raw_db(db_path(engine.root, USER_P)) as conn:
        return conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]


@pytest.mark.parametrize("target", ["memory", "project", "profile"])
def test_rob1_forgetting_a_chain_deeper_than_the_interpreter_stack(engine, target):
    root = _chain(engine)
    forget = {"memory": ForgetTarget("memory", root.id), "project": ForgetTarget("project", "proj-a"),
              "profile": ForgetTarget("profile", USER_P.partition.profile)}[target]
    receipt = engine.forget(USER_P, forget)
    assert receipt.receipt.status == "ok"
    if target == "memory":
        assert receipt.deleted.get("memories") == 1 and receipt.deleted.get("derived_memories") == DEPTH
    assert engine.list(USER_P, lifecycles=None) == [] and _records(engine) == 0


@pytest.mark.parametrize("recover", ["reconcile", "reopen"])
def test_rob1_an_unapplied_deep_forget_recovers(make_engine, monkeypatch, recover):
    engine = make_engine()
    root = _chain(engine)

    def overflow(self, *args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded")  # what the recursive cascade raised

    monkeypatch.setattr(ForgettingService, "apply_tombstone", overflow)
    with pytest.raises(RecursionError):
        engine.forget(USER_P, ForgetTarget("memory", root.id))
    monkeypatch.undo()
    ctx = engine._partitions[USER_P.partition.partition_id]  # (partition_context() would reconcile)
    assert ctx.partition.ledger.head()[0] > ctx.partition.deletion_generation()  # the entry is durable, unapplied
    if recover == "reconcile":
        assert engine.reconcile(USER_P)["reapplied"] == 1
    else:
        engine.close()
        engine = make_engine()
    assert engine.list(USER_P, lifecycles=None) == [] and _records(engine) == 0
    assert json.dumps(engine.reconcile(USER_P))  # healthy: nothing left to apply
