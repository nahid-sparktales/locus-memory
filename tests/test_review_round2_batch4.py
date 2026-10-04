"""Regression tests for review round 2, batch 4 (reproduced robustness defects).

R2-ROB-4  validated mappings had no nesting-depth bound: an INGEST-only agent could archive a deeply
          nested attachment that made every later history search over its scope raise RecursionError
          (also after reopen); on 3.10 deep input raised a raw RecursionError from validation.
R2-ROB-5  the history projection top-up (messages appended after a search had hydrated) ignored
          max_projection_bytes, the hydration batch size and the deadline: one search loaded every
          appended row in a single query and reported COMPLETE.
R2-ROB-6  build_context honoured deadline_ms only at the ranking stage: loading, planning and
          rendering every approved record (each candidate refused by a full slice was still
          rendered and tokenized) ran unbounded first.
R2-ROB-7  remember() decrypted every approved record of the scope inside its write transaction
          (possible_conflicts): O(N) per write while every other writer waited.
R2-ROB-8  episode records had no byte bound and every attempt kept a full sealed copy of the whole
          episode in record_revisions, so storage grew quadratically with the number of attempts.

Each test reproduces the report's scenario and asserts the correct outcome. All data lives in
pytest tmp dirs.
"""
from __future__ import annotations

import random
import sys
import threading
import time

import pytest

from conftest import access_for
from foundation_support import count, db_path
from locus_memory import core as core_mod
from locus_memory.context import compiler as compiler_mod
from locus_memory.context.compiler import R_LOAD_DEADLINE, R_SELECT_DEADLINE
from locus_memory.errors import ValidationError
from locus_memory.history import archive as archive_mod
from locus_memory.history.archive import UNREADABLE_ATTACHMENT, HistoryArchive
from locus_memory.host import EngineConfig
from locus_memory.learning import episodes as episodes_mod
from locus_memory.models import (
    Actor,
    ContextRequest,
    EpisodeReport,
    IngestionEvent,
    Lifecycle,
    MemoryKind,
    MemoryRecord,
    Operation,
    RememberRequest,
    ResultStatus,
    Scope,
    SourceKind,
    SourceRef,
    Validity,
)
from locus_memory.storage.partition import new_id
from locus_memory.storage.records import UNREADABLE_MAPPING, RecordStore
from locus_memory.validation import MAX_MAPPING_DEPTH, check_mapping

PROJ_A = Scope.of(project="proj-a")
PROJ_B = Scope.of(project="proj-b")
USER = access_for(projects=("proj-a", "proj-b"), agents=("agent-1",), repositories=("repo-a",))
AGENT = access_for(actor=Actor.AGENT, projects=("proj-a",), agents=("agent-1",), repositories=("repo-a",),
                   operations={Operation.READ, Operation.PROPOSE, Operation.INGEST})


def _nest(depth: int) -> dict:
    """A mapping ``depth`` levels deep ({"a": {"a": ... {}}})."""
    value: dict = {}
    for _ in range(depth - 1):
        value = {"a": value}
    return value


def _event(seq: int, text: str, *, session: str = "s1", scope: Scope = PROJ_A, **extra) -> IngestionEvent:
    return IngestionEvent(event_id=f"{session}-e{seq}", session_ref=session, sequence=seq, role="user", text=text,
                          occurred_at=1_700_000_000.0 + seq, scope=scope, **extra)


def _seed_approved(engine, access, n: int, scope: Scope, *, content=None, title=None) -> list[str]:
    """``n`` approved records written in one transaction (setup only; remember() is exercised
    separately)."""
    ctx = engine.partition_context(access.partition)
    now = ctx.clock()
    ids = []
    with ctx.partition.db.write() as conn:
        for i in range(n):
            at = now - n + i
            record = MemoryRecord(
                id=new_id("m"), revision=1, kind=MemoryKind.FACT, lifecycle=Lifecycle.APPROVED, scope=scope,
                title=title(i) if title else f"seeded {i}",
                content=content(i) if content else f"seeded fact number {i}",
                sources=(SourceRef(SourceKind.USER_ACTION, f"seed-{new_id()}", observed_at=at),),
                created_at=at, updated_at=at, event_time=at, ingested_at=at)
            ctx.records.write(conn, record, change="created", actor=Actor.USER, expected_revision=None,
                              generation=ctx.partition.bump(conn))
            ids.append(record.id)
    return ids


# =========================================================================== R2-ROB-4
_MAPPING_FIELDS = [
    pytest.param(lambda d: SourceRef(SourceKind.DOCUMENT, "doc-1", locator=d), id="SourceRef.locator"),
    pytest.param(lambda d: Validity(applicability=d), id="Validity.applicability"),
    pytest.param(lambda d: IngestionEvent(event_id="e1", session_ref="s1", sequence=0, role="user", text="x",
                                          occurred_at=1.0, host_refs=d), id="IngestionEvent.host_refs"),
    pytest.param(lambda d: IngestionEvent(event_id="e1", session_ref="s1", sequence=0, role="user", text="x",
                                          occurred_at=1.0, attachments=(d,)), id="IngestionEvent.attachments"),
    pytest.param(lambda d: EpisodeReport(episode_id="ep-1", task_ref="t1", attempt_ref="a1", objective="o",
                                         environment=d), id="EpisodeReport.environment"),
    pytest.param(lambda d: EpisodeReport(episode_id="ep-1", task_ref="t1", attempt_ref="a1", objective="o",
                                         usage=d), id="EpisodeReport.usage"),
]


@pytest.mark.parametrize("make", _MAPPING_FIELDS)
@pytest.mark.parametrize("depth", [MAX_MAPPING_DEPTH + 1, 1_500])
def test_rob4_a_too_deep_mapping_is_a_validation_error(make, depth):
    # 1,500 levels is ~10.5 KB (under the 16 KB size bound): it used to be accepted on 3.14 and
    # raised a raw RecursionError from json.dumps on 3.10.
    with pytest.raises(ValidationError, match="nested too deeply"):
        make(_nest(depth))


@pytest.mark.parametrize("make", _MAPPING_FIELDS)
def test_rob4_mappings_within_the_depth_bound_are_accepted(make):
    make(_nest(MAX_MAPPING_DEPTH))
    make({"a": [1, {"b": [2, 3]}], "c": "d"})


def test_rob4_lists_count_towards_the_depth_and_recursion_never_escapes():
    value: list = []
    for _ in range(5_000):
        value = [value]
    with pytest.raises(ValidationError):
        check_mapping({"k": value}, "locator")
    cyclic: dict = {}
    cyclic["self"] = cyclic  # a cycle is just infinitely deep
    with pytest.raises(ValidationError):
        check_mapping(cyclic, "locator")


def test_rob4_an_ingest_only_agent_cannot_poison_history_search(make_engine):
    engine = make_engine()
    engine.ingest_event(USER, _event(0, "hello normal"))
    assert engine.search_history(USER, "hello").status == ResultStatus.COMPLETE
    with pytest.raises(ValidationError, match="nested too deeply"):
        IngestionEvent(event_id="e1", session_ref="s2", sequence=0, role="tool", text="tool output",
                       occurred_at=2.0, scope=PROJ_A, attachments=(_nest(990),))
    with pytest.raises(ValidationError):
        engine.services(AGENT).history.ingest_batch(AGENT, [{
            "event_id": "e1", "session_ref": "s2", "sequence": 0, "role": "tool", "text": "tool output",
            "occurred_at": 2.0, "scope": PROJ_A.as_dict(), "attachments": [_nest(990)]}])
    with pytest.raises(ValidationError):
        engine.remember(USER, RememberRequest(content="x fact", scope=PROJ_A, sources=(
            SourceRef(SourceKind.DOCUMENT, "doc-1", locator=_nest(1_500)),)))
    result = engine.search_history(USER, "hello")
    assert result.status == ResultStatus.COMPLETE and len(result.hits) == 1


def _archive_deep_row(engine, depth: int) -> str:
    """Archive a message whose attachment is ``depth`` levels deep, as a build without the depth
    bound could (validation is bypassed; the stack is raised only while writing it)."""
    archive = engine.services(USER).history
    event = _event(1, "tool output with a deep attachment", attachments=({"ref": "ok"},))
    object.__setattr__(event, "attachments", (_nest(depth), {"ref": "fine"}))
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(limit, 20_000))
    try:
        receipt = archive.ingest_batch(USER, [event])[0]
    finally:
        sys.setrecursionlimit(limit)
    return receipt.message_id


# Deep enough that the old read path (to_dict -> to_jsonable, one frame per level on 3.12+, two on
# 3.10) exceeds the default recursion limit, shallow enough for each interpreter's C json codec.
_POISON_DEPTH = 1_500 if sys.version_info >= (3, 12) else 600


def test_rob4_a_preexisting_deep_row_does_not_break_search_browse_or_context(make_engine, root):
    engine = make_engine()
    engine.ingest_event(USER, _event(0, "hello normal"))
    deep_id = _archive_deep_row(engine, _POISON_DEPTH)
    for _reopened in range(2):
        result = engine.search_history(USER, "hello OR tool")
        assert result.status in (ResultStatus.COMPLETE, ResultStatus.INSUFFICIENT_EVIDENCE), result.coverage
        result = engine.search_history(USER, "deep attachment")
        assert result.status == ResultStatus.COMPLETE
        [hit] = result.hits
        assert hit.handle == deep_id
        # The unservable attachment is replaced by a content-free marker; the others are kept.
        assert hit.message.attachments == (UNREADABLE_ATTACHMENT, {"ref": "fine"})
        hit.to_json()  # every later reader can serialize it
        browsed = engine.browse_history(USER, "s1")
        assert [m.message_id for m in browsed["messages"]][-1] == deep_id
        assert browsed["messages"][-1].attachments[0] == UNREADABLE_ATTACHMENT
        packet = engine.build_context(USER, ContextRequest(query="deep attachment", token_allowance=2000,
                                                           include_history=True))
        assert compiler_mod.R_HISTORY_FAILED not in packet.coverage.partial_reasons
        assert deep_id in packet.history_handles
        engine.close()
        engine = make_engine()  # persisted rows: the same after reopen


def test_rob4_a_stored_record_with_an_over_deep_mapping_stays_readable(make_engine):
    # A build without the depth bound accepted a 40-level locator / applicability; the bound must
    # not make that (authenticated) record unreadable - only the mapping is withheld.
    engine = make_engine()
    source = SourceRef(SourceKind.DOCUMENT, "doc-1", locator={"page": 1})
    object.__setattr__(source, "locator", _nest(MAX_MAPPING_DEPTH + 8))
    validity = Validity(applicability={"os": "mac"})
    object.__setattr__(validity, "applicability", _nest(MAX_MAPPING_DEPTH + 8))
    ctx = engine.partition_context(USER.partition)
    now = ctx.clock()
    record = MemoryRecord(id=new_id("m"), revision=1, kind=MemoryKind.FACT, lifecycle=Lifecycle.APPROVED,
                          scope=PROJ_A, title="deploy notes", content="deploys run on fridays", sources=(source,),
                          validity=validity, created_at=now, updated_at=now)
    with ctx.partition.db.write() as conn:
        ctx.records.write(conn, record, change="created", actor=Actor.USER, expected_revision=None,
                          generation=ctx.partition.bump(conn))
    stored = engine.get(USER, record.id)
    assert stored.sources[0].locator == UNREADABLE_MAPPING
    assert stored.validity.applicability == UNREADABLE_MAPPING
    assert record.id in [r.id for r in engine.list(USER)]
    packet = engine.build_context(USER, ContextRequest(query="deploys", token_allowance=2_000))
    assert record.id in [item.record_id for item in packet.items]


def test_rob4_an_unreadable_row_is_skipped_and_reported_not_fatal(make_engine, monkeypatch):
    engine = make_engine()
    archive = engine.services(USER).history
    ids = [r.message_id for r in archive.ingest_batch(USER, [_event(i, f"needle {i}") for i in range(3)])]
    original = HistoryArchive._open_message

    def open_message(self, row, session):
        if row["id"] == ids[1]:
            raise RecursionError("maximum recursion depth exceeded")  # e.g. decoded on another interpreter
        return original(self, row, session)

    monkeypatch.setattr(HistoryArchive, "_open_message", open_message)
    result = engine.search_history(USER, "needle")
    assert {hit.handle for hit in result.hits} == {ids[0], ids[2]}
    assert result.status == ResultStatus.PARTIAL
    assert any("could not be read" in reason for reason in result.coverage.partial_reasons)
    assert result.coverage.total == 3 and result.coverage.searched == 2
    assert archive.coverage_status(USER)["unreadable"] == 1


# =========================================================================== R2-ROB-5
_BYTE_CAP = 1 << 20
_BATCH = 10
_SIZE = 50_000


def _small_engine(make_engine, root_dir=None):
    return make_engine(config=EngineConfig(max_projection_bytes=_BYTE_CAP, history_hydration_batch=_BATCH),
                       root_dir=root_dir)


def _append_large(engine, start: int, n: int, size: int = _SIZE) -> None:
    filler = ("lorem ipsum dolor sit amet consectetur " * (size // 40 + 1))[:size]
    engine.services(USER).history.ingest_batch(USER, [_event(j, f"{filler} {j}") for j in range(start, start + n)])


def _projection(engine):
    archive = engine.services(USER).history
    return archive._projections[USER.grants.fingerprint()]


def test_rob5_top_up_respects_the_projection_byte_cap(make_engine):
    engine = _small_engine(make_engine)
    engine.ingest_event(USER, _event(0, "hello world first message"))
    assert engine.search_history(USER, "hello").status == ResultStatus.COMPLETE and _projection(engine).exhausted
    _append_large(engine, 1, 100)  # ~5 MB appended after the projection was fully hydrated
    result = engine.search_history(USER, "hello")
    proj = _projection(engine)
    # It used to load all 101 rows (~4.9 MB, 4.7x the cap) and report COMPLETE.
    assert proj.bytes <= _BYTE_CAP + 2 * _SIZE
    assert proj.hydrated < 101
    assert result.status == ResultStatus.PARTIAL
    assert any("max_projection_bytes" in reason for reason in result.coverage.partial_reasons)
    assert result.coverage.missing and result.coverage.searched == proj.hydrated


class _AlwaysExpired:
    def __init__(self, ms, clock=None):
        pass

    expired = True

    def remaining_s(self):
        return 0.0


def test_rob5_top_up_honours_an_expired_deadline_and_later_searches_resume(make_engine, monkeypatch):
    engine = make_engine(config=EngineConfig(history_hydration_batch=_BATCH))
    engine.ingest_event(USER, _event(0, "hello world first message"))
    engine.search_history(USER, "hello")
    assert _projection(engine).exhausted
    _append_large(engine, 1, 60, size=2_000)
    with monkeypatch.context() as patch:
        patch.setattr(archive_mod, "Deadline", _AlwaysExpired)
        result = engine.search_history(USER, "hello", deadline_ms=1)
    # At most one batch (it used to load all 60 appended rows and report COMPLETE).
    assert _projection(engine).hydrated == 1 + _BATCH
    assert result.status == ResultStatus.PARTIAL
    assert any("deadline" in reason for reason in result.coverage.partial_reasons)
    result = engine.search_history(USER, "hello")  # no deadline: resumes where it stopped
    assert result.status == ResultStatus.COMPLETE and _projection(engine).hydrated == 61


def test_rob5_initial_hydration_stops_at_the_byte_cap_within_a_batch(make_engine):
    # One default-sized batch (2,000 rows) of 50 KB messages is ~100 MB: the cap now applies per row.
    engine = make_engine(config=EngineConfig(max_projection_bytes=_BYTE_CAP))
    _append_large(engine, 0, 120)
    result = engine.search_history(USER, "lorem")
    proj = _projection(engine)
    assert proj.bytes <= _BYTE_CAP + 2 * _SIZE and proj.hydrated < 120
    assert result.status == ResultStatus.PARTIAL and not proj.exhausted


def test_rob5_top_up_runs_in_bounded_batches_and_catches_up(make_engine, monkeypatch):
    engine = make_engine(config=EngineConfig(history_hydration_batch=_BATCH))
    engine.ingest_event(USER, _event(0, "hello world first message"))
    engine.search_history(USER, "hello")
    _append_large(engine, 1, 45, size=500)
    limits = []
    original = HistoryArchive._top_up_batch

    def batch(self, conn, proj, grants, limit):
        limits.append(limit)
        if len(limits) == 2:  # a chat keeps appending (another thread) while the top-up runs
            writer = threading.Thread(target=engine.services(USER).history.ingest_batch,
                                      args=(USER, [_event(99, "hello appended meanwhile")]))
            writer.start()
            writer.join(10)
        return original(self, conn, proj, grants, limit)

    monkeypatch.setattr(HistoryArchive, "_top_up_batch", batch)
    result = engine.search_history(USER, "hello")
    assert result.status == ResultStatus.COMPLETE and _projection(engine).hydrated == 47
    assert len(limits) >= 5 and all(limit <= _BATCH for limit in limits)
    assert any(hit.message.text == "hello appended meanwhile" for hit in result.hits)


# =========================================================================== R2-ROB-6
_BIG = "x" * 1_500


def _count_renders(monkeypatch) -> list[int]:
    renders = [0]
    original = compiler_mod._Candidate._render

    def counting(self):
        renders[0] += 1
        return original(self)

    monkeypatch.setattr(compiler_mod._Candidate, "_render", counting)
    return renders


def test_rob6_selection_does_not_render_every_candidate_of_a_full_slice(make_engine, monkeypatch):
    engine = make_engine()
    _seed_approved(engine, USER, 600, PROJ_A, content=lambda i: f"fact number {i} about deployments {_BIG}")
    renders = _count_renders(monkeypatch)
    # No query: the relevance slices fall back to recency order with every member queued.
    packet = engine.build_context(USER, ContextRequest(token_allowance=2_000))
    slices = len(ContextRequest(token_allowance=1).slices)
    assert 1 <= len(packet.items) <= 5
    # It used to render (redact, scan, neutralize) and tokenize all 600 records.
    assert renders[0] <= len(packet.items) + compiler_mod._MAX_SLICE_MISSES * slices + slices
    assert packet.status == ResultStatus.COMPLETE
    assert {o.reason for o in packet.omissions} <= {"slice_cap", "budget"}
    assert len({o.record_id for o in packet.omissions}) >= 590  # still accounted for


def test_rob6_an_expired_deadline_bounds_loading_planning_and_selection(make_engine, monkeypatch):
    engine = make_engine()
    _seed_approved(engine, USER, 1_200, PROJ_A, content=lambda i: f"fact number {i} about deployments {_BIG}")
    renders = _count_renders(monkeypatch)
    decodes = [0]
    original_decode = RecordStore._decode

    def decode(self, row):
        decodes[0] += 1
        return original_decode(self, row)

    monkeypatch.setattr(RecordStore, "_decode", decode)
    monkeypatch.setattr(compiler_mod, "Deadline", _AlwaysExpired)
    packet = engine.build_context(USER, ContextRequest(query="deployments", token_allowance=2_000, deadline_ms=1))
    # It used to decrypt all 1,200 records and render every one of them before the first check.
    assert decodes[0] <= compiler_mod._LOAD_CHUNK + 1
    assert renders[0] <= len(ContextRequest(token_allowance=1).slices) + 1
    assert packet.status == ResultStatus.PARTIAL
    assert R_LOAD_DEADLINE in packet.coverage.partial_reasons
    assert packet.coverage.searched <= compiler_mod._LOAD_CHUNK and packet.coverage.total == 1_200
    assert packet.items  # the pinned/most recent records still make a (small) packet
    # A deadline-degraded packet is transient: the same request without the deadline recompiles.
    monkeypatch.undo()
    again = engine.build_context(USER, ContextRequest(query="deployments", token_allowance=2_000, deadline_ms=1))
    assert again.costs.get("cache") != "hit"


def test_rob6_selection_stops_at_the_deadline_after_one_round(make_engine, monkeypatch):
    engine = make_engine()
    _seed_approved(engine, USER, 300, PROJ_A, content=lambda i: f"tiny fact {i}")
    times = iter([False] * 10_000)

    class ExpiresDuringSelection:
        def __init__(self, ms, clock=None):
            self.ms = ms

        @property
        def expired(self):
            caller = sys._getframe(1).f_code.co_name
            return caller == "_select" or next(times)

        def remaining_s(self):
            return 10.0

    monkeypatch.setattr(compiler_mod, "Deadline", ExpiresDuringSelection)
    packet = engine.build_context(USER, ContextRequest(token_allowance=50_000, deadline_ms=1_000))
    assert R_SELECT_DEADLINE in packet.coverage.partial_reasons and packet.status == ResultStatus.PARTIAL
    assert 1 <= len(packet.items) <= len(ContextRequest(token_allowance=1).slices)
    monkeypatch.undo()
    full = engine.build_context(USER, ContextRequest(token_allowance=50_000))
    assert full.status == ResultStatus.COMPLETE and len(full.items) > len(packet.items)


def test_rob6_a_real_deadline_is_honoured_within_a_small_multiple(make_engine):
    engine = make_engine()
    _seed_approved(engine, USER, 3_000, PROJ_A, content=lambda i: f"fact number {i} about deployments {_BIG}")
    engine.remember(USER, RememberRequest(content="generation bump", scope=PROJ_A))
    started = time.perf_counter()
    packet = engine.build_context(USER, ContextRequest(query="deployments", token_allowance=2_000, deadline_ms=50))
    elapsed = time.perf_counter() - started
    # It took ~1.3 s for 3,000 records (36x the deadline). Generous bound for slow CI machines.
    assert elapsed < 0.6, elapsed
    assert packet.status == ResultStatus.PARTIAL and packet.items


# =========================================================================== R2-ROB-7
def _count_conflict_decodes(monkeypatch) -> dict:
    state = {"in_scan": False, "decodes": 0}
    original_decode = RecordStore._decode
    original_scan = core_mod.CoreService.possible_conflicts

    def decode(self, row):
        if state["in_scan"]:
            state["decodes"] += 1
        return original_decode(self, row)

    def scan(self, *args, **kwargs):
        state["in_scan"] = True
        try:
            return original_scan(self, *args, **kwargs)
        finally:
            state["in_scan"] = False

    monkeypatch.setattr(RecordStore, "_decode", decode)
    monkeypatch.setattr(core_mod.CoreService, "possible_conflicts", scan)
    return state


def test_rob7_remember_decrypts_a_bounded_number_of_records_in_its_write_transaction(make_engine, monkeypatch):
    engine = make_engine()
    limit = core_mod.CONFLICT_SCAN_LIMIT
    _seed_approved(engine, USER, limit + 100, PROJ_A, title=lambda i: f"alpha{i} beta{i}")
    _seed_approved(engine, USER, 300, PROJ_B, title=lambda i: f"zeta omega {i}")  # another scope
    state = _count_conflict_decodes(monkeypatch)
    result = engine.remember(USER, RememberRequest(content="totally new content", title="zeta omega",
                                                   scope=PROJ_A))
    # It used to decrypt every approved record of the scope (and of every other granted scope).
    assert state["decodes"] <= limit + 2
    assert result.receipt.details["possible_conflicts"] == []
    assert core_mod.CONFLICT_SCAN_LIMITATION in result.receipt.limitations
    # The bound does not grow with the scope.
    _seed_approved(engine, USER, 300, PROJ_A, title=lambda i: f"gamma{i} delta{i}")
    state["decodes"] = 0
    engine.remember(USER, RememberRequest(content="another new content", title="zeta omega", scope=PROJ_A))
    assert state["decodes"] <= limit + 2


def test_rob7_recent_same_topic_records_are_still_reported(make_engine, monkeypatch):
    engine = make_engine()
    _seed_approved(engine, USER, 50, PROJ_A, title=lambda i: f"alpha{i} beta{i}")
    _seed_approved(engine, USER, 50, PROJ_B, title=lambda i: "deploy window friday")
    [same_topic] = _seed_approved(engine, USER, 1, PROJ_A, title=lambda i: "deploy window friday",
                                  content=lambda i: "deploys happen on friday")
    state = _count_conflict_decodes(monkeypatch)
    result = engine.remember(USER, RememberRequest(content="deploys happen on monday",
                                                   title="deploy window monday", scope=PROJ_A))
    assert result.receipt.details["possible_conflicts"] == [same_topic]  # proj-b's are another scope
    assert core_mod.CONFLICT_SCAN_LIMITATION not in result.receipt.limitations  # the scope was scanned whole
    assert state["decodes"] <= 52  # only proj-a's approved records (50 + 1 + the new one)
    request = RememberRequest(content="deploys happen on tuesday", title="deploy window tuesday", scope=PROJ_A)
    first = engine.remember(USER, request, idempotency_key="k-1")
    again = engine.remember(USER, request, idempotency_key="k-1")
    assert again.receipt.idempotent_replay and again.receipt.limitations == first.receipt.limitations
    assert again.receipt.details["possible_conflicts"] == first.receipt.details["possible_conflicts"]


# =========================================================================== R2-ROB-8
def _blob(rnd: random.Random, n: int) -> str:
    words = ["alpha", "beta", "gamma", "delta", "omega", "sigma", "kappa", "theta"]
    return " ".join(rnd.choice(words) + str(rnd.randint(0, 99_999)) for _ in range(n // 6))[:n]


def _report(rnd: random.Random, attempt: int, *, items: int, chars: int = 1_990) -> EpisodeReport:
    return EpisodeReport(
        episode_id="ep-1", task_ref="task-1", attempt_ref=f"att-{attempt}", scope=PROJ_A,
        objective=_blob(rnd, 300), approach=_blob(rnd, 500),
        failure_modes=tuple(_blob(rnd, chars) for _ in range(items)),
        uncertainties=tuple(_blob(rnd, chars) for _ in range(items)),
    )


def test_rob8_an_oversized_report_is_refused(make_engine):
    engine = make_engine()
    rnd = random.Random(1)
    # Within every per-field limit (256 items x 2,000 chars) but ~1 MB of narrative in one report.
    report = _report(rnd, 1, items=256)
    with pytest.raises(ValidationError, match="narrative"):
        engine.record_episode(AGENT, report)
    assert engine.list_episodes(USER) == []


def _episode_sizes(root, access) -> tuple[int, int, int, int]:
    path = db_path(root, access)
    record_id_sql = "(SELECT record_id FROM episodes WHERE episode_id='ep-1')"
    current = count(path, f"SELECT length(ciphertext) FROM records WHERE id={record_id_sql}")
    revisions = count(path, f"SELECT COALESCE(SUM(length(ciphertext)), 0) FROM record_revisions"
                            f" WHERE record_id={record_id_sql}")
    kept = count(path, f"SELECT COUNT(*) FROM record_revisions WHERE record_id={record_id_sql} AND purged=0")
    total = count(path, f"SELECT COUNT(*) FROM record_revisions WHERE record_id={record_id_sql}")
    return current, revisions, kept, total


def test_rob8_episode_storage_is_bounded_and_grows_linearly(make_engine, root, monkeypatch):
    monkeypatch.setattr(episodes_mod, "MAX_EPISODE_BYTES", 1_500_000)
    engine = make_engine()
    rnd = random.Random(2)
    sizes = []
    attempt = 0
    with pytest.raises(ValidationError, match="new episode_id"):
        while attempt < 40:
            attempt += 1
            episode, _receipt = engine.record_episode(AGENT, _report(rnd, attempt, items=30))  # ~120 KB each
            assert len(episode.attempts) == attempt
            current, revisions, kept, total = _episode_sizes(root, USER)
            sizes.append(current)
            # Only the current revision keeps a payload: revisions no longer hold a full copy per
            # attempt (they used to sum to ~the sum of every earlier record size).
            assert kept == 1 and total >= attempt
            assert revisions <= current
    assert 2 <= attempt - 1 < 40  # several attempts fit, then the budget refuses the next one
    assert sizes[-1] <= 1_500_000 + 64 * 1024
    episode = engine.get_episode(USER, "ep-1")
    assert len(episode.attempts) == attempt - 1  # the refused attempt left nothing behind
    # Re-reporting an attempt replaces it (it does not add to the episode).
    before = _episode_sizes(root, USER)[0]
    engine.record_episode(AGENT, _report(random.Random(3), 1, items=1))
    assert _episode_sizes(root, USER)[0] < before
