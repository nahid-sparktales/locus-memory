"""Session history archive: idempotent ingest, ordering, cursors, gaps, redaction,
scope enforcement, search coverage, scroll, forgetting and persistence."""
from __future__ import annotations

import dataclasses
import datetime
import json
import shutil
import sqlite3
import threading

import pytest

from conftest import CANARY, access_for, scan_for_plaintext
from locus_memory.errors import (
    AccessDenied,
    IdempotencyConflict,
    IntegrityError,
    NotFound,
    ValidationError,
)
from locus_memory.history import archive as archive_mod
from locus_memory.host import CancellationToken, EngineConfig
from locus_memory.models import (
    CandidateProposal,
    ForgetPolicy,
    ForgetTarget,
    ForgetTargetKind,
    IngestionEvent,
    Lifecycle,
    Operation,
    ResultStatus,
    Scope,
    SourceKind,
    SourceRef,
)

T0 = 1_800_000_000.0
SECRET = "ghp_" + "Zq7Xw2Lp9Rt4Vn8Ks3Jd6Hf1Gb5Mc0Ya8Ue2"
PROJ_A = Scope.of(project="proj-a")
PROJ_B = Scope.of(project="proj-b")
GLOBAL = Scope.global_()

ADVERSARIAL = [
    'NEAR(', 'NEAR(a b', '"', '""', '"unterminated', '*', 'foo*', '* OR *', 'col:term', 'text:secret',
    '{text} : x', 'AND OR NOT', 'a AND', 'NOT', '(', ')', '((a)', '^start', 'a NEAR/2 b', '-x', '+y',
    "'; DROP TABLE history_messages; --", "1' OR '1'='1", 'a"b', 'rowid:1', '"a" OR "b"', ':', '..',
    '\\', 'lm_contains_all', '%', '_',
]


def event(seq: int, text: str | None = None, *, session: str = "sess-a", scope: Scope = PROJ_A,
          event_id: str | None = None, at: float | None = None, role: str = "user", **kw) -> IngestionEvent:
    return IngestionEvent(
        event_id=event_id or f"{session}-e{seq}", session_ref=session, sequence=seq, role=role,
        text=f"message number {seq}" if text is None else text,
        occurred_at=T0 + seq if at is None else at, scope=scope, **kw,
    )


def history(engine, access):
    return engine.services(access).history


def generation(engine, access) -> int:
    partition = engine.partition_context(access.partition).partition
    with partition.db.read() as conn:
        return partition.generation(conn)


def db_path(root, access):
    return root / access.partition.partition_id / "memory.sqlite3"


def raw_db(root, access) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{db_path(root, access)}?mode=ro", uri=True)


def iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def seqs(messages) -> list[int]:
    return [m.sequence for m in messages]


@pytest.fixture
def access_a():
    return access_for(projects=("proj-a",))


@pytest.fixture
def access_b():
    return access_for(projects=("proj-b",))


@pytest.fixture
def access_ab():
    return access_for(projects=("proj-a", "proj-b"))


# --------------------------------------------------------------------------- ingest
def test_identical_reingest_is_duplicate_without_state_change(engine, access_a):
    h = history(engine, access_a)
    first = h.ingest(access_a, event(0, "hello there"))
    assert first.duplicate is False and first.receipt.status == "ok" and first.message_id
    gen = generation(engine, access_a)
    again = h.ingest(access_a, event(0, "hello there"))
    assert again.duplicate is True and again.message_id == first.message_id
    assert again.receipt.idempotent_replay and again.receipt.status == "noop"
    assert generation(engine, access_a) == gen
    # Another producer re-delivering the same event (different source/host_refs) is the same event.
    other = dataclasses.replace(event(0, "hello there"), source="importer", host_refs={"line": 7})
    assert h.ingest(access_a, other).duplicate is True
    assert seqs(h.browse(access_a, "sess-a")["messages"]) == [0]


def test_message_id_and_source_token_are_deterministic(engine, root, access_a):
    h = history(engine, access_a)
    receipt = h.ingest(access_a, event(0))
    ctx = engine.partition_context(access_a.partition)
    expected = "h" + ctx.partition.token("message", "sess-a|sess-a-e0")[:30]
    assert receipt.message_id == expected == h.message_id_for("sess-a", "sess-a-e0")
    with raw_db(root, access_a) as conn:
        token = conn.execute("SELECT source_token FROM history_messages WHERE id=?", (expected,)).fetchone()[0]
    assert token == ctx.records.source_token(f"message:{expected}")


def test_same_event_id_with_different_content_conflicts(engine, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "original text"))
    with pytest.raises(IdempotencyConflict):
        h.ingest(access_a, event(0, "edited text"))
    with pytest.raises(IdempotencyConflict):  # same event, now flagged as an injection
        h.ingest(access_a, event(0, "original text", is_memory_injection=True))
    with pytest.raises(IdempotencyConflict):  # a different event cannot reuse the sequence
        h.ingest(access_a, event(0, "original text", event_id="another-event"))
    messages = h.browse(access_a, "sess-a")["messages"]
    assert [m.text for m in messages] == ["original text"]


def test_out_of_order_arrival_gives_deterministic_order(engine, access_a):
    h = history(engine, access_a)
    for seq in (3, 0, 2):
        h.ingest(access_a, event(seq))
    page = h.browse(access_a, "sess-a")
    assert seqs(page["messages"]) == [0, 2, 3]
    assert page["gaps"] == [{"from_seq": 1, "to_seq": 1, "reason": "not_received"}]
    assert h.cursor(access_a, "host", "sess-a") == 0
    h.ingest(access_a, event(1))
    page = h.browse(access_a, "sess-a")
    assert seqs(page["messages"]) == [0, 1, 2, 3]
    assert page["gaps"] == []
    assert h.cursor(access_a, "host", "sess-a") == 3
    # The same events delivered in order to another session produce the same ordering.
    for seq in range(4):
        h.ingest(access_a, event(seq, session="sess-in-order"))
    assert [m.text for m in h.browse(access_a, "sess-in-order")["messages"]] == \
        [m.text for m in page["messages"]]


def test_gaps_are_recorded_split_and_closed(engine, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(0))
    h.ingest(access_a, event(5))
    assert h.browse(access_a, "sess-a")["gaps"] == [{"from_seq": 1, "to_seq": 4, "reason": "not_received"}]
    h.ingest(access_a, event(3))
    gaps = h.browse(access_a, "sess-a")["gaps"]
    assert gaps == [{"from_seq": 1, "to_seq": 2, "reason": "not_received"},
                    {"from_seq": 4, "to_seq": 4, "reason": "not_received"}]
    window = h.scroll(access_a, h.message_id_for("sess-a", "sess-a-e5"), before=1, after=1)
    assert seqs(window["messages"]) == [3, 5]
    assert {"from_seq": 4, "to_seq": 4, "reason": "not_received"} in window["gaps"]
    assert h.cursor(access_a, "host", "sess-a") == 0
    for seq in (1, 2, 4):
        h.ingest(access_a, event(seq))
    assert h.browse(access_a, "sess-a")["gaps"] == []
    assert h.cursor(access_a, "host", "sess-a") == 5


def test_stream_starting_above_zero_reports_leading_gap(engine, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(2))
    assert h.cursor(access_a, "host", "sess-a") is None
    assert h.browse(access_a, "sess-a")["gaps"] == [{"from_seq": 0, "to_seq": 1, "reason": "not_received"}]


def test_cursors_are_per_producer_and_durable_across_restart(make_engine, access_a, access_b):
    engine = make_engine()
    h = history(engine, access_a)
    for seq in range(3):
        h.ingest(access_a, dataclasses.replace(event(seq), source="hook"))
    assert h.cursor(access_a, "hook", "sess-a") == 2
    assert h.cursor(access_a, "importer", "sess-a") is None
    assert h.cursor(access_a, "hook", "sess-unknown") is None
    assert h.cursor(access_b, "hook", "sess-a") is None  # not visible to another scope
    engine.close()
    reopened = make_engine()
    assert history(reopened, access_a).cursor(access_a, "hook", "sess-a") == 2
    history(reopened, access_a).ingest(access_a, dataclasses.replace(event(3), source="hook"))
    assert history(reopened, access_a).cursor(access_a, "hook", "sess-a") == 3


def test_secrets_are_redacted_before_storage_and_not_searchable(engine, root, access_a):
    assert len(SECRET) == 40
    h = history(engine, access_a)
    attachment = {"ref": "att://diagram-1", "note": f"token {SECRET}", "access": {"project": "proj-a"}}
    receipt = h.ingest(access_a, event(0, f"my token is {SECRET} keep it safe {CANARY}", role="tool",
                                       tool_name="shell", attachments=(attachment,)))
    assert receipt.redactions == ("github_token",)
    assert receipt.receipt.details["redactions"] == ["github_token"]
    message = h.browse(access_a, "sess-a")["messages"][0]
    assert SECRET not in message.text and "[REDACTED:github_token]" in message.text
    assert SECRET not in json.dumps(message.to_dict())
    assert message.redactions == ("github_token",)
    assert message.attachments[0]["access"] == {"project": "proj-a"}
    assert message.attachments[0]["ref"] == "att://diagram-1"
    assert h.search(access_a, SECRET).hits == ()
    assert h.search(access_a, SECRET[4:]).hits == ()
    assert h.search(access_a, CANARY).hits  # ordinary text stays searchable
    window = h.scroll(access_a, receipt.message_id)
    assert window["gaps"] == [{"from_seq": 0, "to_seq": 0, "reason": "redacted",
                               "message_id": receipt.message_id, "categories": ["github_token"]}]
    assert scan_for_plaintext(root, SECRET) == []
    assert scan_for_plaintext(root, SECRET[4:]) == []
    engine.close()
    assert scan_for_plaintext(root, SECRET) == []
    assert scan_for_plaintext(root, CANARY) == []


def test_injected_memory_and_generated_summaries_are_not_evidence(engine, access_a, agent_access):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "real user message"))
    injected = h.ingest(access_a, event(1, "<memory-context>user likes tabs</memory-context>",
                                        is_memory_injection=True))
    assert injected.skipped_reason == "memory_injection"
    assert injected.message_id is None and injected.duplicate is False
    summary = h.ingest(access_a, event(2, "Summary: user likes tabs", role="assistant",
                                       is_generated_summary=True))
    assert summary.skipped_reason == "generated_summary"
    h.ingest(access_a, event(3, "another real message"))
    assert h.search(access_a, "tabs").hits == ()
    page = h.browse(access_a, "sess-a")
    assert seqs(page["messages"]) == [0, 3]
    assert {"from_seq": 1, "to_seq": 1, "reason": "skipped_memory_injection"} in page["gaps"]
    assert {"from_seq": 2, "to_seq": 2, "reason": "skipped_generated_summary"} in page["gaps"]
    assert h.cursor(access_a, "host", "sess-a") == 3  # skipped events still advance the cursor
    replay = h.ingest(access_a, event(1, "<memory-context>user likes tabs</memory-context>",
                                      is_memory_injection=True))
    assert replay.duplicate and replay.skipped_reason == "memory_injection"
    # The injected block can never be cited as evidence for a candidate.
    fake = h.message_id_for("sess-a", "sess-a-e1")
    with pytest.raises(ValidationError):
        engine.propose(agent_access, CandidateProposal(
            content="User likes tabs", sources=(SourceRef(SourceKind.MESSAGE, fake),), scope=PROJ_A))


def test_ingest_requires_operation_and_granted_scope(engine, access_a, access_ab):
    h = history(engine, access_ab)
    with pytest.raises(AccessDenied):
        h.ingest(access_a, event(0, "x", session="sess-b", scope=PROJ_B))
    reader = access_for(projects=("proj-a",), operations={Operation.READ})
    with pytest.raises(AccessDenied):
        h.ingest(reader, event(0))
    with pytest.raises(AccessDenied):  # one unauthorized event fails the whole batch
        h.ingest_batch(access_a, [event(0), event(0, "y", session="sess-b", scope=PROJ_B)])
    assert h.sessions(access_ab) == []
    # A session stays bound to the scope of its first event.
    h.ingest(access_ab, event(0))
    with pytest.raises(AccessDenied):
        h.ingest(access_ab, event(1, scope=PROJ_B))
    with pytest.raises(AccessDenied):
        h.ingest(access_ab, event(1, scope=Scope.of(project="proj-a", agent="agent-1")))


def test_directly_constructed_events_are_normalized(engine, access_a, access_b):
    h = history(engine, access_a)
    loose = IngestionEvent(event_id="loose-1", session_ref="sess-a", sequence=0, role="user", text="loose",
                           occurred_at=int(T0), scope={"project": "proj-a"})  # type: ignore[arg-type]
    receipt = h.ingest(access_a, loose)
    assert receipt.message_id and h.browse(access_a, "sess-a")["messages"][0].occurred_at == T0
    with pytest.raises(AccessDenied):  # a dict scope is still checked against the grants
        h.ingest(access_b, dataclasses.replace(loose, event_id="loose-2", session_ref="sess-x"))


def test_hidden_reasoning_roles_are_rejected(engine, access_a):
    with pytest.raises(ValidationError):
        event(0, role="reasoning")
    with pytest.raises(ValidationError):
        history(engine, access_a).ingest_batch(access_a, [{
            "event_id": "e1", "session_ref": "sess-a", "sequence": 0, "role": "thinking",
            "text": "hidden", "occurred_at": T0, "scope": {"project": "proj-a"}}])


def test_ingest_batch_is_atomic_and_detects_in_batch_duplicates(engine, access_a):
    h = history(engine, access_a)
    with pytest.raises(IdempotencyConflict):
        h.ingest_batch(access_a, [event(0), event(1), event(0, "changed")])
    assert h.sessions(access_a) == []
    receipts = h.ingest_batch(access_a, [event(0), event(1), event(0)])
    assert [r.duplicate for r in receipts] == [False, False, True]
    assert receipts[0].message_id == receipts[2].message_id
    assert h.cursor(access_a, "host", "sess-a") == 1


# --------------------------------------------------------------------------- search
def test_search_is_authorized_only_including_counts(engine, access_a, access_b, access_ab):
    h = history(engine, access_ab)
    h.ingest(access_ab, event(0, "deploy pipeline alpha", session="sess-a", scope=PROJ_A))
    h.ingest(access_ab, event(0, "deploy pipeline beta", session="sess-b", scope=PROJ_B))
    h.ingest(access_ab, event(0, "deploy pipeline global", session="sess-g", scope=GLOBAL))

    result = h.search(access_a, "deploy pipeline")
    assert {hit.message.session_ref for hit in result.hits} == {"sess-a", "sess-g"}
    assert result.coverage.total == 2 and result.coverage.searched == 2
    assert result.status == ResultStatus.COMPLETE
    result_b = h.search(access_b, "deploy pipeline")
    assert {hit.message.session_ref for hit in result_b.hits} == {"sess-b", "sess-g"}
    nobody = access_for()
    assert {hit.message.session_ref for hit in h.search(nobody, "deploy").hits} == {"sess-g"}

    # Filtering on another scope's session looks exactly like filtering on a missing one.
    hidden = h.search(access_a, "deploy", session_ref="sess-b")
    missing = h.search(access_a, "deploy", session_ref="sess-nope")
    assert hidden.hits == missing.hits == ()
    assert hidden.coverage == missing.coverage and hidden.coverage.total == 0
    assert hidden.status == missing.status

    assert {s["session_ref"] for s in h.sessions(access_a)} == {"sess-a", "sess-g"}
    status = h.coverage_status(access_a)
    assert status["messages"] == 2 and status["sessions"] == 2
    assert engine.status(access_a).index["history"]["messages"] == 2

    handle_b = next(hit.handle for hit in result_b.hits if hit.message.session_ref == "sess-b")
    with pytest.raises(NotFound):
        h.scroll(access_a, handle_b)
    with pytest.raises(NotFound):
        h.browse(access_a, "sess-b")
    with pytest.raises(NotFound):
        h.scroll(access_a, "h" + "0" * 30)


def test_search_requires_read(engine, access_a):
    history(engine, access_a).ingest(access_a, event(0))
    ingest_only = access_for(projects=("proj-a",), operations={Operation.INGEST})
    with pytest.raises(AccessDenied):
        history(engine, access_a).search(ingest_only, "message")
    with pytest.raises(AccessDenied):
        history(engine, access_a).scroll(ingest_only, history(engine, access_a).message_id_for("sess-a", "sess-a-e0"))


def test_fts_queries_identifiers_and_unicode(engine, access_a):
    h = history(engine, access_a)
    texts = [
        "Please call ingest_batch() after editing parse_config.py",
        "Le café est très bon",
        "東京タワーに行った",
        "Fixed KeyError in module naïve_parser",
        "AND OR NOT are just words here",
    ]
    for seq, text in enumerate(texts):
        h.ingest(access_a, event(seq, text))

    def found(query):
        return [hit.message.sequence for hit in h.search(access_a, query).hits]

    assert found("ingest_batch") == [0]
    assert found("parse_config.py") == [0]
    assert found("ingest*") == [0]
    assert found("cafe") == [1] and found("CAFÉ") == [1]
    assert found("naive_parser") == [3] and found("keyerror") == [3]
    assert found("東京") == [2]
    assert h.search(access_a, "東京").hits[0].score_kind == "substring_recency"
    assert found("AND OR NOT") == [4]
    assert found("nonexistentterm") == []
    first = h.search(access_a, "ingest_batch").hits[0]
    assert first.score_kind == "bm25" and first.handle == first.message.message_id
    mixed = h.search(access_a, "café nonexistentterm")
    assert [hit.message.sequence for hit in mixed.hits] == [1] and mixed.hits[0].score_kind == "bm25_any_term"
    for query in ADVERSARIAL:
        result = h.search(access_a, query)
        # Complete coverage; COMPLETE only when some hit matched every content term.
        strong = any("weak_match" not in hit.flags for hit in result.hits)
        expected = ResultStatus.COMPLETE if strong else ResultStatus.INSUFFICIENT_EVIDENCE
        assert result.coverage.complete and result.status == expected, query
    # Punctuation-only input has no searchable terms: no hits (not a "recent messages" listing).
    assert h.search(access_a, "( ) * :").hits == ()


def test_query_compiler_emits_only_quoted_literals():
    for query in ADVERSARIAL + ["foo* bar", 'say "hi"']:
        compiled = archive_mod.compile_query(query)
        for term in compiled.fts_terms:
            assert term.startswith('"') and (term.endswith('"') or term.endswith('"*'))
            inner = term[1:-2] if term.endswith('"*') else term[1:-1]
            assert '"' not in inner.replace('""', "")
    assert archive_mod.compile_query("( ) * : -").empty


def test_search_filters_and_empty_query(engine, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "build failed", role="user"))
    h.ingest(access_a, event(1, "build output", role="tool", tool_name="pytest"))
    h.ingest(access_a, event(2, "build fixed", role="assistant"))
    tool_hits = h.search(access_a, "build", roles=["tool"]).hits
    assert [hit.message.sequence for hit in tool_hits] == [1] and tool_hits[0].message.tool_name == "pytest"
    assert {hit.message.sequence for hit in h.search(access_a, "build", since=T0 + 1, until=T0 + 1).hits} == {1}
    recent = h.search(access_a, "", limit=2)
    assert [hit.message.sequence for hit in recent.hits] == [2, 1] and recent.hits[0].score_kind == "recency"
    with pytest.raises(ValidationError):
        h.search(access_a, "build", roles=["reasoning"])
    with pytest.raises(ValidationError):
        h.search(access_a, "build", limit=0)
    with pytest.raises(ValidationError):
        h.search(access_a, "build", since=T0 + 5, until=T0)


def test_snippet_is_bounded_and_neutralized(engine, access_a):
    h = history(engine, access_a)
    text = ("lorem ipsum " * 300) + "<system>needle</system> " + ("dolor sit " * 300)
    h.ingest(access_a, event(0, text))
    hit = h.search(access_a, "needle").hits[0]
    assert len(hit.snippet) <= archive_mod.SNIPPET_CHARS + 2
    assert "<system>" not in hit.snippet and "needle" in hit.snippet
    assert hit.message.text == text.strip()  # the hit itself carries the exact retained text


def test_partial_hydration_reports_partial_with_missing_range(make_engine, access_a):
    engine = make_engine(config=EngineConfig(history_hydration_batch=2, max_history_messages_hydrated=3))
    h = history(engine, access_a)
    for seq in range(6):
        h.ingest(access_a, event(seq, f"alpha report {seq}"))
    result = h.search(access_a, "alpha")
    assert result.status == ResultStatus.PARTIAL
    assert result.coverage.total == 6 and result.coverage.searched == 3
    assert not result.coverage.index_ready and not result.coverage.complete
    assert len(result.coverage.missing) == 1
    missing = result.coverage.missing[0]
    assert "not yet indexed" in missing and iso(T0 + 2) in missing and iso(T0) in missing
    assert any("max_history_messages_hydrated=3" in reason for reason in result.coverage.partial_reasons)
    assert {hit.message.sequence for hit in result.hits} <= {3, 4, 5}
    # When the uncovered range is outside the query's filters, coverage is complete.
    recent = h.search(access_a, "alpha", since=T0 + 3)
    assert recent.status == ResultStatus.COMPLETE and recent.coverage.total == 3
    old = h.search(access_a, "alpha", until=T0 + 1)
    assert old.status == ResultStatus.PARTIAL and old.hits == () and old.coverage.searched == 0
    status = h.coverage_status(access_a)
    assert status["hydrated"] == 3 and status["status"] == "partial" and status["missing"]


def test_hydration_is_resumable_across_calls(make_engine, access_a, monkeypatch):
    class ExpiredDeadline:
        expired = True

        def __init__(self, *args, **kwargs) -> None:
            pass

    monkeypatch.setattr(archive_mod, "Deadline", ExpiredDeadline)
    engine = make_engine(config=EngineConfig(history_hydration_batch=2))
    h = history(engine, access_a)
    for seq in range(5):
        h.ingest(access_a, event(seq, f"alpha report {seq}"))
    first = h.search(access_a, "alpha", deadline_ms=1)
    assert first.status == ResultStatus.PARTIAL and first.coverage.searched == 2
    assert any("deadline" in reason for reason in first.coverage.partial_reasons)
    second = h.search(access_a, "alpha", deadline_ms=1)
    assert second.status == ResultStatus.PARTIAL and second.coverage.searched == 4
    third = h.search(access_a, "alpha", deadline_ms=1)
    assert third.status == ResultStatus.COMPLETE and third.coverage.searched == 5
    assert len(third.hits) == 5


def test_cancellation_keeps_progress(make_engine, access_a):
    engine = make_engine(config=EngineConfig(history_hydration_batch=2))
    h = history(engine, access_a)
    for seq in range(5):
        h.ingest(access_a, event(seq, f"alpha report {seq}"))
    token = CancellationToken()
    token.cancel()
    assert h.search(access_a, "alpha", cancel=token).status == ResultStatus.CANCELLED

    class CancelAfterFirstBatch:
        def __init__(self) -> None:
            self.checks = 0

        @property
        def cancelled(self) -> bool:
            self.checks += 1
            return self.checks > 2  # entry check + first batch pass, then cancel

    result = h.search(access_a, "alpha", cancel=CancelAfterFirstBatch())
    assert result.status == ResultStatus.CANCELLED and result.hits == ()
    assert h.coverage_status(access_a)["hydrated"] == 2
    final = h.search(access_a, "alpha")
    assert final.status == ResultStatus.COMPLETE and len(final.hits) == 5


def test_projection_rebuilt_when_generation_changes(engine, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "first entry"))
    assert h.search(access_a, "zeta").hits == ()
    h.ingest(access_a, event(1, "zeta arrives later"))
    assert [hit.message.sequence for hit in h.search(access_a, "zeta").hits] == [1]


# --------------------------------------------------------------------------- scroll
def test_scroll_boundaries_and_exact_text(engine, access_a):
    h = history(engine, access_a)
    texts = [f"line {i}:  exact   spacing\n\tkept {i} <tool>x</tool>" for i in range(10)]
    for seq, text in enumerate(texts):
        h.ingest(access_a, event(seq, text))
    handle = lambda seq: h.message_id_for("sess-a", f"sess-a-e{seq}")  # noqa: E731

    window = h.scroll(access_a, handle(5), before=2, after=2)
    assert seqs(window["messages"]) == [3, 4, 5, 6, 7]
    assert [m.text for m in window["messages"]] == texts[3:8]
    assert window["has_more_before"] and window["has_more_after"]
    start = h.scroll(access_a, handle(0), before=5, after=0)
    assert seqs(start["messages"]) == [0] and not start["has_more_before"] and start["has_more_after"]
    end = h.scroll(access_a, handle(9), before=0, after=5)
    assert seqs(end["messages"]) == [9] and end["has_more_before"] and not end["has_more_after"]
    everything = h.scroll(access_a, handle(4), before=50, after=50)
    assert [m.text for m in everything["messages"]] == texts
    assert not everything["has_more_before"] and not everything["has_more_after"]
    with pytest.raises(ValidationError):
        h.scroll(access_a, handle(5), before=51)
    with pytest.raises(ValidationError):
        h.scroll(access_a, handle(5), after=-1)
    with pytest.raises(NotFound):
        h.scroll(access_a, "not-a-handle")
    page = h.browse(access_a, "sess-a", from_seq=4, limit=3)
    assert seqs(page["messages"]) == [4, 5, 6] and page["has_more"] and page["next_seq"] == 7


# --------------------------------------------------------------------------- forgetting
def test_forget_session_removes_search_scroll_cursor_and_derived_memory(engine, root, access_a,
                                                                         agent_access):
    h = history(engine, access_a)
    first = h.ingest(access_a, event(0, "the user prefers dark roast coffee"))
    h.ingest(access_a, event(1, "brewing at ninety degrees"))
    h.ingest(access_a, event(0, "dark roast mentioned elsewhere", session="sess-other"))
    derived = engine.propose(agent_access, CandidateProposal(
        content="User prefers dark roast coffee", scope=PROJ_A,
        sources=(SourceRef(SourceKind.MESSAGE, first.message_id),)))
    assert {hit.message.session_ref for hit in h.search(access_a, "roast").hits} == {"sess-a", "sess-other"}

    receipt = engine.forget(access_a, ForgetTarget(ForgetTargetKind.SESSION, "sess-a"))
    assert receipt.deleted["messages"] == 2 and receipt.deleted["sessions"] == 1
    assert {hit.message.session_ref for hit in h.search(access_a, "roast").hits} == {"sess-other"}
    assert h.search(access_a, "ninety").hits == ()
    with pytest.raises(NotFound):
        h.scroll(access_a, first.message_id)
    with pytest.raises(NotFound):
        h.browse(access_a, "sess-a")
    assert h.cursor(access_a, "host", "sess-a") is None
    assert {s["session_ref"] for s in h.sessions(access_a)} == {"sess-other"}
    with pytest.raises(NotFound):
        engine.get(access_a, derived.record.id)
    token = engine.partition_context(access_a.partition).partition.token("session", "sess-a")
    with raw_db(root, access_a) as conn:
        for table, column in (("history_messages", "session_token"), ("history_sessions", "session_token"),
                              ("history_gaps", "session_token"), ("cursors", "stream_token")):
            assert conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {column}=?", (token,)).fetchone()[0] == 0
    # A host replay of the forgotten session is not re-archived.
    replay = h.ingest(access_a, event(0, "the user prefers dark roast coffee"))
    assert replay.skipped_reason == "forgotten" and replay.message_id is None
    assert h.search(access_a, "roast").coverage.total == 1


def test_forget_session_also_removes_memories_citing_the_session(engine, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "we agreed to ship on fridays"))
    memory = engine.propose(access_a, CandidateProposal(
        content="Team ships on Fridays", scope=PROJ_A, sources=(SourceRef(SourceKind.SESSION, "sess-a"),)))
    engine.forget(access_a, ForgetTarget(ForgetTargetKind.SESSION, "sess-a"))
    with pytest.raises(NotFound):
        engine.get(access_a, memory.record.id)


def test_forget_message_without_archive_deletion_retains_message(engine, access_a, agent_access):
    h = history(engine, access_a)
    receipts = [h.ingest(access_a, event(seq, f"fact number {seq} quokka")) for seq in range(3)]
    middle = receipts[1].message_id
    derived = engine.propose(agent_access, CandidateProposal(
        content="Quokkas are relevant", scope=PROJ_A, sources=(SourceRef(SourceKind.MESSAGE, middle),)))
    result = engine.forget(access_a, ForgetTarget(ForgetTargetKind.SOURCE, f"message:{middle}"))
    assert result.retained_by_policy.get("messages") == 1
    assert "messages" not in result.deleted
    window = h.scroll(access_a, middle, before=0, after=0)
    assert [m.text for m in window["messages"]] == ["fact number 1 quokka"]
    with pytest.raises(NotFound):
        engine.get(access_a, derived.record.id)


def test_forget_message_with_archive_deletion_records_gap(engine, access_a):
    h = history(engine, access_a)
    receipts = [h.ingest(access_a, event(seq, f"entry {seq} " + ("wombat" if seq == 1 else "koala")))
                for seq in range(3)]
    middle = receipts[1].message_id
    result = engine.forget(access_a, ForgetTarget(ForgetTargetKind.SOURCE, f"message:{middle}"),
                           policy=ForgetPolicy(delete_source_archive=True))
    assert result.deleted["messages"] == 1
    with pytest.raises(NotFound):
        h.scroll(access_a, middle)
    window = h.scroll(access_a, receipts[0].message_id, before=0, after=5)
    assert seqs(window["messages"]) == [0, 2]
    assert {"from_seq": 1, "to_seq": 1, "reason": "forgotten"} in window["gaps"]
    assert h.search(access_a, "wombat").hits == ()
    assert h.search(access_a, "koala").coverage.total == 2
    assert h.sessions(access_a)[0]["message_count"] == 2
    assert h.cursor(access_a, "host", "sess-a") == 2
    assert h.ingest(access_a, event(1, "entry 1 wombat")).skipped_reason == "forgotten"
    with pytest.raises(IdempotencyConflict):
        h.ingest(access_a, event(1, "a different event", event_id="new-event"))


def test_forgetting_another_scopes_message_is_denied(engine, access_a, access_b):
    h = history(engine, access_a)
    receipt = h.ingest(access_a, event(0, "private to project a"))
    with pytest.raises(AccessDenied):
        engine.forget(access_b, ForgetTarget(ForgetTargetKind.SOURCE, f"message:{receipt.message_id}"),
                      policy=ForgetPolicy(delete_source_archive=True))
    with pytest.raises(AccessDenied):
        engine.forget(access_b, ForgetTarget(ForgetTargetKind.SESSION, "sess-a"))
    assert h.browse(access_a, "sess-a")["messages"][0].text == "private to project a"


def test_forget_project_scope_removes_its_sessions(engine, access_ab):
    h = history(engine, access_ab)
    h.ingest(access_ab, event(0, "aardvark in a", session="sess-a", scope=PROJ_A))
    h.ingest(access_ab, event(0, "aardvark in b", session="sess-b", scope=PROJ_B))
    receipt = engine.forget(access_ab, ForgetTarget(ForgetTargetKind.PROJECT, "proj-a"))
    assert receipt.deleted["sessions"] == 1
    assert {hit.message.session_ref for hit in h.search(access_ab, "aardvark").hits} == {"sess-b"}
    assert h.ingest(access_ab, event(0, "aardvark in a", session="sess-a", scope=PROJ_A)).skipped_reason \
        == "forgotten"
    fresh = h.ingest(access_ab, event(0, "new aardvark", session="sess-a2", scope=PROJ_A))
    assert fresh.message_id is not None  # the project itself continues


def test_forget_profile_wipes_history(engine, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "something to wipe"))
    h.ingest(access_a, event(1, "injected", is_memory_injection=True))
    receipt = engine.forget(access_a, ForgetTarget(ForgetTargetKind.PROFILE, "default"))
    assert receipt.deleted["messages"] == 1
    assert h.sessions(access_a) == [] and h.coverage_status(access_a)["messages"] == 0
    assert h.cursor(access_a, "host", "sess-a") is None
    assert h.ingest(access_a, event(0, "something new")).message_id is not None  # fresh start


def test_ledger_replay_purges_a_restored_backup(make_engine, root, tmp_path, access_a):
    engine = make_engine()
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "restorable armadillo"))
    h.ingest(access_a, event(0, "kept armadillo", session="sess-keep"))
    engine.close()
    db = db_path(root, access_a)
    backup = tmp_path / "backup.sqlite3"
    shutil.copy2(db, backup)
    with sqlite3.connect(backup) as conn:  # the backup really holds the session to be forgotten
        assert conn.execute("SELECT COUNT(*) FROM history_messages").fetchone()[0] == 2

    engine = make_engine()
    engine.forget(access_a, ForgetTarget(ForgetTargetKind.SESSION, "sess-a"))
    engine.close()
    shutil.copy2(backup, db)
    for suffix in ("-wal", "-shm"):
        db.with_name(db.name + suffix).unlink(missing_ok=True)

    engine = make_engine()  # reconcile re-applies the tombstone from its token alone
    h = history(engine, access_a)
    assert {hit.message.session_ref for hit in h.search(access_a, "armadillo").hits} == {"sess-keep"}
    with pytest.raises(NotFound):
        h.browse(access_a, "sess-a")
    assert h.ingest(access_a, event(0, "restorable armadillo")).skipped_reason == "forgotten"


# --------------------------------------------------------------------------- evidence verification
def test_verify_source_through_core_propose(engine, access_a, access_ab, agent_access):
    h = history(engine, access_ab)
    good = h.ingest(access_ab, event(0, "user said tabs"))
    other = h.ingest(access_ab, event(0, "project b message", session="sess-b", scope=PROJ_B))
    ok = engine.propose(agent_access, CandidateProposal(
        content="User prefers tabs", scope=PROJ_A, sources=(SourceRef(SourceKind.MESSAGE, good.message_id),)))
    assert ok.record.lifecycle == Lifecycle.CANDIDATE
    for fabricated in ("h" + "0" * 30, "message-xyz", other.message_id):
        with pytest.raises(ValidationError):
            engine.propose(agent_access, CandidateProposal(
                content=f"Fabricated claim {fabricated}", scope=PROJ_A,
                sources=(SourceRef(SourceKind.MESSAGE, fabricated),)))
    session_ok = engine.propose(agent_access, CandidateProposal(
        content="Session-level claim", scope=PROJ_A, sources=(SourceRef(SourceKind.SESSION, "sess-a"),)))
    assert session_ok.record.lifecycle == Lifecycle.CANDIDATE
    for session_ref in ("sess-missing", "sess-b"):
        with pytest.raises(ValidationError):
            engine.propose(agent_access, CandidateProposal(
                content=f"Claim about {session_ref}", scope=PROJ_A,
                sources=(SourceRef(SourceKind.SESSION, session_ref),)))
    partition = engine.partition_context(access_a.partition).partition
    with partition.db.read() as conn:
        assert h.verify_source(conn, access_a, SourceRef(SourceKind.MESSAGE, good.message_id)) is True
        assert h.verify_source(conn, access_a, SourceRef(SourceKind.MESSAGE, other.message_id)) is False
        assert h.verify_source(conn, access_a, SourceRef(SourceKind.COMMIT, "abc123")) is None
        assert h.verify_source(conn, access_a, SourceRef(SourceKind.EPISODE, "ep1")) is None
        assert h.session_visible(conn, access_a, "sess-b") is False
        assert h.session_visible(conn, access_a, "sess-a") is True
        assert h.session_visible(conn, access_a, "sess-missing") is None


# --------------------------------------------------------------------------- confidentiality / integrity
def test_no_plaintext_on_disk_after_ingest_and_search(engine, root):
    scope_value = "proj-plaintext-scope-9e2"
    access = access_for(projects=(scope_value,))
    h = history(engine, access)
    needles = {
        "session": "sess-plaintext-ref-5d1c", "event": "evt-plaintext-id-4e8",
        "tool": "tool-plaintext-name-3a7", "path": "/Users/someone/attachment-plaintext-path-8b4.txt",
        "host_ref": "host-plaintext-ref-1f6", "producer": "producer-plaintext-label-2c9",
    }
    h.ingest(access, IngestionEvent(
        event_id=needles["event"], session_ref=needles["session"], sequence=0, role="tool",
        text=f"{CANARY} body text", occurred_at=T0, scope=Scope.of(project=scope_value),
        source=needles["producer"], tool_name=needles["tool"],
        attachments=({"ref": "file://" + needles["path"], "access": {"project": scope_value}},),
        host_refs={"transcript": needles["host_ref"]},
    ))
    hits = h.search(access, CANARY).hits
    assert hits and hits[0].message.tool_name == needles["tool"]
    h.scroll(access, hits[0].handle)
    h.browse(access, needles["session"])
    h.sessions(access)
    h.coverage_status(access)
    assert h.cursor(access, needles["producer"], needles["session"]) == 0
    for needle in [CANARY, scope_value, *needles.values()]:
        assert scan_for_plaintext(root, needle) == [], needle
    engine.close()
    for needle in [CANARY, scope_value, *needles.values()]:
        assert scan_for_plaintext(root, needle) == [], needle


def test_restart_persistence(make_engine, access_a):
    engine = make_engine()
    h = history(engine, access_a)
    ids = [h.ingest(access_a, event(seq, f"persistent narwhal {seq}")).message_id for seq in range(3)]
    engine.close()
    reopened = make_engine()
    h = history(reopened, access_a)
    result = h.search(access_a, "narwhal")
    assert result.status == ResultStatus.COMPLETE and {hit.handle for hit in result.hits} == set(ids)
    assert [m.text for m in h.browse(access_a, "sess-a")["messages"]] == \
        [f"persistent narwhal {seq}" for seq in range(3)]
    assert h.cursor(access_a, "host", "sess-a") == 2
    assert h.ingest(access_a, event(1, "persistent narwhal 1")).duplicate is True


def test_tampered_scope_index_fails_closed(engine, root, access_a, access_ab):
    h = history(engine, access_ab)
    h.ingest(access_ab, event(0, "visible pangolin", session="sess-a", scope=PROJ_A))
    h.ingest(access_ab, event(0, "hidden pangolin", session="sess-b", scope=PROJ_B))
    token = engine.partition_context(access_a.partition).partition.token("session", "sess-b")
    with sqlite3.connect(db_path(root, access_a)) as conn:  # attacker strips the scope rows
        conn.execute("DELETE FROM history_session_scopes WHERE session_token=?", (token,))
    with pytest.raises(IntegrityError):
        h.search(access_a, "pangolin")
    with pytest.raises(IntegrityError):
        h.sessions(access_a)


def test_tampered_message_metadata_fails_authentication(engine, root, access_a):
    h = history(engine, access_a)
    receipt = h.ingest(access_a, event(0, "authentic"))
    h.ingest(access_a, event(1, "second"))
    with sqlite3.connect(db_path(root, access_a)) as conn:
        conn.execute("UPDATE history_messages SET role='assistant' WHERE id=?", (receipt.message_id,))
    with pytest.raises(IntegrityError):
        h.browse(access_a, "sess-a")


def test_reseal_rotates_archive_rows_to_the_new_data_key(engine, root, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "rotate me"))
    h.ingest(access_a, event(1, "and me"))
    partition = engine.partition_context(access_a.partition).partition
    with partition.db.write() as conn:
        new_dek = partition.keyring.new_data_key(conn)
        assert h.reseal(conn, limit=100) == 3  # one session row + two messages
        assert h.reseal(conn, limit=100) == 0
    with raw_db(root, access_a) as conn:
        assert {r[0] for r in conn.execute("SELECT dek_id FROM history_messages")} == {new_dek}
        assert {r[0] for r in conn.execute("SELECT dek_id FROM history_sessions")} == {new_dek}
    assert [m.text for m in h.browse(access_a, "sess-a")["messages"]] == ["rotate me", "and me"]


# --------------------------------------------------------------------------- races / receipts
def _ingest_from_other_thread(engine, access, ev) -> None:
    errors: list[BaseException] = []

    def run() -> None:
        try:
            history(engine, access).ingest(access, ev)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    worker.join()
    assert not errors, errors


def test_search_restarts_when_archive_changes_before_answering(engine, access_a, monkeypatch):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "lynx early"))
    original = archive_mod.HistoryArchive._query_projection
    calls = {"n": 0}

    def racing(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:  # a concurrent writer commits after hydration, before the answer
            _ingest_from_other_thread(engine, access_a, event(1, "lynx late"))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(archive_mod.HistoryArchive, "_query_projection", racing)
    result = h.search(access_a, "lynx")
    assert calls["n"] == 2
    assert {hit.message.sequence for hit in result.hits} == {0, 1}
    assert result.status == ResultStatus.COMPLETE and result.coverage.total == 2


def test_search_reports_unavailable_when_archive_keeps_changing(engine, access_a, monkeypatch):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "lynx early"))
    original = archive_mod.HistoryArchive._query_projection
    counter = iter(range(1, 100))

    def always_racing(self, *args, **kwargs):
        _ingest_from_other_thread(engine, access_a, event(next(counter), "lynx again"))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(archive_mod.HistoryArchive, "_query_projection", always_racing)
    result = h.search(access_a, "lynx")
    assert result.status == ResultStatus.UNAVAILABLE and result.hits == ()
    assert result.coverage.total is None and not result.coverage.complete


def test_scope_forget_receipt_counts_only_reportable_sessions(engine, access_a):
    both = access_for(projects=("proj-a",), agents=("agent-x",))
    h = history(engine, both)
    h.ingest(both, event(0, "okapi plain", session="sess-plain", scope=PROJ_A))
    h.ingest(both, event(0, "okapi agent", session="sess-agent",
                         scope=Scope.of(project="proj-a", agent="agent-x")))
    partition = engine.partition_context(access_a.partition).partition
    value_token = engine.partition_context(access_a.partition).records.scope_value_token("project", "proj-a")
    with partition.db.read() as conn:
        assert h.hidden_sessions_for_scope(conn, access_a, "project", value_token) == 1
        assert h.hidden_sessions_for_scope(conn, both, "project", value_token) == 0
    receipt = engine.forget(access_a, ForgetTarget(ForgetTargetKind.PROJECT, "proj-a"))
    # Both sessions are deleted, but the caller's receipt never counts the one it cannot read.
    assert receipt.deleted.get("sessions") == 1 and receipt.deleted.get("messages") == 1
    assert h.sessions(both) == [] and h.search(both, "okapi").hits == ()


def test_purge_with_access_counts_only_granted_sessions(engine, access_a):
    both = access_for(projects=("proj-a",), agents=("agent-x",))
    h = history(engine, both)
    h.ingest(both, event(0, "tapir plain", session="sess-plain", scope=PROJ_A))
    h.ingest(both, event(0, "tapir agent", session="sess-agent",
                         scope=Scope.of(project="proj-a", agent="agent-x")))
    ctx = engine.partition_context(access_a.partition)
    with ctx.partition.db.write() as conn:
        counts = h.purge(conn, "scope:project", ctx.records.scope_value_token("project", "proj-a"),
                         ForgetPolicy(), access=access_a)
    assert counts == {"messages": 1, "sessions": 1}
    assert h.sessions(both) == []
    with ctx.partition.db.write() as conn:
        assert h.purge(conn, "memory", "m123", ForgetPolicy()) == {}
        assert h.purge(conn, "source", ctx.records.source_token("commit:abc"), ForgetPolicy()) == {}


# --------------------------------------------------------------------------- match strength (weak_match)
def test_strong_hits_need_every_content_term_and_weak_hits_fill_the_rest(engine, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "Decision: the deploy target is flyio."))
    h.ingest(access_a, event(1, "the deploy script lives in ops"))
    h.ingest(access_a, event(2, "lunch target is noon"))
    # Stopwords ("what", "is", "the") are not required for a strong match.
    result = h.search(access_a, "What is the deploy target?")
    assert [hit.message.sequence for hit in result.hits][:1] == [0]
    assert result.hits[0].score_kind == "bm25" and result.hits[0].flags == ()
    rest = result.hits[1:]
    assert {hit.message.sequence for hit in rest} == {1, 2}
    assert all(hit.score_kind == "bm25_any_term" and hit.flags == ("weak_match",) for hit in rest)
    assert result.status == ResultStatus.COMPLETE  # one hit matched every content term
    # Only partial matches: hits are kept, but the search does not claim evidence.
    weak = h.search(access_a, "deploy noon")
    assert {hit.message.sequence for hit in weak.hits} == {0, 1, 2}
    assert all("weak_match" in hit.flags for hit in weak.hits)
    assert weak.status == ResultStatus.INSUFFICIENT_EVIDENCE and weak.coverage.complete
    # No hit at all is also insufficient evidence; an empty query is a recency listing.
    assert h.search(access_a, "nonexistentterm").status == ResultStatus.INSUFFICIENT_EVIDENCE
    listing = h.search(access_a, "", limit=2)
    assert listing.status == ResultStatus.COMPLETE and listing.hits[0].flags == ()


def test_only_stopword_query_terms_are_all_required(engine, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "this is it"))
    h.ingest(access_a, event(1, "it is what it is"))
    result = h.search(access_a, "what is it")
    # All-stopword query: every term is a content term, so only seq 1 is a strong hit.
    assert [(hit.message.sequence, hit.flags) for hit in result.hits] == [(1, ()), (0, ("weak_match",))]
    assert result.status == ResultStatus.COMPLETE
    compiled = archive_mod.compile_query("What is the deploy* target?")
    assert compiled.content_fts_terms == ('"deploy"*', '"target?"')
    assert compiled.content_plain_terms == ("deploy", "target?")


def test_partial_hydration_keeps_partial_status_even_with_only_weak_hits(make_engine, access_a):
    engine = make_engine(config=EngineConfig(max_history_messages_hydrated=1, history_hydration_batch=1))
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "old marmot burrow"))
    h.ingest(access_a, event(1, "new marmot sighting"))
    result = h.search(access_a, "marmot burrow")
    assert result.status == ResultStatus.PARTIAL  # coverage first: unknown stays unknown
    assert [hit.message.sequence for hit in result.hits] == [1] and result.hits[0].flags == ("weak_match",)


# --------------------------------------------------------------------------- correction propagation
def _remember(engine, access, content, sources, scope=PROJ_A):
    from locus_memory.models import RememberRequest

    return engine.remember(access, RememberRequest(content=content, scope=scope, sources=tuple(sources))).record


def _correct(engine, access, record, content, sources=()):
    from locus_memory.models import Correction

    return engine.correct(access, record.id, Correction(content=content, sources=tuple(sources)),
                          expected_revision=None).record


def _msg(message_id):
    return SourceRef(SourceKind.MESSAGE, message_id)


def _flags(result):
    return {hit.message.sequence: hit.flags for hit in result.hits}


def test_correction_flags_superseded_messages_without_removing_them(engine, root, access_a):
    h = history(engine, access_a)
    old = h.ingest(access_a, event(0, "the deploy target is flyio")).message_id
    new = h.ingest(access_a, event(1, "change of plan: the deploy target is render")).message_id
    other = h.ingest(access_a, event(2, "the deploy runbook is in the wiki")).message_id
    record = _remember(engine, access_a, "deploy target is flyio", [_msg(old)])
    assert _flags(h.search(access_a, "deploy target")) == {0: (), 1: (), 2: ("weak_match",)}

    _correct(engine, access_a, record, "deploy target is render", [_msg(new)])
    result = h.search(access_a, "deploy target")
    assert _flags(result) == {0: ("superseded_by_correction",), 1: (), 2: ("weak_match",)}
    assert result.status == ResultStatus.COMPLETE
    # Opt-in filter: the superseded message is left out of the hits ...
    filtered = h.search(access_a, "deploy target", exclude_corrected=True)
    assert [hit.message.sequence for hit in filtered.hits] == [1, 2]
    assert filtered.coverage.total == 3  # ... but it is still archived and counted
    # ... and the user's archive is untouched.
    assert [m.text for m in h.browse(access_a, "sess-a")["messages"]][0] == "the deploy target is flyio"
    assert h.scroll(access_a, old, before=0, after=0)["messages"][0].message_id == old
    # Tokens only: no message ids, session refs or content in the annotation table.
    with raw_db(root, access_a) as conn:
        rows = conn.execute("SELECT source_token, record_id, session_token FROM history_corrections").fetchall()
    assert len(rows) == 1 and rows[0][1] == record.id and rows[0][2] is None
    assert old not in rows[0][0] and "sess-a" not in json.dumps(rows) and "flyio" not in json.dumps(rows)
    assert other not in json.dumps(rows)
    with pytest.raises(ValidationError):
        h.search(access_a, "deploy", exclude_corrected="yes")


def test_correction_without_content_change_or_of_recited_source_flags_nothing(engine, access_a):
    h = history(engine, access_a)
    m0 = h.ingest(access_a, event(0, "tabs are preferred")).message_id
    m1 = h.ingest(access_a, event(1, "actually spaces are preferred")).message_id
    record = _remember(engine, access_a, "tabs are preferred", [_msg(m0)])
    from locus_memory.models import Correction

    engine.correct(access_a, record.id, Correction(reason="retitle only", title="Indentation"),
                   expected_revision=None)
    assert _flags(h.search(access_a, "preferred")) == {0: (), 1: ()}
    # A correction that cites the old message again does not flag it.
    _correct(engine, access_a, record, "tabs are strongly preferred", [_msg(m0)])
    assert _flags(h.search(access_a, "preferred")) == {0: (), 1: ()}
    # Superseding m0 flags it; correcting back while citing m0 again clears it and flags m1.
    record = _correct(engine, access_a, record, "spaces are preferred", [_msg(m1)])
    assert _flags(h.search(access_a, "preferred")) == {0: ("superseded_by_correction",), 1: ()}
    _correct(engine, access_a, record, "tabs are preferred after all", [_msg(m0)])
    assert _flags(h.search(access_a, "preferred")) == {0: (), 1: ("superseded_by_correction",)}


def test_session_source_flags_messages_up_to_the_correction_time(engine, clock, access_a):
    h = history(engine, access_a)
    clock.now = T0 + 10
    h.ingest(access_a, event(0, "the release train leaves on mondays"))
    h.ingest(access_a, event(1, "release notes are drafted on fridays"))
    record = _remember(engine, access_a, "release train leaves on mondays",
                       [SourceRef(SourceKind.SESSION, "sess-a")])
    _correct(engine, access_a, record, "release train leaves on tuesdays")
    h.ingest(access_a, event(2, "release retro after the train", at=T0 + 20))
    assert _flags(h.search(access_a, "release")) == {0: ("superseded_by_correction",),
                                                     1: ("superseded_by_correction",), 2: ()}
    assert [hit.message.sequence for hit in h.search(access_a, "release", exclude_corrected=True).hits] == [2]


def test_flags_are_shown_only_to_callers_who_may_see_the_corrected_memory(engine, access_ab):
    h = history(engine, access_ab)
    shared = h.ingest(access_ab, event(0, "the shared budget is ten units", session="sess-g", scope=GLOBAL))
    record = _remember(engine, access_ab, "budget is ten units", [_msg(shared.message_id)], scope=PROJ_B)
    _correct(engine, access_ab, record, "budget is twelve units")
    only_a = access_for(projects=("proj-a",))
    assert _flags(h.search(only_a, "budget units")) == {0: ()}  # proj-b memory activity is not revealed
    assert h.search(only_a, "budget units", exclude_corrected=True).hits[0].message.message_id == shared.message_id
    assert _flags(h.search(access_ab, "budget units")) == {0: ("superseded_by_correction",)}


def _corrections(root, access) -> int:
    with raw_db(root, access) as conn:
        return conn.execute("SELECT COUNT(*) FROM history_corrections").fetchone()[0]


def _flagged_setup(engine, access_a, text="the shuttle departs at nine"):
    h = history(engine, access_a)
    old = h.ingest(access_a, event(0, text)).message_id
    new = h.ingest(access_a, event(1, "update: the shuttle departs at ten")).message_id
    record = _remember(engine, access_a, "shuttle departs at nine", [_msg(old)])
    _correct(engine, access_a, record, "shuttle departs at ten", [_msg(new)])
    assert _flags(h.search(access_a, "shuttle departs"))[0] == ("superseded_by_correction",)
    return h, old, record


def test_forgetting_the_memory_purges_its_correction_rows(engine, root, access_a):
    h, _old, record = _flagged_setup(engine, access_a)
    assert _corrections(root, access_a) == 1
    engine.forget(access_a, ForgetTarget(ForgetTargetKind.MEMORY, record.id))
    assert _corrections(root, access_a) == 0
    assert _flags(h.search(access_a, "shuttle departs")) == {0: (), 1: ()}


def test_forgetting_the_source_purges_rows_even_when_the_archive_copy_is_kept(engine, root, access_a):
    h, old, _record = _flagged_setup(engine, access_a)
    engine.forget(access_a, ForgetTarget(ForgetTargetKind.SOURCE, f"message:{old}"))
    assert _corrections(root, access_a) == 0
    assert h.scroll(access_a, old, before=0, after=0)["messages"][0].text == "the shuttle departs at nine"


def test_forgetting_the_session_or_profile_purges_correction_rows(engine, root, access_a):
    _flagged_setup(engine, access_a)
    engine.forget(access_a, ForgetTarget(ForgetTargetKind.SESSION, "sess-a"))
    assert _corrections(root, access_a) == 0
    other = access_for(profile="second", projects=("proj-a",))
    _flagged_setup(engine, other)
    assert _corrections(root, other) == 1
    engine.forget(other, ForgetTarget(ForgetTargetKind.PROFILE, "second"))
    assert _corrections(root, other) == 0


def test_forgetting_a_session_source_identity_purges_session_rows(engine, root, access_a):
    h = history(engine, access_a)
    h.ingest(access_a, event(0, "the kiln fires at dawn"))
    keeper = h.ingest(access_a, event(0, "kiln log", session="sess-k")).message_id
    record = _remember(engine, access_a, "kiln fires at dawn",
                       [SourceRef(SourceKind.SESSION, "sess-a"), _msg(keeper)])
    _correct(engine, access_a, record, "kiln fires at dusk")
    assert _corrections(root, access_a) == 2
    engine.forget(access_a, ForgetTarget(ForgetTargetKind.SOURCE, "session:sess-a"))
    with raw_db(root, access_a) as conn:
        assert conn.execute("SELECT COUNT(*) FROM history_corrections WHERE session_token IS NOT NULL"
                            ).fetchone()[0] == 0
