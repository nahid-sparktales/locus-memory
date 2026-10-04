"""Regression tests for review round 3, batch 3 (reproduced defects).

R3-RG-2  history hydration (or a ranker) spent the whole shared deadline, so selection stopped after
         its first round and packets carried about one memory per slice (R_SELECT_DEADLINE).
R3-RG-3  consolidation checked "already summarized" against the raw chunk ids while the summary is
         derived from the servable subset only: with one unservable input (an excluded path, a
         read-time-expired transient record) every run re-sent the chunk to the external summarizer
         and stored another summary.
R3-RG-4  _MAX_SLICE_MISSES counted every refusal, so records too large for a slice retired it while
         empty: a small record that fit was omitted with a false slice_cap reason in a COMPLETE packet.
R3-API-2 boolean model fields were never validated and from_dict used bool(): "false" became True
         (the sensitive gate was bypassed, an event was skipped as a memory injection and its real
         delivery then conflicted forever, a retention was pinned).
R3-API-3 the secret and sensitive gates scanned only content, title and tags: credentials in reason,
         rationale, subject or predicate were stored, returned and exported.

Each test reproduces the report's scenario and asserts the correct outcome. All data lives in
pytest tmp dirs.
"""
from __future__ import annotations

import functools
import itertools
import json
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from conftest import access_for
from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.cli import main
from locus_memory.context import compiler as compiler_mod
from locus_memory.context.budget import TokenMeter
from locus_memory.context.compiler import R_SELECT_DEADLINE, R_SELECT_TRUNCATED
from locus_memory.errors import SensitiveContent, ValidationError
from locus_memory.history.archive import HistoryArchive
from locus_memory.host import EngineConfig, HostCapabilities
from locus_memory.models import (
    AccessContext,
    Actor,
    CandidateProposal,
    Confidence,
    ContextRequest,
    Correction,
    ForgetPolicy,
    ForgetTarget,
    IngestionEvent,
    Lifecycle,
    MemoryKind,
    MemoryRecord,
    Operation,
    PartitionRef,
    Query,
    RememberRequest,
    ResultStatus,
    Retention,
    Scope,
    ScopeGrants,
    SliceSpec,
    SourceKind,
    SourceRef,
)
from locus_memory.providers.base import DATA_MEMORY_TEXT, ConsentGrant, StaticConsentPolicy
from locus_memory.providers.fake import FakeSummarizer
from locus_memory.storage.partition import new_id

GIT = shutil.which("git")
PROJ = Scope.of(project="proj-a")
USER = access_for(projects=("proj-a",), sessions=("s1",))
TOK = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # GitHub-format token (36 chars)
HEALTH = "I was diagnosed with diabetes last year"


def _seed_approved(engine, access, n: int, scope: Scope, *, content, title=None) -> list[str]:
    """``n`` approved records written in one transaction, oldest first (setup only)."""
    ctx = engine.partition_context(access.partition)
    now = ctx.clock()
    ids = []
    with ctx.partition.db.write() as conn:
        for i in range(n):
            at = now - n + i
            record = MemoryRecord(
                id=new_id("m"), revision=1, kind=MemoryKind.FACT, lifecycle=Lifecycle.APPROVED, scope=scope,
                title=title(i) if title else f"seeded {i}", content=content(i),
                sources=(SourceRef(SourceKind.USER_ACTION, f"seed-{new_id()}", observed_at=at),),
                created_at=at, updated_at=at, event_time=at, ingested_at=at)
            ctx.records.write(conn, record, change="created", actor=Actor.USER, expected_revision=None,
                              generation=ctx.partition.bump(conn))
            ids.append(record.id)
    return ids


# =========================================================================== R3-RG-2
_RG2_PROJECT = Scope.of(project="p")
_RG2_ACCESS = AccessContext(principal="u", partition=PartitionRef("standard", "default"), actor=Actor.USER,
                            grants=ScopeGrants(projects=frozenset({"p"})), operations=frozenset(Operation))
# Small hydration batches stand in for a large archive: hydrating it takes far longer than the
# deadline (the report measured 60k messages with the default batch size).
_RG2_CONFIG = EngineConfig(history_hydration_batch=5)
_RG2_DEADLINE_MS = 300


def _rg2_request(*, history: bool, deadline: int | None) -> ContextRequest:
    return ContextRequest(token_allowance=4_000, query="deploy pipeline", include_history=history,
                          deadline_ms=deadline)


@pytest.fixture(scope="module")
def rg2_store(tmp_path_factory):
    """4,000 archived messages and 40 small approved decisions, written once; each test reopens
    the store so the history projection is not hydrated (a fresh process)."""
    root = tmp_path_factory.mktemp("rg2") / "root"
    keys = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    engine = MemoryEngine(root, keys, config=_RG2_CONFIG)
    history = engine.services(_RG2_ACCESS).history
    batch = []
    for i in range(4_000):
        batch.append(IngestionEvent(event_id=f"e{i}", session_ref=f"s{i // 500}", sequence=i, role="user",
                                    text=f"chat message {i} about the deploy pipeline {secrets.token_hex(8)}",
                                    occurred_at=1.7e9 + i, scope=_RG2_PROJECT))
        if len(batch) == 500:
            history.ingest_batch(_RG2_ACCESS, batch)
            batch = []
    for i in range(40):
        engine.remember(_RG2_ACCESS, RememberRequest(content=f"Decision {i}: the deploy pipeline uses stage {i}",
                                                     title=f"deploy decision {i}", scope=_RG2_PROJECT))
    engine.close()
    opened: list[MemoryEngine] = []

    def reopen() -> MemoryEngine:
        opened.append(MemoryEngine(root, keys, config=_RG2_CONFIG))
        return opened[-1]

    yield reopen
    for item in opened:
        try:
            item.close()
        except Exception:
            pass


def test_rg2_history_hydration_with_a_deadline_still_fills_the_packet(rg2_store):
    full = rg2_store().build_context(_RG2_ACCESS, _rg2_request(history=False, deadline=None))
    assert full.status == ResultStatus.COMPLETE and len(full.items) >= 20

    engine = rg2_store()  # unhydrated history projection
    started = time.perf_counter()
    packet = engine.build_context(_RG2_ACCESS, _rg2_request(history=True, deadline=_RG2_DEADLINE_MS))
    elapsed = time.perf_counter() - started
    # The scenario: real (unmocked) hydration did not finish within the deadline.
    assert any("history" in reason for reason in packet.coverage.partial_reasons)
    # It used to return 1 item (R_SELECT_DEADLINE): history had spent the whole shared deadline.
    assert R_SELECT_DEADLINE not in packet.coverage.partial_reasons
    assert len(packet.items) >= len(full.items) - 1
    assert elapsed < 5.0, elapsed  # still bounded (history gets a share of the deadline)

    # The starvation came back after every forget (the hydrated projection is discarded).
    engine.forget(_RG2_ACCESS, ForgetTarget("session", "s0"))
    after = engine.build_context(_RG2_ACCESS, _rg2_request(history=True, deadline=_RG2_DEADLINE_MS))
    assert R_SELECT_DEADLINE not in after.coverage.partial_reasons
    assert len(after.items) >= len(full.items) - 1


def test_rg2_a_ranker_that_spends_the_whole_deadline_does_not_starve_selection(rg2_store, monkeypatch):
    full = rg2_store().build_context(_RG2_ACCESS, _rg2_request(history=False, deadline=None))
    original = compiler_mod.ContextCompiler._rank

    def slow_rank(self, access, request, plan, deadline, cancel):
        result = original(self, access, request, plan, deadline, cancel)
        time.sleep(request.deadline_ms / 1000)  # a provider answering after the whole budget
        return result

    monkeypatch.setattr(compiler_mod.ContextCompiler, "_rank", slow_rank)
    packet = rg2_store().build_context(_RG2_ACCESS, _rg2_request(history=False, deadline=_RG2_DEADLINE_MS))
    # It used to stop after one round: 1 item, R_SELECT_DEADLINE.
    assert len(packet.items) >= len(full.items) - 1
    assert R_SELECT_DEADLINE not in packet.coverage.partial_reasons


def test_rg2_upstream_stages_get_a_share_of_the_deadline(make_engine, monkeypatch):
    engine = make_engine()
    engine.remember(USER, RememberRequest(content="deploy pipeline uses blue green", scope=PROJ))
    seen = []
    original = HistoryArchive.search

    @functools.wraps(original)  # keeps the signature the compiler binds arguments by
    def search(self, *args, **kwargs):
        seen.append(kwargs.get("deadline_ms"))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(HistoryArchive, "search", search)
    packet = engine.build_context(USER, ContextRequest(token_allowance=2_000, query="deploy", include_history=True,
                                                       deadline_ms=10_000))
    assert packet.items
    # History (like ranking) is forwarded a share of the deadline; the rest stays for selection.
    assert seen and seen[0] is not None and seen[0] <= 10_000 * compiler_mod._UPSTREAM_DEADLINE_SHARE


def test_rg2_select_deadline_is_documented():
    docs = (Path(__file__).parent.parent / "docs" / "architecture.md").read_text(encoding="utf-8")
    for name in ("R_SELECT_DEADLINE", "R_SELECT_TRUNCATED", "R_LOAD_DEADLINE", "R_RANK_DEADLINE", "not_evaluated"):
        assert name in docs, name


# =========================================================================== R3-RG-3
def _consolidation_engine(root, keys, clock, **host):
    n = itertools.count()
    summarizer = FakeSummarizer("cloud-sum", egress=True, output=lambda items: f"summary v{next(n)}: " + " | ".join(
        item["content"][:30] for item in items))  # different on every call (a real model)
    consent = StaticConsentPolicy([ConsentGrant(provider="cloud-sum", scope=None,
                                                data_classes=frozenset({DATA_MEMORY_TEXT}), granted_at=clock() - 1)])
    engine = MemoryEngine(root, keys, host=HostCapabilities(clock=clock, providers={"cloud-sum": summarizer},
                                                            consent=consent, **host))
    return engine, summarizer


def _three_runs(engine, summarizer, access):
    counts = []
    for _ in range(3):
        engine.consolidate(access, {"summarize": True})
        stored = engine.list(access, lifecycles=None, kinds=(MemoryKind.SUMMARY,))
        counts.append((len(stored), len(summarizer.calls)))
    return counts


def _git(repo, *args):
    subprocess.run([GIT, "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=repo, check=True,
                   capture_output=True)


@pytest.mark.skipif(GIT is None, reason="git required")
def test_rg3_a_chunk_with_an_excluded_observation_is_summarized_once(tmp_path, keys, clock):
    allowed = (tmp_path / "allowed").resolve()
    repo = allowed / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", ".")
    (repo / "settings_prod.py").write_text('"""prod db host db-17.internal"""\nX = 1\n')
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
    first.close()
    # The host now excludes one file: its observation stays 'approved' until the next snapshot.
    engine, summarizer = _consolidation_engine(root, keys, clock, allowed_repository_roots=(allowed,),
                                               repository_exclude_patterns=["settings_prod.py"])
    try:
        counts = _three_runs(engine, summarizer, access)
    finally:
        engine.close()
    # It used to be [(1, 1), (2, 2), (3, 3)]: every run re-sent the chunk and stored a summary.
    assert counts == [(1, 1), (1, 1), (1, 1)], counts
    assert "db-17.internal" not in json.dumps(summarizer.calls)  # the excluded file never leaves


def test_rg3_a_chunk_with_a_read_time_expired_input_is_summarized_once(tmp_path, keys, clock):
    access = access_for(projects=("proj-a",))
    engine, summarizer = _consolidation_engine(tmp_path / "root", keys, clock)
    try:
        for i in range(4):
            engine.remember(access, RememberRequest(content=f"the service {i} deploys with make release {i}",
                                                    scope=PROJ))
        engine.remember(access, RememberRequest(content="the staging box is borrowed this week", scope=PROJ,
                                                retention=Retention("transient", clock() + 10, False)))
        clock.advance(20)  # expired at read time; maintenance has not persisted it (or is fenced)
        counts = _three_runs(engine, summarizer, access)
    finally:
        engine.close()
    assert counts == [(1, 1), (1, 1), (1, 1)], counts
    assert all("staging box" not in item["content"] for call in summarizer.calls for item in call)


# =========================================================================== R3-RG-4
def _big(i: int) -> str:
    return " ".join(f"obs{i}x{j}" for j in range(1_500))  # far over the 1200-token project slice cap


def test_rg4_a_small_record_behind_oversized_ones_is_selected(make_engine, clock):
    engine = make_engine()
    small = engine.remember(USER, RememberRequest(content="deploy with make release", scope=PROJ)).record.id
    for i in range(40):
        clock.advance(60)
        engine.remember(USER, RememberRequest(content=_big(i), scope=PROJ))
    packet = engine.build_context(USER, ContextRequest(token_allowance=20_000))
    # It used to omit it as slice_cap (never measured) after 32 refusals of oversized records.
    assert [item.record_id for item in packet.items] == [small]
    assert packet.status == ResultStatus.COMPLETE and packet.coverage.partial_reasons == ()
    cap = {spec.name: spec.max_tokens for spec in ContextRequest(token_allowance=1).slices}["project_and_repository"]
    assert len(packet.omissions) == 40
    assert all(o.reason == "slice_cap" and o.tokens is not None and o.tokens > cap for o in packet.omissions)


def test_rg4_records_left_unevaluated_are_reported_honestly(make_engine, clock, monkeypatch):
    engine = make_engine()
    small = _seed_approved(engine, USER, 1, PROJ, content=lambda i: "deploy with make release")[0]
    clock.advance(1_000)
    over = compiler_mod._MAX_SLICE_OVERSIZED + 6
    _seed_approved(engine, USER, over, PROJ, content=_big)
    renders = [0]
    original = compiler_mod._Candidate._render

    def counting(self):
        renders[0] += 1
        return original(self)

    monkeypatch.setattr(compiler_mod._Candidate, "_render", counting)
    packet = engine.build_context(USER, ContextRequest(token_allowance=20_000))
    assert renders[0] <= compiler_mod._MAX_SLICE_OVERSIZED + 1  # the work bound is kept
    reasons = {o.record_id: o for o in packet.omissions}
    # Not claimed to exceed the cap or the budget: it was never measured, and it would have fit.
    assert reasons[small].reason == "not_evaluated" and reasons[small].tokens is None
    assert packet.status == ResultStatus.PARTIAL and R_SELECT_TRUNCATED in packet.coverage.partial_reasons
    assert all(o.reason in ("slice_cap", "not_evaluated") for o in packet.omissions)
    assert all(o.tokens is not None for o in packet.omissions if o.reason == "slice_cap")


def _same_size_records(engine, n):
    return _seed_approved(engine, USER, n, PROJ, content=lambda i: f"fact {i:04d} " + "y" * 200,
                          title=lambda i: f"t{i:04d}")


@pytest.mark.parametrize("spare, complete", [(-1, True), (0, False)])
def test_rg4_a_crowded_slice_is_complete_only_when_nothing_else_can_fit(make_engine, spare, complete):
    engine = make_engine()
    _same_size_records(engine, 40)
    roomy = engine.build_context(USER, ContextRequest(
        token_allowance=100_000, slices=(SliceSpec("s", 100_000, (), None, False),)))
    sizes = {item.tokens for item in roomy.items}
    assert len(roomy.items) == 40 and len(sizes) == 1
    (cost,) = sizes
    shortest = TokenMeter(None, chars_per_token=3.5, margin=1.15).count(compiler_mod._SHORTEST_LINE)
    cap = 2 * cost + shortest + spare  # two fit; the room left is just below / at the shortest line
    packet = engine.build_context(USER, ContextRequest(
        token_allowance=100_000, slices=(SliceSpec("s", cap, (), None, False),)))
    assert len(packet.items) == 2
    if complete:  # provably nothing else fits: slice_cap is the truth
        assert packet.status == ResultStatus.COMPLETE
        assert {o.reason for o in packet.omissions} == {"slice_cap"}
    else:  # a shorter record could still have fit: not claimed as slice_cap
        assert packet.status == ResultStatus.PARTIAL and R_SELECT_TRUNCATED in packet.coverage.partial_reasons
        assert "not_evaluated" in {o.reason for o in packet.omissions}
        assert all(o.tokens is not None for o in packet.omissions if o.reason == "slice_cap")


# =========================================================================== R3-API-2
_BAD_BOOLS = ("false", "no", 0, 1, "true")
_EVENT = {"event_id": "e1", "session_ref": "s1", "sequence": 0, "role": "user",
          "text": "deploy uses blue green", "occurred_at": 1_000.0}
_FIELDS = [
    pytest.param(lambda b: RememberRequest(content="x", allow_sensitive=b),
                 lambda b: RememberRequest.from_dict({"content": "x", "allow_sensitive": b}), id="remember.allow_sensitive"),
    pytest.param(lambda b: Correction(content="x", allow_sensitive=b),
                 lambda b: Correction.from_dict({"content": "x", "allow_sensitive": b}), id="correction.allow_sensitive"),
    pytest.param(lambda b: IngestionEvent(**_EVENT, is_memory_injection=b),
                 lambda b: IngestionEvent.from_dict({**_EVENT, "is_memory_injection": b}), id="event.is_memory_injection"),
    pytest.param(lambda b: IngestionEvent(**_EVENT, is_generated_summary=b),
                 lambda b: IngestionEvent.from_dict({**_EVENT, "is_generated_summary": b}),
                 id="event.is_generated_summary"),
    pytest.param(lambda b: Query(text="x", include_stale=b),
                 lambda b: Query.from_dict({"text": "x", "include_stale": b}), id="query.include_stale"),
    pytest.param(lambda b: Retention(pinned=b), lambda b: Retention.from_dict({"pinned": b}), id="retention.pinned"),
    pytest.param(lambda b: Confidence(0.5, b), lambda b: Confidence.from_dict({"value": 0.5, "calibrated": b}),
                 id="confidence.calibrated"),
    pytest.param(lambda b: SourceRef(SourceKind.DOCUMENT, "doc-1", available=b),
                 lambda b: SourceRef.from_dict({"kind": "document", "ref": "doc-1", "available": b}),
                 id="source.available"),
    pytest.param(lambda b: ForgetPolicy(delete_source_archive=b), None, id="forget_policy.delete_source_archive"),
]


@pytest.mark.parametrize("bad", _BAD_BOOLS)
@pytest.mark.parametrize("build, parse", _FIELDS)
def test_api2_boolean_fields_accept_only_real_booleans(build, parse, bad):
    with pytest.raises(ValidationError):
        build(bad)
    if parse is not None:
        with pytest.raises(ValidationError):
            parse(bad)
    build(True)
    build(False)
    if parse is not None:
        parse(True)
        parse(False)
        parse(None)  # JSON null: the field's default


def test_api2_string_false_no_longer_bypasses_the_sensitive_gate(engine):
    access = access_for(projects=("p",))
    with pytest.raises(SensitiveContent):  # control: JSON false
        engine.remember(access, RememberRequest.from_dict({"content": HEALTH, "allow_sensitive": False}))
    with pytest.raises(ValidationError):  # it used to be stored (bool("false") is True)
        engine.remember(access, RememberRequest.from_dict({"content": HEALTH, "allow_sensitive": "false"}))
    with pytest.raises(ValidationError):
        RememberRequest(content=HEALTH, allow_sensitive="no")
    record = engine.remember(access, RememberRequest(content="the user likes tea", scope=Scope.of(project="p"))).record
    with pytest.raises(ValidationError):
        engine.correct(access, record.id, Correction.from_dict({"content": HEALTH, "allow_sensitive": "false"}),
                       expected_revision=1)
    assert [r.id for r in engine.list(access)] == [record.id]
    assert engine.get(access, record.id).content == "the user likes tea"
    with pytest.raises(ValidationError):  # bool("false") pinned it (a pinned record never expires)
        engine.set_pinned(access, record.id, "false", expected_revision=1)
    assert engine.get(access, record.id).retention.pinned is False


def test_api2_a_string_false_event_is_refused_and_the_real_one_archives(engine):
    with pytest.raises(ValidationError):
        IngestionEvent.from_dict({**_EVENT, "is_memory_injection": "false"})
    receipt = engine.ingest_event(USER, IngestionEvent.from_dict({**_EVENT, "is_memory_injection": False}))
    assert receipt.message_id is not None and not receipt.skipped_reason
    assert len(engine.search_history(USER, "blue green").hits) == 1


def test_api2_cli_history_ingest_names_the_invalid_line(capsys, tmp_path):
    root = tmp_path / "cli-root"

    def cli(*args):
        code = main(["--root", str(root), "--json", *args])
        return code, json.loads(capsys.readouterr().out)

    assert cli("init")[0] == 0
    bad, good = tmp_path / "bad.jsonl", tmp_path / "good.jsonl"
    bad.write_text(json.dumps({**_EVENT, "text": "first"}) + "\n" + json.dumps({**_EVENT, "is_memory_injection": "false"})
                   + "\n")
    good.write_text(json.dumps({**_EVENT, "is_memory_injection": False}) + "\n")
    code, data = cli("history", "ingest", "--file", str(bad))
    # It used to exit 0 with {"skipped": {"memory_injection": 1}}, and the real event then conflicted.
    assert code != 0 and data["error"] == "invalid_request" and "line 2" in data["message"]
    code, data = cli("history", "ingest", "--file", str(good))
    assert code == 0 and data["stored"] == 1 and data["skipped"] == {}


def test_api2_flags_an_earlier_build_stored_unvalidated_still_read(make_engine):
    """The models refuse non-bools now; a record an earlier build sealed with ``pinned: 1`` must still
    decode (as that build read it), not make every read of it fail."""
    engine = make_engine()
    ctx = engine.partition_context(USER.partition)
    now = ctx.clock()
    retention = Retention("durable", None, False)
    object.__setattr__(retention, "pinned", 1)
    source = SourceRef(SourceKind.USER_ACTION, "seed-legacy", observed_at=now)
    object.__setattr__(source, "available", 0)
    record = MemoryRecord(id=new_id("m"), revision=1, kind=MemoryKind.FACT, lifecycle=Lifecycle.APPROVED,
                          scope=PROJ, title="old", content="written by an earlier build", sources=(source,),
                          retention=retention, created_at=now, updated_at=now)
    with ctx.partition.db.write() as conn:
        ctx.records.write(conn, record, change="created", actor=Actor.USER, expected_revision=None,
                          generation=ctx.partition.bump(conn))
    got = engine.get(USER, record.id)
    assert got.retention.pinned is True and got.content == "written by an earlier build"
    assert [r.id for r in engine.list(USER)] == [record.id]


# =========================================================================== R3-API-3
def _agent():
    return access_for(actor=Actor.AGENT, projects=("p",), operations={Operation.PROPOSE, Operation.READ})


@pytest.fixture
def api3(engine):
    user = access_for(projects=("p",))
    source = engine.remember(user, RememberRequest(content="source memory", scope=Scope.of(project="p"))).record
    return engine, user, source


@pytest.mark.parametrize("fields", [
    {"reason": "token is " + TOK},
    {"subject": "ci-bot " + TOK},
    {"predicate": "password=hunter2hunter2"},
])
def test_api3_remember_refuses_secrets_in_every_stored_field(api3, fields):
    engine, user, _ = api3
    with pytest.raises(SensitiveContent):
        engine.remember(user, RememberRequest(content="Deploys use the CI bot", scope=Scope.of(project="p"), **fields))
    assert TOK not in json.dumps(engine.export(user), default=str)
    assert "hunter2" not in json.dumps(engine.export(user), default=str)


def test_api3_remember_applies_the_sensitive_gate_to_the_reason(api3):
    engine, user, _ = api3
    with pytest.raises(SensitiveContent):
        engine.remember(user, RememberRequest(content="prefers short replies", scope=Scope.of(project="p"),
                                              reason="because they were diagnosed with a disorder"))
    kept = engine.remember(user, RememberRequest(content="prefers short replies", scope=Scope.of(project="p"),
                                                 reason="because they were diagnosed with a disorder",
                                                 allow_sensitive=True))  # the host attests it
    assert "diagnosed" in engine.get(user, kept.record.id).reason


@pytest.mark.parametrize("fields", [
    {"rationale": "bot key " + TOK},
    {"subject": TOK},
    {"predicate": "password=hunter2hunter2"},
    {"rationale": "because the user was diagnosed with a disorder"},  # R5.3: never inferred
    {"proposer": "bot-" + TOK},
])
def test_api3_agent_proposals_are_gated_on_every_stored_field(api3, fields):
    engine, user, source = api3
    with pytest.raises(SensitiveContent):
        engine.propose(_agent(), CandidateProposal(content="CI uses the bot account",
                                                   sources=(SourceRef(SourceKind.MEMORY, source.id),),
                                                   scope=Scope.of(project="p"), **fields))
    assert engine.list(user, lifecycles=(Lifecycle.CANDIDATE,)) == []


def test_api3_correct_and_reject_never_store_a_credential_in_the_reason(api3):
    engine, user, source = api3
    with pytest.raises(SensitiveContent):
        engine.correct(user, source.id, Correction(title="CI bot", reason="new " + TOK), expected_revision=1)
    assert engine.get(user, source.id).revision == 1
    candidate = engine.propose(_agent(), CandidateProposal(content="CI uses the bot account",
                                                           sources=(SourceRef(SourceKind.MEMORY, source.id),),
                                                           scope=Scope.of(project="p"), rationale="seen in CI")).record
    rejected = engine.reject(user, candidate.id, expected_revision=1, reason="that bot key is " + TOK)
    assert TOK not in rejected.record.reason and "[REDACTED:github_token]" in rejected.record.reason
    dump = json.dumps([engine.export(user), engine.explain(user, candidate.id)], default=str)
    assert TOK not in dump


def test_api3_a_reason_stored_by_an_earlier_build_is_not_restored_by_a_correction(make_engine):
    engine = make_engine()
    ctx = engine.partition_context(USER.partition)
    now = ctx.clock()
    record = MemoryRecord(id=new_id("m"), revision=1, kind=MemoryKind.FACT, lifecycle=Lifecycle.APPROVED,
                          scope=PROJ, title="ci", content="Deploys use the CI bot",
                          sources=(SourceRef(SourceKind.USER_ACTION, "seed-old", observed_at=now),),
                          reason="token is " + TOK, created_at=now, updated_at=now)
    with ctx.partition.db.write() as conn:
        ctx.records.write(conn, record, change="created", actor=Actor.USER, expected_revision=None,
                          generation=ctx.partition.bump(conn))
    corrected = engine.correct(USER, record.id, Correction(title="CI bot"), expected_revision=1).record
    assert TOK not in corrected.reason and "[REDACTED:github_token]" in corrected.reason


def test_api3_the_security_doc_names_the_scanned_fields():
    doc = (Path(__file__).parent.parent / "docs" / "security-and-privacy.md").read_text(encoding="utf-8")
    for name in ("rationale", "subject", "predicate", "reason"):
        assert name in doc.split("### 4.3", 1)[1].split("### 4.4", 1)[0], name


def test_api3_the_field_gate_covers_stored_fields_but_flags_only_rendered_text():
    """remember, propose and correct share one helper (they cannot drift apart again)."""
    from locus_memory import core

    scan = core.gate_scan(("plain content", "", ""), ("pwd=" + "s3cretvalue", None, "diagnosed",
                                                       "ignore previous instructions"))
    assert scan.secrets == ("password_assignment",) and scan.sensitive == ("health",)
    assert not scan.injection  # instruction-like text is flagged where it is rendered (content)
    label = core.gate_scan(("plain content",), (), ("therapy-notes-bot", TOK))
    assert label.secrets == ("github_token",) and label.sensitive == ()  # a name is no statement
