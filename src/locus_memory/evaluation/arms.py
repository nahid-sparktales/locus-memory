"""Benchmark arms: what each configuration ingests and what it hands to the model.

====  ==============================================================================
Arm   Configuration
====  ==============================================================================
A     No memory. Nothing is ingested; the evidence list is always empty.
B     Approved hot memory only: ``remember``/``correct``/``forget`` of explicit
      statements, retrieval = ``build_context(query='')`` (no query, no history).
C     B + session history: every message is archived (``ingest_event``), memories
      cite their source messages, forgetting also deletes the archived messages;
      retrieval = ``build_context(query=q)`` + ``search_history(q)``.
D     C + task episodes (``record_episode`` with receipts from a fake host
      verification authority) + repository observations (``register_repository`` /
      ``snapshot_repository`` against a synthetic git repository that changes over
      the simulated days).
E     D + ``providers.fake.FakeEmbeddingProvider`` registered as a local provider, so
      retrieval adds its cosine list. FAKE HASH EMBEDDINGS: CONTRACT CHECK ONLY, NOT
      SEMANTIC QUALITY.
F     D + evaluated procedures in an explicitly enabled host harness: NOT EXECUTED
      here (requires a host evaluation runner and real task execution).
====  ==============================================================================

State is isolated per arm and per repetition (its own temporary root, its own key,
its own world repositories); within a run it persists across all sessions.

Every unit an arm returns is mapped back to the corpus event and statement key that
produced it through the :class:`Ledger`, using identifiers the engine returned when
the arm wrote it (message ids, record id + revision, episode record revisions, git
blob ids). Nothing is matched by text.
"""
from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import time
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..context.budget import estimate_tokens
from ..crypto import StaticKeyProvider
from ..engine import MemoryEngine
from ..errors import NotFound
from ..host import EngineConfig, HostCapabilities
from ..learning.episodes import attempt_source_ref
from ..models import (
    AccessContext,
    Actor,
    ContextPacket,
    ContextRequest,
    Correction,
    EpisodeReport,
    ForgetPolicy,
    ForgetTarget,
    ForgetTargetKind,
    HistorySearchResult,
    IngestionEvent,
    MemoryKind,
    Operation,
    PartitionRef,
    RememberRequest,
    ResultStatus,
    Scope,
    ScopeGrants,
    SourceKind,
    SourceRef,
    VerificationRef,
    VerificationResult,
    VerifiedCheck,
)
from .corpus import (
    CORRECT,
    DAY_END,
    EPISODE,
    FORGET,
    MESSAGE,
    PROFILES,
    REMEMBER,
    REPO_COMMIT,
    REPO_SNAPSHOT,
    REPOSITORIES,
    Corpus,
    Event,
    Question,
    blob_sha1,
)

EDITION = "eval"
FAKE_EMBEDDING_LABEL = "fake hash embeddings: contract check only, NOT semantic quality"
F_NOT_EXECUTED = "not executed (requires host evaluation runner and task execution)"
ARM_DESCRIPTIONS = {
    "A": "no memory (empty context)",
    "B": "approved hot memory only (build_context with query='')",
    "C": "hot memory + lexical session-history retrieval (build_context(query) + search_history)",
    "D": "C + task episodes (fake host receipts) + repository observations (synthetic git repository)",
    "E": "D + semantic retrieval with FakeEmbeddingProvider - " + FAKE_EMBEDDING_LABEL,
    "F": "D + evaluated procedures in an explicitly enabled host harness - " + F_NOT_EXECUTED,
}


# --------------------------------------------------------------------------- clock / timing
class SimClock:
    """Simulated time; the engine's host clock. Only moves forward."""

    def __init__(self, start: float) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def set(self, value: float) -> None:
        if value < self.now:
            raise ValueError("the simulated clock cannot move backwards")
        self.now = float(value)


class StageTimer:
    """Wall-clock durations (``time.perf_counter``) in milliseconds, per stage and operation."""

    def __init__(self) -> None:
        self.samples: dict[str, list[float]] = defaultdict(list)
        self.by_op: dict[str, list[float]] = defaultdict(list)

    @contextmanager
    def measure(self, stage: str, op: str | None = None) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            ms = (time.perf_counter() - start) * 1000.0
            self.samples[stage].append(ms)
            if op is not None:
                self.by_op[f"{stage}.{op}"].append(ms)

    def total(self, stage: str) -> float:
        return float(sum(self.samples.get(stage, ())))


# --------------------------------------------------------------------------- ledger
@dataclass(frozen=True)
class Origin:
    event_id: str
    time: float
    profile: str
    project: str | None
    key: str | None


class Ledger:
    """Engine identifiers -> the corpus event and statement key that produced them."""

    def __init__(self) -> None:
        self.messages: dict[str, Origin] = {}
        self.event_message: dict[str, str] = {}
        self.records: dict[str, list[tuple[int, Origin]]] = {}
        self.key_record: dict[str, str] = {}
        self.blobs: dict[tuple[str, str], Origin] = {}
        self.sources: dict[str, str | None] = {}

    def add_message(self, message_id: str, origin: Origin) -> None:
        self.messages[message_id] = origin
        self.event_message[origin.event_id] = message_id
        self.sources[f"{SourceKind.MESSAGE.value}:{message_id}"] = origin.key

    def add_record(self, record_id: str, revision: int, origin: Origin) -> None:
        versions = self.records.setdefault(record_id, [])
        versions.append((int(revision), origin))
        versions.sort(key=lambda item: item[0])
        if origin.key is not None:
            self.key_record[origin.key] = record_id

    def record(self, record_id: str, revision: int | None) -> Origin | None:
        versions = self.records.get(record_id)
        if not versions:
            return None
        if revision is None:
            return versions[-1][1]
        chosen = None
        for from_revision, origin in versions:
            if from_revision <= revision:
                chosen = origin
        return chosen if chosen is not None else versions[0][1]

    def message(self, message_id: str) -> Origin | None:
        return self.messages.get(message_id)


# --------------------------------------------------------------------------- evidence
@dataclass(frozen=True)
class Unit:
    """One piece of evidence an arm hands to the model, resolved against the ledger."""

    channel: str  # "context" (packet item) | "history" (archived message)
    unit_id: str
    revision: int | None
    reported_scope: dict[str, str]
    sources: tuple[str, ...]
    origin: Origin | None
    reported_time: float | None = None  # engine-reported timestamp (history messages)
    reasons: tuple[str, ...] = ()

    @property
    def key(self) -> str | None:
        return self.origin.key if self.origin is not None else None


@dataclass
class Evidence:
    units: list[Unit] = field(default_factory=list)
    packet: ContextPacket | None = None
    history: HistorySearchResult | None = None
    history_text: str = ""
    timings: dict[str, float] = field(default_factory=dict)
    warm_consistent: bool = True

    @property
    def text(self) -> str:
        return (self.packet.text if self.packet is not None else "") + "\n" + self.history_text


def interleave(context: list[Unit], history: list[Unit]) -> list[Unit]:
    """Round-robin across channels (scores of different channels are not comparable)."""
    out: list[Unit] = []
    for i in range(max(len(context), len(history))):
        if i < len(context):
            out.append(context[i])
        if i < len(history):
            out.append(history[i])
    return out


# --------------------------------------------------------------------------- world (synthetic git)
class World:
    """Synthetic git repositories that change over simulated time (D/E only)."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.git = shutil.which("git")
        self.created: set[str] = set()

    @property
    def available(self) -> bool:
        return self.git is not None

    def path(self, repository: str) -> Path:
        return self.root / repository

    def _run(self, cwd: Path, *args: str, at: float) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        stamp = f"@{int(at)} +0000"
        env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C",
                    "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp})
        subprocess.run(
            [self.git or "git", "-c", "user.name=Eval Bot", "-c", "user.email=eval@example.invalid",
             "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull,
             *args], cwd=cwd, env=env, check=True, capture_output=True, timeout=30)

    def commit(self, repository: str, files: dict[str, str], message: str, at: float) -> None:
        repo = self.path(repository)
        if repository not in self.created:
            repo.mkdir(parents=True, exist_ok=True)
            self._run(repo, "init", "-q", ".", at=at)
            self.created.add(repository)
        for rel, content in files.items():
            target = repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        self._run(repo, "add", "-A", at=at)
        self._run(repo, "commit", "-q", "--allow-empty", "-m", message, at=at)


class ChronologicalAuthority:
    """Fake host VerificationAuthority: resolves a receipt only once it has been issued."""

    def __init__(self, clock: SimClock) -> None:
        self.clock = clock
        self.results: dict[str, VerificationResult] = {}

    def issue(self, receipt_id: str, *, task_ref: str, checks: list[list[Any]], issued_at: float,
              trusted: bool = True) -> None:
        self.results[receipt_id] = VerificationResult(
            receipt_id=receipt_id, trusted=trusted, task_ref=task_ref, issued_at=issued_at,
            checks=tuple(VerifiedCheck(str(n), bool(p), bool(r)) for n, p, r in checks))

    def resolve(self, receipt_id: str) -> VerificationResult | None:
        result = self.results.get(receipt_id)
        if result is None or (result.issued_at is not None and result.issued_at > self.clock()):
            return None  # a receipt from the future does not exist yet
        return result


# --------------------------------------------------------------------------- access
def write_access(profile: str) -> AccessContext:
    projects = PROFILES[profile]
    return AccessContext(
        principal=f"eval-{profile}", partition=PartitionRef(EDITION, profile), actor=Actor.USER,
        grants=ScopeGrants(projects=frozenset(projects),
                           repositories=frozenset(REPOSITORIES[p] for p in projects)),
        operations=frozenset(Operation), purpose="evaluation",
    )


def question_grants(project: str | None) -> ScopeGrants:
    if project is None:
        return ScopeGrants()
    return ScopeGrants(projects=frozenset({project}), repositories=frozenset({REPOSITORIES[project]}))


def question_access(question: Question) -> AccessContext:
    """The trusted context the host would build for this question (its scope only)."""
    return AccessContext(
        principal=f"eval-{question.profile}", partition=PartitionRef(EDITION, question.profile),
        actor=Actor.AGENT, grants=question_grants(question.project), operations=frozenset({Operation.READ}),
        purpose="evaluation",
    )


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def directory_bytes(root: Path, *, include_journals: bool = True) -> int:
    """Bytes of every file under ``root``; ``include_journals=False`` skips SQLite -wal/-shm files."""
    total = 0
    if root.exists():
        for path in root.rglob("*"):
            if not path.is_file() or (not include_journals and path.name.endswith(("-wal", "-shm"))):
                continue
            try:
                total += path.stat().st_size
            except OSError:
                continue
    return total


# --------------------------------------------------------------------------- arms
@dataclass(frozen=True)
class ArmConfig:
    token_allowance: int = 800
    history_k: int = 5
    embedding_dimensions: int = 64


class Arm:
    """Base arm. Subclasses switch capabilities on; behaviour is driven by the flags."""

    name = "?"
    memory = False  # remember / correct / forget, context packets
    history = False  # archive messages, search_history, query-relevant context
    episodes = False
    repository = False
    semantic = False

    def __init__(self, corpus: Corpus, workdir: Path, config: ArmConfig, timer: StageTimer) -> None:
        self.corpus = corpus
        self.workdir = Path(workdir)
        self.config = config
        self.timer = timer
        self.clock = SimClock(corpus.events[0].time - 60.0 if corpus.events else 0.0)
        self.ledger = Ledger()
        self.store_root = self.workdir / "store"
        self.world = World(self.workdir / "world")
        self.authority = ChronologicalAuthority(self.clock)
        self.keys = StaticKeyProvider({"eval-k1": secrets.token_bytes(32)})
        self.embedder: Any = None
        self.engine: MemoryEngine | None = None
        self.registered: set[str] = set()
        self.notes: dict[str, Any] = {"deletion_self_check_failures": 0, "repository_available": None,
                                      "snapshots": 0, "snapshot_states": {}, "unmapped_observations": 0}
        self._event_by_id = {e.eid: e for e in corpus.events}

    @property
    def description(self) -> str:
        return ARM_DESCRIPTIONS.get(self.name, self.name)

    # ------------------------------------------------------------------ lifecycle
    def _host(self) -> HostCapabilities:
        providers: dict[str, Any] = {}
        if self.semantic:
            from ..providers.fake import FakeEmbeddingProvider

            if self.embedder is None:
                self.embedder = FakeEmbeddingProvider("fake-embed", dimensions=self.config.embedding_dimensions)
            providers["fake-embed"] = self.embedder
        roots = (self.world.root,) if self.repository and self.world.available else ()
        return HostCapabilities(clock=self.clock, verification=self.authority if self.episodes else None,
                                allowed_repository_roots=roots, providers=providers)

    def open(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        if self.repository:
            self.world.root.mkdir(parents=True, exist_ok=True)
            self.notes["repository_available"] = self.world.available
        if self.memory:
            self.engine = MemoryEngine(self.store_root, self.keys, host=self._host(), config=EngineConfig())

    def close(self) -> None:
        if self.engine is not None:
            self.engine.close()
            self.engine = None

    def storage_bytes(self, *, include_journals: bool = True) -> int:
        return directory_bytes(self.store_root, include_journals=include_journals)

    # ------------------------------------------------------------------ events
    def apply(self, event: Event) -> None:
        self.clock.set(event.time)
        handler = {
            MESSAGE: self._message, REMEMBER: self._remember, CORRECT: self._correct, FORGET: self._forget,
            EPISODE: self._episode, REPO_COMMIT: self._repo_commit, REPO_SNAPSHOT: self._repo_snapshot,
            DAY_END: self._day_end,
        }[event.type]
        handler(event)

    def _origin(self, event: Event, key: str | None, project: str | None = "event") -> Origin:
        scope = event.data.get("project") if project == "event" else project
        return Origin(event.eid, event.time, event.profile, scope, key)

    def _message(self, event: Event) -> None:
        if not self.history:
            return
        d = event.data
        access = write_access(event.profile)
        item = IngestionEvent(event_id=event.eid, session_ref=d["session_ref"], sequence=d["seq"], role=d["role"],
                              text=d["text"], occurred_at=event.time, scope=Scope.of(project=d.get("project")),
                              source="eval-host")
        with self.timer.measure("ingest", "ingest_event"):
            receipt = self.engine.ingest_event(access, item)
        if receipt.message_id:
            self.ledger.add_message(receipt.message_id, self._origin(event, d.get("key")))

    def _cite(self, event_ids: list[str]) -> tuple[SourceRef, ...]:
        """Message sources (history arms) or host-attested user actions naming the event (B)."""
        out = []
        for eid in event_ids:
            message_id = self.ledger.event_message.get(eid)
            if self.history and message_id is not None:
                out.append(SourceRef(SourceKind.MESSAGE, message_id, actor=Actor.USER))
            else:
                ref = f"event:{eid}"
                out.append(SourceRef(SourceKind.USER_ACTION, ref, actor=Actor.USER))
                self.ledger.sources[f"{SourceKind.USER_ACTION.value}:{ref}"] = self._event_by_id[eid].data.get("key")
        return tuple(out)

    def _remember(self, event: Event) -> None:
        if not self.memory:
            return
        d = event.data
        request = RememberRequest(content=d["content"], kind=MemoryKind.parse(d["kind"]),
                                  scope=Scope.of(project=d.get("project")), sources=self._cite(d["cites"]))
        with self.timer.measure("ingest", "remember"):
            result = self.engine.remember(write_access(event.profile), request)
        self.ledger.add_record(result.record.id, result.record.revision, self._origin(event, d["key"]))

    def _correct(self, event: Event) -> None:
        if not self.memory:
            return
        d = event.data
        record_id = self.ledger.key_record[d["old_key"]]
        correction = Correction(content=d["content"], sources=self._cite(d["cites"]), reason="user correction")
        with self.timer.measure("ingest", "correct"):
            result = self.engine.correct(write_access(event.profile), record_id, correction, expected_revision=None)
        old = self.ledger.record(record_id, None)
        project = old.project if old is not None else None
        self.ledger.add_record(record_id, result.record.revision, self._origin(event, d["new_key"], project))

    def _forget(self, event: Event) -> None:
        if not self.memory:
            return
        d = event.data
        access = write_access(event.profile)
        record_id = self.ledger.key_record.get(d["key"])
        if record_id is not None:
            with self.timer.measure("ingest", "forget_memory"):
                try:
                    self.engine.forget(access, ForgetTarget(ForgetTargetKind.MEMORY, record_id))
                except NotFound:
                    pass  # already removed with its source
        if self.history:
            policy = ForgetPolicy(delete_source_archive=True)
            for eid in d["cites"]:
                message_id = self.ledger.event_message.get(eid)
                if message_id is None:
                    continue
                with self.timer.measure("ingest", "forget_source"):
                    self.engine.forget(access, ForgetTarget(ForgetTargetKind.SOURCE, f"message:{message_id}"),
                                       policy=policy)
        if record_id is not None:  # self-check: the record is gone for its own writer
            try:
                self.engine.get(access, record_id)
                self.notes["deletion_self_check_failures"] += 1
            except NotFound:
                pass

    def _episode(self, event: Event) -> None:
        if not self.episodes:
            return
        d = event.data
        refs = []
        for receipt in d["receipts"]:
            self.authority.issue(receipt["receipt_id"], task_ref=d["task_ref"], checks=receipt["checks"],
                                 issued_at=event.time, trusted=receipt.get("trusted", True))
            refs.append(VerificationRef(receipt["receipt_id"]))
            self.ledger.sources[f"{SourceKind.VERIFICATION_RECEIPT.value}:{receipt['receipt_id']}"] = d["key"]
        report = EpisodeReport(
            episode_id=d["episode_id"], task_ref=d["task_ref"], attempt_ref=d["attempt_ref"],
            objective=d["objective"], scope=Scope.of(project=d["project"]), verification=tuple(refs),
            claimed_outcome=d["claimed"], failure_modes=tuple(d.get("failure_modes") or ()),
            uncertainties=tuple(d.get("uncertainties") or ()), started_at=event.time - 600.0, ended_at=event.time,
        )
        with self.timer.measure("ingest", "record_episode"):
            episode, _receipt = self.engine.record_episode(write_access(event.profile), report)
        attempt = f"{SourceKind.TASK_ATTEMPT.value}:{attempt_source_ref(d['task_ref'], d['attempt_ref'])}"
        self.ledger.sources[attempt] = d["key"]
        self.ledger.add_record(episode.record_id, episode.revision, self._origin(event, d["key"]))

    def _repo_commit(self, event: Event) -> None:
        if not self.repository or not self.world.available:
            return
        d = event.data
        files = {path: spec["content"] for path, spec in d["files"].items()}
        with self.timer.measure("world", "git_commit"):  # the world changing, not a memory cost
            self.world.commit(d["repository"], files, d["message"], event.time)
        for spec in d["files"].values():
            blob = blob_sha1(spec["content"].encode())
            self.ledger.blobs[(d["repository"], blob)] = self._origin(event, spec.get("key"))
            self.ledger.sources[f"{SourceKind.BLOB_RANGE.value}:{d['repository']}:{blob}"] = spec.get("key")

    def _repo_snapshot(self, event: Event) -> None:
        if not self.repository or not self.world.available:
            return
        d = event.data
        repository = d["repository"]
        access = write_access(event.profile)
        if repository not in self.registered:
            with self.timer.measure("ingest", "register_repository"):
                self.engine.register_repository(access, self.world.path(repository), repository_id=repository,
                                                scope=Scope.of(project=d["project"], repository=repository))
            self.registered.add(repository)
        with self.timer.measure("ingest", "snapshot_repository"):
            snap = self.engine.snapshot_repository(access, repository)
        self.notes["snapshots"] += 1
        state = str(snap.get("state"))
        self.notes["snapshot_states"][state] = self.notes["snapshot_states"].get(state, 0) + 1
        for record in self.engine.repository_observations(access, repository):
            if record.id in self.ledger.records:
                continue
            blob = next((s.ref.split(":", 1)[1] for s in record.sources
                         if s.kind == SourceKind.BLOB_RANGE and s.ref.startswith(repository + ":")), None)
            origin = self.ledger.blobs.get((repository, blob or ""))
            if origin is None:
                self.notes["unmapped_observations"] += 1
                origin = Origin(event.eid, event.time, event.profile, d["project"], None)
            else:
                origin = Origin(event.eid, event.time, origin.profile, d["project"], origin.key)
            self.ledger.add_record(record.id, record.revision, origin)

    def _day_end(self, event: Event) -> None:
        if not self.memory:
            return
        for profile in PROFILES:
            with self.timer.measure("maintenance", "maintain"):
                self.engine.maintain(write_access(profile))

    # ------------------------------------------------------------------ retrieval
    def context_request(self, question: Question) -> ContextRequest:
        return ContextRequest(token_allowance=self.config.token_allowance,
                              query=question.text if self.history else "")

    def retrieval_access(self, question: Question) -> AccessContext:
        return question_access(question)

    def _context_units(self, packet: ContextPacket) -> list[Unit]:
        units = []
        for item in packet.items:
            units.append(Unit("context", item.record_id, item.revision, item.scope.as_dict(), tuple(item.sources),
                              self.ledger.record(item.record_id, item.revision), None, tuple(item.reasons)))
        return units

    def _history_units(self, result: HistorySearchResult) -> list[Unit]:
        units = []
        for hit in result.hits:
            message = hit.message
            units.append(Unit("history", message.message_id, None, message.scope.as_dict(), (),
                              self.ledger.message(message.message_id), float(message.occurred_at),
                              (f"history_rank:{hit.rank}", f"score_kind:{hit.score_kind}")))
        return units

    def render_history(self, result: HistorySearchResult) -> str:
        lines = [f"[h:{h.message.message_id} {h.message.role} {_iso(h.message.occurred_at)}] {h.message.text}"
                 for h in result.hits]
        return "\n".join(lines)

    def estimate(self, text: str) -> int:
        config = self.engine.config if self.engine is not None else EngineConfig()
        return estimate_tokens(text, config.estimate_chars_per_token, config.estimate_margin) if text else 0

    def retrieve(self, question: Question) -> Evidence:
        self.clock.set(question.asked_at)
        if not self.memory:
            return Evidence()
        access = self.retrieval_access(question)
        request = self.context_request(question)
        evidence = Evidence()
        with self.timer.measure("context_build", "cold"):
            start = time.perf_counter()
            packet = self.engine.build_context(access, request)
            evidence.timings["context_ms"] = (time.perf_counter() - start) * 1000.0
        evidence.packet = packet
        history_units: list[Unit] = []
        if self.history:
            with self.timer.measure("retrieval", "cold"):
                start = time.perf_counter()
                result = self.engine.search_history(access, question.text, limit=self.config.history_k)
                evidence.timings["history_ms"] = (time.perf_counter() - start) * 1000.0
            evidence.history = result
            evidence.history_text = self.render_history(result)
            history_units = self._history_units(result)
        # Warm repeat: same request against the same state (caches/projections reused).
        with self.timer.measure("context_build", "warm"):
            start = time.perf_counter()
            again = self.engine.build_context(access, request)
            evidence.timings["context_warm_ms"] = (time.perf_counter() - start) * 1000.0
        consistent = [(i.record_id, i.revision) for i in again.items] == [(i.record_id, i.revision)
                                                                            for i in packet.items]
        if self.history:
            with self.timer.measure("retrieval", "warm"):
                start = time.perf_counter()
                result2 = self.engine.search_history(access, question.text, limit=self.config.history_k)
                evidence.timings["history_warm_ms"] = (time.perf_counter() - start) * 1000.0
            consistent = consistent and [h.message.message_id for h in result2.hits] == [
                h.message.message_id for h in evidence.history.hits]
        evidence.warm_consistent = consistent
        evidence.units = interleave(self._context_units(packet), history_units)
        return evidence

    def engine_signalled_no_evidence(self, evidence: Evidence) -> bool | None:
        """Did the engine itself report "nothing relevant"? None when the arm has no query channel."""
        if not self.history or evidence.packet is None:
            return None
        relevant = any(r.startswith("relevance_rank:") for u in evidence.units if u.channel == "context"
                       for r in u.reasons)
        history_empty = evidence.history is None or not evidence.history.hits or \
            evidence.history.status == ResultStatus.INSUFFICIENT_EVIDENCE
        return history_empty and not relevant

    # ------------------------------------------------------------------ cold open / disk checks
    def cold_open_probe(self, probes: list[Question]) -> dict[str, Any]:
        """Close, reopen on the same store, and time the first (cold) and second (warm) retrieval."""
        if not self.memory or not probes:
            return {}
        self.close()
        out: dict[str, list[float]] = defaultdict(list)
        start = time.perf_counter()
        self.engine = MemoryEngine(self.store_root, self.keys, host=self._host(), config=EngineConfig())
        out["open_ms"].append((time.perf_counter() - start) * 1000.0)
        for question in probes:
            self.clock.set(max(self.clock.now, question.asked_at))
            access = self.retrieval_access(question)
            request = self.context_request(question)
            for phase in ("cold", "warm"):
                start = time.perf_counter()
                self.engine.build_context(access, request)
                out[f"context_{phase}_ms"].append((time.perf_counter() - start) * 1000.0)
                if self.history:
                    start = time.perf_counter()
                    self.engine.search_history(access, question.text, limit=self.config.history_k)
                    out[f"history_{phase}_ms"].append((time.perf_counter() - start) * 1000.0)
        return {k: round(sum(v), 3) for k, v in out.items()}

    def plaintext_hits(self, needles: list[str]) -> int:
        """Files under the store containing any needle verbatim (content must never be plaintext)."""
        hits = 0
        encoded = [n.encode() for n in needles if len(n) >= 8]
        if not self.store_root.exists():
            return 0
        for path in self.store_root.rglob("*"):
            if not path.is_file():
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            hits += sum(1 for needle in encoded if needle in data)
        return hits

    def provider_usage(self) -> dict[str, Any]:
        if self.embedder is None:
            return {}
        texts = sum(len(call) for call in self.embedder.calls)
        return {"provider": "fake-embed", "label": FAKE_EMBEDDING_LABEL, "embed_calls": len(self.embedder.calls),
                "texts_embedded": texts, "cost_micros": 0, "egress": False}


class ArmA(Arm):
    name = "A"


class ArmB(Arm):
    name = "B"
    memory = True


class ArmC(ArmB):
    name = "C"
    history = True


class ArmD(ArmC):
    name = "D"
    episodes = True
    repository = True


class ArmE(ArmD):
    name = "E"
    semantic = True


ARMS: dict[str, type[Arm]] = {"A": ArmA, "B": ArmB, "C": ArmC, "D": ArmD, "E": ArmE}
