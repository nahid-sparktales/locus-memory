"""Synthetic, seeded, chronological corpus for the cumulative-usefulness benchmark.

Everything here is invented: two profiles (``alpha``, ``beta``), three projects
(``atlas`` and ``borealis`` for alpha, ``cobalt`` for beta), fictional values and
fictional company names. No real user data is read or produced.

The *structure* (which kind of statement happens on which simulated day, which
question is asked when, which keys are gold/forbidden) is fixed; the seed varies
the values, wording, filler chatter, background facts, minute-level timing and
question paraphrases. Every repetition therefore exercises the same categories on
a different surface.

Ground truth is expressed as *statement keys*. A key names one statement (for
example ``atlas.deploy@v2``); every engine unit that can carry it - an archived
message, a memory record revision, an episode revision, a repository observation
of one file version - is mapped back to its key by the arm that wrote it. Metrics
never compare free text with free text, except the clearly labelled extractive
proxy (``KeyInfo.answer``).

Chronology: every event and question has a unique simulated timestamp;
:func:`validate_corpus` checks that gold keys exist before a question is asked and
are neither deleted nor superseded at that time.
"""
from __future__ import annotations

import hashlib
import json
import random
from dataclasses import asdict, dataclass, field
from typing import Any

CORPUS_FORMAT = "locus-memory-eval-corpus/1"
TIME_ZERO = 1_800_000_000.0  # simulated epoch; never compared with wall-clock time
DAY = 86_400.0
HOUR = 3_600.0
DAYS = 14

PROFILES: dict[str, tuple[str, ...]] = {"alpha": ("atlas", "borealis"), "beta": ("cobalt",)}
REPOSITORIES: dict[str, str] = {"atlas": "atlas-repo", "borealis": "borealis-repo", "cobalt": "cobalt-repo"}

# Event types (``Event.type``).
MESSAGE = "message"
REMEMBER = "remember"
CORRECT = "correct"
FORGET = "forget"
EPISODE = "episode"
REPO_COMMIT = "repo_commit"
REPO_SNAPSHOT = "repo_snapshot"
DAY_END = "day_end"
EVENT_TYPES = (MESSAGE, REMEMBER, CORRECT, FORGET, EPISODE, REPO_COMMIT, REPO_SNAPSHOT, DAY_END)

# Question categories.
CATEGORIES = (
    "preference", "project_decision", "correction", "multi_session", "distractor", "stale_repository",
    "repository", "episode", "deletion_before", "deletion", "missing_evidence", "cross_scope",
    "cross_profile", "long_horizon",
)
ABSTAIN_CATEGORIES = frozenset({"deletion", "missing_evidence", "cross_scope", "cross_profile"})


class CorpusError(ValueError):
    """The generated corpus violates its own chronology or ground-truth invariants."""


# --------------------------------------------------------------------------- model
@dataclass(frozen=True)
class KeyInfo:
    """One ground-truth statement. ``project=None`` means profile-global."""

    key: str
    profile: str
    project: str | None
    kind: str  # preference | decision | constraint | fact | chat | claim | repository | episode
    answer: str  # verbatim answer phrase (extractive proxy only)
    introduced_at: float | None = None
    superseded_at: float | None = None  # replaced by a user correction
    stale_at: float | None = None  # the world changed (file edited, later task attempt)
    deleted_at: float | None = None  # the user asked to forget it


@dataclass(frozen=True)
class Event:
    eid: str
    time: float
    profile: str
    type: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Question:
    qid: str
    profile: str
    asked_at: float
    project: str | None  # the trusted scope the host grants for this question
    text: str
    category: str
    gold: tuple[tuple[str, ...], ...]  # requirements; any key of a requirement satisfies it
    forbidden: tuple[str, ...] = ()  # deleted / other-scope / superseded / stale keys
    distractors: tuple[str, ...] = ()  # same-scope similar wording, unverified claims
    expect_abstain: bool = False

    @property
    def day(self) -> int:
        return int((self.asked_at - TIME_ZERO) // DAY)


@dataclass(frozen=True)
class Corpus:
    seed: int
    size: str
    events: tuple[Event, ...]
    questions: tuple[Question, ...]
    keys: dict[str, KeyInfo]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": CORPUS_FORMAT, "seed": self.seed, "size": self.size,
            "events": [asdict(e) for e in self.events],
            "questions": [asdict(q) for q in self.questions],
            "keys": {k: asdict(v) for k, v in sorted(self.keys.items())},
        }

    def summary(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        for event in self.events:
            by_type[event.type] = by_type.get(event.type, 0) + 1
        by_category: dict[str, int] = {}
        for question in self.questions:
            by_category[question.category] = by_category.get(question.category, 0) + 1
        return {
            "seed": self.seed, "size": self.size, "hash": corpus_hash(self), "days": DAYS,
            "events": len(self.events), "events_by_type": dict(sorted(by_type.items())),
            "questions": len(self.questions), "questions_by_category": dict(sorted(by_category.items())),
            "abstention_questions": sum(1 for q in self.questions if q.expect_abstain),
            "keys": len(self.keys), "profiles": {p: list(v) for p, v in PROFILES.items()},
        }


def corpus_hash(corpus: Corpus) -> str:
    payload = json.dumps(corpus.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def blob_sha1(data: bytes) -> str:
    """git's blob id for ``data`` (object format sha1): maps observations to file versions."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


# --------------------------------------------------------------------------- value pools
DATABASES = ["postgres 16", "mysql 8", "cockroachdb", "mariadb 11", "sql server 2022"]
STAGING_DATABASES = ["sqlite", "postgres in docker", "duckdb"]
DEPLOY_TARGETS = ["fly.io", "render.com", "a kubernetes cluster", "aws lambda", "a single hetzner vm",
                  "google cloud run"]
API_STYLES = ["REST with OpenAPI", "GraphQL", "gRPC", "JSON-RPC"]
LATENCY = ["200 ms", "250 ms", "350 ms", "500 ms"]
LICENSES = ["no GPL dependencies", "only MIT or Apache-2.0 dependencies", "no AGPL dependencies"]
QUEUES = ["rabbitmq", "kafka", "amazon sqs", "redis streams"]
CACHES = ["redis", "memcached", "an in-process LRU cache", "valkey"]
CI_PROVIDERS = ["GitHub Actions", "GitLab CI", "Buildkite", "CircleCI", "Jenkins"]
FRONTENDS = ["react", "svelte", "vue", "solid", "htmx"]
RETENTION = ["30 days", "90 days", "180 days", "one year"]
PILOT_CUSTOMERS = ["Harborline Freight", "Bluefin Cargo", "Lumen Transit", "Kestrel Rail"]
CITIES = ["Lisbon", "Oslo", "Kyoto", "Quito", "Tallinn"]
RUNTIMES = ["go 1.22", "rust stable", "node 20", "java 21"]
SEARCH_ENGINES = ["opensearch", "meilisearch", "typesense"]
EXPORT_FORMATS = ["parquet", "csv", "jsonl", "avro"]
EXPORT_PARTITIONS = ["day", "customer", "region"]
JOB_TIMES = ["02:00", "03:30", "04:15", "01:45"]
RATE_LIMITS = ["60", "120", "300", "600"]
PORTS = ["8080", "8443", "9000", "5000"]
WORKERS = ["2", "4", "8"]
TTLS = ["60", "120", "300", "900"]
INDENTS = ["tabs", "4 spaces", "2 spaces"]
COMMIT_STYLES = ["conventional commits", "short imperative subjects", "a ticket id prefix"]
TEST_RUNNERS = ["pytest", "unittest", "ward", "nose2"]
ANSWER_STYLES = ["terse answers with code first", "detailed explanations before code", "bullet-point summaries"]
EDITORS = ["neovim", "vscode", "helix", "emacs"]
TIMEZONES = ["UTC+1", "UTC-5", "UTC+9", "UTC+5:30"]

BACKGROUND_TOOLS: list[tuple[str, list[str]]] = [
    ("formatting", ["black", "ruff format", "yapf"]),
    ("linting", ["ruff", "flake8", "pylint"]),
    ("structured logging", ["structlog", "loguru", "stdlib logging"]),
    ("outgoing HTTP calls", ["httpx", "requests", "aiohttp"]),
    ("schema migrations", ["alembic", "yoyo", "django migrations"]),
    ("feature flags", ["unleash", "flagsmith", "a yaml flag file"]),
    ("metrics", ["prometheus", "statsd", "opentelemetry metrics"]),
    ("tracing", ["opentelemetry", "jaeger", "zipkin"]),
    ("task scheduling", ["celery beat", "apscheduler", "cron"]),
    ("dependency locking", ["uv lock", "pip-tools", "poetry lock"]),
    ("API docs", ["mkdocs", "sphinx", "redoc"]),
    ("load testing", ["locust", "k6", "vegeta"]),
    ("error tracking", ["sentry", "rollbar", "bugsnag"]),
    ("container builds", ["docker buildx", "buildpacks", "kaniko"]),
    ("type checking", ["mypy strict", "pyright", "pytype"]),
    ("release notes", ["towncrier", "git-cliff", "a CHANGES file"]),
    ("property tests", ["hypothesis", "schemathesis", "a custom fuzzer"]),
    ("config parsing", ["pydantic settings", "dynaconf", "environs"]),
]
BACKGROUND_PREFERENCES: list[tuple[str, list[str]]] = [
    ("docstrings", ["google style", "numpy style", "sphinx style"]),
    ("line length", ["100 characters", "88 characters", "120 characters"]),
    ("the terminal shell", ["zsh", "fish", "bash"]),
    ("branch names", ["feature/ prefixes", "ticket-number prefixes", "short kebab-case names"]),
    ("pull requests", ["small PRs", "stacked PRs", "one PR per ticket"]),
    ("type hints", ["full type hints", "type hints on public APIs only", "gradual typing"]),
    ("log output", ["structured json logs", "plain text logs", "logfmt lines"]),
    ("dependency updates", ["weekly batches", "renovate auto-merge", "monthly reviews"]),
    ("code review comments", ["inline suggestions", "a summary comment", "pairing calls"]),
]
COMPONENTS = ["auth", "billing", "search", "export", "scheduler", "uploads", "reporting", "notifications",
              "gateway", "cli", "importer", "audit log"]
FILES = ["handlers.py", "models.py", "utils.py", "client.py", "views.py", "tasks.py", "schema.py"]

USER_FILLER = [
    "Can you check why the {c} tests in {p} are slow?",
    "Let's rename {f} in {p} to something clearer.",
    "Remind me to review the {c} change tomorrow.",
    "The {c} module in {p} needs better error messages.",
    "I'm seeing a timeout in the {c} handler again.",
    "Draft a short changelog entry for the {c} fix.",
    "Which files did we touch in {f} last time?",
    "Let's pair on the {c} refactor in {p} later this week.",
    "Please add a regression test for the {c} bug.",
    "The {c} code path still logs too much.",
]
ASSISTANT_FILLER = [
    "I looked at the {c} code; the slowdown comes from repeated setup in each test.",
    "Renamed it and updated the imports that referenced {f}.",
    "Noted, I'll keep the {c} change small and focused.",
    "The timeout came from a missing retry in {c}; I added one with a short backoff.",
    "Here is a changelog entry for the {c} fix.",
    "I added a regression test that reproduces the {c} bug.",
    "I reduced the {c} log output to warnings and errors.",
    "The {c} refactor is mostly mechanical; I listed the touched files.",
]
GLOBAL_FILLER = [
    "Thanks, that helped.",
    "Can you summarize what we did today?",
    "Let's continue tomorrow morning.",
    "I'll be offline for a couple of hours.",
    "Quick question about my setup before we start.",
    "Please keep answers short today.",
]
GLOBAL_ASSISTANT_FILLER = [
    "Sure, here's a short summary of today's work.",
    "Understood, talk tomorrow.",
    "Happy to help; what's the question?",
    "Okay, I'll keep it brief.",
]


# --------------------------------------------------------------------------- builder
class _Builder:
    def __init__(self, seed: int, size: str) -> None:
        self.rng = random.Random(seed)
        self.seed = seed
        self.size = size
        self.events: list[Event] = []
        self.questions: list[Question] = []
        self.keys: dict[str, dict[str, Any]] = {}
        self._eid = 0
        self._qslot: dict[int, int] = {}
        self.filler_range = (3, 6) if size == "full" else (0, 1)

    # ------------------------------------------------------------------ keys
    def key(self, key: str, profile: str, project: str | None, kind: str, answer: str) -> str:
        if key in self.keys:
            raise CorpusError(f"duplicate key {key}")
        self.keys[key] = {"key": key, "profile": profile, "project": project, "kind": kind, "answer": answer}
        return key

    def _introduce(self, key: str | None, time: float) -> None:
        if key is not None:
            info = self.keys[key]
            if info.get("introduced_at") is None:
                info["introduced_at"] = time

    def mark(self, key: str, field_name: str, time: float) -> None:
        info = self.keys[key]
        if info.get(field_name) is None:
            info[field_name] = time

    # ------------------------------------------------------------------ events
    def event(self, time: float, profile: str, type_: str, **data: Any) -> Event:
        self._eid += 1
        event = Event(f"ev{self._eid:05d}", time, profile, type_, data)
        self.events.append(event)
        return event

    def session(self, profile: str, project: str | None, day: int, hour: float) -> _Session:
        return _Session(self, profile, project, day, hour)

    def at(self, day: int, hour: float, minute: float = 0.0) -> float:
        return TIME_ZERO + day * DAY + hour * HOUR + minute * 60.0

    # ------------------------------------------------------------------ questions
    def ask(self, day: int, profile: str, project: str | None, category: str, templates: list[str],
            gold: list[list[str]] | None = None, *, forbidden: list[str] = (), distractors: list[str] = (),
            abstain: bool = False, **fmt: str) -> None:
        slot = self._qslot.get(day, 0)
        self._qslot[day] = slot + 1
        asked_at = self.at(day, 19.0) + slot * 15.0 + self.rng.randint(0, 9)
        text = self.rng.choice(templates).format(**fmt)
        self.questions.append(Question(
            qid=f"q{len(self.questions) + 1:03d}", profile=profile, asked_at=asked_at, project=project,
            text=text, category=category, gold=tuple(tuple(r) for r in (gold or ())),
            forbidden=tuple(forbidden), distractors=tuple(distractors), expect_abstain=abstain,
        ))

    def build(self) -> Corpus:
        events = tuple(sorted(self.events, key=lambda e: e.time))
        questions = tuple(sorted(self.questions, key=lambda q: q.asked_at))
        keys = {k: KeyInfo(**v) for k, v in sorted(self.keys.items())}
        return Corpus(self.seed, self.size, events, questions, keys)


class _Session:
    """Consecutive events of one host session (one scope, one hour slot)."""

    def __init__(self, builder: _Builder, profile: str, project: str | None, day: int, hour: float) -> None:
        self.b = builder
        self.profile = profile
        self.project = project
        self.ref = f"{profile}-{project or 'general'}-d{day:02d}-h{int(hour):02d}"
        self.cursor = builder.at(day, hour) + builder.rng.randint(0, 300)
        self.end = builder.at(day, hour) + 3_300.0  # sessions stay inside their hour slot
        self.seq = 0

    def _tick(self) -> float:
        now = self.cursor
        if now >= self.end:
            raise CorpusError(f"session {self.ref} overflows its hour slot")
        self.cursor += self.b.rng.randint(25, 95)
        return now

    def say(self, role: str, text: str, key: str | None = None) -> str:
        time = self._tick()
        event = self.b.event(time, self.profile, MESSAGE, session_ref=self.ref, seq=self.seq, role=role,
                             text=text, project=self.project, key=key)
        self.seq += 1
        self.b._introduce(key, time)
        return event.eid

    def remember(self, key: str, kind: str, content: str, cites: list[str], project: str | None = "same") -> None:
        time = self._tick()
        scope = self.project if project == "same" else project
        self.b.event(time, self.profile, REMEMBER, key=key, kind=kind, content=content, project=scope,
                     cites=list(cites))
        self.b._introduce(key, time)

    def correct(self, old_key: str, new_key: str, content: str, cites: list[str]) -> None:
        time = self._tick()
        self.b.event(time, self.profile, CORRECT, old_key=old_key, new_key=new_key, content=content,
                     cites=list(cites))
        self.b.mark(old_key, "superseded_at", time)
        self.b._introduce(new_key, time)

    def forget(self, key: str, cites: list[str]) -> None:
        time = self._tick()
        self.b.event(time, self.profile, FORGET, key=key, cites=list(cites))
        self.b.mark(key, "deleted_at", time)

    def filler(self, count: int | None = None) -> None:
        rng = self.b.rng
        lo, hi = self.b.filler_range
        count = rng.randint(lo, hi) if count is None else count
        for _ in range(count):
            fmt = {"c": rng.choice(COMPONENTS), "f": rng.choice(FILES), "p": self.project or "the project"}
            if self.project is None:
                self.say("user", rng.choice(GLOBAL_FILLER))
                self.say("assistant", rng.choice(GLOBAL_ASSISTANT_FILLER))
            else:
                self.say("user", rng.choice(USER_FILLER).format(**fmt))
                self.say("assistant", rng.choice(ASSISTANT_FILLER).format(**fmt))

    def statement(self, key: str, kind: str, message: str, memory: str, *, echo: str | None = None,
                  remember: bool = True) -> list[str]:
        """A user statement (+ optional assistant echo) that the host remembers as approved memory."""
        cites = [self.say("user", message, key)]
        if echo is not None:
            cites.append(self.say("assistant", echo, key))
        if remember:
            self.remember(key, kind, memory, cites)
        return cites


# --------------------------------------------------------------------------- generation
def generate_corpus(seed: int = 0, *, size: str = "full") -> Corpus:
    """Deterministic corpus for ``seed``. ``size='small'`` keeps the structure, drops most filler."""
    if size not in ("full", "small"):
        raise ValueError("size must be 'full' or 'small'")
    b = _Builder(seed, size)
    rng = b.rng
    n_bg_tools = 14 if size == "full" else 4
    n_bg_prefs = 6 if size == "full" else 2

    def pick(pool: list[str], *exclude: str) -> str:
        return rng.choice([x for x in pool if x not in exclude])

    v: dict[str, str] = {}
    v["atlas.db"] = pick(DATABASES)
    v["borealis.db"] = pick(DATABASES, v["atlas.db"])
    v["cobalt.db"] = pick(DATABASES)
    v["atlas.staging"] = pick(STAGING_DATABASES)
    v["atlas.deploy1"] = pick(DEPLOY_TARGETS)
    v["atlas.deploy2"] = pick(DEPLOY_TARGETS, v["atlas.deploy1"])
    v["borealis.deploy"] = pick(DEPLOY_TARGETS, v["atlas.deploy1"], v["atlas.deploy2"])
    v["cobalt.deploy"] = pick(DEPLOY_TARGETS)
    v["atlas.api"] = pick(API_STYLES)
    v["atlas.latency"] = pick(LATENCY)
    v["atlas.license"] = pick(LICENSES)
    v["atlas.queue"] = pick(QUEUES)
    v["atlas.ci"] = pick(CI_PROVIDERS)
    v["cobalt.ci"] = pick(CI_PROVIDERS)
    v["cache1"] = pick(CACHES)
    v["cache2"] = pick(CACHES, v["cache1"])
    v["ttl1"] = pick(TTLS)
    v["ttl2"] = pick(TTLS, v["ttl1"])
    v["rate"] = pick(RATE_LIMITS)
    v["port"] = pick(PORTS)
    v["workers"] = pick(WORKERS)
    v["front1"] = pick(FRONTENDS)
    v["front2"] = pick(FRONTENDS, v["front1"])
    v["retention"] = pick(RETENTION)
    v["pilot"] = pick(PILOT_CUSTOMERS)
    v["city"] = pick(CITIES)
    v["runtime"] = pick(RUNTIMES)
    v["search"] = pick(SEARCH_ENGINES)
    v["search_index"] = rng.choice(["docs-v2", "catalog-main", "records-live"])
    v["export1"] = pick(EXPORT_FORMATS)
    v["export2"] = pick(EXPORT_FORMATS, v["export1"])
    v["export_part"] = pick(EXPORT_PARTITIONS)
    v["job_time"] = pick(JOB_TIMES)
    for profile in PROFILES:
        v[f"{profile}.indent"] = pick(INDENTS, *(() if profile == "alpha" else (v["alpha.indent"],)))
        v[f"{profile}.commits"] = pick(COMMIT_STYLES, *(() if profile == "alpha" else (v["alpha.commits"],)))
        v[f"{profile}.answers"] = pick(ANSWER_STYLES, *(() if profile == "alpha" else (v["alpha.answers"],)))
        v[f"{profile}.editor"] = pick(EDITORS, *(() if profile == "alpha" else (v["alpha.editor"],)))
    v["alpha.tests1"] = pick(TEST_RUNNERS)
    v["alpha.tests2"] = pick(TEST_RUNNERS, v["alpha.tests1"])
    v["alpha.tz"] = pick(TIMEZONES)

    # Background facts/preferences: budget competitors and same-scope lexical noise.
    background: dict[str, list[tuple[str, str, str]]] = {}
    for project in ("atlas", "borealis", "cobalt"):
        purposes = rng.sample(BACKGROUND_TOOLS, k=n_bg_tools)
        background[project] = [(f"{project}.bg.{i:02d}", purpose, rng.choice(tools))
                               for i, (purpose, tools) in enumerate(purposes)]
    bg_prefs: dict[str, list[tuple[str, str, str]]] = {}
    for profile in PROFILES:
        purposes = rng.sample(BACKGROUND_PREFERENCES, k=n_bg_prefs)
        bg_prefs[profile] = [(f"{profile}.bgpref.{i:02d}", purpose, rng.choice(values))
                             for i, (purpose, values) in enumerate(purposes)]

    # ---------------------------------------------------------------- keys
    K = b.key
    for profile in PROFILES:
        K(f"{profile}.pref.indent", profile, None, "preference", f"{v[f'{profile}.indent']} for indentation")
        K(f"{profile}.pref.commits", profile, None, "preference", f"commit messages with {v[f'{profile}.commits']}")
        K(f"{profile}.pref.answers", profile, None, "preference", v[f"{profile}.answers"])
        K(f"{profile}.pref.editor", profile, None, "preference", f"code in {v[f'{profile}.editor']}")
        for key, purpose, value in bg_prefs[profile]:
            K(key, profile, None, "preference", f"{value} for {purpose}")
    K("alpha.pref.tests@v1", "alpha", None, "preference", f"tests with {v['alpha.tests1']}")
    K("alpha.pref.tests@v2", "alpha", None, "preference", f"tests with {v['alpha.tests2']}")
    K("alpha.pref.timezone", "alpha", None, "preference", f"timezone is {v['alpha.tz']}")
    K("alpha.fact.city", "alpha", None, "fact", f"city for weather examples is {v['city']}")
    K("atlas.db", "alpha", "atlas", "decision", f"production database is {v['atlas.db']}")
    K("atlas.staging_db", "alpha", "atlas", "fact", f"staging database is {v['atlas.staging']}")
    K("atlas.deploy@v1", "alpha", "atlas", "decision", f"deploy target is {v['atlas.deploy1']}")
    K("atlas.deploy@v2", "alpha", "atlas", "decision", f"deploy target is {v['atlas.deploy2']}")
    K("atlas.latency", "alpha", "atlas", "constraint", f"latency must stay under {v['atlas.latency']}")
    K("atlas.api", "alpha", "atlas", "decision", f"API style is {v['atlas.api']}")
    K("atlas.license", "alpha", "atlas", "constraint", v["atlas.license"])
    K("atlas.queue", "alpha", "atlas", "decision", f"job queue is {v['atlas.queue']}")
    K("atlas.ci", "alpha", "atlas", "decision", f"CI provider is {v['atlas.ci']}")
    K("atlas.cache_chat", "alpha", "atlas", "chat", f"cache backend is {v['cache1']}")
    K("borealis.db", "alpha", "borealis", "decision", f"production database is {v['borealis.db']}")
    K("borealis.frontend@v1", "alpha", "borealis", "decision", f"frontend framework is {v['front1']}")
    K("borealis.frontend@v2", "alpha", "borealis", "decision", f"frontend framework is {v['front2']}")
    K("borealis.retention", "alpha", "borealis", "constraint", f"retention is capped at {v['retention']}")
    K("borealis.pilot", "alpha", "borealis", "fact", f"pilot customer is {v['pilot']}")
    K("borealis.deploy", "alpha", "borealis", "decision", f"deploy target is {v['borealis.deploy']}")
    K("borealis.toolchain_chat", "alpha", "borealis", "chat", "starting the borealis build toolchain upgrade")
    K("cobalt.runtime", "beta", "cobalt", "decision", f"runtime is {v['runtime']}")
    K("cobalt.db", "beta", "cobalt", "decision", f"production database is {v['cobalt.db']}")
    K("cobalt.deploy", "beta", "cobalt", "decision", f"deploy target is {v['cobalt.deploy']}")
    K("cobalt.ci", "beta", "cobalt", "decision", f"CI provider is {v['cobalt.ci']}")
    for project, facts in background.items():
        profile = "beta" if project == "cobalt" else "alpha"
        for key, purpose, tool in facts:
            K(key, profile, project, "decision", f"uses {tool} for {purpose}")
    # Repository facts (one key per file version; answer = the docstring's first line).
    repo_doc = {
        "repo.atlas.cache@v1": f"Cache backend: {v['cache1']} with a TTL of {v['ttl1']} seconds.",
        "repo.atlas.cache@v2": f"Cache backend: {v['cache2']} with a TTL of {v['ttl2']} seconds.",
        "repo.atlas.ratelimit": f"Rate limit: {v['rate']} requests per minute per API key.",
        "repo.atlas.settings": f"Service port: {v['port']}; worker count: {v['workers']}.",
        "repo.borealis.search": f"Search engine: {v['search']}, index named {v['search_index']}.",
        "repo.borealis.export@v1": f"Export format: {v['export1']} files partitioned by {v['export_part']}.",
        "repo.borealis.export@v2": f"Export format: {v['export2']} files partitioned by {v['export_part']}.",
        "repo.cobalt.jobs": f"Nightly job schedule: runs at {v['job_time']} UTC.",
    }
    for key, doc in repo_doc.items():
        project = key.split(".")[1]
        K(key, "beta" if project == "cobalt" else "alpha", project, "repository", doc)
    # Episodes (answer = objective + derived outcome as rendered by the engine).
    tasks = {
        "atlas": "Add rate limiting to the atlas API",
        "borealis": "Upgrade the borealis build toolchain",
        "cobalt": "Fix the flaky cobalt integration test",
    }
    K("ep.atlas.ratelimit@a1", "alpha", "atlas", "episode", f"Episode: {tasks['atlas']} Outcome: failure")
    K("ep.atlas.ratelimit@a2", "alpha", "atlas", "episode",
      f"Episode: {tasks['atlas']} Outcome: verified_success")
    K("ep.borealis.toolchain@a1", "alpha", "borealis", "episode",
      f"Episode: {tasks['borealis']} Outcome: interrupted")
    K("ep.cobalt.flaky@a1", "beta", "cobalt", "episode", f"Episode: {tasks['cobalt']} Outcome: partial")
    K("ep.cobalt.flaky@a2", "beta", "cobalt", "episode", f"Episode: {tasks['cobalt']} Outcome: verified_success")
    K("claim.atlas.ratelimit", "alpha", "atlas", "claim", "is done and all tests pass")

    # ---------------------------------------------------------------- helpers
    def bg_statements(s: _Session, items: list[tuple[str, str, str]]) -> None:
        project = s.project
        for key, purpose, tool in items:
            s.statement(key, "decision", f"{project} uses {tool} for {purpose}.", f"{project} uses {tool} for {purpose}.")

    def bg_pref_statements(s: _Session, items: list[tuple[str, str, str]]) -> None:
        for key, purpose, value in items:
            s.statement(key, "preference", f"I prefer {value} for {purpose}.", f"User prefers {value} for {purpose}.")

    def chunks(items: list[Any], n: int) -> list[list[Any]]:
        out: list[list[Any]] = [[] for _ in range(n)]
        for i, item in enumerate(items):
            out[i % n].append(item)
        return out

    bg_by_day = {p: chunks(background[p], 5) for p in background}  # spread over days 0, 1, 2, 3, 10
    pref_by_day = {p: chunks(bg_prefs[p], 3) for p in bg_prefs}  # days 0, 2, 8

    def repo_file(key: str, body: str) -> str:
        return f'"""{repo_doc[key]}"""\n{body}'

    files = {
        "repo.atlas.cache@v1": ("atlas/cache.py", repo_file(
            "repo.atlas.cache@v1", "import os\n\n\ndef make_cache():\n    return os.environ.get('CACHE_URL')\n")),
        "repo.atlas.cache@v2": ("atlas/cache.py", repo_file(
            "repo.atlas.cache@v2", "import os\n\n\ndef make_cache():\n    return os.environ.get('CACHE_URL')\n\n\n"
                                   "def flush_all():\n    return None\n")),
        "repo.atlas.ratelimit": ("atlas/ratelimit.py", repo_file(
            "repo.atlas.ratelimit", "\n\ndef allow(client_id):\n    return bool(client_id)\n")),
        "repo.atlas.settings": ("atlas/settings.py", repo_file(
            "repo.atlas.settings", f"PORT = {v['port']}\nWORKERS = {v['workers']}\n")),
        "repo.borealis.search": ("borealis/search.py", repo_file(
            "repo.borealis.search", "\n\nclass SearchClient:\n    pass\n")),
        "repo.borealis.export@v1": ("borealis/export.py", repo_file(
            "repo.borealis.export@v1", "import csv\n\n\ndef export_rows(rows):\n    return list(rows)\n")),
        "repo.borealis.export@v2": ("borealis/export.py", repo_file(
            "repo.borealis.export@v2", "import json\n\n\ndef export_rows(rows):\n    return list(rows)\n")),
        "repo.cobalt.jobs": ("cobalt/jobs.py", repo_file(
            "repo.cobalt.jobs", "\n\ndef nightly():\n    return 'scheduled'\n")),
    }

    def commit(day: int, profile: str, project: str, keys: list[str], message: str, minute: float) -> None:
        time = b.at(day, 18.0, minute) + rng.randint(0, 50)
        payload = {}
        for key in keys:
            path, content = files[key]
            payload[path] = {"content": content, "key": key}
            b._introduce(key, time)
        b.event(time, profile, REPO_COMMIT, project=project, repository=REPOSITORIES[project], files=payload,
                message=message)
        b.event(time + 600 + rng.randint(0, 50), profile, REPO_SNAPSHOT, project=project,
                repository=REPOSITORIES[project])

    def repo_init(profile: str, project: str, minute: float) -> None:
        time = b.at(0, 18.0, minute) + rng.randint(0, 50)
        b.event(time, profile, REPO_COMMIT, project=project, repository=REPOSITORIES[project],
                files={"README.md": {"content": f"# {project}\n\nSynthetic evaluation repository.\n", "key": None}},
                message="initial commit")
        b.event(time + 600 + rng.randint(0, 50), profile, REPO_SNAPSHOT, project=project,
                repository=REPOSITORIES[project])

    def episode(day: int, hour: float, profile: str, project: str, key: str, attempt: str, claimed: str,
                checks: list[tuple[str, bool]], **extra: Any) -> None:
        time = b.at(day, hour) + rng.randint(0, 600)
        receipts = []
        if checks:
            receipts.append({"receipt_id": f"rcpt-{project}-{attempt}-{seed}", "trusted": True,
                             "checks": [[name, passed, True] for name, passed in checks]})
        b.event(time, profile, EPISODE, project=project, key=key, episode_id=f"ep-{project}-task",
                task_ref=f"task-{project}", attempt_ref=attempt, objective=tasks[project], claimed=claimed,
                receipts=receipts, **extra)
        b._introduce(key, time)

    # ---------------------------------------------------------------- alpha: general sessions (08:00)
    for day in range(DAYS):
        s = b.session("alpha", None, day, 8.0)
        if day == 0:
            s.statement("alpha.pref.indent", "preference", f"I prefer {v['alpha.indent']} for indentation.",
                        f"User prefers {v['alpha.indent']} for indentation.")
            s.statement("alpha.pref.commits", "preference",
                        f"Please write commit messages with {v['alpha.commits']}.",
                        f"User wants commit messages with {v['alpha.commits']}.")
            bg_pref_statements(s, pref_by_day["alpha"][0])
        elif day == 1:
            s.statement("alpha.pref.tests@v1", "preference", f"I run tests with {v['alpha.tests1']}.",
                        f"User runs tests with {v['alpha.tests1']}.")
            s.statement("alpha.fact.city", "fact", f"My city for weather examples is {v['city']}.",
                        f"User's city for weather examples is {v['city']}.",
                        echo=f"Noted: your city for weather examples is {v['city']}.")
            s.statement("alpha.pref.answers", "preference", f"When answering, I want {v['alpha.answers']}.",
                        f"User wants {v['alpha.answers']} when answering.")
        elif day == 2:
            s.statement("alpha.pref.editor", "preference", f"I edit code in {v['alpha.editor']}.",
                        f"User edits code in {v['alpha.editor']}.")
            bg_pref_statements(s, pref_by_day["alpha"][1])
        elif day == 3:
            s.statement("alpha.pref.timezone", "preference",
                        f"Schedule things for me in my timezone; my timezone is {v['alpha.tz']}.",
                        f"User's timezone is {v['alpha.tz']}.")
        elif day == 5:
            cites = [e.eid for e in b.events if e.type == MESSAGE and e.data.get("key") == "alpha.fact.city"]
            s.say("user", "Please forget the city I gave you for weather examples.")
            s.forget("alpha.fact.city", cites)
            s.say("assistant", "Done, I removed it.")
        elif day == 6:
            cite = s.say("user", f"Update: I switched, I now run tests with {v['alpha.tests2']}.", "alpha.pref.tests@v2")
            s.correct("alpha.pref.tests@v1", "alpha.pref.tests@v2", f"User runs tests with {v['alpha.tests2']}.",
                      [cite])
        elif day == 8:
            bg_pref_statements(s, pref_by_day["alpha"][2])
        s.filler()

    # ---------------------------------------------------------------- alpha: atlas (09:00)
    for day in range(DAYS):
        s = b.session("alpha", "atlas", day, 9.0)
        if day == 0:
            s.statement("atlas.db", "decision", f"Decision for atlas: the production database is {v['atlas.db']}.",
                        f"atlas production database is {v['atlas.db']}.")
            s.statement("atlas.staging_db", "fact",
                        f"For atlas staging, the staging database is {v['atlas.staging']} for now.",
                        f"atlas staging database is {v['atlas.staging']}.")
            bg_statements(s, bg_by_day["atlas"][0])
        elif day == 1:
            s.statement("atlas.deploy@v1", "decision", f"Decision: the atlas deploy target is {v['atlas.deploy1']}.",
                        f"atlas deploy target is {v['atlas.deploy1']}.",
                        echo=f"Recorded: the atlas deploy target is {v['atlas.deploy1']}.")
            s.statement("atlas.latency", "constraint",
                        f"Constraint for atlas: p95 API latency must stay under {v['atlas.latency']}.",
                        f"atlas constraint: p95 API latency must stay under {v['atlas.latency']}.")
            bg_statements(s, bg_by_day["atlas"][1])
        elif day == 2:
            s.say("user", f"Heads up: in atlas the cache backend is {v['cache1']} right now.", "atlas.cache_chat")
            s.statement("atlas.api", "decision", f"For atlas the API style is {v['atlas.api']}.",
                        f"atlas API style is {v['atlas.api']}.")
            bg_statements(s, bg_by_day["atlas"][2])
        elif day == 3:
            s.statement("atlas.queue", "decision", f"Decision: the atlas job queue is {v['atlas.queue']}.",
                        f"atlas job queue is {v['atlas.queue']}.")
            s.statement("atlas.license", "constraint", f"Constraint for atlas: {v['atlas.license']}.",
                        f"atlas dependency constraint: {v['atlas.license']}.")
            s.say("user", "Please add rate limiting to the atlas API.")
            s.say("assistant", "Rate limiting for the atlas API is done and all tests pass.", "claim.atlas.ratelimit")
            bg_statements(s, bg_by_day["atlas"][3])
        elif day == 4:
            s.statement("atlas.ci", "decision", f"For atlas the CI provider is {v['atlas.ci']}.",
                        f"atlas CI provider is {v['atlas.ci']}.")
        elif day == 6:
            cite = s.say("user", f"Change of plan for atlas: the deploy target is {v['atlas.deploy2']} from now on.",
                         "atlas.deploy@v2")
            s.correct("atlas.deploy@v1", "atlas.deploy@v2", f"atlas deploy target is {v['atlas.deploy2']}.", [cite])
        elif day == 10:
            bg_statements(s, bg_by_day["atlas"][4])
        s.filler()

    # ---------------------------------------------------------------- alpha: borealis (13:00)
    for day in range(DAYS):
        s = b.session("alpha", "borealis", day, 13.0)
        if day == 0:
            s.statement("borealis.db", "decision",
                        f"Decision for borealis: the production database is {v['borealis.db']}.",
                        f"borealis production database is {v['borealis.db']}.")
            bg_statements(s, bg_by_day["borealis"][0])
        elif day == 1:
            s.statement("borealis.frontend@v1", "decision", f"The borealis frontend framework is {v['front1']}.",
                        f"borealis frontend framework is {v['front1']}.")
            s.statement("borealis.retention", "constraint",
                        f"Constraint for borealis: user data retention is capped at {v['retention']}.",
                        f"borealis constraint: user data retention is capped at {v['retention']}.")
            bg_statements(s, bg_by_day["borealis"][1])
        elif day == 2:
            s.statement("borealis.pilot", "fact", f"The borealis pilot customer is {v['pilot']}; keep that internal.",
                        f"borealis pilot customer is {v['pilot']}.",
                        echo=f"Noted, the borealis pilot customer is {v['pilot']}.")
            s.statement("borealis.deploy", "decision", f"Decision: the borealis deploy target is {v['borealis.deploy']}.",
                        f"borealis deploy target is {v['borealis.deploy']}.")
            bg_statements(s, bg_by_day["borealis"][2])
        elif day == 3:
            bg_statements(s, bg_by_day["borealis"][3])
        elif day == 4:
            s.say("user", "We are starting the borealis build toolchain upgrade now.", "borealis.toolchain_chat")
        elif day == 8:
            cite = s.say("user", f"We are rewriting it: the borealis frontend framework is {v['front2']} now.",
                         "borealis.frontend@v2")
            s.correct("borealis.frontend@v1", "borealis.frontend@v2", f"borealis frontend framework is {v['front2']}.",
                      [cite])
        elif day == 9:
            cites = [e.eid for e in b.events if e.type == MESSAGE and e.data.get("key") == "borealis.pilot"]
            s.say("user", "Please forget who the borealis pilot customer is.")
            s.forget("borealis.pilot", cites)
        elif day == 10:
            bg_statements(s, bg_by_day["borealis"][4])
        s.filler()

    # ---------------------------------------------------------------- beta: general (10:00) and cobalt (15:00)
    for day in range(DAYS):
        s = b.session("beta", None, day, 10.0)
        if day == 0:
            s.statement("beta.pref.indent", "preference", f"I prefer {v['beta.indent']} for indentation.",
                        f"User prefers {v['beta.indent']} for indentation.")
            s.statement("beta.pref.commits", "preference", f"Please write commit messages with {v['beta.commits']}.",
                        f"User wants commit messages with {v['beta.commits']}.")
            bg_pref_statements(s, pref_by_day["beta"][0])
        elif day == 1:
            s.statement("beta.pref.answers", "preference", f"When answering, I want {v['beta.answers']}.",
                        f"User wants {v['beta.answers']} when answering.")
            s.statement("beta.pref.editor", "preference", f"I edit code in {v['beta.editor']}.",
                        f"User edits code in {v['beta.editor']}.")
        elif day == 3:
            bg_pref_statements(s, pref_by_day["beta"][1])
        elif day == 7:
            bg_pref_statements(s, pref_by_day["beta"][2])
        s.filler()
    for day in range(DAYS):
        s = b.session("beta", "cobalt", day, 15.0)
        if day == 0:
            s.statement("cobalt.runtime", "decision", f"Decision for cobalt: the runtime is {v['runtime']}.",
                        f"cobalt runtime is {v['runtime']}.")
            s.statement("cobalt.db", "decision", f"Decision for cobalt: the production database is {v['cobalt.db']}.",
                        f"cobalt production database is {v['cobalt.db']}.")
            bg_statements(s, bg_by_day["cobalt"][0])
        elif day == 1:
            s.statement("cobalt.deploy", "decision", f"Decision: the cobalt deploy target is {v['cobalt.deploy']}.",
                        f"cobalt deploy target is {v['cobalt.deploy']}.")
            s.statement("cobalt.ci", "decision", f"For cobalt the CI provider is {v['cobalt.ci']}.",
                        f"cobalt CI provider is {v['cobalt.ci']}.")
            bg_statements(s, bg_by_day["cobalt"][1])
        elif day == 2:
            s.say("user", "The cobalt integration test is flaky again; please take a look.")
            bg_statements(s, bg_by_day["cobalt"][2])
        elif day == 5:
            bg_statements(s, bg_by_day["cobalt"][3])
        elif day == 10:
            bg_statements(s, bg_by_day["cobalt"][4])
        s.filler()

    # ---------------------------------------------------------------- repositories (18:00, snapshots +10 min)
    repo_init("alpha", "atlas", 0)
    repo_init("alpha", "borealis", 20)
    repo_init("beta", "cobalt", 40)
    commit(1, "beta", "cobalt", ["repo.cobalt.jobs"], "add nightly jobs", 40)
    commit(2, "alpha", "atlas", ["repo.atlas.cache@v1"], "add cache module", 0)
    commit(3, "alpha", "atlas", ["repo.atlas.ratelimit"], "add rate limiter", 0)
    commit(3, "alpha", "borealis", ["repo.borealis.search"], "add search client", 20)
    commit(5, "alpha", "atlas", ["repo.atlas.settings"], "add settings", 0)
    commit(5, "alpha", "borealis", ["repo.borealis.export@v1"], "add export", 20)
    commit(7, "alpha", "atlas", ["repo.atlas.cache@v2"], "switch cache backend", 0)
    b.mark("repo.atlas.cache@v1", "stale_at", b.events[-2].time)
    b.mark("atlas.cache_chat", "stale_at", b.events[-2].time)
    commit(9, "alpha", "borealis", ["repo.borealis.export@v2"], "change export format", 20)
    b.mark("repo.borealis.export@v1", "stale_at", b.events[-2].time)

    # ---------------------------------------------------------------- episodes (16:00-17:00), fake host receipts
    episode(3, 16.0, "alpha", "atlas", "ep.atlas.ratelimit@a1", "a1", "verified_success", [("unit-tests", False)],
            failure_modes=["the limiter rejected valid burst traffic in unit tests"])
    episode(7, 16.0, "alpha", "atlas", "ep.atlas.ratelimit@a2", "a2", "verified_success",
            [("unit-tests", True), ("load-test", True)])
    b.mark("ep.atlas.ratelimit@a1", "stale_at", b.events[-1].time)
    episode(4, 16.5, "alpha", "borealis", "ep.borealis.toolchain@a1", "a1", "interrupted", [],
            uncertainties=["the session ended before the lockfile was regenerated"])
    episode(2, 16.75, "beta", "cobalt", "ep.cobalt.flaky@a1", "a1", "partial", [])
    episode(8, 16.75, "beta", "cobalt", "ep.cobalt.flaky@a2", "a2", "verified_success", [("integration-tests", True)])
    b.mark("ep.cobalt.flaky@a1", "stale_at", b.events[-1].time)

    for day in range(DAYS):
        b.event(b.at(day, 23.0), "*", DAY_END, day=day)

    # ---------------------------------------------------------------- questions (19:00+)
    A, B_ = "alpha", "beta"
    other_db = ["borealis.db", "cobalt.db"]
    b.ask(1, A, None, "deletion_before", ["Which city should weather examples use for me?",
                                           "What city do I use for weather examples?"], [["alpha.fact.city"]])
    b.ask(1, A, "atlas", "project_decision", ["Which production database does atlas run on?",
                                               "What is the atlas production database?"], [["atlas.db"]],
          forbidden=other_db, distractors=["atlas.staging_db"])
    b.ask(1, B_, "cobalt", "project_decision", ["Which runtime does cobalt use?", "What runtime is cobalt built on?"],
          [["cobalt.runtime"]])
    b.ask(2, A, "atlas", "project_decision", ["Where does atlas deploy?", "What is the atlas deploy target?"],
          [["atlas.deploy@v1"]], forbidden=["borealis.deploy", "cobalt.deploy"])
    b.ask(2, A, None, "preference", ["Which test runner do I use?", "What do I run tests with?"],
          [["alpha.pref.tests@v1"]])
    b.ask(2, B_, "cobalt", "preference", ["How should code be indented for me?", "What indentation do I prefer?"],
          [["beta.pref.indent"]], forbidden=["alpha.pref.indent"])
    b.ask(3, A, "atlas", "repository", ["Which cache backend does atlas use?", "What is the atlas cache backend?"],
          [["repo.atlas.cache@v1", "atlas.cache_chat"]])
    b.ask(3, A, "atlas", "project_decision", ["What is the atlas latency constraint?",
                                               "How fast must the atlas API respond at p95?"], [["atlas.latency"]])
    b.ask(3, A, "borealis", "project_decision", ["What frontend framework does borealis use?",
                                                  "Which framework is the borealis frontend built with?"],
          [["borealis.frontend@v1"]])
    b.ask(3, A, "borealis", "deletion_before", ["Who is the borealis pilot customer?",
                                                 "Which customer is piloting borealis?"], [["borealis.pilot"]])
    b.ask(4, A, "atlas", "episode", ["Did the atlas rate limiting change pass verification?",
                                     "Is the atlas API rate limiting verified as working?"],
          [["ep.atlas.ratelimit@a1"]], distractors=["claim.atlas.ratelimit"])
    b.ask(4, A, "atlas", "repository", ["What rate limit is configured for the atlas API?",
                                        "How many requests per minute does atlas allow per API key?"],
          [["repo.atlas.ratelimit"]])
    b.ask(4, A, "atlas", "distractor", ["Which database does atlas staging use?",
                                        "What is the atlas staging database?"], [["atlas.staging_db"]],
          distractors=["atlas.db"])
    b.ask(4, B_, "cobalt", "project_decision", ["What CI provider does cobalt use?", "Where does cobalt run CI?"],
          [["cobalt.ci"]], forbidden=["atlas.ci"])
    b.ask(5, A, "borealis", "episode", ["Was the borealis build toolchain upgrade completed?",
                                        "Did the borealis toolchain upgrade finish?"],
          [["ep.borealis.toolchain@a1"]], distractors=["borealis.toolchain_chat"])
    b.ask(5, A, "borealis", "repository", ["Which search engine backs borealis search?",
                                           "What search engine does borealis use?"], [["repo.borealis.search"]])
    b.ask(5, A, None, "cross_scope", ["What is the atlas production database?",
                                      "Which database does atlas use in production?"], abstain=True,
          forbidden=["atlas.db", "borealis.db"])
    b.ask(6, A, None, "deletion", ["Which city should weather examples use for me?",
                                   "What city do I use for weather examples?"], abstain=True,
          forbidden=["alpha.fact.city"])
    b.ask(6, A, "borealis", "missing_evidence", ["What CI provider does borealis use?",
                                                 "Where does borealis run CI?"], abstain=True,
          forbidden=["atlas.ci", "cobalt.ci"])
    b.ask(6, A, "atlas", "repository", ["Which port does the atlas service listen on?",
                                        "What port is configured for the atlas service?"], [["repo.atlas.settings"]])
    b.ask(6, B_, "cobalt", "episode", ["Is the flaky cobalt integration test fixed?",
                                       "What happened with the flaky cobalt integration test?"],
          [["ep.cobalt.flaky@a1"]])
    b.ask(7, A, None, "correction", ["Which test runner do I use?", "What do I run tests with?"],
          [["alpha.pref.tests@v2"]], forbidden=["alpha.pref.tests@v1"])
    b.ask(7, A, "atlas", "correction", ["Where does atlas deploy now?", "What is the current atlas deploy target?"],
          [["atlas.deploy@v2"]], forbidden=["atlas.deploy@v1", "borealis.deploy", "cobalt.deploy"])
    b.ask(7, A, "atlas", "missing_evidence", ["What on-call rotation does atlas use?",
                                              "Who is on call for atlas this week?"], abstain=True)
    b.ask(8, A, "atlas", "stale_repository", ["Which cache backend does atlas use now?",
                                              "What is the current atlas cache backend?"],
          [["repo.atlas.cache@v2"]], forbidden=["repo.atlas.cache@v1", "atlas.cache_chat"])
    b.ask(8, A, "atlas", "episode", ["What is the verified status of the atlas rate limiting work?",
                                     "Has atlas rate limiting been verified yet?"],
          [["ep.atlas.ratelimit@a2"]], forbidden=["ep.atlas.ratelimit@a1"], distractors=["claim.atlas.ratelimit"])
    b.ask(8, B_, "cobalt", "cross_profile", ["Where does atlas deploy?", "What is the atlas deploy target?"],
          abstain=True, forbidden=["atlas.deploy@v1", "atlas.deploy@v2", "borealis.deploy"])
    b.ask(9, A, "atlas", "multi_session", ["For the atlas release checklist: which production database and which"
                                           " deploy target?", "Which database and deploy target should the atlas"
                                                              " release use?"],
          [["atlas.db"], ["atlas.deploy@v2"]], forbidden=["atlas.deploy@v1"] + other_db,
          distractors=["atlas.staging_db"])
    b.ask(9, A, "borealis", "correction", ["What frontend framework does borealis use now?",
                                           "Which framework is the borealis frontend built with today?"],
          [["borealis.frontend@v2"]], forbidden=["borealis.frontend@v1"])
    b.ask(9, B_, "cobalt", "repository", ["When does the cobalt nightly job run?",
                                          "What time is the cobalt nightly job scheduled?"], [["repo.cobalt.jobs"]])
    b.ask(9, B_, "cobalt", "episode", ["Is the flaky cobalt integration test fixed and verified?",
                                       "Has the cobalt integration test fix been verified?"],
          [["ep.cobalt.flaky@a2"]], forbidden=["ep.cobalt.flaky@a1"])
    b.ask(10, A, "atlas", "cross_scope", ["What frontend framework does borealis use?",
                                          "Which framework is the borealis frontend built with?"], abstain=True,
          forbidden=["borealis.frontend@v1", "borealis.frontend@v2"])
    b.ask(10, A, "borealis", "deletion", ["Who is the borealis pilot customer?", "Which customer is piloting borealis?"],
          abstain=True, forbidden=["borealis.pilot"])
    b.ask(10, A, "atlas", "multi_session", ["Which job queue does atlas use, and what is its latency constraint?",
                                            "What queue and latency limit apply to atlas?"],
          [["atlas.queue"], ["atlas.latency"]])
    b.ask(10, A, "atlas", "missing_evidence", ["What is the atlas staging deploy target?",
                                               "Where do atlas staging builds deploy?"], abstain=True,
          forbidden=["atlas.deploy@v1", "borealis.deploy"], distractors=["atlas.deploy@v2", "atlas.staging_db"])
    b.ask(11, A, "borealis", "stale_repository", ["What export format does borealis use?",
                                                  "Which file format do borealis exports use?"],
          [["repo.borealis.export@v2"]], forbidden=["repo.borealis.export@v1"])
    b.ask(11, A, "borealis", "multi_session", ["What data retention limit and which production database apply to"
                                               " borealis?", "Which database does borealis use and how long is user"
                                                             " data kept?"],
          [["borealis.retention"], ["borealis.db"]], forbidden=["atlas.db", "cobalt.db"])
    # Long-horizon recall of early background facts (budget pressure for recency-only context).
    for day, profile, project in ((11, A, "atlas"), (11, A, "atlas"), (12, A, "borealis"), (12, B_, "cobalt")):
        early = [f for f in bg_by_day[project][0] + bg_by_day[project][1]]
        asked = {q.gold[0][0] for q in b.questions if q.category == "long_horizon"}
        key, purpose, _tool = rng.choice([f for f in early if f[0] not in asked])
        b.ask(day, profile, project, "long_horizon", [f"Which tool does {project} use for {purpose}?",
                                                      f"What does {project} use for {purpose}?"], [[key]])
    b.ask(12, B_, "cobalt", "multi_session", ["Which production database and deploy target does cobalt use?",
                                              "What database and deploy target does cobalt have?"],
          [["cobalt.db"], ["cobalt.deploy"]], forbidden=["atlas.db", "borealis.db", "atlas.deploy@v2"])
    b.ask(12, A, None, "long_horizon", ["How should commit messages be written for me?",
                                        "What commit message style do I want?"], [["alpha.pref.commits"]],
          forbidden=["beta.pref.commits"])
    b.ask(12, A, "borealis", "missing_evidence", ["What is the borealis staging database?",
                                                  "Which database does borealis staging use?"], abstain=True,
          forbidden=["atlas.staging_db"], distractors=["borealis.db"])
    b.ask(13, B_, "cobalt", "missing_evidence", ["What is the cobalt staging deploy target?",
                                                 "Where do cobalt staging builds deploy?"], abstain=True,
          forbidden=["atlas.deploy@v2", "borealis.deploy"], distractors=["cobalt.deploy"])
    b.ask(13, A, "atlas", "long_horizon", ["What API style does atlas use?", "How does atlas expose its API?"],
          [["atlas.api"]])
    b.ask(13, A, None, "long_horizon", ["Which editor do I use?", "What do I edit code in?"],
          [["alpha.pref.editor"]], forbidden=["beta.pref.editor"])
    b.ask(13, B_, None, "preference", ["How do I like answers to be written?", "What answer style do I want?"],
          [["beta.pref.answers"]], forbidden=["alpha.pref.answers"])
    corpus = b.build()
    validate_corpus(corpus)
    return corpus


# --------------------------------------------------------------------------- validation
def validate_corpus(corpus: Corpus) -> None:
    """Chronology and ground-truth invariants; raises :class:`CorpusError`."""
    times = [e.time for e in corpus.events] + [q.asked_at for q in corpus.questions]
    if len(set(times)) != len(times):
        raise CorpusError("every event and question needs a unique timestamp (deterministic ordering)")
    if [e.time for e in corpus.events] != sorted(e.time for e in corpus.events):
        raise CorpusError("events are not in time order")
    for event in corpus.events:
        if event.type not in EVENT_TYPES:
            raise CorpusError(f"unknown event type {event.type}")
        for key in _event_keys(event):
            if key not in corpus.keys:
                raise CorpusError(f"event {event.eid} references unknown key {key}")
    by_id = {e.eid: e for e in corpus.events}
    for event in corpus.events:
        for cite in event.data.get("cites", ()):
            if cite not in by_id or by_id[cite].time >= event.time:
                raise CorpusError(f"event {event.eid} cites a missing or later event")
    for question in corpus.questions:
        if question.category not in CATEGORIES:
            raise CorpusError(f"unknown category {question.category}")
        if question.expect_abstain != (question.category in ABSTAIN_CATEGORIES):
            raise CorpusError(f"{question.qid}: abstention flag disagrees with its category")
        if question.expect_abstain and question.gold:
            raise CorpusError(f"{question.qid}: an abstention question cannot have gold keys")
        if not question.expect_abstain and not question.gold:
            raise CorpusError(f"{question.qid}: an answerable question needs gold keys")
        t = question.asked_at
        for requirement in question.gold:
            if not requirement:
                raise CorpusError(f"{question.qid}: empty requirement")
            live = []
            for key in requirement:
                info = corpus.keys.get(key)
                if info is None:
                    raise CorpusError(f"{question.qid}: unknown gold key {key}")
                if info.profile != question.profile:
                    raise CorpusError(f"{question.qid}: gold key {key} belongs to another profile")
                if info.project not in (None, question.project):
                    raise CorpusError(f"{question.qid}: gold key {key} is outside the question's scope")
                if info.introduced_at is None or info.introduced_at >= t:
                    raise CorpusError(f"{question.qid}: gold key {key} is not known before the question")
                live.append(not any(x is not None and x < t for x in (info.deleted_at, info.superseded_at,
                                                                      info.stale_at)))
            if not any(live):
                raise CorpusError(f"{question.qid}: every key of a requirement is outdated at question time")
        for key in (*question.forbidden, *question.distractors):
            if key not in corpus.keys:
                raise CorpusError(f"{question.qid}: unknown key {key}")


def _event_keys(event: Event) -> list[str]:
    data = event.data
    keys = [data.get("key"), data.get("old_key"), data.get("new_key")]
    keys += [f.get("key") for f in (data.get("files") or {}).values()]
    return [k for k in keys if k]
