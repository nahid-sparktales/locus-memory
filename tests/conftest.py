"""Shared fixtures. All data lives in pytest tmp dirs; nothing touches real app data or keychains."""
from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.host import EngineConfig, HostCapabilities
from locus_memory.models import AccessContext, Actor, Operation, PartitionRef, ScopeGrants

CANARY = "CANARY-7f3e9a1c-plaintext-must-not-hit-disk"


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def keys() -> StaticKeyProvider:
    return StaticKeyProvider({"k1": secrets.token_bytes(32)})


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "memory-root"


@pytest.fixture
def make_engine(root, keys, clock):
    engines: list[MemoryEngine] = []

    def factory(*, host: HostCapabilities | None = None, config: EngineConfig | None = None,
                key_provider=None, root_dir: Path | None = None) -> MemoryEngine:
        host = host or HostCapabilities(clock=clock)
        if host.clock is None:
            host.clock = clock
        engine = MemoryEngine(root_dir or root, key_provider or keys, host=host, config=config)
        engines.append(engine)
        return engine

    yield factory
    for engine in engines:
        try:
            engine.close()
        except Exception:
            pass


@pytest.fixture
def engine(make_engine) -> MemoryEngine:
    return make_engine()


def access_for(*, profile: str = "default", edition: str = "standard", actor: Actor = Actor.USER,
               projects=(), repositories=(), agents=(), teams=(), sessions=(), devices=(),
               worktrees=(), legacy_targets=(), operations=None, principal: str = "user-1") -> AccessContext:
    return AccessContext(
        principal=principal, partition=PartitionRef(edition, profile), actor=actor,
        grants=ScopeGrants(projects=frozenset(projects), repositories=frozenset(repositories),
                           agents=frozenset(agents), teams=frozenset(teams), sessions=frozenset(sessions),
                           devices=frozenset(devices), worktrees=frozenset(worktrees),
                           legacy_targets=frozenset(legacy_targets)),
        operations=frozenset(Operation) if operations is None else frozenset(operations),
    )


@pytest.fixture
def user_access() -> AccessContext:
    return access_for(projects=("proj-a",), agents=("agent-1",), repositories=("repo-a",))


@pytest.fixture
def agent_access() -> AccessContext:
    return access_for(actor=Actor.AGENT, projects=("proj-a",), agents=("agent-1",), repositories=("repo-a",),
                      operations={Operation.READ, Operation.PROPOSE, Operation.INGEST})


def scan_for_plaintext(directory: Path, needle: str) -> list[Path]:
    """Return every file under ``directory`` whose bytes contain ``needle``."""
    hits = []
    data = needle.encode()
    for path in directory.rglob("*"):
        if path.is_file():
            try:
                if data in path.read_bytes():
                    hits.append(path)
            except OSError:
                continue
    return hits
