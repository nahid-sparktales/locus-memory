"""Host-supplied capabilities and engine configuration.

The package never discovers these itself: no Keychain access, no app-data
scanning, no network, no scheduling. A host (Locus, a workflow runner, the CLI)
injects what it is willing to provide; everything else is unavailable and
operations that need it fail explicitly.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .models import Actor, VerificationResult


@runtime_checkable
class TokenCounter(Protocol):
    """Model-appropriate tokenizer supplied by the host."""

    def __call__(self, text: str) -> int: ...


@runtime_checkable
class VerificationAuthority(Protocol):
    """Resolves host verification receipt ids into trusted check results.

    Only this authority can establish that required checks passed; an agent's
    claim of success is never enough.
    """

    def resolve(self, receipt_id: str) -> VerificationResult | None: ...


@runtime_checkable
class EvaluationRunner(Protocol):
    """Host-approved runner for procedural candidates. The engine never executes steps."""

    def evaluate(self, manifest: dict[str, Any], *, deadline_s: float) -> dict[str, Any]: ...


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()
        self.reason = ""

    def cancel(self, reason: str = "cancelled") -> None:
        self.reason = reason
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class Deadline:
    def __init__(self, ms: int | None, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._end = None if ms is None else clock() + ms / 1000

    @property
    def expired(self) -> bool:
        return self._end is not None and self._clock() >= self._end

    def remaining_s(self) -> float | None:
        return None if self._end is None else max(self._end - self._clock(), 0.0)


@dataclass
class HostCapabilities:
    clock: Callable[[], float] = time.time
    token_counter: TokenCounter | None = None
    verification: VerificationAuthority | None = None
    evaluation_runner: EvaluationRunner | None = None
    # Roots the host allows repository registration under. Empty = repository memory disabled.
    allowed_repository_roots: Sequence[Path] = ()
    ledger_mirror: Any = None  # storage.ledger.LedgerMirror
    consent: Any = None  # providers.base.ConsentPolicy; None = no external egress
    providers: dict[str, Any] = field(default_factory=dict)
    # Actors whose approve/reject the host attests as human review.
    approval_actors: frozenset[Actor] = frozenset({Actor.USER})


@dataclass
class EngineConfig:
    candidate_ttl_seconds: float = 30 * 24 * 3600  # parity with Locus MemoryVault
    serving_mode: str = "enabled"  # disabled | shadow | enabled (host rollout control)
    canonical_backend: str = "package"  # legacy | package (reported, enforced by migrations.state)
    max_projection_records: int = 50_000
    max_projection_bytes: int = 64 * 1024 * 1024
    history_hydration_batch: int = 2_000
    max_history_messages_hydrated: int = 200_000
    busy_timeout_ms: int = 5_000
    estimate_chars_per_token: float = 3.5  # conservative estimator when no tokenizer
    estimate_margin: float = 1.15
    log_content: bool = False  # never enable in production; content stays out of logs

    def __post_init__(self) -> None:
        if self.serving_mode not in {"disabled", "shadow", "enabled"}:
            raise ValueError("serving_mode must be disabled, shadow, or enabled")
        if self.canonical_backend not in {"legacy", "package"}:
            raise ValueError("canonical_backend must be legacy or package")
