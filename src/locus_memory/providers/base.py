"""Provider contracts, consent, and guarded calls.

Nothing here is enabled by default. A host registers provider objects in
``HostCapabilities.providers`` (``name -> object`` exposing ``.descriptor``) and, for
every provider whose descriptor says ``egress=True`` (data leaves the device),
supplies a :class:`ConsentPolicy` in ``HostCapabilities.consent``. Without a policy
every egress call that would send user data raises :class:`ConsentRequired`; a local
(non-egress) provider needs no consent but must still be registered by the host.

Provider outputs are untrusted data. They are validated strictly (lengths, types,
finiteness, dimensions, cited evidence) and can never change access, approve memory,
enable tools, change budgets or waive verification.

:class:`GuardedCall` wraps every provider invocation with: a deadline (cooperative:
``deadline_s`` is passed to the provider, and a reply that arrives after the deadline
is discarded), cancellation checks, a local token-bucket rate limit, a circuit
breaker driven by the injected clock, bounded retries (at most two, only for
retryable errors) with exponential backoff, and one usage receipt per attempt that
reached the provider (unknown cost is recorded as unknown, never as zero).
"""
from __future__ import annotations

import math
import numbers
import re
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .. import safety
from .. import validation as v
from ..errors import (
    Cancelled,
    ConsentRequired,  # noqa: F401 - re-exported for provider adapters
    DeadlineExceeded,
    ProviderError,
    ValidationError,
)
from ..host import Deadline
from ..models import AccessContext, Model, Scope

# --------------------------------------------------------------------------- capabilities
EMBED = "embed"
RERANK = "rerank"
EXTRACT = "extract"
EXTERNAL_SYNC = "external_sync"
EXTERNAL_DELETE = "external_delete"
SUMMARIZE = "summarize"
CAPABILITIES = frozenset({EMBED, RERANK, EXTRACT, EXTERNAL_SYNC, EXTERNAL_DELETE, SUMMARIZE})

# Methods a provider object must expose for each declared capability. A capability
# declared without its methods is not negotiated (reported, never faked).
CAPABILITY_METHODS: dict[str, tuple[str, ...]] = {
    EMBED: ("embed",),
    RERANK: ("rerank",),
    EXTRACT: ("extract",),
    EXTERNAL_SYNC: ("sync", "list_items"),
    EXTERNAL_DELETE: ("delete",),
    SUMMARIZE: ("summarize",),
}

# --------------------------------------------------------------------------- data classes
DATA_MEMORY_TEXT = "memory_text"
DATA_TRANSCRIPTS = "transcripts"
DATA_REPOSITORY_SOURCE = "repository_source"
DATA_CLASSES = frozenset({DATA_MEMORY_TEXT, DATA_TRANSCRIPTS, DATA_REPOSITORY_SOURCE})

DEFAULT_DEADLINE_MS = 30_000
MAX_RETRIES = 2
MAX_SUMMARY_CHARS = 4_000  # longest summary text accepted from a provider


# --------------------------------------------------------------------------- errors
class TransientProviderError(ProviderError):
    """Raised by provider adapters for failures worth a bounded retry (timeouts, 429, 5xx)."""

    code = "provider_transient"


class ProviderRateLimited(ProviderError):
    """The local token bucket refused the call; no request was sent."""

    code = "provider_rate_limited"


class CircuitOpen(ProviderError):
    """The provider failed repeatedly; calls fail fast until the cooldown elapses."""

    code = "provider_circuit_open"


# Exceptions a provider may raise that are worth retrying. Everything else fails at once.
RETRYABLE_EXCEPTIONS: tuple[type[BaseException], ...] = (TransientProviderError, TimeoutError, ConnectionError)


# --------------------------------------------------------------------------- descriptor
def _frozen_strings(value: Any, field_name: str, allowed: frozenset[str]) -> frozenset[str]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise ValidationError(f"{field_name} must be a collection")
    out = frozenset(str(item) for item in value)
    unknown = out - allowed
    if unknown:
        raise ValidationError(f"{field_name} contains unsupported values")
    return out


def _check_provider_name(value: Any, field_name: str = "provider name") -> str:
    return v.check_id(value, field_name)


@dataclass(frozen=True)
class ProviderDescriptor(Model):
    """Host-registered facts about one provider (never read from the provider's replies).

    ``egress`` is True when data sent to the provider leaves the device. ``dimensions``
    is required for embedding providers. ``cost_per_unit_micros=None`` means the cost is
    unknown (recorded as unknown, never as zero); a local model the host knows to be free
    declares ``0``. Rate-limit and circuit-breaker settings are host policy.
    """

    name: str
    capabilities: frozenset[str]
    egress: bool
    data_classes_accepted: frozenset[str] = frozenset({DATA_MEMORY_TEXT})
    model: str = "unspecified"
    version: str = "0"
    dimensions: int | None = None
    preprocessing_version: str = "1"
    cost_per_unit_micros: int | None = None
    max_batch: int = 64
    rate_limit_per_s: float | None = None
    rate_burst: int = 10
    failure_threshold: int = 3
    cooldown_s: float = 30.0
    notes: str = ""

    def __post_init__(self) -> None:
        _check_provider_name(self.name)
        caps = _frozen_strings(self.capabilities, "capabilities", CAPABILITIES)
        if not caps:
            raise ValidationError("a provider must declare at least one capability")
        object.__setattr__(self, "capabilities", caps)
        if not isinstance(self.egress, bool):
            raise ValidationError("egress must be true or false")
        object.__setattr__(self, "data_classes_accepted",
                           _frozen_strings(self.data_classes_accepted, "data_classes_accepted", DATA_CLASSES))
        v.check_label(self.model, "model")
        v.check_label(self.version, "version")
        v.check_label(self.preprocessing_version, "preprocessing_version")
        if EMBED in caps:
            v.check_int(self.dimensions, "dimensions", lo=1, hi=16_384)
        elif self.dimensions is not None:
            v.check_int(self.dimensions, "dimensions", lo=1, hi=16_384)
        if self.cost_per_unit_micros is not None:
            v.check_int(self.cost_per_unit_micros, "cost_per_unit_micros", lo=0, hi=10**12)
        v.check_int(self.max_batch, "max_batch", lo=1, hi=4_096)
        if self.rate_limit_per_s is not None:
            v.check_finite(self.rate_limit_per_s, "rate_limit_per_s", lo=1e-6, hi=1e6)
        v.check_int(self.rate_burst, "rate_burst", lo=1, hi=100_000)
        v.check_int(self.failure_threshold, "failure_threshold", lo=1, hi=1_000)
        v.check_finite(self.cooldown_s, "cooldown_s", lo=0.0, hi=86_400.0)
        if not isinstance(self.notes, str) or len(self.notes) > 300:
            raise ValidationError("notes must be at most 300 characters")


# --------------------------------------------------------------------------- protocols
@runtime_checkable
class EmbeddingProvider(Protocol):
    descriptor: ProviderDescriptor

    def embed(self, texts: list[str], *, deadline_s: float | None) -> list[list[float]]: ...


@runtime_checkable
class Reranker(Protocol):
    descriptor: ProviderDescriptor

    def rerank(self, query: str, texts: list[str], *, deadline_s: float | None) -> list[float]: ...


@runtime_checkable
class Extractor(Protocol):
    """Receives ``[{"id", "text", "data_class"}]``; returns proposal dicts.

    Each output dict may contain only: ``content`` (required), ``evidence_ids`` (required,
    ids from the input), ``kind``, ``title``, ``tags``, ``confidence``, ``subject``,
    ``predicate``, ``basis`` (``model_interpretation`` | ``hypothesis``), ``rationale``.
    """

    descriptor: ProviderDescriptor

    def extract(self, evidence: list[dict[str, Any]], *, deadline_s: float | None) -> list[dict[str, Any]]: ...


@runtime_checkable
class Summarizer(Protocol):
    """Receives ``[{"kind", "basis", "title", "content"}]`` and returns one summary string.

    Items are memory text (data class ``memory_text``) with secrets redacted and prompt
    markup neutralized; record ids, scopes and sources are never sent. The reply is
    untrusted: it must be a non-empty ``str`` of at most ``MAX_SUMMARY_CHARS`` characters,
    without control characters or credential-like content (see :func:`validate_summary`),
    or the call fails with ``ProviderError``. The hub never persists the reply; a caller
    such as consolidation may store it only as an unapproved ``summary`` candidate.
    """

    descriptor: ProviderDescriptor

    def summarize(self, items: list[dict[str, Any]], *, deadline_s: float | None) -> str: ...


@runtime_checkable
class ExternalMemoryService(Protocol):
    """A third-party memory store. Every write carries an idempotency key.

    ``sync`` returns ``{external_ref: "stored" | ...}``; ``delete`` returns
    ``{external_ref: "deleted" | "not_found" | ...}``; only those statuses count as
    confirmation. ``list_items`` reports what the service holds (``[{"external_ref": ...}]``)
    and is used only to refuse resurrection - nothing reported is ever imported.
    """

    descriptor: ProviderDescriptor

    def sync(self, items: list[dict[str, Any]], *, idempotency_key: str,
             deadline_s: float | None) -> dict[str, str]: ...

    def delete(self, external_refs: list[str], *, idempotency_key: str,
               deadline_s: float | None) -> dict[str, str]: ...

    def list_items(self, *, deadline_s: float | None) -> list[dict[str, Any]]: ...


# --------------------------------------------------------------------------- consent
@dataclass(frozen=True)
class ConsentGrant(Model):
    """One host-recorded consent: this provider may receive these data classes for this scope.

    ``scope=None`` is profile-wide. A scoped grant covers data whose scope contains every
    constraint of the grant (``{project: A}`` covers ``{project: A, agent: X}``, not
    ``{project: B}`` and not profile-global data). Transcripts and repository source
    additionally need the explicit ``allow_transcripts`` / ``allow_source`` flags.
    """

    provider: str
    scope: Scope | None = None
    data_classes: frozenset[str] = frozenset({DATA_MEMORY_TEXT})
    allow_transcripts: bool = False
    allow_source: bool = False
    granted_at: float = 0.0
    expires_at: float | None = None

    def __post_init__(self) -> None:
        _check_provider_name(self.provider, "consent provider")
        if self.scope is not None and not isinstance(self.scope, Scope):
            object.__setattr__(self, "scope", Scope.from_dict(self.scope))
        object.__setattr__(self, "data_classes",
                           _frozen_strings(self.data_classes, "consent data_classes", DATA_CLASSES))
        for name in ("allow_transcripts", "allow_source"):
            if not isinstance(getattr(self, name), bool):
                raise ValidationError(f"{name} must be true or false")
        v.check_timestamp(self.granted_at, "granted_at", optional=False)
        v.check_timestamp(self.expires_at, "expires_at")

    def active(self, now: float) -> bool:
        return self.granted_at <= now and (self.expires_at is None or now < self.expires_at)

    def covers(self, scope: Scope, data_class: str) -> bool:
        if data_class not in self.data_classes:
            return False
        if data_class == DATA_TRANSCRIPTS and not self.allow_transcripts:
            return False
        if data_class == DATA_REPOSITORY_SOURCE and not self.allow_source:
            return False
        if self.scope is None:
            return True
        mine = scope.as_dict()
        return all(mine.get(dim) == value for dim, value in self.scope.constraints)


@runtime_checkable
class ConsentPolicy(Protocol):
    """Host-supplied. Returns the grants that apply to this caller and provider."""

    def grants(self, access: AccessContext, provider: str) -> list[ConsentGrant]: ...


class StaticConsentPolicy:
    """A fixed list of grants (for hosts that keep consent in their own settings, and tests)."""

    def __init__(self, grants: Iterable[ConsentGrant] = ()) -> None:
        self._lock = threading.Lock()
        self._grants: list[ConsentGrant] = []
        for grant in grants:
            self.add(grant)

    def add(self, grant: ConsentGrant) -> None:
        if not isinstance(grant, ConsentGrant):
            raise ValidationError("consent grants must be ConsentGrant objects")
        with self._lock:
            self._grants.append(grant)

    def revoke(self, provider: str) -> int:
        with self._lock:
            before = len(self._grants)
            self._grants = [g for g in self._grants if g.provider != provider]
            return before - len(self._grants)

    def grants(self, access: AccessContext, provider: str) -> list[ConsentGrant]:
        with self._lock:
            return [g for g in self._grants if g.provider == provider]


# --------------------------------------------------------------------------- breaker & bucket
class CircuitBreaker:
    """closed -> open after ``threshold`` consecutive failed attempts; open -> half-open after
    ``cooldown_s`` (measured with the injected clock); half-open admits one trial call."""

    def __init__(self, clock: Callable[[], float], *, threshold: int = 3, cooldown_s: float = 30.0) -> None:
        self._clock = clock
        self.threshold = threshold
        self.cooldown_s = cooldown_s
        self._lock = threading.Lock()
        self._state = "closed"
        self._failures = 0
        self._opened_at: float | None = None
        self._trial = False

    def acquire(self) -> None:
        with self._lock:
            if self._state == "open":
                waited = self._clock() - (self._opened_at or 0.0)
                if waited < self.cooldown_s:
                    raise CircuitOpen("the provider failed repeatedly; calls are paused",
                                      details={"retry_after_s": round(self.cooldown_s - waited, 3)})
                self._state = "half_open"
                self._trial = False
            if self._state == "half_open":
                if self._trial:
                    raise CircuitOpen("the provider is being probed; calls are paused",
                                      details={"retry_after_s": 0.0})
                self._trial = True

    def success(self) -> None:
        with self._lock:
            self._state = "closed"
            self._failures = 0
            self._opened_at = None
            self._trial = False

    def failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._state == "half_open" or self._failures >= self.threshold:
                self._state = "open"
                self._opened_at = self._clock()
            self._trial = False

    def release(self) -> None:
        """An admitted call ended without a verdict (cancelled before any reply)."""
        with self._lock:
            self._trial = False

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            state = self._state
            retry_after = None
            if state == "open":
                waited = self._clock() - (self._opened_at or 0.0)
                if waited >= self.cooldown_s:
                    state = "half_open"
                else:
                    retry_after = round(self.cooldown_s - waited, 3)
            return {"state": state, "consecutive_failures": self._failures, "retry_after_s": retry_after,
                    "threshold": self.threshold, "cooldown_s": self.cooldown_s}


class TokenBucket:
    """Local rate limit (``rate_per_s=None`` = unlimited). Never sleeps; refuses instead."""

    def __init__(self, clock: Callable[[], float], *, rate_per_s: float | None, burst: int) -> None:
        self._clock = clock
        self.rate = rate_per_s
        self.burst = burst
        self._tokens = float(burst)
        self._updated = clock()
        self._lock = threading.Lock()

    def try_acquire(self) -> float:
        """Take a token; returns 0.0 on success, else the seconds until one is available."""
        if self.rate is None:
            return 0.0
        with self._lock:
            now = self._clock()
            elapsed = max(0.0, now - self._updated)
            self._tokens = min(float(self.burst), self._tokens + elapsed * self.rate)
            self._updated = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0
            return (1.0 - self._tokens) / self.rate


# --------------------------------------------------------------------------- usage
@dataclass(frozen=True)
class UsageRecord(Model):
    """One provider attempt. ``cost_micros=None`` with ``cost_known=False`` means unknown."""

    provider: str
    operation: str
    created_at: float
    units: int
    cost_micros: int | None
    cost_known: bool
    outcome: str  # ok | error | timeout | late_discarded | cancelled_discarded | invalid_output


def usage_record(descriptor: ProviderDescriptor, operation: str, units: int, outcome: str,
                 now: float) -> UsageRecord:
    price = descriptor.cost_per_unit_micros
    return UsageRecord(
        provider=descriptor.name, operation=operation, created_at=now, units=int(units),
        cost_micros=None if price is None else price * int(units), cost_known=price is not None,
        outcome=outcome,
    )


# --------------------------------------------------------------------------- guarded call
def _cancelled(cancel: Any) -> bool:
    return cancel is not None and bool(getattr(cancel, "cancelled", False))


@dataclass
class GuardedCall:
    """Runs one logical provider operation under the governance rules described above."""

    descriptor: ProviderDescriptor
    breaker: CircuitBreaker
    bucket: TokenBucket
    clock: Callable[[], float]
    usage: Callable[[UsageRecord], None]
    sleep: Callable[[float], None] = time.sleep
    max_retries: int = MAX_RETRIES
    backoff_base_s: float = 0.05
    backoff_max_s: float = 1.0
    attempts: int = field(default=0, init=False)

    def _check(self, cancel: Any, deadline: Deadline) -> None:
        if _cancelled(cancel):
            raise Cancelled("the provider call was cancelled before it was sent")
        if deadline.expired:
            raise DeadlineExceeded("the deadline passed before the provider call",
                                   details={"provider": self.descriptor.name})

    def _record(self, operation: str, units: int, outcome: str) -> None:
        self.usage(usage_record(self.descriptor, operation, units, outcome, self.clock()))

    def run(self, operation: str, call: Callable[[float | None], Any], *, units: int,
            deadline: Deadline, cancel: Any = None, validate: Callable[[Any], Any]) -> Any:
        name = self.descriptor.name
        attempt = 0
        while True:
            self._check(cancel, deadline)
            self.breaker.acquire()
            wait = self.bucket.try_acquire()
            if wait > 0:
                self.breaker.release()
                raise ProviderRateLimited("the local rate limit for this provider was reached; nothing was sent",
                                          details={"provider": name, "retry_after_s": round(wait, 3)})
            self.attempts += 1
            try:
                raw = call(deadline.remaining_s())
            except Exception as exc:  # provider adapters are untrusted code
                retryable = isinstance(exc, RETRYABLE_EXCEPTIONS)
                self.breaker.failure()
                self._record(operation, units, "timeout" if isinstance(exc, TimeoutError) else "error")
                if retryable and attempt < self.max_retries and not _cancelled(cancel):
                    delay = min(self.backoff_base_s * (2 ** attempt), self.backoff_max_s)
                    remaining = deadline.remaining_s()
                    if remaining is not None and delay >= remaining:
                        raise DeadlineExceeded("the deadline leaves no time for another attempt",
                                               details={"provider": name, "attempts": attempt + 1}) from None
                    self.sleep(delay)
                    attempt += 1
                    continue
                # Never chain or echo the provider's exception: its text may contain user data.
                raise ProviderError(
                    "the provider call failed",
                    details={"provider": name, "operation": operation, "attempts": attempt + 1,
                             "retryable": retryable, "error_type": type(exc).__name__[:64]},
                ) from None
            if _cancelled(cancel):
                self.breaker.release()
                self._record(operation, units, "cancelled_discarded")
                raise Cancelled("the call was cancelled; the provider reply was discarded")
            if deadline.expired:
                self.breaker.failure()
                self._record(operation, units, "late_discarded")
                raise DeadlineExceeded("the provider replied after the deadline; the reply was discarded",
                                       details={"provider": name, "operation": operation})
            try:
                value = validate(raw)
            except ProviderError:
                self.breaker.failure()
                self._record(operation, units, "invalid_output")
                raise
            except Exception:  # a validator must never let malformed output through
                self.breaker.failure()
                self._record(operation, units, "invalid_output")
                raise ProviderError("the provider output could not be validated",
                                    details={"provider": name, "operation": operation}) from None
            self.breaker.success()
            self._record(operation, units, "ok")
            return value


# --------------------------------------------------------------------------- output validation
def as_list(raw: Any, what: str) -> list[Any]:
    """Accept a list/tuple (or an array exposing ``tolist``); anything else is invalid."""
    if isinstance(raw, (list, tuple)):
        return list(raw)
    tolist = getattr(raw, "tolist", None)
    if callable(tolist) and not isinstance(raw, (str, bytes, dict)):
        converted = tolist()
        if isinstance(converted, list):
            return converted
    raise ProviderError(f"{what} must be a list")


def finite_number(value: Any) -> float | None:
    """A finite real number (bools excluded) as float, else None."""
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def validate_vectors(raw: Any, *, count: int, dimensions: int) -> list[tuple[float, ...]]:
    """Exactly ``count`` finite vectors of ``dimensions`` numbers; returned unit-normalized."""
    vectors = as_list(raw, "embedding output")
    if len(vectors) != count:
        raise ProviderError("the embedding output count does not match the input",
                            details={"expected": count, "received": len(vectors)})
    out: list[tuple[float, ...]] = []
    for vector in vectors:
        values = as_list(vector, "an embedding")
        if len(values) != dimensions:
            raise ProviderError("an embedding has the wrong dimensions",
                                details={"expected": dimensions, "received": len(values)})
        floats = []
        for item in values:
            number = finite_number(item)
            if number is None:
                raise ProviderError("embedding values must be finite numbers")
            floats.append(number)
        norm = math.hypot(*floats)
        if not math.isfinite(norm) or norm == 0.0:
            raise ProviderError("an embedding has a zero or non-finite norm")
        out.append(tuple(x / norm for x in floats))
    return out


def validate_scores(raw: Any, *, count: int) -> list[float]:
    scores = as_list(raw, "rerank output")
    if len(scores) != count:
        raise ProviderError("the rerank output count does not match the input",
                            details={"expected": count, "received": len(scores)})
    out = []
    for item in scores:
        number = finite_number(item)
        if number is None:
            raise ProviderError("rerank scores must be finite numbers")
        out.append(number)
    return out


def validate_confirmations(raw: Any, refs: Iterable[str], *, accepted: frozenset[str]) -> set[str]:
    """Refs the provider explicitly confirmed with an accepted status. Anything else is unconfirmed."""
    if not isinstance(raw, dict):
        raise ProviderError("the provider confirmation must be an object")
    confirmed = set()
    for ref in refs:
        status = raw.get(ref)
        if isinstance(status, str) and status in accepted:
            confirmed.add(ref)
    return confirmed


_SUMMARY_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def validate_summary(raw: Any, *, max_chars: int = MAX_SUMMARY_CHARS) -> str:
    """A plain, non-empty, bounded ``str`` that encodes as UTF-8, has no control characters
    (tab and newlines allowed) and no credential-like content; returned stripped, with
    prompt markup neutralized. Anything else raises ``ProviderError`` (never echoing it)."""
    if type(raw) is not str:  # a str subclass could override len/strip; a stream never ends
        raise ProviderError("the summary must be text", details={"reason": "not_text"})
    text = raw.strip()
    if not text:
        raise ProviderError("the summary is empty", details={"reason": "empty"})
    if len(text) > max_chars:
        raise ProviderError("the summary is too long", details={"reason": "too_long", "max_chars": max_chars})
    if _SUMMARY_CONTROL.search(text):
        raise ProviderError("the summary contains control characters", details={"reason": "control_characters"})
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise ProviderError("the summary is not well-formed text", details={"reason": "malformed_text"}) from None
    secrets = safety.scan(text).secrets
    if secrets:
        raise ProviderError("the summary contains credential-like content",
                            details={"reason": "secret_in_output", "categories": list(secrets)})
    return safety.neutralize_markup(text)


def validate_listing(raw: Any, *, max_items: int) -> list[str]:
    items = as_list(raw, "the provider listing")
    if len(items) > max_items:
        raise ProviderError("the provider listing is too large", details={"max_items": max_items})
    refs: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            raise ProviderError("listing entries must be objects")
        ref = item.get("external_ref")
        if not isinstance(ref, str) or not v.REF_PATTERN.fullmatch(ref):
            raise ProviderError("listing entries need a valid external_ref")
        refs.append(ref)
    return refs


__all__ = [
    "CAPABILITIES", "CAPABILITY_METHODS", "DATA_CLASSES", "DATA_MEMORY_TEXT", "DATA_REPOSITORY_SOURCE",
    "DATA_TRANSCRIPTS", "DEFAULT_DEADLINE_MS", "EMBED", "EXTERNAL_DELETE", "EXTERNAL_SYNC", "EXTRACT",
    "MAX_RETRIES", "MAX_SUMMARY_CHARS", "RERANK", "RETRYABLE_EXCEPTIONS", "SUMMARIZE", "CircuitBreaker",
    "CircuitOpen", "ConsentGrant", "ConsentPolicy", "ConsentRequired", "EmbeddingProvider",
    "ExternalMemoryService", "Extractor", "GuardedCall", "ProviderDescriptor", "ProviderRateLimited",
    "Reranker", "StaticConsentPolicy", "Summarizer", "TokenBucket", "TransientProviderError", "UsageRecord",
    "as_list", "finite_number", "usage_record", "validate_confirmations", "validate_listing",
    "validate_scores", "validate_summary", "validate_vectors",
]
