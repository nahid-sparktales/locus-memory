"""Typed, versioned public models.

All models are immutable dataclasses with ``to_dict``; request models also have
validating ``from_dict`` constructors so hosts and the CLI can pass JSON.

Design rules encoded here:
* Security boundary (partition), scope, kind, storage role and lifecycle are
  independent dimensions.
* Unknown confidence is ``None``; model confidence is labelled uncalibrated.
* Ranking scores are never probabilities (``score_kind`` says what they are).
"""
from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import validation as v
from .errors import ValidationError

API_VERSION = "1.0"
RECORD_SCHEMA_VERSION = 1


# --------------------------------------------------------------------------- enums
class _Enum(str, enum.Enum):
    @classmethod
    def parse(cls, value: Any, field_name: str | None = None):
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            allowed = ", ".join(item.value for item in cls)
            raise ValidationError(f"{field_name or cls.__name__} must be one of: {allowed}") from exc

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


class Lifecycle(_Enum):
    CANDIDATE = "candidate"
    APPROVED = "approved"
    REJECTED = "rejected"
    STALE = "stale"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"
    FORGOTTEN = "forgotten"


class MemoryKind(_Enum):
    PREFERENCE = "preference"
    FACT = "fact"
    DECISION = "decision"
    CONSTRAINT = "constraint"
    RELATIONSHIP = "relationship"  # legacy Locus kind, preserved
    REPOSITORY_OBSERVATION = "repository_observation"
    EPISODE = "episode"
    PROCEDURE = "procedure"
    SUMMARY = "summary"  # derived consolidation output


class StatementBasis(_Enum):
    """How the statement is known; separates observations from interpretations."""

    USER_STATED = "user_stated"
    OBSERVED = "observed"  # parsed directly from a source (e.g. a file's import list)
    SOURCE_ATTRIBUTED = "source_attributed"  # "X said Y" - not a fact about the user
    MODEL_INTERPRETATION = "model_interpretation"
    HYPOTHESIS = "hypothesis"
    LEGACY = "legacy"  # imported from Locus MemoryVault without basis metadata


class ScopeDimension(_Enum):
    PROJECT = "project"
    REPOSITORY = "repository"
    WORKTREE = "worktree"
    AGENT = "agent"
    TEAM = "team"
    SESSION = "session"
    DEVICE = "device"
    # Locus MemoryVault target hashes that cannot yet be mapped to a host id.
    LEGACY_TARGET = "legacy_target"


class SourceKind(_Enum):
    MESSAGE = "message"
    USER_ACTION = "user_action"
    COMMIT = "commit"
    BLOB_RANGE = "blob_range"
    TASK_ATTEMPT = "task_attempt"
    VERIFICATION_RECEIPT = "verification_receipt"
    SESSION = "session"
    DOCUMENT = "document"
    MEMORY = "memory"  # derivation from another memory record
    LEGACY_IMPORT = "legacy_import"
    PROVIDER = "provider"
    EPISODE = "episode"
    EVALUATION_RECEIPT = "evaluation_receipt"


class Actor(_Enum):
    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    SYSTEM = "system"
    HOST = "host"
    PROVIDER = "provider"


class Operation(_Enum):
    READ = "read"
    WRITE = "write"  # remember / correct
    PROPOSE = "propose"
    APPROVE = "approve"  # approve / reject candidates
    FORGET = "forget"
    EXPORT = "export"
    INGEST = "ingest"
    MAINTAIN = "maintain"
    ADMIN = "admin"  # key rotation, migration, partition-wide operations


class StorageRole(_Enum):
    CANONICAL = "canonical"
    SOURCE_ARCHIVE = "source_archive"
    DERIVED_INDEX = "derived_index"
    CONTEXT_RECEIPT = "context_receipt"


class ResultStatus(_Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    UNAVAILABLE = "unavailable"
    CANCELLED = "cancelled"


class MeasureKind(_Enum):
    MEASURED = "measured"
    ESTIMATED = "estimated"
    UNAVAILABLE = "unavailable"


class EpisodeOutcome(_Enum):
    VERIFIED_SUCCESS = "verified_success"
    FAILURE = "failure"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"
    UNKNOWN = "unknown"


class ProcedureState(_Enum):
    NOMINATED = "nominated"
    CANDIDATE = "candidate"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    UNSAFE = "unsafe"
    EVALUATING = "evaluating"
    FAILED_EVALUATION = "failed_evaluation"
    EVALUATED = "evaluated"
    APPROVED = "approved"
    EXPORTED = "exported"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    REVOKED_EVIDENCE = "revoked_evidence"


# --------------------------------------------------------------------------- serde
def to_jsonable(value: Any) -> Any:
    custom = getattr(value, "_jsonable", None)
    if callable(custom) and not isinstance(value, type):
        return custom()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)
                if not f.metadata.get("exclude")}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [to_jsonable(item) for item in value]
        return sorted(items, key=json.dumps) if isinstance(value, (set, frozenset)) else items
    if isinstance(value, dict):
        return {str(k): to_jsonable(item) for k, item in value.items()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


class Model:
    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False, allow_nan=False)


def canonical_json(value: Any) -> str:
    return json.dumps(to_jsonable(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


# --------------------------------------------------------------------------- security
@dataclass(frozen=True)
class PartitionRef(Model):
    """A security domain: edition + profile. Never shared implicitly."""

    edition: str
    profile: str

    def __post_init__(self) -> None:
        v.check_label(self.edition, "edition")
        v.check_label(self.profile, "profile")

    @property
    def partition_id(self) -> str:
        if "|" in self.edition or "|" in self.profile:
            # The v1 encoding is ambiguous when a label contains the separator
            # (("a|b", "c") vs ("a", "b|c")); such refs use an unambiguous,
            # length-prefixed encoding. Ids of all other refs are unchanged.
            material = (f"locus-memory/partition/v2|{len(self.edition)}:{self.edition}"
                        f"|{len(self.profile)}:{self.profile}")
        else:
            material = f"locus-memory/partition/v1|{self.edition}|{self.profile}"
        return "p" + hashlib.sha256(material.encode()).hexdigest()[:31]


@dataclass(frozen=True)
class Scope(Model):
    """Intersecting scope constraints within a partition.

    An empty scope is profile-global. ``{project: P, agent: A}`` is visible only
    to an access context authorized for both P and A.
    """

    constraints: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        normalized: dict[str, str] = {}
        for dim, value in self.constraints:
            name = ScopeDimension.parse(dim, "scope dimension").value
            if name in normalized:
                raise ValidationError(f"scope dimension {name} appears twice")
            normalized[name] = v.check_label(value, f"scope {name}", max_chars=512)
        object.__setattr__(self, "constraints", tuple(sorted(normalized.items())))

    @classmethod
    def global_(cls) -> Scope:
        return cls(())

    @classmethod
    def of(cls, **dims: str | None) -> Scope:
        return cls(tuple((k, val) for k, val in dims.items() if val))

    @classmethod
    def from_dict(cls, raw: Any) -> Scope:
        if raw is None:
            return cls.global_()
        if isinstance(raw, Scope):
            return raw
        if isinstance(raw, dict) and "constraints" in raw:
            raw = raw["constraints"]
        if isinstance(raw, dict):
            return cls(tuple((k, val) for k, val in raw.items() if val not in (None, "")))
        if isinstance(raw, (list, tuple)):
            return cls(tuple((str(a), str(b)) for a, b in raw))
        raise ValidationError("scope must be an object of dimension -> value")

    def get(self, dim: ScopeDimension | str) -> str | None:
        name = dim.value if isinstance(dim, ScopeDimension) else dim
        return dict(self.constraints).get(name)

    def as_dict(self) -> dict[str, str]:
        return dict(self.constraints)

    @property
    def is_global(self) -> bool:
        return not self.constraints

    def key(self) -> str:
        return canonical_json(self.constraints)

    def _jsonable(self) -> dict[str, str]:
        return self.as_dict()


@dataclass(frozen=True)
class ScopeGrants(Model):
    """Scope values the authenticated caller may use in this call."""

    projects: frozenset[str] = frozenset()
    repositories: frozenset[str] = frozenset()
    worktrees: frozenset[str] = frozenset()
    agents: frozenset[str] = frozenset()
    teams: frozenset[str] = frozenset()
    sessions: frozenset[str] = frozenset()
    devices: frozenset[str] = frozenset()
    legacy_targets: frozenset[str] = frozenset()

    _DIM_FIELDS = {
        "project": "projects", "repository": "repositories", "worktree": "worktrees",
        "agent": "agents", "team": "teams", "session": "sessions", "device": "devices",
        "legacy_target": "legacy_targets",
    }

    def __post_init__(self) -> None:
        for name in self._DIM_FIELDS.values():
            values = getattr(self, name)
            if isinstance(values, str):
                values = (values,)
            cleaned = frozenset(v.check_label(item, name, max_chars=512) for item in values or ())
            if len(cleaned) > v.MAX_LIST:
                raise ValidationError(f"too many {name} grants")
            object.__setattr__(self, name, cleaned)

    def values_for(self, dim: str) -> frozenset[str]:
        return getattr(self, self._DIM_FIELDS[dim])

    def allows(self, scope: Scope) -> bool:
        return all(value in self.values_for(dim) for dim, value in scope.constraints)

    def fingerprint(self) -> str:
        return content_hash({k: sorted(self.values_for(k)) for k in self._DIM_FIELDS})

    @classmethod
    def from_dict(cls, raw: Any) -> ScopeGrants:
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise ValidationError("grants must be an object")
        kwargs = {}
        for dim, name in cls._DIM_FIELDS.items():
            value = raw.get(name, raw.get(dim))
            if value is None:
                continue
            kwargs[name] = frozenset([value] if isinstance(value, str) else value)
        return cls(**kwargs)


ALL_OPERATIONS = frozenset(Operation)


@dataclass(frozen=True)
class AccessContext(Model):
    """Trusted access context. Built by the host from authenticated state only.

    Nothing a model or transcript says can widen it: engine methods take scope
    *requests* separately and check them against these grants.
    """

    principal: str
    partition: PartitionRef
    actor: Actor = Actor.USER
    grants: ScopeGrants = field(default_factory=ScopeGrants)
    operations: frozenset[Operation] = frozenset({Operation.READ})
    purpose: str = "interactive"
    issuer: str = "host"

    def __post_init__(self) -> None:
        v.check_label(self.principal, "principal")
        if not isinstance(self.partition, PartitionRef):
            raise ValidationError("access partition must be a PartitionRef")
        if not isinstance(self.grants, ScopeGrants):
            raise ValidationError("access grants must be ScopeGrants")
        if isinstance(self.operations, (str, Operation)):
            raise ValidationError("operations must be a collection of operations")
        object.__setattr__(self, "actor", Actor.parse(self.actor, "actor"))
        object.__setattr__(
            self, "operations", frozenset(Operation.parse(op, "operation") for op in self.operations)
        )
        v.check_label(self.purpose, "purpose")
        v.check_label(self.issuer, "issuer")

    def fingerprint(self) -> str:
        return content_hash({
            "principal": self.principal, "partition": self.partition.partition_id,
            "actor": self.actor.value, "grants": self.grants.fingerprint(),
            "operations": sorted(op.value for op in self.operations),
        })


# --------------------------------------------------------------------------- provenance
@dataclass(frozen=True)
class SourceRef(Model):
    kind: SourceKind
    ref: str
    actor: Actor = Actor.USER
    locator: dict[str, Any] = field(default_factory=dict)
    fingerprint: str | None = None  # sha256 of the evidence text when known
    observed_at: float | None = None
    extraction_version: str | None = None
    available: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", SourceKind.parse(self.kind, "source kind"))
        object.__setattr__(self, "actor", Actor.parse(self.actor, "source actor"))
        v.check_ref(self.ref, "source ref")
        object.__setattr__(self, "locator", v.check_mapping(self.locator, "source locator"))
        if self.fingerprint is not None and not (
            isinstance(self.fingerprint, str) and len(self.fingerprint) <= 128
        ):
            raise ValidationError("source fingerprint is invalid")
        object.__setattr__(self, "observed_at", v.check_timestamp(self.observed_at, "observed_at"))

    def identity(self) -> str:
        return f"{self.kind.value}:{self.ref}"

    @classmethod
    def from_dict(cls, raw: Any) -> SourceRef:
        if isinstance(raw, SourceRef):
            return raw
        if not isinstance(raw, dict):
            raise ValidationError("source must be an object")
        return cls(
            kind=raw.get("kind"), ref=raw.get("ref"), actor=raw.get("actor", "user"),
            locator=raw.get("locator") or {}, fingerprint=raw.get("fingerprint"),
            observed_at=raw.get("observed_at"), extraction_version=raw.get("extraction_version"),
            available=bool(raw.get("available", True)),
        )


def attempt_source_ref(task_ref: str, attempt_ref: str) -> str:
    """Canonical, unambiguous TASK_ATTEMPT source ref for (task_ref, attempt_ref)."""
    v.check_ref(task_ref, "task_ref")
    v.check_ref(attempt_ref, "attempt_ref")
    digest = hashlib.sha256(f"{task_ref}\x00{attempt_ref}".encode()).hexdigest()
    return "attempt-" + digest[:48]


_HEX_OBJECT = frozenset("0123456789abcdefABCDEF")


def canonical_source(source: SourceRef) -> SourceRef:
    """The one spelling of a source every index, tombstone and suppression keys on.

    Verifiers accept alternative spellings (a raw attempt ref plus ``locator.task_ref``;
    upper-case git object ids); storing or tokenizing the caller's spelling would let an
    alias miss tombstones and suppressions of the canonical one.
    """
    if source.kind == SourceKind.TASK_ATTEMPT and not source.ref.startswith("attempt-"):
        task_ref = source.locator.get("task_ref") if isinstance(source.locator, dict) else None
        if isinstance(task_ref, str):
            try:
                ref = attempt_source_ref(task_ref, source.ref)
            except ValidationError:
                return source
            return dataclasses.replace(source, ref=ref,
                                       locator={**source.locator, "task_ref": task_ref, "attempt_ref": source.ref})
        return source
    if source.kind in (SourceKind.BLOB_RANGE, SourceKind.COMMIT):
        canonical = canonical_identity(source.identity()).split(":", 1)[1]
        return source if canonical == source.ref else dataclasses.replace(source, ref=canonical)
    return source


def canonical_identity(identity: str) -> str:
    """Canonical form of a source identity string (``kind:ref``) where it is knowable without
    context: git object ids are lower-cased. A raw task-attempt ref cannot be canonicalized
    without its task ref and is returned unchanged."""
    kind, sep, ref = identity.partition(":")
    if sep and kind in (SourceKind.BLOB_RANGE.value, SourceKind.COMMIT.value):
        repository, sep2, obj = ref.partition(":")
        if sep2 and obj and set(obj) <= _HEX_OBJECT:
            return f"{kind}:{repository}:{obj.lower()}"
    return identity


@dataclass(frozen=True)
class Confidence(Model):
    value: float | None = None
    calibrated: bool = False
    method: str = "unknown"

    def __post_init__(self) -> None:
        if self.value is not None:
            object.__setattr__(self, "value", v.check_finite(self.value, "confidence", lo=0.0, hi=1.0))
        if self.value is None and self.calibrated:
            raise ValidationError("unknown confidence cannot be calibrated")

    @classmethod
    def unknown(cls) -> Confidence:
        return cls()

    @classmethod
    def from_dict(cls, raw: Any) -> Confidence:
        if raw is None:
            return cls()
        if isinstance(raw, Confidence):
            return raw
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            return cls(value=float(raw), calibrated=False, method="uncalibrated")
        if isinstance(raw, dict):
            return cls(raw.get("value"), bool(raw.get("calibrated", False)),
                       str(raw.get("method") or "unknown")[:64])
        raise ValidationError("confidence must be a number or object")


@dataclass(frozen=True)
class Validity(Model):
    valid_from: float | None = None
    valid_until: float | None = None
    applicability: dict[str, Any] = field(default_factory=dict)
    # Repository-backed facts: (path, blob hash) pairs the statement depends on.
    source_hashes: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        start = v.check_timestamp(self.valid_from, "valid_from")
        end = v.check_timestamp(self.valid_until, "valid_until")
        if start is not None and end is not None and end <= start:
            raise ValidationError("valid_until must be after valid_from")
        object.__setattr__(self, "valid_from", start)
        object.__setattr__(self, "valid_until", end)
        object.__setattr__(self, "applicability", v.check_mapping(self.applicability, "applicability"))
        hashes = tuple((str(p)[:1024], str(h)[:128]) for p, h in self.source_hashes)
        object.__setattr__(self, "source_hashes", hashes)

    @classmethod
    def from_dict(cls, raw: Any) -> Validity:
        if raw is None:
            return cls()
        if isinstance(raw, Validity):
            return raw
        if not isinstance(raw, dict):
            raise ValidationError("validity must be an object")
        return cls(raw.get("valid_from"), raw.get("valid_until"), raw.get("applicability") or {},
                   tuple(tuple(x) for x in raw.get("source_hashes") or ()))


@dataclass(frozen=True)
class Retention(Model):
    policy: str = "durable"  # durable | transient | session
    expires_at: float | None = None
    pinned: bool = False

    def __post_init__(self) -> None:
        if self.policy not in {"durable", "transient", "session"}:
            raise ValidationError("retention policy must be durable, transient, or session")
        object.__setattr__(self, "expires_at", v.check_timestamp(self.expires_at, "expires_at"))

    @classmethod
    def from_dict(cls, raw: Any) -> Retention:
        if raw is None:
            return cls()
        if isinstance(raw, Retention):
            return raw
        return cls(str(raw.get("policy") or "durable"), raw.get("expires_at"), bool(raw.get("pinned")))


@dataclass(frozen=True)
class Links(Model):
    supersedes: tuple[str, ...] = ()
    superseded_by: str | None = None
    conflicts_with: tuple[str, ...] = ()
    derived_from: tuple[str, ...] = ()  # memory ids this record was derived from


# --------------------------------------------------------------------------- records
@dataclass(frozen=True)
class MemoryRecord(Model):
    id: str
    revision: int
    kind: MemoryKind
    lifecycle: Lifecycle
    scope: Scope
    title: str
    content: str
    tags: tuple[str, ...] = ()
    basis: StatementBasis = StatementBasis.USER_STATED
    confidence: Confidence = field(default_factory=Confidence)
    subject: str | None = None
    predicate: str | None = None
    sources: tuple[SourceRef, ...] = ()
    validity: Validity = field(default_factory=Validity)
    retention: Retention = field(default_factory=Retention)
    links: Links = field(default_factory=Links)
    created_at: float = 0.0
    updated_at: float = 0.0
    event_time: float | None = None
    ingested_at: float | None = None
    reason: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    schema_version: int = RECORD_SCHEMA_VERSION

    @property
    def pinned(self) -> bool:
        return self.retention.pinned


@dataclass(frozen=True)
class RevisionInfo(Model):
    record_id: str
    revision: int
    lifecycle: Lifecycle
    created_at: float
    change: str  # created | corrected | approved | rejected | superseded | ...
    actor: Actor
    reason: str = ""
    purged: bool = False  # payload removed by forgetting/retention


# --------------------------------------------------------------------------- requests
def _sources(raw: Any) -> tuple[SourceRef, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        raise ValidationError("sources must be a list")
    if len(raw) > v.MAX_SOURCES:
        raise ValidationError("too many sources")
    return tuple(SourceRef.from_dict(item) for item in raw)


def _coerce_common(obj: Any) -> None:
    """Coerce nested request fields (hosts may pass plain dicts/lists) and bound them."""
    object.__setattr__(obj, "scope", Scope.from_dict(obj.scope))
    object.__setattr__(obj, "sources", _sources(obj.sources))
    object.__setattr__(obj, "validity", Validity.from_dict(obj.validity))
    object.__setattr__(obj, "confidence", Confidence.from_dict(obj.confidence))


@dataclass(frozen=True)
class RememberRequest(Model):
    """An explicit, host-authorized durable memory (user preference or fact)."""

    content: str
    kind: MemoryKind = MemoryKind.FACT
    scope: Scope = field(default_factory=Scope)
    title: str = ""
    tags: tuple[str, ...] = ()
    basis: StatementBasis = StatementBasis.USER_STATED
    sources: tuple[SourceRef, ...] = ()
    subject: str | None = None
    predicate: str | None = None
    validity: Validity = field(default_factory=Validity)
    retention: Retention = field(default_factory=Retention)
    reason: str = ""
    confidence: Confidence = field(default_factory=Confidence)
    memory_id: str | None = None  # caller-chosen stable id (e.g. legacy-compatible)
    allow_sensitive: bool = False  # host attests the user explicitly asked to keep it

    def __post_init__(self) -> None:
        object.__setattr__(self, "content", v.check_text(self.content, "content", max_chars=v.MAX_CONTENT_CHARS))
        object.__setattr__(self, "kind", MemoryKind.parse(self.kind, "kind"))
        object.__setattr__(self, "basis", StatementBasis.parse(self.basis, "basis"))
        object.__setattr__(self, "title", v.check_text(self.title or "", "title", max_chars=v.MAX_TITLE_CHARS, allow_empty=True))
        object.__setattr__(self, "tags", v.check_tags(self.tags))
        object.__setattr__(self, "reason", v.check_text(self.reason or "", "reason", max_chars=v.MAX_REASON_CHARS, allow_empty=True))
        _coerce_common(self)
        object.__setattr__(self, "retention", Retention.from_dict(self.retention))
        if self.memory_id is not None:
            v.check_id(self.memory_id, "memory_id")
        for name in ("subject", "predicate"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, v.check_label(value, name, max_chars=256))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> RememberRequest:
        if not isinstance(raw, dict):
            raise ValidationError("request must be an object")
        return cls(
            content=raw.get("content"), kind=raw.get("kind", "fact"),
            scope=Scope.from_dict(raw.get("scope")), title=raw.get("title") or "",
            tags=tuple(raw.get("tags") or ()), basis=raw.get("basis", "user_stated"),
            sources=_sources(raw.get("sources")), subject=raw.get("subject"),
            predicate=raw.get("predicate"), validity=Validity.from_dict(raw.get("validity")),
            retention=Retention.from_dict(raw.get("retention")), reason=raw.get("reason") or "",
            confidence=Confidence.from_dict(raw.get("confidence")), memory_id=raw.get("memory_id"),
            allow_sensitive=bool(raw.get("allow_sensitive", False)),
        )


@dataclass(frozen=True)
class CandidateProposal(Model):
    """An unapproved memory proposed by an agent, extractor, consolidation or import."""

    content: str
    sources: tuple[SourceRef, ...]
    kind: MemoryKind = MemoryKind.FACT
    scope: Scope = field(default_factory=Scope)
    title: str = ""
    tags: tuple[str, ...] = ()
    basis: StatementBasis = StatementBasis.MODEL_INTERPRETATION
    confidence: Confidence = field(default_factory=Confidence)
    subject: str | None = None
    predicate: str | None = None
    validity: Validity = field(default_factory=Validity)
    rationale: str = ""
    proposer: str = "agent"
    derived_from: tuple[str, ...] = ()
    observed_generation: int | None = None  # commit-time staleness check for derived work

    def __post_init__(self) -> None:
        object.__setattr__(self, "content", v.check_text(self.content, "content", max_chars=v.MAX_CONTENT_CHARS))
        object.__setattr__(self, "kind", MemoryKind.parse(self.kind, "kind"))
        object.__setattr__(self, "basis", StatementBasis.parse(self.basis, "basis"))
        object.__setattr__(self, "title", v.check_text(self.title or "", "title", max_chars=v.MAX_TITLE_CHARS, allow_empty=True))
        object.__setattr__(self, "tags", v.check_tags(self.tags))
        object.__setattr__(self, "rationale", v.check_text(self.rationale or "", "rationale", max_chars=v.MAX_REASON_CHARS, allow_empty=True))
        v.check_label(self.proposer, "proposer")
        _coerce_common(self)
        if not self.sources:
            raise ValidationError("a candidate requires at least one evidence source")
        if isinstance(self.derived_from, str) or len(self.derived_from) > v.MAX_SOURCES:
            raise ValidationError("derived_from must be a list of at most 64 memory ids")
        object.__setattr__(self, "derived_from", tuple(v.check_id(item, "derived_from") for item in self.derived_from))
        for name in ("subject", "predicate"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, v.check_label(value, name, max_chars=256))
        if self.observed_generation is not None:
            v.check_int(self.observed_generation, "observed_generation", lo=0)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CandidateProposal:
        if not isinstance(raw, dict):
            raise ValidationError("proposal must be an object")
        return cls(
            content=raw.get("content"), sources=_sources(raw.get("sources")),
            kind=raw.get("kind", "fact"), scope=Scope.from_dict(raw.get("scope")),
            title=raw.get("title") or "", tags=tuple(raw.get("tags") or ()),
            basis=raw.get("basis", "model_interpretation"),
            confidence=Confidence.from_dict(raw.get("confidence")),
            subject=raw.get("subject"), predicate=raw.get("predicate"),
            validity=Validity.from_dict(raw.get("validity")), rationale=raw.get("rationale") or "",
            proposer=raw.get("proposer") or "agent", derived_from=tuple(raw.get("derived_from") or ()),
            observed_generation=raw.get("observed_generation"),
        )


@dataclass(frozen=True)
class Correction(Model):
    content: str | None = None
    title: str | None = None
    tags: tuple[str, ...] | None = None
    validity: Validity | None = None
    retention: Retention | None = None
    reason: str = ""
    sources: tuple[SourceRef, ...] = ()
    allow_sensitive: bool = False  # host attests the user explicitly asked to keep it

    def __post_init__(self) -> None:
        if self.content is not None:
            object.__setattr__(self, "content", v.check_text(self.content, "content", max_chars=v.MAX_CONTENT_CHARS))
        if self.title is not None:
            object.__setattr__(self, "title", v.check_text(self.title, "title", max_chars=v.MAX_TITLE_CHARS, allow_empty=True))
        if self.tags is not None:
            object.__setattr__(self, "tags", v.check_tags(self.tags))
        object.__setattr__(self, "reason", v.check_text(self.reason or "", "reason", max_chars=v.MAX_REASON_CHARS, allow_empty=True))
        object.__setattr__(self, "sources", _sources(self.sources))
        if self.validity is not None:
            object.__setattr__(self, "validity", Validity.from_dict(self.validity))
        if self.retention is not None:
            object.__setattr__(self, "retention", Retention.from_dict(self.retention))
        if all(getattr(self, name) is None for name in ("content", "title", "tags", "validity", "retention")):
            raise ValidationError("a correction must change something")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Correction:
        if not isinstance(raw, dict):
            raise ValidationError("correction must be an object")
        return cls(
            content=raw.get("content"), title=raw.get("title"),
            tags=tuple(raw["tags"]) if raw.get("tags") is not None else None,
            validity=Validity.from_dict(raw["validity"]) if raw.get("validity") is not None else None,
            retention=Retention.from_dict(raw["retention"]) if raw.get("retention") is not None else None,
            reason=raw.get("reason") or "", sources=_sources(raw.get("sources")),
            allow_sensitive=bool(raw.get("allow_sensitive", False)),
        )


class ForgetTargetKind(_Enum):
    MEMORY = "memory"
    SOURCE = "source"  # a source identity (e.g. message:<id>) and everything derived from it
    SESSION = "session"
    PROJECT = "project"
    REPOSITORY = "repository"
    AGENT = "agent"
    PROFILE = "profile"


@dataclass(frozen=True)
class ForgetTarget(Model):
    kind: ForgetTargetKind
    ref: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ForgetTargetKind.parse(self.kind, "forget target"))
        if self.kind == ForgetTargetKind.MEMORY:
            v.check_id(self.ref, "memory id")
        else:
            v.check_label(self.ref, "forget target ref", max_chars=512)


@dataclass(frozen=True)
class ForgetPolicy(Model):
    purge_revisions: bool = True
    suppress_relearning: bool = True  # source-linked suppression when the source remains
    delete_source_archive: bool = False  # also delete archived transcript messages
    include_derived: bool = True


@dataclass(frozen=True)
class Query(Model):
    text: str = ""
    kinds: tuple[MemoryKind, ...] = ()
    lifecycles: tuple[Lifecycle, ...] = (Lifecycle.APPROVED,)
    scope_filter: Scope | None = None  # narrow within grants; never widens
    limit: int = 8
    since: float | None = None
    until: float | None = None
    at_time: float | None = None  # validity evaluation time (defaults to now)
    include_stale: bool = False
    deadline_ms: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "text", v.check_text(self.text or "", "query", max_chars=v.MAX_QUERY_CHARS, allow_empty=True))
        object.__setattr__(self, "kinds", tuple(MemoryKind.parse(k, "kind") for k in self.kinds))
        object.__setattr__(self, "lifecycles", tuple(Lifecycle.parse(k, "lifecycle") for k in self.lifecycles))
        v.check_int(self.limit, "limit", lo=1, hi=200)
        v.check_timestamp(self.since, "since")
        v.check_timestamp(self.until, "until")
        v.check_timestamp(self.at_time, "at_time")
        if self.deadline_ms is not None:
            v.check_int(self.deadline_ms, "deadline_ms", lo=1, hi=600_000)

    @classmethod
    def from_dict(cls, raw: Any) -> Query:
        if isinstance(raw, str):
            return cls(text=raw)
        if not isinstance(raw, dict):
            raise ValidationError("query must be text or an object")
        return cls(
            text=raw.get("text") or "", kinds=tuple(raw.get("kinds") or ()),
            lifecycles=tuple(raw.get("lifecycles") or ("approved",)),
            scope_filter=Scope.from_dict(raw["scope_filter"]) if raw.get("scope_filter") else None,
            limit=int(raw.get("limit", 8)), since=raw.get("since"), until=raw.get("until"),
            at_time=raw.get("at_time"), include_stale=bool(raw.get("include_stale", False)),
            deadline_ms=raw.get("deadline_ms"),
        )


# --------------------------------------------------------------------------- results
@dataclass(frozen=True)
class Coverage(Model):
    """What a search or context build could actually see."""

    total: int | None = None  # items in authorized namespace (None = unknown)
    searched: int = 0
    index_ready: bool = True
    missing: tuple[str, ...] = ()  # human-readable missing coverage, e.g. "sessions before 2026-01"
    partial_reasons: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return self.index_ready and not self.missing and not self.partial_reasons


@dataclass(frozen=True)
class SearchHit(Model):
    record: MemoryRecord
    rank: int
    score: float
    score_kind: str  # e.g. "rrf" - a rank-fusion value, NOT a probability of truth
    reasons: tuple[str, ...] = ()
    matched: tuple[str, ...] = ()  # ranker names that matched
    snippet: str = ""
    conflicts: tuple[str, ...] = ()
    current: bool = True  # False when validity/source hashes say it is historical


@dataclass(frozen=True)
class SearchResult(Model):
    hits: tuple[SearchHit, ...]
    status: ResultStatus
    coverage: Coverage
    query_hash: str = ""
    elapsed_ms: float | None = None


@dataclass(frozen=True)
class Receipt(Model):
    """Proof of a completed (or refused) operation. Never issued before commit."""

    receipt_id: str
    operation: str
    status: str  # ok | noop | rejected | partial
    created_at: float
    partition_id: str
    record_ids: tuple[str, ...] = ()
    revisions: tuple[int, ...] = ()
    generation: int = 0
    idempotent_replay: bool = False
    details: dict[str, Any] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class WriteResult(Model):
    record: MemoryRecord
    receipt: Receipt
    conflicts: tuple[str, ...] = ()


# --------------------------------------------------------------------------- context
@dataclass(frozen=True)
class SliceSpec(Model):
    name: str
    max_tokens: int
    kinds: tuple[MemoryKind, ...] = ()
    scope_dims: tuple[str, ...] | None = None  # None = any; () = global only
    query_relevant: bool = False  # select by relevance to the request query


DEFAULT_SLICES: tuple[SliceSpec, ...] = (
    SliceSpec("user_preferences", 500, (MemoryKind.PREFERENCE,), (), False),
    SliceSpec("profile_facts", 800, (MemoryKind.FACT, MemoryKind.CONSTRAINT, MemoryKind.RELATIONSHIP, MemoryKind.DECISION), (), False),
    SliceSpec("project_and_repository", 1200, (MemoryKind.DECISION, MemoryKind.CONSTRAINT, MemoryKind.FACT, MemoryKind.PREFERENCE, MemoryKind.REPOSITORY_OBSERVATION, MemoryKind.SUMMARY), ("project", "repository", "worktree", "team"), True),
    SliceSpec("agent", 400, (), ("agent",), True),
    SliceSpec("episodes", 600, (MemoryKind.EPISODE,), None, True),
    SliceSpec("procedures", 600, (MemoryKind.PROCEDURE,), None, True),
)


@dataclass(frozen=True)
class ContextRequest(Model):
    token_allowance: int
    query: str = ""
    slices: tuple[SliceSpec, ...] = DEFAULT_SLICES
    include_history: bool = False
    history_limit: int = 3
    repository: str | None = None
    files: tuple[str, ...] = ()
    at_time: float | None = None
    conflict_policy: str = "annotate"  # annotate | omit
    exclude_ids: tuple[str, ...] = ()  # already injected by another path (no double injection)
    deadline_ms: int | None = None
    # Optional cap on the number of injected items (None = no cap; 0 = inject nothing). Applied
    # in selection order (round-robin across slices); omitted items get reason "max_items".
    max_items: int | None = None
    # Rendered item order: "slices" (default: slice order, then selection order within a slice)
    # or "relevance" (strong query matches first, by relevance rank; then the rest in slice order).
    order: str = "slices"

    ORDERS = frozenset({"slices", "relevance"})
    MAX_ITEMS_LIMIT = 10_000

    def __post_init__(self) -> None:
        v.check_int(self.token_allowance, "token_allowance", lo=0, hi=1_000_000)
        object.__setattr__(self, "query", v.check_text(self.query or "", "query", max_chars=v.MAX_QUERY_CHARS, allow_empty=True))
        if self.conflict_policy not in {"annotate", "omit"}:
            raise ValidationError("conflict_policy must be annotate or omit")
        v.check_int(self.history_limit, "history_limit", lo=0, hi=50)
        if self.max_items is not None:
            v.check_int(self.max_items, "max_items", lo=0, hi=self.MAX_ITEMS_LIMIT)
        if self.order not in self.ORDERS:
            raise ValidationError("order must be slices or relevance")


@dataclass(frozen=True)
class ContextItem(Model):
    record_id: str
    revision: int
    slice: str
    kind: MemoryKind
    scope: Scope
    tokens: int
    reasons: tuple[str, ...]
    sources: tuple[str, ...]  # source identities
    conflict_note: str = ""


@dataclass(frozen=True)
class ContextOmission(Model):
    record_id: str | None
    reason: str  # budget | conflict | stale | unapproved | duplicate | excluded | expired | slice_cap | max_items
    slice: str = ""
    tokens: int | None = None


@dataclass(frozen=True)
class ContextPacket(Model):
    receipt_id: str
    text: str
    items: tuple[ContextItem, ...]
    omissions: tuple[ContextOmission, ...]
    conflicts: tuple[tuple[str, str], ...]
    token_count: int
    token_count_kind: MeasureKind
    token_allowance: int
    coverage: Coverage
    snapshot_hash: str
    generation: int
    created_at: float
    status: ResultStatus = ResultStatus.COMPLETE
    history_handles: tuple[str, ...] = ()
    costs: dict[str, Any] = field(default_factory=dict)
    # Content-free evidence-strength flags (see context/compiler.py): "weak_evidence_only" (a query
    # was given but no item was selected by a lexical/exact match in a query-relevant slice) and
    # "history_weak_only" (history was searched and returned no hit that matched every content term).
    flags: tuple[str, ...] = ()


# --------------------------------------------------------------------------- history
@dataclass(frozen=True)
class IngestionEvent(Model):
    event_id: str
    session_ref: str
    sequence: int
    role: str  # user | assistant | tool
    text: str
    occurred_at: float
    scope: Scope = field(default_factory=Scope)
    source: str = "host"  # producer name for cursors
    tool_name: str | None = None
    attachments: tuple[dict[str, Any], ...] = ()
    is_memory_injection: bool = False  # injected memory block - never ingested as evidence
    is_generated_summary: bool = False
    host_refs: dict[str, Any] = field(default_factory=dict)

    ROLES = frozenset({"user", "assistant", "tool"})

    def __post_init__(self) -> None:
        v.check_ref(self.event_id, "event_id")
        v.check_ref(self.session_ref, "session_ref")
        v.check_int(self.sequence, "sequence", lo=0)
        if self.role not in self.ROLES:
            raise ValidationError("role must be user, assistant, or tool (hidden reasoning is never ingested)")
        object.__setattr__(self, "text", v.check_text(self.text, "text", max_chars=v.MAX_MESSAGE_CHARS, allow_empty=True))
        object.__setattr__(self, "occurred_at", v.check_timestamp(self.occurred_at, "occurred_at", optional=False))
        object.__setattr__(self, "scope", Scope.from_dict(self.scope))
        if self.tool_name is not None:
            object.__setattr__(self, "tool_name", v.check_label(self.tool_name, "tool_name", max_chars=128))
        v.check_label(self.source, "source")
        object.__setattr__(self, "host_refs", v.check_mapping(self.host_refs, "host_refs"))
        if len(self.attachments) > 32:
            raise ValidationError("too many attachments")
        object.__setattr__(self, "attachments", tuple(v.check_mapping(a, "attachment") for a in self.attachments))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> IngestionEvent:
        if not isinstance(raw, dict):
            raise ValidationError("event must be an object")
        return cls(
            event_id=raw.get("event_id"), session_ref=raw.get("session_ref"),
            sequence=raw.get("sequence"), role=raw.get("role"), text=raw.get("text", ""),
            occurred_at=raw.get("occurred_at"), scope=Scope.from_dict(raw.get("scope")),
            source=raw.get("source") or "host", tool_name=raw.get("tool_name"),
            attachments=tuple(raw.get("attachments") or ()),
            is_memory_injection=bool(raw.get("is_memory_injection", False)),
            is_generated_summary=bool(raw.get("is_generated_summary", False)),
            host_refs=raw.get("host_refs") or {},
        )


@dataclass(frozen=True)
class HistoryMessage(Model):
    message_id: str
    event_id: str
    session_ref: str
    sequence: int
    role: str
    text: str
    occurred_at: float
    ingested_at: float
    scope: Scope
    redactions: tuple[str, ...] = ()
    attachments: tuple[dict[str, Any], ...] = ()
    tool_name: str | None = None


@dataclass(frozen=True)
class HistoryHit(Model):
    message: HistoryMessage
    rank: int
    score: float
    score_kind: str
    snippet: str
    handle: str  # expansion handle for bounded scroll
    # Annotations, never removals: "weak_match" (matched only some of the query's content terms)
    # and "superseded_by_correction" (the message is a cited source of a memory whose content was
    # later corrected; see history/archive.py).
    flags: tuple[str, ...] = ()


@dataclass(frozen=True)
class HistorySearchResult(Model):
    hits: tuple[HistoryHit, ...]
    status: ResultStatus
    coverage: Coverage


@dataclass(frozen=True)
class IngestReceipt(Model):
    receipt: Receipt
    message_id: str | None
    duplicate: bool
    skipped_reason: str | None = None
    redactions: tuple[str, ...] = ()


# --------------------------------------------------------------------------- episodes & procedures
@dataclass(frozen=True)
class VerificationRef(Model):
    receipt_id: str
    issuer: str = "host"

    def __post_init__(self) -> None:
        v.check_ref(self.receipt_id, "verification receipt id")


@dataclass(frozen=True)
class VerifiedCheck(Model):
    name: str
    passed: bool
    required: bool = True
    detail: str = ""


@dataclass(frozen=True)
class VerificationResult(Model):
    """What the host's verification authority attests for a receipt id."""

    receipt_id: str
    trusted: bool
    checks: tuple[VerifiedCheck, ...] = ()
    issued_at: float | None = None
    task_ref: str | None = None
    # Capabilities the host attests the verified work actually used (None: not attested). The
    # only capability evidence procedures accept; an agent's self-reported environment is not.
    capabilities: tuple[str, ...] | None = None


@dataclass(frozen=True)
class EpisodeReport(Model):
    episode_id: str  # stable logical id; a resumed attempt reuses it
    task_ref: str
    attempt_ref: str
    objective: str
    scope: Scope = field(default_factory=Scope)
    run_ref: str | None = None
    environment: dict[str, Any] = field(default_factory=dict)
    repository_snapshot: str | None = None
    approach: str = ""
    affected_paths: tuple[str, ...] = ()
    verification: tuple[VerificationRef, ...] = ()
    claimed_outcome: EpisodeOutcome = EpisodeOutcome.UNKNOWN
    failure_modes: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()
    proposed_lessons: tuple[str, ...] = ()
    usage: dict[str, Any] = field(default_factory=dict)
    context_receipts: tuple[str, ...] = ()
    started_at: float | None = None
    ended_at: float | None = None

    def __post_init__(self) -> None:
        v.check_id(self.episode_id, "episode_id")
        v.check_ref(self.task_ref, "task_ref")
        v.check_ref(self.attempt_ref, "attempt_ref")
        object.__setattr__(self, "objective", v.check_text(self.objective, "objective", max_chars=4_000))
        object.__setattr__(self, "approach", v.check_text(self.approach or "", "approach", max_chars=8_000, allow_empty=True))
        object.__setattr__(self, "claimed_outcome", EpisodeOutcome.parse(self.claimed_outcome, "claimed_outcome"))
        object.__setattr__(self, "environment", v.check_mapping(self.environment, "environment"))
        object.__setattr__(self, "usage", v.check_mapping(self.usage, "usage"))
        for name in ("affected_paths", "failure_modes", "uncertainties", "proposed_lessons", "context_receipts"):
            values = getattr(self, name)
            if len(values) > v.MAX_LIST:
                raise ValidationError(f"too many {name}")
            object.__setattr__(self, name, tuple(v.check_text(x, name, max_chars=2_000) for x in values))
        v.check_timestamp(self.started_at, "started_at")
        v.check_timestamp(self.ended_at, "ended_at")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EpisodeReport:
        if not isinstance(raw, dict):
            raise ValidationError("episode must be an object")
        return cls(
            episode_id=raw.get("episode_id"), task_ref=raw.get("task_ref"),
            attempt_ref=raw.get("attempt_ref"), objective=raw.get("objective"),
            scope=Scope.from_dict(raw.get("scope")), run_ref=raw.get("run_ref"),
            environment=raw.get("environment") or {},
            repository_snapshot=raw.get("repository_snapshot"), approach=raw.get("approach") or "",
            affected_paths=tuple(raw.get("affected_paths") or ()),
            verification=tuple(VerificationRef(**x) if isinstance(x, dict) else VerificationRef(str(x))
                               for x in raw.get("verification") or ()),
            claimed_outcome=raw.get("claimed_outcome", "unknown"),
            failure_modes=tuple(raw.get("failure_modes") or ()),
            uncertainties=tuple(raw.get("uncertainties") or ()),
            proposed_lessons=tuple(raw.get("proposed_lessons") or ()),
            usage=raw.get("usage") or {}, context_receipts=tuple(raw.get("context_receipts") or ()),
            started_at=raw.get("started_at"), ended_at=raw.get("ended_at"),
        )


@dataclass(frozen=True)
class Episode(Model):
    episode_id: str
    record_id: str
    revision: int
    task_ref: str
    attempts: tuple[str, ...]
    objective: str
    scope: Scope
    outcome: EpisodeOutcome
    claimed_outcome: EpisodeOutcome
    outcome_basis: str  # why the outcome was assigned (e.g. "host receipts: 3/3 required checks passed")
    verification: tuple[VerificationResult, ...]
    approach: str
    affected_paths: tuple[str, ...]
    failure_modes: tuple[str, ...]
    uncertainties: tuple[str, ...]
    proposed_lessons: tuple[str, ...]
    usage: dict[str, Any]
    context_receipts: tuple[str, ...]
    repository_snapshot: str | None
    environment: dict[str, Any]
    updated_at: float


@dataclass(frozen=True)
class ProcedureDraft(Model):
    name: str
    purpose: str
    applicability: str
    steps: tuple[str, ...]
    scope: Scope = field(default_factory=Scope)
    preconditions: tuple[str, ...] = ()
    expected_outcomes: tuple[str, ...] = ()
    negative_cases: tuple[str, ...] = ()
    known_failures: tuple[str, ...] = ()
    requested_capabilities: tuple[str, ...] = ()
    evidence_episode_ids: tuple[str, ...] = ()
    rollback: str = ""
    supersedes: str | None = None

    def __post_init__(self) -> None:
        v.check_label(self.name, "procedure name", max_chars=120)
        object.__setattr__(self, "purpose", v.check_text(self.purpose, "purpose", max_chars=2_000))
        object.__setattr__(self, "applicability", v.check_text(self.applicability, "applicability", max_chars=2_000))
        if not self.steps:
            raise ValidationError("a procedure needs at least one step")
        for name in ("steps", "preconditions", "expected_outcomes", "negative_cases",
                     "known_failures", "requested_capabilities"):
            values = getattr(self, name)
            if len(values) > 64:
                raise ValidationError(f"too many {name}")
            object.__setattr__(self, name, tuple(v.check_text(x, name, max_chars=2_000) for x in values))
        for item in self.evidence_episode_ids:
            v.check_id(item, "evidence episode id")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ProcedureDraft:
        if not isinstance(raw, dict):
            raise ValidationError("procedure must be an object")
        return cls(
            name=raw.get("name"), purpose=raw.get("purpose"), applicability=raw.get("applicability"),
            steps=tuple(raw.get("steps") or ()), scope=Scope.from_dict(raw.get("scope")),
            preconditions=tuple(raw.get("preconditions") or ()),
            expected_outcomes=tuple(raw.get("expected_outcomes") or ()),
            negative_cases=tuple(raw.get("negative_cases") or ()),
            known_failures=tuple(raw.get("known_failures") or ()),
            requested_capabilities=tuple(raw.get("requested_capabilities") or ()),
            evidence_episode_ids=tuple(raw.get("evidence_episode_ids") or ()),
            rollback=raw.get("rollback") or "", supersedes=raw.get("supersedes"),
        )


@dataclass(frozen=True)
class Procedure(Model):
    procedure_id: str
    record_id: str
    version: int
    state: ProcedureState
    draft: ProcedureDraft
    independent_evidence: int
    evidence_episode_ids: tuple[str, ...]
    safety_findings: tuple[str, ...]
    evaluation_receipts: tuple[str, ...]
    state_history: tuple[tuple[str, float, str], ...]  # (state, at, reason)
    updated_at: float


@dataclass(frozen=True)
class ForgetReceipt(Model):
    receipt: Receipt
    target: ForgetTarget
    deleted: dict[str, int]  # category -> count (memories, revisions, messages, embeddings, ...)
    suppressed_sources: int
    regenerate_required: tuple[str, ...]  # mixed-source derived ids removed for regeneration
    retained_by_policy: dict[str, int]
    pending_external: tuple[str, ...]  # provider deletions queued, not yet confirmed
    deletion_generation: int
    # True when the post-forget WAL checkpoint could not complete (a concurrent reader): the
    # purge is committed but deleted pages may linger on disk until the retried checkpoint runs.
    physical_purge_pending: bool = False


@dataclass(frozen=True)
class EngineStatus(Model):
    api_version: str
    partition_id: str
    schema_version: int
    canonical_backend: str
    serving_mode: str
    counts: dict[str, int]  # only for the caller's authorized namespace
    generation: int
    deletion_generation: int
    key_id: str
    cipher: str
    fts5_available: bool
    index: dict[str, Any]
    providers: dict[str, Any]
    limitations: tuple[str, ...]


# Public names only (keeps ``from .models import *`` from re-exporting stdlib modules).
__all__ = sorted(
    [name for name, obj in list(globals().items())
     if not name.startswith("_") and getattr(obj, "__module__", None) == __name__]
    + ["API_VERSION", "RECORD_SCHEMA_VERSION", "ALL_OPERATIONS", "DEFAULT_SLICES"]
)
