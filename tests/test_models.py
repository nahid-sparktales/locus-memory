"""Models, validation and policy helpers: bounded, typed, never widening access."""
from __future__ import annotations

import math

import pytest

import locus_memory
from locus_memory import errors as errors_module
from locus_memory import policy
from locus_memory import validation as v
from locus_memory.errors import (
    AccessDenied,
    MemoryEngineError,
    NotFound,
    SuppressedError,
    ValidationError,
)
from locus_memory.host import HostCapabilities
from locus_memory.models import (
    AccessContext,
    Actor,
    CandidateProposal,
    Confidence,
    Correction,
    ForgetPolicy,
    ForgetTarget,
    ForgetTargetKind,
    IngestionEvent,
    Lifecycle,
    MemoryKind,
    MemoryRecord,
    Operation,
    PartitionRef,
    Query,
    RememberRequest,
    Retention,
    Scope,
    ScopeGrants,
    SourceKind,
    SourceRef,
    Validity,
    canonical_json,
    content_hash,
)
from locus_memory.storage.records import record_from_dict

DOC = SourceRef(SourceKind.DOCUMENT, "doc-1")


# ---------------------------------------------------------------------------- scope & grants
def test_scope_normalizes_order_and_case_of_dimensions():
    a = Scope.of(project="p", agent="x")
    b = Scope((("AGENT", "x"), ("project", "p")))
    assert a == b
    assert a.constraints == (("agent", "x"), ("project", "p"))
    assert a.key() == b.key()


@pytest.mark.parametrize("constraints", [
    (("project", "a"), ("PROJECT", "b")),  # duplicate dimension
    (("planet", "earth"),),  # unknown dimension
    (("project", "bad\x07value"),),  # control character
    (("project", ""),),  # empty value
    (("project", "x" * 513),),  # too long
])
def test_scope_rejects_malformed_constraints(constraints):
    with pytest.raises(ValidationError):
        Scope(constraints)


def test_scope_from_dict_forms():
    assert Scope.from_dict(None).is_global
    assert Scope.from_dict({"project": "p", "agent": None}) == Scope.of(project="p")
    assert Scope.from_dict([["team", "t"]]) == Scope.of(team="t")
    assert Scope.from_dict({"constraints": {"device": "d"}}) == Scope.of(device="d")
    with pytest.raises(ValidationError):
        Scope.from_dict("project=p")


def test_grants_allow_only_when_every_dimension_is_granted():
    grants = ScopeGrants(projects=frozenset({"p"}), agents=frozenset({"a"}))
    assert grants.allows(Scope.global_())
    assert grants.allows(Scope.of(project="p"))
    assert grants.allows(Scope.of(project="p", agent="a"))
    # Nearest failure: one granted dimension is not enough for an intersecting scope.
    assert not grants.allows(Scope.of(project="p", agent="other"))
    assert not grants.allows(Scope.of(project="p", team="t"))
    assert not grants.allows(Scope.of(device="d"))


def test_grants_validate_values_and_bounds():
    assert ScopeGrants(projects="solo").projects == frozenset({"solo"})
    with pytest.raises(ValidationError):
        ScopeGrants(projects=frozenset({"bad\nvalue"}))
    with pytest.raises(ValidationError):
        ScopeGrants(projects=frozenset(f"p{i}" for i in range(v.MAX_LIST + 1)))
    assert ScopeGrants.from_dict({"project": "p", "agents": ["a"]}).allows(Scope.of(project="p", agent="a"))
    with pytest.raises(ValidationError):
        ScopeGrants.from_dict(["p"])


def test_partition_ids_are_stable_and_distinct():
    a = PartitionRef("standard", "alice")
    assert a.partition_id == PartitionRef("standard", "alice").partition_id
    ids = {a.partition_id, PartitionRef("standard", "bob").partition_id,
           PartitionRef("dev", "alice").partition_id}
    assert len(ids) == 3
    assert all(pid.startswith("p") and len(pid) == 32 and pid.isalnum() for pid in ids)
    # Existing ids are stable (v1 derivation) ...
    import hashlib
    expected = "p" + hashlib.sha256(b"locus-memory/partition/v1|standard|alice").hexdigest()[:31]
    assert a.partition_id == expected
    # ... and there is no delimiter confusion between edition and profile.
    assert PartitionRef("a|b", "c").partition_id != PartitionRef("a", "b|c").partition_id
    with pytest.raises(ValidationError):
        PartitionRef("standard", "")
    with pytest.raises(ValidationError):
        PartitionRef("standard", "bob\x00")


def test_access_context_validates_its_shape():
    ref = PartitionRef("standard", "default")
    ctx = AccessContext(principal="u", partition=ref, actor="agent", operations={"read", "propose"})
    assert ctx.actor == Actor.AGENT and ctx.operations == {Operation.READ, Operation.PROPOSE}
    with pytest.raises(ValidationError):
        AccessContext(principal="u", partition={"edition": "standard", "profile": "default"})
    with pytest.raises(ValidationError):
        AccessContext(principal="u", partition=ref, grants={"projects": ["p"]})
    with pytest.raises(ValidationError):
        AccessContext(principal="u", partition=ref, operations="admin")
    with pytest.raises(ValidationError):
        AccessContext(principal="u", partition=ref, operations={"superuser"})
    with pytest.raises(ValidationError):
        AccessContext(principal="u", partition=ref, actor="root")
    # The fingerprint changes with every security-relevant field.
    other = AccessContext(principal="u", partition=ref, actor="agent", operations={"read"})
    assert ctx.fingerprint() != other.fingerprint()


# ---------------------------------------------------------------------------- confidence & values
def test_unknown_confidence_stays_unknown():
    unknown = Confidence()
    assert unknown.value is None and not unknown.calibrated and unknown.method == "unknown"
    assert Confidence.from_dict(None) == unknown
    with pytest.raises(ValidationError):
        Confidence(None, True)  # unknown cannot claim calibration


def test_numeric_confidence_is_uncalibrated_and_bounded():
    c = Confidence.from_dict(0.7)
    assert c.value == 0.7 and not c.calibrated and c.method == "uncalibrated"
    for bad in (1.5, -0.1, math.nan, math.inf, True):
        with pytest.raises(ValidationError):
            Confidence(bad)
    with pytest.raises(ValidationError):
        Confidence.from_dict("high")


def test_validity_and_retention_bounds():
    with pytest.raises(ValidationError):
        Validity(valid_from=10, valid_until=10)
    with pytest.raises(ValidationError):
        Validity(valid_from=math.nan)
    with pytest.raises(ValidationError):
        Validity(valid_until=v.MAX_TIMESTAMP + 1)
    with pytest.raises(ValidationError):
        Retention(policy="forever")
    with pytest.raises(ValidationError):
        Retention(expires_at="tomorrow")
    assert Retention.from_dict({"policy": "transient", "expires_at": 5, "pinned": 1}).pinned is True


# ---------------------------------------------------------------------------- requests
@pytest.mark.parametrize("kwargs", [
    {"content": ""},
    {"content": "   "},
    {"content": "x" * (v.MAX_CONTENT_CHARS + 1)},
    {"content": "nul \x00 byte"},
    {"content": "ok", "title": "t" * (v.MAX_TITLE_CHARS + 1)},
    {"content": "ok", "tags": [f"t{i}" for i in range(v.MAX_TAGS + 1)]},
    {"content": "ok", "memory_id": "../escape"},
    {"content": "ok", "subject": "bad\x1bsubject"},
    {"content": "ok", "kind": "opinion"},
    {"content": "ok", "basis": "rumour"},
    {"content": "ok", "sources": "message:1"},
])
def test_remember_request_rejects_invalid_input(kwargs):
    with pytest.raises(ValidationError):
        RememberRequest(**kwargs)


def test_remember_request_coerces_plain_json_shapes():
    request = RememberRequest(content="  likes tea  ", scope={"project": "p"},
                              sources=[{"kind": "document", "ref": "doc-1"}],
                              validity={"valid_until": 2_000_000_000}, retention={"policy": "transient"},
                              confidence=0.4, tags=["B", "a", "a"])
    assert request.content == "likes tea"
    assert request.scope == Scope.of(project="p")
    assert request.sources == (DOC,)
    assert isinstance(request.validity, Validity) and request.validity.valid_until == 2_000_000_000
    assert request.retention.policy == "transient"
    assert request.confidence == Confidence(0.4, False, "uncalibrated")
    assert request.tags == ("a", "b")
    assert RememberRequest.from_dict(request.to_dict()) == request


def test_candidate_requires_evidence_and_valid_derivations():
    with pytest.raises(ValidationError):
        CandidateProposal(content="x", sources=())
    with pytest.raises(ValidationError):
        CandidateProposal(content="x", sources=(DOC,), derived_from=("not an id!",))
    with pytest.raises(ValidationError):
        CandidateProposal(content="x", sources=(DOC,), derived_from="m1")  # a string is not a list
    with pytest.raises(ValidationError):
        CandidateProposal(content="x", sources=(DOC,), derived_from=tuple(f"m{i}" for i in range(65)))
    with pytest.raises(ValidationError):
        CandidateProposal(content="x", sources=(DOC,), observed_generation="3")
    with pytest.raises(ValidationError):
        CandidateProposal(content="x", sources=(DOC,), observed_generation=-1)
    with pytest.raises(ValidationError):
        CandidateProposal(content="x", sources=[{"kind": "document", "ref": f"d{i}"} for i in range(65)])
    proposal = CandidateProposal.from_dict({"content": "x", "sources": [{"kind": "document", "ref": "doc-1"}],
                                            "scope": {"agent": "a"}, "observed_generation": 4})
    assert proposal.sources == (DOC,) and proposal.observed_generation == 4
    assert proposal.basis.value == "model_interpretation"


def test_correction_must_change_something_and_coerces():
    with pytest.raises(ValidationError):
        Correction(reason="nothing")
    c = Correction(validity={"valid_until": 2_000_000_000})
    assert isinstance(c.validity, Validity)
    assert Correction.from_dict({"tags": ["X"]}).tags == ("x",)


@pytest.mark.parametrize("ref", ["../etc/passwd", "a b", "", "x" * 257, "line\nbreak", "a/../b"])
def test_source_ref_rejects_unsafe_references(ref):
    with pytest.raises(ValidationError):
        SourceRef(SourceKind.MESSAGE, ref)


def test_source_ref_locator_must_be_small_finite_json():
    with pytest.raises(ValidationError):
        SourceRef(SourceKind.DOCUMENT, "d", locator={"x": math.nan})
    with pytest.raises(ValidationError):
        SourceRef(SourceKind.DOCUMENT, "d", locator={"x": "y" * 20_000})
    with pytest.raises(ValidationError):
        SourceRef(SourceKind.DOCUMENT, "d", locator={"x": object()})
    assert SourceRef.from_dict({"kind": "document", "ref": "d"}).identity() == "document:d"


def test_forget_target_and_query_validation():
    with pytest.raises(ValidationError):
        ForgetTarget(ForgetTargetKind.MEMORY, "m 1")
    with pytest.raises(ValidationError):
        ForgetTarget("everything", "x")
    assert ForgetTarget("project", "Project A").ref == "Project A"
    for bad in ({"limit": 0}, {"limit": 201}, {"deadline_ms": 0}, {"since": math.inf}, {"lifecycles": ("live",)}):
        with pytest.raises(ValidationError):
            Query(**bad)
    assert Query.from_dict("tea").text == "tea"


def test_ingestion_event_never_accepts_hidden_reasoning():
    base = {"event_id": "e1", "session_ref": "s1", "sequence": 0, "text": "hi", "occurred_at": 1.0}
    with pytest.raises(ValidationError):
        IngestionEvent(role="reasoning", **base)
    with pytest.raises(ValidationError):
        IngestionEvent(role="user", **{**base, "sequence": -1})
    assert IngestionEvent(role="tool", **base).role == "tool"


# ---------------------------------------------------------------------------- serde
def test_canonical_json_is_deterministic_and_finite():
    assert canonical_json({"b": 1, "a": [2, {"d": 3, "c": 4}]}) == '{"a":[2,{"c":4,"d":3}],"b":1}'
    assert canonical_json(frozenset({"b", "a"})) == '["a","b"]'
    assert content_hash({"x": 1}) == content_hash({"x": 1})
    with pytest.raises(ValueError):
        canonical_json({"x": math.nan})


def test_record_roundtrips_through_its_stored_form():
    record = MemoryRecord(
        id="m1", revision=3, kind=MemoryKind.DECISION, lifecycle=Lifecycle.STALE,
        scope=Scope.of(project="p", agent="a"), title="t", content="c", tags=("x",),
        confidence=Confidence(0.5, False, "model_uncalibrated"), subject="s", predicate="p",
        sources=(DOC, SourceRef(SourceKind.MEMORY, "m0")), validity=Validity(1.0, 2.0),
        retention=Retention("transient", 9.0, True), created_at=1.0, updated_at=2.0, extra={"k": [1]},
    )
    assert record_from_dict(record.to_dict()) == record


def test_forget_policy_defaults_are_conservative():
    p = ForgetPolicy()
    assert p.purge_revisions and p.suppress_relearning and p.include_derived
    assert not p.delete_source_archive


# ---------------------------------------------------------------------------- validation helpers
def test_validation_helpers():
    assert v.check_ref("message:abc/1@x") == "message:abc/1@x"
    with pytest.raises(ValidationError):
        v.check_ref("a..b")
    with pytest.raises(ValidationError):
        v.check_int(True, "n")
    with pytest.raises(ValidationError):
        v.check_int(1.0, "n")
    with pytest.raises(ValidationError):
        v.check_finite("nan", "x")
    with pytest.raises(ValidationError):
        v.check_finite(5, "x", lo=0, hi=1)
    assert v.check_timestamp("", "t") is None
    with pytest.raises(ValidationError):
        v.check_timestamp(None, "t", optional=False)
    assert v.normalize_for_fingerprint("  Hello,   WORLD!! ") == "hello world"
    with pytest.raises(ValidationError):
        v.check_mapping({f"k{i}": i for i in range(65)}, "m")


# ---------------------------------------------------------------------------- policy
def _access(**grants) -> AccessContext:
    return AccessContext(principal="u", partition=PartitionRef("standard", "default"),
                         grants=ScopeGrants(**{k: frozenset(val) for k, val in grants.items()}),
                         operations=frozenset(Operation))


def test_narrow_restricts_and_never_widens():
    access = _access(projects={"a", "b"}, agents={"x"})
    narrowed = policy.narrow(access.grants, Scope.of(project="a"))
    assert narrowed.projects == {"a"} and narrowed.agents == {"x"}
    assert policy.narrow(access.grants, None) is access.grants
    with pytest.raises(AccessDenied):
        policy.narrow(access.grants, Scope.of(project="c"))
    with pytest.raises(AccessDenied):
        policy.narrow(access.grants, Scope.of(team="t"))  # dimension with no grants at all


def test_require_visible_hides_existence():
    access = _access(projects={"a"})
    record = MemoryRecord(id="m1", revision=1, kind=MemoryKind.FACT, lifecycle=Lifecycle.APPROVED,
                          scope=Scope.of(project="b"), title="", content="c")
    with pytest.raises(NotFound) as unauthorized:
        policy.require_visible(access, record)
    with pytest.raises(NotFound) as missing:
        policy.require_visible(access, None)
    assert str(unauthorized.value) == str(missing.value)


def test_authoring_and_review_are_actor_bound():
    host = HostCapabilities()
    for actor in (Actor.AGENT, Actor.TOOL, Actor.PROVIDER, Actor.SYSTEM):
        access = AccessContext(principal="u", partition=PartitionRef("standard", "default"), actor=actor,
                               operations=frozenset(Operation))
        with pytest.raises(AccessDenied):
            policy.require_author(access)
        with pytest.raises(AccessDenied):
            policy.require_reviewer(access, host)
    host_actor = AccessContext(principal="u", partition=PartitionRef("standard", "default"), actor=Actor.HOST,
                               operations=frozenset(Operation))
    policy.require_author(host_actor)
    with pytest.raises(AccessDenied):  # a host is not a reviewer unless it attests human review
        policy.require_reviewer(host_actor, host)
    policy.require_reviewer(host_actor, HostCapabilities(approval_actors=frozenset({Actor.HOST})))


# ---------------------------------------------------------------------------- public surface
def test_every_error_is_exported_with_a_unique_code():
    classes = [obj for obj in vars(errors_module).values()
               if isinstance(obj, type) and issubclass(obj, MemoryEngineError)]
    assert SuppressedError in classes
    for cls in classes:
        assert getattr(locus_memory, cls.__name__) is cls
    codes = [cls.code for cls in classes]
    assert len(codes) == len(set(codes))
    err = ValidationError("bad", details={"field": "x"})
    assert err.to_dict() == {"error": "invalid_request", "message": "bad", "details": {"field": "x"}}


def test_suppressed_error_is_shared_with_core():
    from locus_memory import core

    assert core.SuppressedError is SuppressedError


def test_package_namespace_does_not_reexport_stdlib_modules():
    for name in ("json", "hashlib", "dataclasses", "enum", "field", "Path", "Any", "v"):
        assert not hasattr(locus_memory, name), name
    for name in ("RememberRequest", "Scope", "MemoryEngine", "canonical_json", "API_VERSION"):
        assert hasattr(locus_memory, name), name


def test_enum_parse_is_forgiving_on_case_only():
    assert Lifecycle.parse(" APPROVED ") is Lifecycle.APPROVED
    with pytest.raises(ValidationError):
        Lifecycle.parse("approve")
