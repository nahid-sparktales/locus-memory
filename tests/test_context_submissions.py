import json

import pytest

from conftest import CANARY, access_for, scan_for_plaintext
from locus_memory.context.compiler import CONTEXT_RECEIPT_TTL_S
from locus_memory.errors import NotFound, ValidationError
from locus_memory.models import ContextRequest, RememberRequest, Scope


def metadata(packet, **extra):
    return dict(context_receipt_id=packet.receipt_id, session_id="session-a", run_id="run-a",
                agent_id="agent-1", turn_id="turn-a", attempt_id="attempt-a", **extra)


def test_submission_is_encrypted_and_survives_restart(make_engine, user_access, root):
    engine = make_engine()
    record = engine.remember(user_access, RememberRequest(content=CANARY)).record
    packet = engine.build_context(user_access, ContextRequest(token_allowance=1200))
    details = metadata(packet, state="uncertain")
    receipt = engine.record_context_submission(user_access, **details)
    engine.record_context_submission(user_access, **{**details, "state": "submitted"},
                                     submission_id=receipt["submission_id"])
    engine.close()
    reopened = make_engine()
    entries = reopened.list_context_submissions(user_access, session_id="session-a", run_id="run-a", agent_id="agent-1")
    assert len(entries) == 1 and entries[0]["state"] == "submitted"
    assert CANARY not in json.dumps(entries)
    assert reopened.explain_context(user_access, entries[0]["context_receipt_id"])["items"][0]["record_id"] == record.id
    assert not scan_for_plaintext(root, CANARY)
    assert not scan_for_plaintext(root, "session-a")


def test_attempts_remain_separate_and_foreign_update_rejected(engine, user_access):
    packet = engine.build_context(user_access, ContextRequest(token_allowance=1200))
    first = engine.record_context_submission(user_access, **metadata(packet))
    engine.record_context_submission(user_access, **{**metadata(packet), "attempt_id": "retry"})
    assert len(engine.list_context_submissions(user_access, session_id="session-a", run_id="run-a", agent_id="agent-1")) == 2
    assert engine.list_context_submissions(user_access, session_id="session-b", run_id="run-a", agent_id="agent-1") == []
    with pytest.raises(NotFound):
        engine.record_context_submission(user_access, **{**metadata(packet), "run_id": "foreign"}, submission_id=first["submission_id"])
    with pytest.raises(ValidationError):
        engine.record_context_submission(user_access, **metadata(packet, reason=CANARY))


def test_narrowed_scope_explanation_never_names_hidden_record(engine, user_access):
    record = engine.remember(user_access, RememberRequest(content=CANARY, scope=Scope.of(agent="agent-1"))).record
    packet = engine.build_context(user_access, ContextRequest(token_allowance=1200))
    engine.record_context_submission(user_access, **metadata(packet))
    restricted = access_for(agents=("other",))
    detail = engine.explain_context(restricted, packet.receipt_id)
    assert detail["items"] == [] and detail["unavailable_items"] == 1
    assert record.id not in json.dumps(detail) and CANARY not in json.dumps(detail)


def test_submission_age_is_enforced_without_new_writes(engine, user_access, clock):
    packet = engine.build_context(user_access, ContextRequest(token_allowance=1200))
    engine.record_context_submission(user_access, **metadata(packet))
    clock.advance(CONTEXT_RECEIPT_TTL_S + 1)
    assert engine.list_context_submissions(user_access, session_id="session-a", run_id="run-a", agent_id="agent-1") == []


def test_context_reference_must_match_submission_grants(engine, user_access):
    packet = engine.build_context(user_access, ContextRequest(token_allowance=1200))
    with pytest.raises(NotFound):
        engine.record_context_submission(access_for(agents=("different",)), **metadata(packet))
