from __future__ import annotations

import pytest

from locus_memory.errors import ValidationError
from locus_memory.models import ContextRequest, RememberRequest, Scope
from locus_memory.retrieval.evidence import assess_evidence
from locus_memory.runtime import _SLICES


@pytest.mark.parametrize("query,text", [
    ("Which production database does atlas use?", "atlas staging database is SQLite"),
    ("Where do atlas staging builds deploy?", "atlas production deploy target is Canary"),
    ("Where do atlas staging builds deploy?", "atlas staging database is SQLite"),
    ("What CI provider does borealis use?", "borealis production database is Postgres"),
    ("What on-call rotation does atlas use?", "atlas database is Postgres"),
    ("Windows install directory", "Linux install directory is /opt/bin"),
    ("Which production database does Orion use?", "Vega production database is PostgreSQL"),
])
def test_hard_negatives_are_not_automatic_evidence(query, text):
    assert not assess_evidence(query, text).admitted


@pytest.mark.parametrize("query,text", [
    ("Which prod db does atlas run?", "atlas production database is Postgres"),
    ("Where is atlas deployed in production?", "atlas production deployment target is London"),
    ("What verification does atlas need?", "atlas requires test results before merge"),
    ("Which IDE do I use?", "preferred editor is VSCode"),
    ("Keep answers brief", "prefers short responses"),
])
def test_held_out_paraphrases_remain_eligible(query, text):
    assert assess_evidence(query, text).admitted


def test_background_preferences_do_not_imply_query_evidence(engine, user_access):
    access = user_access
    pref = engine.remember(access, RememberRequest(content="Prefer short answers", kind="preference")).record
    other = engine.remember(access, RememberRequest(content="atlas staging database is SQLite",
                            kind="fact", scope=Scope.of(project="proj-a"))).record
    packet = engine.build_context(access, ContextRequest(token_allowance=2000,
        query="Where do atlas staging builds deploy?", slices=_SLICES,
        order="relevance", evidence_policy="conservative"))
    assert pref.id in {item.record_id for item in packet.items}
    assert other.id not in {item.record_id for item in packet.items}
    assert "no_query_evidence" in packet.flags
    assert "background preference; not factual query evidence" in packet.text
    assert next(item for item in packet.omissions if item.record_id == other.id).reason == "topic_mismatch"


def test_production_packet_orders_relevant_fact_before_background(engine, user_access):
    access = user_access
    engine.remember(access, RememberRequest(content="Prefer short answers", kind="preference"))
    fact = engine.remember(access, RememberRequest(content="atlas production database is Postgres",
                          kind="fact", scope=Scope.of(project="proj-a"))).record
    packet = engine.build_context(access, ContextRequest(token_allowance=2000,
        query="Which production database does atlas use?", slices=_SLICES,
        order="relevance", evidence_policy="conservative"))
    assert packet.items[0].record_id == fact.id
    assert "no_query_evidence" not in packet.flags


def test_conservative_policy_is_explicit_and_validated():
    assert ContextRequest(token_allowance=100).evidence_policy == "legacy"
    with pytest.raises(ValidationError):
        ContextRequest(token_allowance=100, evidence_policy="semantic-confidence")


def test_imperative_task_formatting_does_not_crowd_out_topic_evidence():
    assert assess_evidence("Set result.json port to the current Orion service port. Use null if unknown.",
                           "Orion service port is 8127.").admitted
    assert assess_evidence("What commit message style do I want?",
                           "Use conventional commits.").admitted
