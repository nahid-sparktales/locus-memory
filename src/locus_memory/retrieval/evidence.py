"""Conservative automatic-context admission, separate from retrieval rank.

This is an auditable lexical heuristic, not a confidence score or an answerability
classifier. Search remains broad; hosts explicitly opt into this stricter prompt
policy. Semantic similarity and existing weak_match flags never bypass qualifier
checks. Preferences can remain background without pretending to answer a question.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .query import STOPWORDS, text_tokens

_NOISE = STOPWORDS | frozenset("do does did use uses using used run runs running tell say says know known remember please give get about current currently now choose chosen should can could would how help explain according need needs want wanted like written runner apply limit target builds provider style user data long code make keep prefer prefers preference preferred message".split())
_ALIASES = {"prod": "production", "live": "production", "stage": "staging", "staged": "staging",
            "db": "database", "databases": "database", "deploys": "deploy", "deployment": "deploy",
            "deployed": "deploy", "deployments": "deploy", "deploying": "deploy", "release": "deploy",
            "releases": "deploy", "rollout": "deploy", "testing": "test", "tests": "test",
            "testcase": "test", "check": "test", "checks": "test", "verification": "test",
            "timezone": "zone", "timezones": "zone", "reside": "livein", "lives": "livein",
            "location": "city", "city": "city", "editor": "editor", "ide": "editor",
            "indentation": "indent", "indenting": "indent", "spaces": "indent", "indent": "indent",
            "commits": "commit", "messages": "message", "edits": "editor", "editing": "editor", "answering": "answer", "indented": "indent", "kept": "retention", "response": "answer", "responses": "answer", "answers": "answer", "concise": "brief",
            "concisely": "brief", "short": "brief", "shorter": "brief", "briefly": "brief"}
# These qualifiers must not be substituted for each other by keyword or semantic rank.
_QUALIFIERS = (frozenset({"production", "staging", "development", "preview"}),
               frozenset({"windows", "linux", "macos"}))
# Topic anchors prevent e.g. a staging database result from answering a staging deployment query.
_TOPICS = frozenset({"database", "deploy", "ci", "oncall", "rotation", "retention", "license",
                    "queue", "editor", "indent", "zone", "city", "test", "cache", "latency", "port", "commit"})


def terms(text: str) -> frozenset[str]:
    normalized = text.lower().replace("on-call", "oncall").replace("on call", "oncall")
    return frozenset(_ALIASES.get(word, word) for word in text_tokens(normalized) if word not in _NOISE)


@dataclass(frozen=True)
class EvidenceDecision:
    admitted: bool
    reason: str
    matched_terms: int = 0
    query_terms: int = 0


def assess_evidence(query: str, text: str) -> EvidenceDecision:
    wanted, found = terms(query), terms(text)
    # A compound request can draw each required fact from a separate record. Qualifiers
    # in the other clause must not disqualify a valid fact (retention AND production DB).
    clauses = re.split(r"\band\b", query, flags=re.IGNORECASE)
    if len(clauses) > 1 and len(wanted & _TOPICS) > 1:
        decisions = [assess_evidence(clause, text) for clause in clauses]
        if any(decision.admitted for decision in decisions):
            return EvidenceDecision(True, "query_evidence", len(wanted & found), len(wanted))
    if not wanted:
        return EvidenceDecision(False, "no_query_evidence")
    overlap = wanted & found
    # Explicitly named entities are anchors, not interchangeable matches. This remains
    # conservative: lowercase prose without structured identity is not entity resolution.
    generic = _NOISE | _TOPICS | {"set", "json", "memory", "reference", "approved", "return"}
    named = {_ALIASES.get(word.lower(), word.lower())
             for word in re.findall(r"\b[A-Z][A-Za-z0-9_-]+\b", query)
             if word.lower() not in generic}
    if named and not named.intersection(found):
        return EvidenceDecision(False, "entity_mismatch", len(overlap), len(wanted))
    for family in _QUALIFIERS:
        requested = wanted & family
        actual = found & family
        if requested and (not requested <= actual):
            return EvidenceDecision(False, "qualifier_mismatch", len(overlap), len(wanted))
    topics = wanted & _TOPICS
    if topics and not (topics & found):
        return EvidenceDecision(False, "topic_mismatch", len(overlap), len(wanted))
    # All terms for tiny queries, at least two and half for ordinary questions.
    # Long task instructions remain broad: two content anchors permit relevant context.
    minimum = min(len(wanted), 2)
    coverage = len(overlap) / len(wanted)
    admitted = len(overlap) >= minimum and (coverage >= 0.5 or bool(topics & found) or len(wanted) > 12)
    return EvidenceDecision(admitted, "query_evidence" if admitted else "insufficient_query_evidence",
                            len(overlap), len(wanted))
