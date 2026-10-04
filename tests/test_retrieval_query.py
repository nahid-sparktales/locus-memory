"""Unit tests for retrieval query parsing and FTS5 MATCH construction (no engine)."""
from __future__ import annotations

import re
import sqlite3

import pytest

from locus_memory.errors import ValidationError
from locus_memory.retrieval import query as q
from locus_memory.validation import MAX_QUERY_CHARS

ADVERSARIAL = [
    'NEAR(', 'NEAR(a b', '"', '""', '"unterminated', '*', 'foo*', '* OR *', 'col:term', 'title:secret',
    '{title body} : x', 'AND OR NOT', 'a AND', 'NOT', '(', ')', '((a)', '^start', 'a NEAR/2 b', '-x', '+y',
    "'; DROP TABLE records; --", "1' OR '1'='1", 'Robert"); DROP TABLE docs;--', '\\', '\x7f', 'a"b',
    'fts_text MATCH x', 'rowid:1', '"a" OR "b"', ':', '#', '.', '/', '..', '../../etc/passwd',
]

# Everything outside double-quoted literals must be our own OR / * glue.
_LITERAL = re.compile(r'"(?:[^"]|"")*"')


def _outside_literals(expression: str) -> str:
    return _LITERAL.sub("", expression)


@pytest.mark.parametrize("text", ADVERSARIAL)
def test_match_expressions_contain_only_quoted_literals(text):
    parsed = q.parse_query(text)
    for build in (q.text_match, q.phrase_match, q.prefix_match, q.ident_match):
        expression = build(parsed)
        if expression is None:
            continue
        leftover = _outside_literals(expression)
        assert set(leftover.split()) <= {"OR", "*"}, (text, expression)


@pytest.mark.parametrize("text", ADVERSARIAL)
def test_adversarial_match_expressions_are_valid_fts5(text):
    """Every built expression is accepted by FTS5 and matches only literal tokens."""
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute(f'CREATE VIRTUAL TABLE t USING fts5(title, body, tokenize="{q.TEXT_TOKENIZER}")')
        conn.execute(f'CREATE VIRTUAL TABLE i USING fts5(ident, tokenize="{q.IDENT_TOKENIZER}")')
        conn.execute("INSERT INTO t(rowid, title, body) VALUES(1, 'near and or not', 'drop table records')")
        conn.execute("INSERT INTO i(rowid, ident) VALUES(1, 'col:term ../../etc/passwd')")
        parsed = q.parse_query(text)
        for table, build in (("t", q.text_match), ("t", q.phrase_match), ("t", q.prefix_match),
                             ("i", q.ident_match)):
            expression = build(parsed)
            if expression is not None:
                conn.execute(f"SELECT rowid FROM {table} WHERE {table} MATCH ?", (expression,)).fetchall()
    finally:
        conn.close()


def test_quote_doubles_internal_quotes():
    assert q.quote('a"b') == '"a""b"'
    assert q.quote("plain") == '"plain"'


def test_tokenization_natural_and_identifiers():
    text = "Fix src/foo_bar.py: MemoryVault.save() broke PR-123 on 2026-03-15."
    words = q.text_tokens(text)
    assert words[:5] == ["fix", "src", "foo", "bar", "py"]
    idents = q.ident_tokens(text)
    assert "src/foo_bar.py" in idents
    assert "memoryvault.save" in idents
    assert "pr-123" in idents
    assert "2026-03-15" in idents  # trailing sentence period stripped
    assert "fix" not in idents and "broke" not in idents


def test_identifier_heuristics():
    assert q.ident_tokens("camelCaseName") == ["camelcasename"]
    assert q.ident_tokens("sha256 v2") == ["sha256", "v2"]
    assert q.ident_tokens("_private __init__.py") == ["_private", "__init__.py"]
    assert q.ident_tokens("plain words only") == []


def test_unicode_normalization():
    assert q.fold("Café") == "cafe"
    assert q.fold("ＣＡＦＥ") == "cafe"  # fullwidth -> NFKC
    assert q.fold("Straße") == "strasse"  # casefold
    assert q.text_tokens("naïve résumé") == ["naive", "resume"]
    assert q.text_tokens("東京タワー 2026") == ["東京タワー", "2026"]
    assert q.text_tokens("🙂🙂") == []


def test_parse_query_terms_phrase_and_ids():
    parsed = q.parse_query("the blue green deployment m0123abcd")
    assert parsed.text_terms == ("blue", "green", "deployment", "m0123abcd")  # stopword dropped
    assert parsed.phrase == ("the", "blue", "green", "deployment", "m0123abcd")
    assert "m0123abcd" in parsed.id_candidates
    assert q.text_match(parsed).endswith('"the blue green deployment m0123abcd"')
    only_stopwords = q.parse_query("the and of")
    assert only_stopwords.text_terms == ("the", "and", "of")  # kept when nothing else remains


def test_id_candidates_keep_case_and_strip_wrapping_punctuation():
    parsed = q.parse_query('see (MemId_9) and "pref-editor".')
    assert "MemId_9" in parsed.id_candidates
    assert "pref-editor" in parsed.id_candidates


def test_empty_and_punctuation_only_queries():
    for text in ("", "   ", "!!!", '"', "***", "🙂"):
        assert q.parse_query(text).empty


def test_term_count_bounded():
    words = " ".join(f"word{i}x" for i in range(40))
    parsed = q.parse_query(words)
    assert len(parsed.text_terms) == q.MAX_TERMS
    assert len(parsed.ident_terms) <= q.MAX_TERMS
    assert len(parsed.id_candidates) <= q.MAX_ID_CANDIDATES
    assert parsed.truncated
    assert parsed.phrase == ()  # too long for a phrase boost
    expression = q.text_match(parsed)
    assert expression.count(" OR ") == q.MAX_TERMS - 1


def test_query_length_bounded():
    with pytest.raises(ValidationError):
        q.parse_query("x" * (MAX_QUERY_CHARS + 1))
    at_limit = ("abcd " * MAX_QUERY_CHARS)[:MAX_QUERY_CHARS]
    assert not q.parse_query(at_limit).empty
    assert q.parse_query("x" * MAX_QUERY_CHARS).empty  # one over-long token is dropped, not truncated
    with pytest.raises(ValidationError):
        q.parse_query("bad\x00nul")


def test_prefix_terms_require_minimum_length():
    parsed = q.parse_query("go deploy")
    assert parsed.prefix_terms == ("deploy",)
    assert q.prefix_match(parsed) == '"deploy" *'
