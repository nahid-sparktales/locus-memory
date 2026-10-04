"""Safe query parsing and FTS5 MATCH construction.

User text is *never* passed to FTS5 as query syntax. This module tokenizes it
itself and builds the MATCH expression from quoted string literals only:

* every term is wrapped in double quotes with internal quotes doubled, so FTS5
  operators (``AND OR NOT NEAR``), column filters (``col:term``), prefix stars,
  parentheses and carets in the input are plain text;
* terms are combined with ``OR`` for recall, and the whole token sequence is
  added as one extra quoted phrase so documents containing the exact phrase
  score higher (phrase boost);
* the input is bounded (``validation.MAX_QUERY_CHARS`` characters, at most
  ``MAX_TERMS`` distinct terms per expression, bounded term length).

Normalization (shared with document projection so both sides agree, and so the
pure-Python fallback agrees with FTS5): NFKC, casefold, diacritics removed.

Two token streams are produced:

* *natural* words: maximal runs of Unicode letters/digits (``_`` and punctuation
  separate words), e.g. ``src/foo_bar.py`` -> ``src foo bar py``;
* *identifiers*: tokens that keep ``_ . / - : #`` together (``src/foo_bar.py``,
  ``memoryvault.save``, ``pr-123``, ``2026-03-15``) when they look like code
  identifiers, paths, dates or references. Trailing sentence punctuation is
  stripped. Detection is a heuristic.

A small English stopword list is dropped from the ``OR`` terms when at least one
non-stopword term remains (heuristic noise reduction; the phrase keeps them).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from ..validation import ID_PATTERN, MAX_QUERY_CHARS, check_text

MAX_TERMS = 24  # distinct terms per MATCH expression
MAX_PHRASE_TERMS = 12  # longer token sequences are not used as a phrase boost
MAX_ID_CANDIDATES = 24
MAX_TERM_CHARS = 128
MAX_IDENT_CHARS = 256
MIN_PREFIX_CHARS = 4  # prefix expansion only for terms at least this long

IDENT_TOKENCHARS = "_./-:#"
TEXT_TOKENIZER = "unicode61 remove_diacritics 2"
IDENT_TOKENIZER = f"unicode61 remove_diacritics 2 tokenchars '{IDENT_TOKENCHARS}'"

_WORD = re.compile(r"[^\W_]+")
_IDENT_CANDIDATE = re.compile(r"\w[\w./:#-]*")
_IDENT_STRIP = "./:#-"
_IDENT_SHAPE = re.compile(r"[_./:#-]|\d.*[^\W\d_]|[^\W\d_].*\d|[a-z][A-Z]")
_ONLY_SEPARATORS = re.compile(r"[_./:#-]+")
_ID_STRIP = "\"'`()[]{}<>,;:.!?"

STOPWORDS = frozenset(
    "a an and are as at be but by for from had has have he her his i if in into is it its "
    "me my no not of on or our she so than that the their them then there these they this "
    "to was we were what when where which who why will with you your".split()
)


def fold(text: str) -> str:
    """NFKC + casefold + diacritics removal (no other changes)."""
    if text.isascii():
        return text.lower()  # identical result for ASCII, much faster
    folded = unicodedata.normalize("NFKC", text).casefold()
    decomposed = unicodedata.normalize("NFKD", folded)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFC", stripped)


def text_tokens(text: str) -> list[str]:
    """Natural-language word tokens in document order (normalized)."""
    if not text:
        return []
    return [t for t in _WORD.findall(fold(text)) if len(t) <= MAX_TERM_CHARS]


def _looks_like_identifier(token: str) -> bool:
    """Heuristic: has a ``_ . / - : #`` separator, mixes letters and digits, or is camelCase."""
    return (len(token) >= 2 and _IDENT_SHAPE.search(token) is not None
            and _ONLY_SEPARATORS.fullmatch(token) is None)


def ident_tokens(text: str) -> list[str]:
    """Identifier/path/date-like tokens kept whole (normalized), in document order."""
    if not text:
        return []
    out: list[str] = []
    normalized = text if text.isascii() else unicodedata.normalize("NFKC", text)
    for raw in _IDENT_CANDIDATE.findall(normalized):
        token = raw.rstrip(_IDENT_STRIP)
        if token.isalpha() and (token.islower() or token[1:].islower()):
            continue  # fast path: plain or Capitalized words are never identifiers
        if not _looks_like_identifier(token):
            continue
        folded = fold(token)
        if 2 <= len(folded) <= MAX_IDENT_CHARS:
            out.append(folded)
    return out


def unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


@dataclass(frozen=True)
class ParsedQuery:
    """A bounded, normalized query. Contains no FTS syntax from the user."""

    text_terms: tuple[str, ...] = ()  # OR'd natural terms (stopwords removed when possible)
    phrase: tuple[str, ...] = ()  # full natural token sequence for the phrase boost (>= 2 tokens)
    ident_terms: tuple[str, ...] = ()  # whole identifiers / paths / dates
    id_candidates: tuple[str, ...] = ()  # case-preserved tokens that could be memory ids
    truncated: bool = False  # more distinct terms than MAX_TERMS were supplied

    @property
    def empty(self) -> bool:
        return not (self.text_terms or self.ident_terms or self.id_candidates)

    @property
    def prefix_terms(self) -> tuple[str, ...]:
        return tuple(t for t in self.text_terms if len(t) >= MIN_PREFIX_CHARS)

    @property
    def all_terms(self) -> tuple[str, ...]:
        """Every normalized term (for snippets and explanations)."""
        return tuple(unique(list(self.ident_terms) + list(self.text_terms)))


def check_query_text(text: object) -> str:
    """Validate raw query text (bounded length, no NUL)."""
    return check_text(text if text is not None else "", "query", max_chars=MAX_QUERY_CHARS,
                      allow_empty=True)


def parse_query(text: str) -> ParsedQuery:
    text = check_query_text(text)
    if not text:
        return ParsedQuery()
    words = text_tokens(text)
    distinct = unique(words)
    content = [w for w in distinct if w not in STOPWORDS]
    terms = content if content else distinct
    idents = unique(ident_tokens(text))
    truncated = len(terms) > MAX_TERMS or len(idents) > MAX_TERMS
    phrase = tuple(words) if 2 <= len(words) <= MAX_PHRASE_TERMS else ()
    ids: list[str] = []
    for raw in unicodedata.normalize("NFKC", text).split():
        candidate = raw.strip(_ID_STRIP)
        if candidate and ID_PATTERN.fullmatch(candidate):
            ids.append(candidate)
    ids = unique(ids)
    if len(ids) > MAX_ID_CANDIDATES:
        truncated = True
    return ParsedQuery(
        text_terms=tuple(terms[:MAX_TERMS]), phrase=phrase, ident_terms=tuple(idents[:MAX_TERMS]),
        id_candidates=tuple(ids[:MAX_ID_CANDIDATES]), truncated=truncated,
    )


# --------------------------------------------------------------------------- MATCH builders
def quote(term: str) -> str:
    """An FTS5 string literal: everything inside is data, never syntax."""
    return '"' + term.replace('"', '""') + '"'


def text_match(query: ParsedQuery) -> str | None:
    """``"t1" OR "t2" ... OR "full phrase"`` over the natural-text table."""
    parts = [quote(t) for t in query.text_terms]
    if query.phrase:
        parts.append(quote(" ".join(query.phrase)))
    return " OR ".join(parts) if parts else None


def phrase_match(query: ParsedQuery) -> str | None:
    return quote(" ".join(query.phrase)) if query.phrase else None


def prefix_match(query: ParsedQuery) -> str | None:
    """``"term" *`` prefix expansion (the star is ours; user stars are inside quotes)."""
    parts = [quote(t) + " *" for t in query.prefix_terms]
    return " OR ".join(parts) if parts else None


def ident_match(query: ParsedQuery) -> str | None:
    parts = [quote(t) for t in query.ident_terms]
    return " OR ".join(parts) if parts else None
