"""In-memory lexical projection of *authorized, decrypted* records.

A projection is built per (partition generation, grants fingerprint, lifecycle
set, kind set) from records that ``RecordStore.authorized`` already filtered in
SQL. It never touches disk:

* FTS5 path: a private ``storage.db.memory_connection()`` (``:memory:``,
  ``temp_store=MEMORY``) holding two FTS5 tables -- FTS5 tokenizers are per table,
  so the two "columns" of the projection are two tables sharing rowids:

  - ``fts_text(title, body)`` with ``unicode61 remove_diacritics 2`` (natural text),
  - ``fts_ident(ident)`` with ``tokenchars '_./-:#'`` so ``src/foo_bar.py``,
    ``memoryvault.save`` and ``pr-123`` are single tokens.

  Both are *contentless* (``content=''``): only the inverted index is kept, not a
  second copy of the text. Each projected document keeps its decrypted record
  (what a hit returns) and compact normalized token strings, so a projection for
  a newer generation can reuse unchanged documents without decrypting or
  re-tokenizing them.

  plus a plain ``docs`` table of filter metadata (event time, valid_from,
  read-time expiry). ``bm25()`` returns LOWER (more negative) values for BETTER
  matches, so results are ordered ascending.

* Fallback path (FTS5 unavailable, or ``FORCE_PYTHON_FALLBACK``): a pure-Python
  BM25 (k1=1.2, b=0.75, FTS5's IDF formula) over the same token streams. Its
  scores are HIGHER = BETTER. Ranker names carry the backend (``bm25_python``).

Both paths index the same normalized tokens (see :mod:`.query`), so they agree
on *which* records match; their BM25 orderings can differ slightly.
"""
from __future__ import annotations

import bisect
import math
import sqlite3
import threading
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from ..errors import IndexUnavailable
from ..models import Lifecycle, MemoryRecord
from ..storage.db import fts5_available, memory_connection
from . import query as q

# Tests and hosts may force the pure-Python path even when FTS5 exists.
FORCE_PYTHON_FALLBACK = False

TITLE_WEIGHT = 2.0
BODY_WEIGHT = 1.0
BM25_K1 = 1.2
BM25_B = 0.75

_FTS5_OK: bool | None = None
_FTS5_LOCK = threading.Lock()


def fts5_usable() -> bool:
    """FTS5 with the tokenizer options we need (cached), unless the fallback is forced."""
    global _FTS5_OK
    if FORCE_PYTHON_FALLBACK:
        return False
    with _FTS5_LOCK:
        if _FTS5_OK is None:
            _FTS5_OK = fts5_available() and _tokenizers_ok()
        return _FTS5_OK


def _tokenizers_ok() -> bool:
    try:
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute(f"CREATE VIRTUAL TABLE a USING fts5(x, tokenize=\"{q.TEXT_TOKENIZER}\")")
            conn.execute(f"CREATE VIRTUAL TABLE b USING fts5(x, tokenize=\"{q.IDENT_TOKENIZER}\")")
            return True
        finally:
            conn.close()
    except sqlite3.Error:
        return False


# --------------------------------------------------------------------------- documents
@dataclass(frozen=True)
class Filters:
    """Per-query eligibility applied inside the index (never widens authorization)."""

    at_time: float  # validity evaluation time
    now: float  # read-time expiry evaluation time
    since: float | None = None
    until: float | None = None


def read_time_expiry(record: MemoryRecord) -> float | None:
    """When a record stops being servable even before maintenance runs (mirrors core.expire_due)."""
    if record.lifecycle == Lifecycle.CANDIDATE:
        return record.retention.expires_at
    if record.lifecycle in (Lifecycle.APPROVED, Lifecycle.STALE):
        if record.retention.policy != "durable" and not record.retention.pinned:
            return record.retention.expires_at
    return None


@dataclass(frozen=True)
class Doc:
    """One projected record. Token streams are kept as compact space-joined strings."""

    idx: int
    record: MemoryRecord
    title_text: str  # normalized natural-language tokens, space-joined
    body_text: str
    ident_text: str  # unique normalized identifiers, space-joined
    ts: float  # event time (falls back to created_at) used by since/until filters
    valid_from: float | None
    expiry: float | None
    nbytes: int  # estimated resident text bytes (record text + normalized index text)

    @property
    def title_tokens(self) -> tuple[str, ...]:
        return tuple(self.title_text.split())

    @property
    def body_tokens(self) -> tuple[str, ...]:
        return tuple(self.body_text.split())

    @property
    def ident(self) -> tuple[str, ...]:
        return tuple(self.ident_text.split())

    @property
    def token_set(self) -> frozenset[str]:
        """Natural-word set used for diversity (Jaccard)."""
        return frozenset(self.title_text.split()) | frozenset(self.body_text.split())

    def eligible(self, f: Filters) -> bool:
        if f.since is not None and self.ts < f.since:
            return False
        if f.until is not None and self.ts > f.until:
            return False
        if self.valid_from is not None and self.valid_from > f.at_time:
            return False
        return not (self.expiry is not None and self.expiry < f.now)


def _body(record: MemoryRecord) -> str:
    return record.content + ("\n" + " ".join(record.tags) if record.tags else "")


def build_doc(idx: int, record: MemoryRecord) -> Doc:
    body = _body(record)
    paths = " ".join(path for path, _ in record.validity.source_hashes)
    title_text = " ".join(q.text_tokens(record.title))
    body_text = " ".join(q.text_tokens(body))
    ident_text = " ".join(q.unique(q.ident_tokens(" ".join((record.title, body, paths)))))
    nbytes = sum(len(part.encode()) for part in (record.title, body, paths, title_text, body_text, ident_text))
    ts = record.event_time if record.event_time is not None else record.created_at
    return Doc(idx=idx, record=record, title_text=title_text, body_text=body_text, ident_text=ident_text,
               ts=float(ts or 0.0), valid_from=record.validity.valid_from,
               expiry=read_time_expiry(record), nbytes=nbytes)


# --------------------------------------------------------------------------- indexes
class LexicalIndex:
    """Common interface. Every method returns doc indexes, best first, plus a raw score."""

    backend = "abstract"
    text_ranker = "lexical"
    ident_ranker = "identifier"
    phrase_ranker = "phrase"
    prefix_ranker = "prefix"

    def __init__(self, docs: list[Doc]) -> None:
        self.docs = docs
        self._ident_postings: dict[str, list[int]] = defaultdict(list)
        for doc in docs:
            for token in doc.ident:
                self._ident_postings[token].append(doc.idx)

    def exact_ident(self, query: q.ParsedQuery, f: Filters) -> dict[int, int]:
        """Docs containing a query identifier as a whole token -> number of identifiers matched."""
        hits: dict[int, int] = defaultdict(int)
        for term in query.ident_terms:
            for idx in self._ident_postings.get(term, ()):
                if self.docs[idx].eligible(f):
                    hits[idx] += 1
        return dict(hits)

    def text(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        raise NotImplementedError

    def phrase(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        raise NotImplementedError

    def prefix(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        raise NotImplementedError

    def identifiers(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        raise NotImplementedError

    def close(self) -> None:
        self.docs = []
        self._ident_postings = defaultdict(list)


class Fts5Index(LexicalIndex):
    backend = "fts5"
    text_ranker = "fts5_bm25"
    ident_ranker = "fts5_ident"
    phrase_ranker = "fts5_phrase"
    prefix_ranker = "fts5_prefix"

    def __init__(self, docs: list[Doc]) -> None:
        super().__init__(docs)
        self._lock = threading.Lock()
        conn = memory_connection()
        try:
            conn.execute("CREATE VIRTUAL TABLE fts_text USING fts5(title, body, content='',"
                         f" tokenize=\"{q.TEXT_TOKENIZER}\")")
            conn.execute(f"CREATE VIRTUAL TABLE fts_ident USING fts5(ident, content='', tokenize=\"{q.IDENT_TOKENIZER}\")")
            conn.execute("CREATE TABLE docs(rowid INTEGER PRIMARY KEY, ts REAL NOT NULL, vfrom REAL, rexp REAL)")
            conn.execute("BEGIN")
            # rowid = idx + 1 (FTS5 rowids should be positive).
            conn.executemany(
                "INSERT INTO fts_text(rowid, title, body) VALUES(?,?,?)",
                ((d.idx + 1, d.title_text, d.body_text) for d in docs),
            )
            conn.executemany(
                "INSERT INTO fts_ident(rowid, ident) VALUES(?,?)",
                ((d.idx + 1, d.ident_text) for d in docs if d.ident_text),
            )
            conn.executemany(
                "INSERT INTO docs(rowid, ts, vfrom, rexp) VALUES(?,?,?,?)",
                ((d.idx + 1, d.ts, d.valid_from, d.expiry) for d in docs),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.close()
            raise
        self._conn: sqlite3.Connection | None = conn

    @staticmethod
    def _filter_sql(f: Filters) -> tuple[str, list[object]]:
        clauses = ["(d.vfrom IS NULL OR d.vfrom <= ?)", "(d.rexp IS NULL OR d.rexp >= ?)"]
        params: list[object] = [f.at_time, f.now]
        if f.since is not None:
            clauses.append("d.ts >= ?")
            params.append(f.since)
        if f.until is not None:
            clauses.append("d.ts <= ?")
            params.append(f.until)
        return " AND ".join(clauses), params

    def _run(self, table: str, rank_expr: str, match: str | None, f: Filters, cap: int
             ) -> list[tuple[int, float]]:
        if not match:
            return []
        where, params = self._filter_sql(f)
        # CROSS JOIN pins the FTS scan as the outer loop (a ``rowid IN (subquery)`` filter
        # makes SQLite evaluate the MATCH once per document instead). bm25(): lower is better.
        sql = (f"SELECT {table}.rowid, {rank_expr} AS s FROM {table} CROSS JOIN docs d"
               f" ON d.rowid = {table}.rowid WHERE {table} MATCH ? AND {where}"
               f" ORDER BY s ASC, {table}.rowid ASC LIMIT ?")
        return self._query(sql, [match, *params, int(cap)])

    def _query(self, sql: str, params: list[object]) -> list[tuple[int, float]]:
        failed = False
        with self._lock:
            if self._conn is None:
                raise IndexUnavailable("the lexical index was released")
            try:
                rows = self._conn.execute(sql, params).fetchall()
            except sqlite3.Error:
                failed = True  # SQLite messages can echo the MATCH text; never propagate them
        if failed:
            raise IndexUnavailable("the lexical index query failed")
        return [(int(rowid) - 1, float(score)) for rowid, score in rows]

    def text(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        return self._run("fts_text", f"bm25(fts_text, {TITLE_WEIGHT}, {BODY_WEIGHT})", q.text_match(query), f, cap)

    def phrase(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        return self._run("fts_text", f"bm25(fts_text, {TITLE_WEIGHT}, {BODY_WEIGHT})", q.phrase_match(query), f, cap)

    def prefix(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        return self._run("fts_text", f"bm25(fts_text, {TITLE_WEIGHT}, {BODY_WEIGHT})", q.prefix_match(query), f, cap)

    def identifiers(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        return self._run("fts_ident", "bm25(fts_ident)", q.ident_match(query), f, cap)

    def raw_bm25(self, match: str) -> list[tuple[int, float]]:
        """Diagnostics/tests: unfiltered ``bm25()`` values for a MATCH built by :mod:`.query`."""
        return self._query(
            f"SELECT rowid, bm25(fts_text, {TITLE_WEIGHT}, {BODY_WEIGHT}) AS s FROM fts_text"
            " WHERE fts_text MATCH ? ORDER BY s ASC, rowid ASC", [match])

    def close(self) -> None:
        with self._lock:
            conn, self._conn = self._conn, None
        if conn is not None:
            conn.close()
        super().close()


class _Bm25:
    """Okapi BM25 with FTS5's IDF (floored at 1e-6). Scores: HIGHER = BETTER."""

    def __init__(self, docs: Iterable[tuple[int, dict[str, float], float]], n_docs: int) -> None:
        self.n = max(n_docs, 1)
        self.postings: dict[str, list[tuple[int, float]]] = defaultdict(list)
        self.length: dict[int, float] = {}
        for idx, tf, length in docs:
            self.length[idx] = length
            for term, count in tf.items():
                self.postings[term].append((idx, count))
        self.avgdl = (sum(self.length.values()) / len(self.length)) if self.length else 1.0
        self.vocabulary = sorted(self.postings)

    def idf(self, term: str) -> float:
        df = len(self.postings.get(term, ()))
        value = math.log((self.n - df + 0.5) / (df + 0.5))
        return value if value > 0 else 1e-6

    def score(self, terms: Iterable[str], allow) -> dict[int, float]:
        scores: dict[int, float] = defaultdict(float)
        for term in terms:
            postings = self.postings.get(term)
            if not postings:
                continue
            idf = self.idf(term)
            for idx, tf in postings:
                if not allow(idx):
                    continue
                norm = BM25_K1 * (1 - BM25_B + BM25_B * self.length[idx] / (self.avgdl or 1.0))
                scores[idx] += idf * (tf * (BM25_K1 + 1)) / (tf + norm)
        return dict(scores)

    def expand_prefix(self, prefix: str, limit: int = 256) -> list[str]:
        start = bisect.bisect_left(self.vocabulary, prefix)
        out = []
        for term in self.vocabulary[start:start + limit]:
            if not term.startswith(prefix):
                break
            out.append(term)
        return out


def _ordered(scores: dict[int, float], cap: int) -> list[tuple[int, float]]:
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:cap]


def _contains_phrase(tokens: tuple[str, ...], phrase: tuple[str, ...]) -> bool:
    n = len(phrase)
    if n == 0 or n > len(tokens):
        return False
    first = phrase[0]
    for i, token in enumerate(tokens[: len(tokens) - n + 1]):
        if token == first and tokens[i:i + n] == phrase:
            return True
    return False


class PythonIndex(LexicalIndex):
    backend = "python"
    text_ranker = "bm25_python"
    ident_ranker = "bm25_python_ident"
    phrase_ranker = "phrase_python"
    prefix_ranker = "prefix_python"

    def __init__(self, docs: list[Doc]) -> None:
        super().__init__(docs)

        def text_tf(doc: Doc) -> tuple[int, dict[str, float], float]:
            tf: dict[str, float] = defaultdict(float)
            title, body = doc.title_tokens, doc.body_tokens
            for token in title:
                tf[token] += TITLE_WEIGHT
            for token in body:
                tf[token] += BODY_WEIGHT
            return doc.idx, tf, float(len(title) + len(body))

        def ident_tf(doc: Doc) -> tuple[int, dict[str, float], float]:
            return doc.idx, dict.fromkeys(doc.ident, 1.0), float(len(doc.ident))

        self._text = _Bm25((text_tf(d) for d in docs), len(docs))
        self._ident = _Bm25((ident_tf(d) for d in docs if d.ident), len(docs))

    def _allow(self, f: Filters):
        docs = self.docs
        return lambda idx: docs[idx].eligible(f)

    def text(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        scores = self._text.score(query.text_terms, self._allow(f))
        if query.phrase:
            phrase_idf = sum(self._text.idf(t) for t in query.phrase)
            for idx, _ in self.phrase(query, f, len(self.docs)):
                scores[idx] = scores.get(idx, 0.0) + phrase_idf  # phrase boost, like FTS5's extra phrase
        return _ordered(scores, cap)

    def phrase(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        if not query.phrase:
            return []
        candidates = None
        for token in set(query.phrase):
            ids = {idx for idx, _ in self._text.postings.get(token, ())}
            candidates = ids if candidates is None else candidates & ids
            if not candidates:
                return []
        allow = self._allow(f)
        matched = {idx for idx in candidates or () if allow(idx)
                   and (_contains_phrase(self.docs[idx].title_tokens, query.phrase)
                        or _contains_phrase(self.docs[idx].body_tokens, query.phrase))}
        scores = self._text.score(query.phrase, matched.__contains__)
        return _ordered(scores, cap)

    def prefix(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        terms: list[str] = []
        for term in query.prefix_terms:
            terms += self._text.expand_prefix(term)
        return _ordered(self._text.score(q.unique(terms), self._allow(f)), cap)

    def identifiers(self, query: q.ParsedQuery, f: Filters, cap: int) -> list[tuple[int, float]]:
        return _ordered(self._ident.score(query.ident_terms, self._allow(f)), cap)


def build_index(docs: list[Doc]) -> tuple[LexicalIndex, str | None]:
    """Build the best available index. Returns (index, degradation note or None)."""
    if fts5_usable():
        try:
            return Fts5Index(docs), None
        except sqlite3.Error:
            return PythonIndex(docs), "lexical_fallback:bm25_python (fts5 index build failed)"
    reason = "forced" if FORCE_PYTHON_FALLBACK else "fts5 unavailable"
    return PythonIndex(docs), f"lexical_fallback:bm25_python ({reason})"
