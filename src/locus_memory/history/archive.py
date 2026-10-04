"""Searchable, encrypted session-history archive.

Storage (one partition database; see ``storage/schema.py``)::

    history_sessions        one row per session_ref (keyed token); the sealed payload
                            holds the session_ref and its scope
    history_session_scopes  keyed scope-value tokens; authorization runs in SQL on these
                            before anything is decrypted
    history_messages        one row per archived event; text, session_ref, event_id,
                            tool name, attachment refs, host refs and redaction
                            categories are sealed; clear columns hold only tokens,
                            sequence numbers, roles and timestamps
    history_skipped         events accepted but deliberately not archived as evidence
                            (injected memory blocks, generated summaries)
    history_gaps            sequence ranges never received ('not_received') and archived
                            messages removed by forgetting ('forgotten')
    history_suppressed      sessions / events purged by forgetting; a host replay does
                            not re-archive them
    history_corrections     cited MESSAGE / SESSION sources of memory revisions whose
                            content was corrected (tokens + record id only); see
                            "Correction propagation" below
    cursors                 per (producer, session): highest contiguous sequence
                            accounted for (rows prefixed ``history:``)

Ordering and cursors. Sequences are per session and 0-based. Every sequence at or
below the highest one seen is, at all times, exactly one of: an archived message, a
skipped event, a forgotten message, or inside a ``not_received`` gap. The contiguous
high-water mark is therefore ``min(not_received.from_seq) - 1`` (or the highest
sequence when there is no open gap). A stream that starts above 0 reports
``[0, first-1]`` as not received until those sequences arrive.

Search. Lexical search runs over an in-memory FTS5 projection (never on disk) of the
decrypted messages of *authorized* sessions only, one projection per grant set,
hydrated newest-first in bounded batches, resumable across calls and capped by
``EngineConfig.max_history_messages_hydrated`` / ``max_projection_bytes``. Any
uncovered range is reported in ``Coverage.missing`` with status PARTIAL; complete
coverage is only claimed when every authorized message matching the filters was
searched. A projection is discarded whenever the partition generation changes.

Match strength. A query is compiled into quoted FTS5 terms; its *content* terms are
the terms that are not stopwords (``retrieval.query.STOPWORDS``; all terms when every
term is a stopword). Hits that contain every content term (FTS5 ``AND``,
``score_kind="bm25"``; or, without FTS5 / when FTS5 finds nothing, e.g. CJK runs, every
content term as a substring, ``"substring_recency"``) are ranked first. Remaining slots
are filled with hits that contain only some content terms (``OR`` over content terms,
``score_kind="bm25_any_term"``); those carry the flag ``weak_match``. Status (when coverage is complete): ``COMPLETE`` when at least
one hit is not weak (or for an empty-query recency listing), ``INSUFFICIENT_EVIDENCE``
when there are no hits or every hit is weak -- the weak hits are still returned. This
is a lexical signal only: it says "no archived message contains every content term
of the query", not "the answer is absent", and a hit that contains every term can
still be irrelevant. Scores are never probabilities.

Correction propagation. When ``CoreService.correct`` changes a memory's content, the
MESSAGE and SESSION sources of the corrected-away revision (minus those the
correction itself cites) are recorded in ``history_corrections``. Hits from such a
message -- or, for a SESSION source, any message of that session at or before the
correction time -- carry the flag ``superseded_by_correction`` when the caller may see
the corrected memory. This is an annotation: the archived message is never removed
or edited (it is the user's transcript). ``search(..., exclude_corrected=True)`` is an
opt-in filter that leaves such messages out of the results. A later correction that
cites a flagged source again clears that source for that memory. Rows are deleted
with the memory and purged when the source, its session, a covering scope or the
profile is forgotten.

The archive is retention only: nothing here extracts, proposes or injects memories.
Transcript text is data; it never changes access, tools, budgets or verification.
"""
from __future__ import annotations

import dataclasses
import datetime
import json
import re
import sqlite3
import threading
import unicodedata
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .. import policy, safety
from .. import validation as v
from ..errors import (
    AccessDenied,
    IdempotencyConflict,
    IntegrityError,
    NotFound,
    ValidationError,
)
from ..host import Deadline
from ..models import (
    AccessContext,
    Coverage,
    ForgetPolicy,
    HistoryHit,
    HistoryMessage,
    HistorySearchResult,
    IngestionEvent,
    IngestReceipt,
    Operation,
    ResultStatus,
    Scope,
    ScopeGrants,
    SourceKind,
    SourceRef,
    content_hash,
)
from ..retrieval.query import STOPWORDS
from ..services import PartitionContext
from ..storage.db import fts5_available, memory_connection

MESSAGES = "history_messages"
SESSIONS = "history_sessions"
ROLES = frozenset(IngestionEvent.ROLES)

SKIP_MEMORY_INJECTION = "memory_injection"
SKIP_GENERATED_SUMMARY = "generated_summary"
SKIP_FORGOTTEN = "forgotten"
GAP_NOT_RECEIVED = "not_received"
GAP_FORGOTTEN = "forgotten"

FLAG_WEAK = "weak_match"
FLAG_SUPERSEDED = "superseded_by_correction"
SCORE_STRONG = "bm25"
SCORE_WEAK = "bm25_any_term"
SCORE_SUBSTRING = "substring_recency"
SCORE_RECENCY = "recency"

MAX_SCROLL = 50
MAX_BROWSE = 200
MAX_SEARCH_LIMIT = 200
MAX_BATCH_EVENTS = 5_000
MAX_QUERY_TERMS = 32
SNIPPET_CHARS = 240
FTS_SNIPPET_TOKENS = 24

_CURSOR_PREFIX = "history:"
_MAX_PROJECTIONS = 4
_MAX_SEARCH_ATTEMPTS = 3
_SEQ_MAX = 2**62
_MESSAGE_ID = re.compile(r"h[0-9a-f]{30}")
_TOKENIZERS = ("unicode61 remove_diacritics 2", "unicode61")
_EDGE_PUNCT = re.compile(r"^\W+|\W+$")


# --------------------------------------------------------------------------- helpers
def _iso(ts: float | None) -> str:
    if ts is None:
        return "unknown"
    return datetime.datetime.fromtimestamp(float(ts), tz=datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _redact_value(value: Any, found: set[str]) -> Any:
    """Redact secret-looking strings anywhere in a small JSON value (keys included)."""
    if isinstance(value, str):
        out, names = safety.redact_secrets(value)
        found.update(names)
        return out
    if isinstance(value, dict):
        return {_redact_value(str(k), found): _redact_value(item, found) for k, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(item, found) for item in value]
    return value


def _fingerprint_payload(event: IngestionEvent) -> dict[str, Any]:
    """What makes two deliveries of one (session_ref, event_id) "the same event".

    The producer label (``source``) and ``host_refs`` are delivery metadata and are
    deliberately excluded: a backfill importer and a live hook may both deliver it.
    """
    return {
        "sequence": event.sequence, "role": event.role, "text": event.text,
        "occurred_at": float(event.occurred_at), "scope": event.scope.as_dict(),
        "tool_name": event.tool_name, "attachments": list(event.attachments),
        "is_memory_injection": bool(event.is_memory_injection),
        "is_generated_summary": bool(event.is_generated_summary),
    }


def _fold(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def _contains_all(text: str | None, terms_json: str) -> int:
    if not text:
        return 0
    folded = _fold(text)
    return int(all(term in folded for term in json.loads(terms_json)))


@dataclass(frozen=True)
class CompiledQuery:
    """A user query compiled into safe FTS5 phrases plus folded substring terms.

    Every whitespace-separated term becomes a quoted FTS5 string, so user text is
    never interpreted as FTS5 syntax (AND/OR/NOT/NEAR/column filters/parentheses).
    The only operator honoured is a trailing ``*`` (prefix match). Terms without any
    letter or digit are dropped. ``content`` marks the terms that are not stopwords
    (all of them when every term is a stopword); a strong match needs every content
    term, a weak match some of them.
    """

    fts_terms: tuple[str, ...]
    plain_terms: tuple[str, ...]
    content: tuple[bool, ...] = ()

    @property
    def empty(self) -> bool:
        return not self.plain_terms

    @property
    def content_fts_terms(self) -> tuple[str, ...]:
        if len(self.content) != len(self.fts_terms) or not any(self.content):
            return self.fts_terms
        return tuple(t for t, keep in zip(self.fts_terms, self.content, strict=True) if keep)

    @property
    def content_plain_terms(self) -> tuple[str, ...]:
        if len(self.content) != len(self.plain_terms) or not any(self.content):
            return self.plain_terms
        return tuple(t for t, keep in zip(self.plain_terms, self.content, strict=True) if keep)


def compile_query(text: str) -> CompiledQuery:
    fts_terms: list[str] = []
    plain_terms: list[str] = []
    content: list[bool] = []
    for raw in text.split():
        term = unicodedata.normalize("NFKC", raw)
        prefix = term.endswith("*")
        core = term.rstrip("*")
        if not any(ch.isalnum() for ch in core):
            continue
        fts_terms.append('"' + core.replace('"', '""') + '"' + ("*" if prefix else ""))
        plain_terms.append(core.casefold())
        content.append(prefix or _EDGE_PUNCT.sub("", core.casefold()) not in STOPWORDS)
        if len(fts_terms) >= MAX_QUERY_TERMS:
            break
    return CompiledQuery(tuple(fts_terms), tuple(plain_terms), tuple(content))


def _snippet_around(text: str, terms: Iterable[str]) -> str:
    folded = text.casefold()
    pos = -1
    if len(folded) == len(text):  # positions only map 1:1 when folding kept the length
        for term in terms:
            idx = folded.find(term)
            if idx >= 0 and (pos < 0 or idx < pos):
                pos = idx
    start = max(0, pos - 60) if pos >= 0 else 0
    piece = text[start:start + SNIPPET_CHARS]
    return ("…" if start > 0 else "") + piece + ("…" if start + SNIPPET_CHARS < len(text) else "")


def _bounded_snippet(snippet: str) -> str:
    snippet = safety.neutralize_markup(snippet or "")
    if len(snippet) > SNIPPET_CHARS + 2:
        snippet = snippet[:SNIPPET_CHARS] + "…"
    return snippet


def _message_from_dict(raw: dict[str, Any], text: str) -> HistoryMessage:
    return HistoryMessage(
        message_id=raw["message_id"], event_id=raw["event_id"], session_ref=raw["session_ref"],
        sequence=int(raw["sequence"]), role=raw["role"], text=text,
        occurred_at=float(raw["occurred_at"]), ingested_at=float(raw["ingested_at"]),
        scope=Scope.from_dict(raw.get("scope")), redactions=tuple(raw.get("redactions") or ()),
        attachments=tuple(raw.get("attachments") or ()), tool_name=raw.get("tool_name"),
    )


@dataclass(frozen=True)
class _Session:
    token: str
    session_ref: str
    scope: Scope
    message_count: int
    first_at: float | None
    last_at: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_ref": self.session_ref, "handle": self.session_ref,
            "scope": self.scope.as_dict(), "message_count": self.message_count,
            "first_at": self.first_at, "last_at": self.last_at,
        }


@dataclass(frozen=True)
class _Filters:
    session_token: str | None = None
    since: float | None = None
    until: float | None = None
    roles: tuple[str, ...] = ()

    def sql(self, alias: str) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if self.session_token is not None:
            clauses.append(f"{alias}.session_token = ?")
            params.append(self.session_token)
        if self.since is not None:
            clauses.append(f"{alias}.occurred_at >= ?")
            params.append(self.since)
        if self.until is not None:
            clauses.append(f"{alias}.occurred_at <= ?")
            params.append(self.until)
        if self.roles:
            clauses.append(f"{alias}.role IN ({','.join('?' * len(self.roles))})")
            params.extend(self.roles)
        return (" AND ".join(clauses) if clauses else "1=1"), params


class _Projection:
    """In-memory FTS5 projection of the decrypted messages one grant set may read."""

    def __init__(self, generation: int, use_fts: bool) -> None:
        self.generation = generation
        self.lock = threading.Lock()
        self.closed = False
        self.hydrated = 0
        self.bytes = 0
        self.exhausted = False
        self.boundary: tuple[float, str] | None = None  # (occurred_at, id) of the oldest hydrated row
        self.sessions: dict[str, _Session] = {}
        self.conn = memory_connection()
        self.conn.row_factory = sqlite3.Row
        self.conn.create_function("lm_contains_all", 2, _contains_all, deterministic=True)
        self.conn.execute(
            "CREATE TABLE msgs(id INTEGER PRIMARY KEY, message_id TEXT NOT NULL UNIQUE,"
            " session_token TEXT NOT NULL, seq INTEGER NOT NULL, role TEXT NOT NULL,"
            " occurred_at REAL NOT NULL, text TEXT NOT NULL, body TEXT NOT NULL)"
        )
        self.conn.execute("CREATE INDEX msgs_time ON msgs(occurred_at)")
        self.fts = False
        if use_fts:
            for tokenizer in _TOKENIZERS:
                try:
                    self.conn.execute(
                        "CREATE VIRTUAL TABLE fts USING fts5(text, content='msgs', content_rowid='id',"
                        f" tokenize='{tokenizer}')"
                    )
                except sqlite3.Error:
                    continue
                self.fts = True
                break

    def add_many(self, messages: list[tuple[str, HistoryMessage]]) -> None:
        conn = self.conn
        conn.execute("BEGIN")
        try:
            for session_token, message in messages:
                body = message.to_dict()
                body.pop("text", None)
                encoded = json.dumps(body, ensure_ascii=False, sort_keys=True)
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO msgs(message_id, session_token, seq, role, occurred_at, text, body)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (message.message_id, session_token, message.sequence, message.role,
                     message.occurred_at, message.text, encoded),
                )
                if cursor.rowcount != 1:
                    continue
                if self.fts:
                    conn.execute("INSERT INTO fts(rowid, text) VALUES(?, ?)", (cursor.lastrowid, message.text))
                self.hydrated += 1
                self.bytes += len(message.text.encode()) + len(encoded)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.conn.close()
            except sqlite3.Error:
                pass


class _Restart(Exception):
    """The archive generation moved while a search was reading it."""


# --------------------------------------------------------------------------- service
class HistoryArchive:
    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx
        self.p = ctx.partition
        self.records = ctx.records
        self._lock = threading.RLock()
        self._projections: OrderedDict[str, _Projection] = OrderedDict()
        self._fts = fts5_available()

    # ------------------------------------------------------------------ tokens / ids
    def session_token(self, session_ref: str) -> str:
        """Same token the forgetting service uses for a SESSION target."""
        return self.p.token("session", session_ref)

    def _event_token(self, session_ref: str, event_id: str) -> str:
        return self.p.token("history-event", f"{session_ref}|{event_id}")

    def message_id_for(self, session_ref: str, event_id: str) -> str:
        """Deterministic message id ('|' cannot occur in either reference)."""
        return "h" + self.p.token("message", f"{session_ref}|{event_id}")[:30]

    def message_source_token(self, message_id: str) -> str:
        return self.records.source_token(f"{SourceKind.MESSAGE.value}:{message_id}")

    def _cursor_source(self, source: str) -> str:
        return _CURSOR_PREFIX + self.p.token("history-cursor", source)[:32]

    @staticmethod
    def _message_fields(session_token: str, seq: int, role: str, event_token: str,
                        occurred_at: float) -> dict[str, Any]:
        return {"session": session_token, "seq": int(seq), "role": role, "event": event_token,
                "at": float(occurred_at)}

    # ------------------------------------------------------------------ authorization
    def _auth_clause(self, grants: ScopeGrants, alias: str) -> tuple[str, list[Any]]:
        """Sessions whose every scope constraint is granted (mirrors RecordStore.authorized)."""
        pairs = self.records.allowed_pairs(grants)
        if pairs:
            return (
                "NOT EXISTS (SELECT 1 FROM history_session_scopes s WHERE"
                f" s.session_token={alias}.session_token AND (s.dim || ':' || s.value_token)"
                f" NOT IN ({','.join('?' * len(pairs))}))",
                list(pairs),
            )
        return (f"NOT EXISTS (SELECT 1 FROM history_session_scopes s WHERE s.session_token={alias}.session_token)",
                [])

    def _open_session(self, row: sqlite3.Row) -> _Session:
        raw = self.p.open_json(SESSIONS, row["session_token"], {"scope": row["scope_token"]},
                               row["dek_id"], row["nonce"], row["ciphertext"])
        if not isinstance(raw, dict) or not isinstance(raw.get("session_ref"), str):
            raise IntegrityError("a stored history session is malformed")
        scope = Scope.from_dict(raw.get("scope"))
        if (self.records.scope_token(scope) != row["scope_token"]
                or self.session_token(raw["session_ref"]) != row["session_token"]):
            raise IntegrityError("history session metadata does not match its authenticated payload")
        return _Session(row["session_token"], raw["session_ref"], scope, int(row["message_count"]),
                        row["first_at"], row["last_at"])

    def _authorized_session(self, conn: sqlite3.Connection, grants: ScopeGrants,
                            session_token: str) -> _Session | None:
        clause, params = self._auth_clause(grants, "hs")
        row = conn.execute(
            f"SELECT hs.* FROM history_sessions hs WHERE hs.session_token=? AND {clause}",
            [session_token, *params],
        ).fetchone()
        if row is None:
            return None
        session = self._open_session(row)
        if not grants.allows(session.scope):  # defense in depth: index must agree with payload
            raise IntegrityError("authorization index disagrees with history session scope")
        return session

    def _open_message(self, row: sqlite3.Row, session: _Session) -> HistoryMessage:
        if row["session_token"] != session.token:
            raise IntegrityError("history message does not belong to the expected session")
        if row["source_token"] != self.message_source_token(row["id"]):
            raise IntegrityError("history message source token is inconsistent")
        fields = self._message_fields(row["session_token"], row["seq"], row["role"], row["event_token"],
                                      row["occurred_at"])
        raw = self.p.open_json(MESSAGES, row["id"], fields, row["dek_id"], row["nonce"], row["ciphertext"])
        if not isinstance(raw, dict) or raw.get("session_ref") != session.session_ref:
            raise IntegrityError("a stored history message is malformed")
        return HistoryMessage(
            message_id=row["id"], event_id=str(raw.get("event_id") or ""), session_ref=session.session_ref,
            sequence=int(row["seq"]), role=row["role"], text=str(raw.get("text") or ""),
            occurred_at=float(row["occurred_at"]), ingested_at=float(row["ingested_at"]),
            scope=session.scope, redactions=tuple(raw.get("redactions") or ()),
            attachments=tuple(raw.get("attachments") or ()), tool_name=raw.get("tool_name"),
        )

    # ------------------------------------------------------------------ ingest
    @staticmethod
    def _coerce_event(event: Any) -> IngestionEvent:
        if isinstance(event, dict):
            event = IngestionEvent.from_dict(event)
        if not isinstance(event, IngestionEvent):
            raise ValidationError("event must be an IngestionEvent")
        if not isinstance(event.scope, Scope):
            event = dataclasses.replace(event, scope=Scope.from_dict(event.scope))
        if not isinstance(event.occurred_at, float):
            event = dataclasses.replace(event, occurred_at=float(event.occurred_at))
        if event.tool_name is not None:
            if not isinstance(event.tool_name, str):
                raise ValidationError("tool_name must be text")
            name = v.check_label(event.tool_name, "tool_name", max_chars=256)
            if name != event.tool_name:
                event = dataclasses.replace(event, tool_name=name)
        return event

    def ingest(self, access: AccessContext, event: IngestionEvent) -> IngestReceipt:
        return self.ingest_batch(access, [event])[0]

    def ingest_batch(self, access: AccessContext, events: Iterable[IngestionEvent]) -> list[IngestReceipt]:
        """Archive events atomically (all or nothing) and return one receipt per event."""
        policy.require(access, Operation.INGEST)
        if isinstance(events, (str, bytes, dict)):
            raise ValidationError("events must be a list")
        items = [self._coerce_event(item) for item in events]
        if len(items) > MAX_BATCH_EVENTS:
            raise ValidationError(f"at most {MAX_BATCH_EVENTS} events per batch")
        for item in items:
            policy.require_scope(access, item.scope)
        if not items:
            return []
        receipts: list[IngestReceipt] = []
        with self.ctx.metrics.timer("history.ingest"), self.p.db.write() as conn:
            now = self.ctx.clock()
            for item in items:
                receipts.append(self._ingest_one(conn, item, now))
        for receipt in receipts:
            outcome = ("duplicate" if receipt.duplicate else "skipped" if receipt.skipped_reason
                       else "stored")
            self.ctx.metrics.incr(f"history.ingest.{outcome}")
        return receipts

    def _ingest_one(self, conn: sqlite3.Connection, event: IngestionEvent, now: float) -> IngestReceipt:
        s_token = self.session_token(event.session_ref)
        e_token = self._event_token(event.session_ref, event.event_id)
        message_id = self.message_id_for(event.session_ref, event.event_id)
        scope_token = self.records.scope_token(event.scope)
        fingerprint = self.p.token("history-fingerprint", content_hash(_fingerprint_payload(event)))
        occurred_at = float(event.occurred_at)

        # 1. A session is bound to the scope of its first event. Checked before any
        #    duplicate/suppression answer so other scopes cannot probe its contents.
        session_row = conn.execute(
            "SELECT scope_token FROM history_sessions WHERE session_token=?", (s_token,)).fetchone()
        if session_row is not None and session_row["scope_token"] != scope_token:
            raise AccessDenied("this session_ref is archived under a different scope")

        # 2. Forgotten sessions / messages are not re-archived from a host replay.
        if self._suppressed(conn, "session", s_token) or self._suppressed(conn, "event", e_token):
            if session_row is not None:
                self._advance_cursor(conn, event.source, s_token, now)
            receipt = self.p.make_receipt(conn, "ingest", "noop",
                                          details={"skipped_reason": SKIP_FORGOTTEN, "sequence": event.sequence})
            self.p.event(conn, "ingest", "skipped", SKIP_FORGOTTEN)
            return IngestReceipt(receipt=receipt, message_id=None, duplicate=False, skipped_reason=SKIP_FORGOTTEN)

        # 3. Idempotency by (session_ref, event_id).
        existing = conn.execute(
            "SELECT id, content_token FROM history_messages WHERE event_token=?", (e_token,)).fetchone()
        skipped = None if existing is not None else conn.execute(
            "SELECT reason, fingerprint_token FROM history_skipped WHERE event_token=?", (e_token,)).fetchone()
        if existing is not None or skipped is not None:
            stored_fp = existing["content_token"] if existing is not None else skipped["fingerprint_token"]
            if stored_fp != fingerprint:
                raise IdempotencyConflict("this event_id was already ingested with different content")
            self._advance_cursor(conn, event.source, s_token, now)
            receipt = self.p.make_receipt(
                conn, "ingest", "noop", persist=False,
                details={"duplicate": True, "sequence": event.sequence,
                         "message_id": existing["id"] if existing is not None else None},
            )
            receipt = dataclasses.replace(receipt, idempotent_replay=True)
            if existing is not None:
                return IngestReceipt(receipt=receipt, message_id=existing["id"], duplicate=True,
                                     redactions=self._redact_event(event)[1])
            return IngestReceipt(receipt=receipt, message_id=None, duplicate=True,
                                 skipped_reason=skipped["reason"])

        # 4. A sequence number belongs to exactly one event.
        if self._seq_taken(conn, s_token, event.sequence):
            raise IdempotencyConflict("this sequence number is already used by a different event in the session")

        if session_row is None:
            self._create_session(conn, s_token, event, scope_token, now)
        self._note_arrival(conn, s_token, event.sequence, now)

        # 5. Injected memory blocks and generated summaries are never evidence.
        if event.is_memory_injection or event.is_generated_summary:
            reason = SKIP_MEMORY_INJECTION if event.is_memory_injection else SKIP_GENERATED_SUMMARY
            conn.execute(
                "INSERT INTO history_skipped(event_token, session_token, seq, reason, fingerprint_token, created_at)"
                " VALUES(?,?,?,?,?,?)", (e_token, s_token, event.sequence, reason, fingerprint, now),
            )
            self._advance_cursor(conn, event.source, s_token, now)
            receipt = self.p.make_receipt(conn, "ingest", "noop",
                                          details={"skipped_reason": reason, "sequence": event.sequence})
            self.p.event(conn, "ingest", "skipped", reason)
            return IngestReceipt(receipt=receipt, message_id=None, duplicate=False, skipped_reason=reason)

        # 6. Archive (secrets redacted first; everything sensitive sealed).
        payload, redactions = self._redact_event(event)
        fields = self._message_fields(s_token, event.sequence, event.role, e_token, occurred_at)
        dek, nonce, ct = self.p.seal_json(MESSAGES, message_id, fields, payload)
        conn.execute(
            "INSERT INTO history_messages(id, session_token, event_token, source_token, seq, role, occurred_at,"
            " ingested_at, content_token, redacted, dek_id, nonce, ciphertext) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (message_id, s_token, e_token, self.message_source_token(message_id), event.sequence, event.role,
             occurred_at, now, fingerprint, int(bool(redactions)), dek, nonce, ct),
        )
        conn.execute(
            "UPDATE history_sessions SET message_count=message_count+1,"
            " first_at=CASE WHEN first_at IS NULL OR ?<first_at THEN ? ELSE first_at END,"
            " last_at=CASE WHEN last_at IS NULL OR ?>last_at THEN ? ELSE last_at END"
            " WHERE session_token=?", (occurred_at, occurred_at, occurred_at, occurred_at, s_token),
        )
        self._advance_cursor(conn, event.source, s_token, now)
        self.p.bump(conn)
        flags = ["instruction_like"] if safety.scan(payload["text"]).injection else []
        receipt = self.p.make_receipt(
            conn, "ingest", "ok",
            details={"message_id": message_id, "sequence": event.sequence,
                     "redactions": list(redactions), "flags": flags},
        )
        self.p.event(conn, "ingest", "ok", "redacted" if redactions else "")
        return IngestReceipt(receipt=receipt, message_id=message_id, duplicate=False, redactions=redactions)

    @staticmethod
    def _redact_event(event: IngestionEvent) -> tuple[dict[str, Any], tuple[str, ...]]:
        found: set[str] = set()
        text, names = safety.redact_secrets(event.text)
        found.update(names)
        tool_name = _redact_value(event.tool_name, found) if event.tool_name is not None else None
        # Attachments keep their refs and access-constraint dicts; contents are never fetched.
        attachments = [_redact_value(item, found) for item in event.attachments]
        host_refs = _redact_value(event.host_refs, found)
        redactions = tuple(sorted(found))
        return ({"event_id": event.event_id, "session_ref": event.session_ref, "text": text,
                 "tool_name": tool_name, "attachments": attachments, "host_refs": host_refs,
                 "redactions": list(redactions), "source": event.source}, redactions)

    def _create_session(self, conn: sqlite3.Connection, s_token: str, event: IngestionEvent,
                        scope_token: str, now: float) -> None:
        payload = {"session_ref": event.session_ref, "scope": event.scope.as_dict(), "created_at": now}
        dek, nonce, ct = self.p.seal_json(SESSIONS, s_token, {"scope": scope_token}, payload)
        conn.execute(
            "INSERT INTO history_sessions(session_token, scope_token, first_at, last_at, message_count,"
            " dek_id, nonce, ciphertext) VALUES(?,?,NULL,NULL,0,?,?,?)", (s_token, scope_token, dek, nonce, ct),
        )
        conn.executemany(
            "INSERT INTO history_session_scopes(session_token, dim, value_token) VALUES(?,?,?)",
            [(s_token, dim, self.records.scope_value_token(dim, value)) for dim, value in event.scope.constraints],
        )

    def _suppressed(self, conn: sqlite3.Connection, kind: str, token: str) -> bool:
        return conn.execute("SELECT 1 FROM history_suppressed WHERE kind=? AND token=?",
                            (kind, token)).fetchone() is not None

    def _seq_taken(self, conn: sqlite3.Connection, s_token: str, seq: int) -> bool:
        return conn.execute(
            "SELECT 1 FROM history_messages WHERE session_token=? AND seq=?"
            " UNION ALL SELECT 1 FROM history_skipped WHERE session_token=? AND seq=?"
            " UNION ALL SELECT 1 FROM history_gaps WHERE session_token=? AND reason=? AND from_seq<=? AND to_seq>=?"
            " LIMIT 1", (s_token, seq, s_token, seq, s_token, GAP_FORGOTTEN, seq, seq),
        ).fetchone() is not None

    def _highest_seq(self, conn: sqlite3.Connection, s_token: str) -> int:
        row = conn.execute(
            "SELECT MAX(v) FROM (SELECT MAX(seq) AS v FROM history_messages WHERE session_token=?"
            " UNION ALL SELECT MAX(seq) FROM history_skipped WHERE session_token=?"
            " UNION ALL SELECT MAX(to_seq) FROM history_gaps WHERE session_token=?)",
            (s_token, s_token, s_token),
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else -1

    def _note_arrival(self, conn: sqlite3.Connection, s_token: str, seq: int, now: float) -> None:
        """Maintain not_received gaps (call before the arriving row is inserted)."""
        row = conn.execute(
            "SELECT from_seq, to_seq FROM history_gaps WHERE session_token=? AND reason=?"
            " AND from_seq<=? AND to_seq>=?", (s_token, GAP_NOT_RECEIVED, seq, seq),
        ).fetchone()
        if row is not None:
            lo, hi = int(row[0]), int(row[1])
            conn.execute("DELETE FROM history_gaps WHERE session_token=? AND from_seq=?", (s_token, lo))
            if lo <= seq - 1:
                self._insert_gap(conn, s_token, lo, seq - 1, GAP_NOT_RECEIVED, now)
            if seq + 1 <= hi:
                self._insert_gap(conn, s_token, seq + 1, hi, GAP_NOT_RECEIVED, now)
            return
        highest = self._highest_seq(conn, s_token)
        if seq > highest + 1:
            self._insert_gap(conn, s_token, highest + 1, seq - 1, GAP_NOT_RECEIVED, now)

    @staticmethod
    def _insert_gap(conn: sqlite3.Connection, s_token: str, lo: int, hi: int, reason: str, now: float) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO history_gaps(session_token, from_seq, to_seq, reason, created_at)"
            " VALUES(?,?,?,?,?)", (s_token, lo, hi, reason, now),
        )

    def _contiguous(self, conn: sqlite3.Connection, s_token: str) -> int:
        row = conn.execute(
            "SELECT MIN(from_seq) FROM history_gaps WHERE session_token=? AND reason=?",
            (s_token, GAP_NOT_RECEIVED),
        ).fetchone()
        if row and row[0] is not None:
            return int(row[0]) - 1
        return self._highest_seq(conn, s_token)

    def _advance_cursor(self, conn: sqlite3.Connection, source: str, s_token: str, now: float) -> None:
        position = self._contiguous(conn, s_token)
        if position < 0:
            return
        conn.execute(
            "INSERT INTO cursors(source, stream_token, position, updated_at) VALUES(?,?,?,?)"
            " ON CONFLICT(source, stream_token) DO UPDATE SET"
            " position=MAX(cursors.position, excluded.position), updated_at=excluded.updated_at",
            (self._cursor_source(source), s_token, position, now),
        )

    def cursor(self, access: AccessContext, source: str, session_ref: str) -> int | None:
        """Highest contiguous sequence accounted for in ``session_ref`` as seen by producer ``source``.

        ``None`` when nothing contiguous from 0 exists yet, when the producer never
        delivered into this session, or when the session is not visible to the caller.
        """
        if Operation.INGEST not in access.operations and Operation.READ not in access.operations:
            raise AccessDenied("operation ingest is not permitted for this caller")
        v.check_label(source, "source")
        v.check_ref(session_ref, "session_ref")
        token = self.session_token(session_ref)
        with self.p.db.read() as conn:
            if self._authorized_session(conn, access.grants, token) is None:
                return None
            row = conn.execute("SELECT position FROM cursors WHERE source=? AND stream_token=?",
                               (self._cursor_source(source), token)).fetchone()
        return int(row[0]) if row else None

    # ------------------------------------------------------------------ search
    def search(self, access: AccessContext, query: str, *, session_ref: str | None = None, limit: int = 10,
               since: float | None = None, until: float | None = None, roles: Iterable[str] | None = None,
               deadline_ms: int | None = None, cancel: Any = None,
               exclude_corrected: bool = False) -> HistorySearchResult:
        """Lexical search over authorized sessions (FTS5 bm25; substring fallback).

        Scores are ranking values (``score_kind`` says which), never probabilities.
        Hits carry ``flags`` (``weak_match``, ``superseded_by_correction``; see the module
        docstring); ``exclude_corrected=True`` leaves superseded messages out of the hits.
        """
        policy.require(access, Operation.READ)
        if not isinstance(exclude_corrected, bool):
            raise ValidationError("exclude_corrected must be a boolean")
        text = v.check_text(query if query is not None else "", "query", max_chars=v.MAX_QUERY_CHARS,
                            allow_empty=True)
        v.check_int(limit, "limit", lo=1, hi=MAX_SEARCH_LIMIT)
        since = v.check_timestamp(since, "since")
        until = v.check_timestamp(until, "until")
        if since is not None and until is not None and until < since:
            raise ValidationError("until must not be before since")
        if deadline_ms is not None:
            v.check_int(deadline_ms, "deadline_ms", lo=1, hi=600_000)
        role_filter = self._check_roles(roles)
        s_token = self.session_token(v.check_ref(session_ref, "session_ref")) if session_ref is not None else None
        filters = _Filters(s_token, since, until, role_filter)
        compiled = compile_query(text)
        deadline = Deadline(deadline_ms)
        if self._is_cancelled(cancel):
            return self._cancelled_result(0)
        with self.ctx.metrics.timer("history.search"):
            for _attempt in range(_MAX_SEARCH_ATTEMPTS):
                try:
                    return self._search_once(access.grants, compiled, filters, limit, deadline, cancel,
                                             raw_query_empty=not text, exclude_corrected=exclude_corrected)
                except _Restart:
                    continue
        self.ctx.metrics.incr("history.search.unavailable")
        return HistorySearchResult(
            hits=(), status=ResultStatus.UNAVAILABLE,
            coverage=Coverage(total=None, searched=0, index_ready=False,
                              partial_reasons=("the archive changed repeatedly during search; retry",)),
        )

    @staticmethod
    def _check_roles(roles: Iterable[str] | None) -> tuple[str, ...]:
        if roles is None:
            return ()
        if isinstance(roles, str):
            roles = (roles,)
        values = tuple(sorted({str(r) for r in roles}))
        if any(r not in ROLES for r in values):
            raise ValidationError("roles must be among user, assistant, tool")
        return values

    @staticmethod
    def _is_cancelled(cancel: Any) -> bool:
        return bool(cancel is not None and getattr(cancel, "cancelled", False))

    @staticmethod
    def _cancelled_result(searched: int) -> HistorySearchResult:
        return HistorySearchResult(
            hits=(), status=ResultStatus.CANCELLED,
            coverage=Coverage(total=None, searched=searched, index_ready=False, partial_reasons=("cancelled",)),
        )

    def _current_projection(self, grants: ScopeGrants) -> _Projection:
        with self.p.db.read() as conn:
            generation = self.p.generation(conn)
        key = grants.fingerprint()
        with self._lock:
            proj = self._projections.get(key)
            if proj is not None and proj.generation == generation and not proj.closed:
                self._projections.move_to_end(key)
                return proj
            if proj is not None:
                del self._projections[key]
                with proj.lock:
                    proj.close()
            proj = _Projection(generation, self._fts)
            self._projections[key] = proj
            while len(self._projections) > _MAX_PROJECTIONS:
                _, old = self._projections.popitem(last=False)
                with old.lock:
                    old.close()
            return proj

    def _search_once(self, grants: ScopeGrants, compiled: CompiledQuery, filters: _Filters, limit: int,
                     deadline: Any, cancel: Any, raw_query_empty: bool,
                     exclude_corrected: bool = False) -> HistorySearchResult:
        proj = self._current_projection(grants)
        with proj.lock:
            if proj.closed:
                raise _Restart
            reasons = self._hydrate(proj, grants, deadline, cancel)
            if reasons is None:
                return self._cancelled_result(proj.hydrated)
            with self.p.db.read() as conn:
                if self.p.generation(conn) != proj.generation:
                    raise _Restart
                corrected = self.corrected_message_ids(conn, grants)
            rows = self._query_projection(proj, compiled, filters, limit, raw_query_empty,
                                          exclude=corrected if exclude_corrected else frozenset())
            fsql, fparams = filters.sql("m")
            searched = int(proj.conn.execute(f"SELECT COUNT(*) FROM msgs m WHERE {fsql}", fparams).fetchone()[0])
            with self.p.db.read() as conn:
                if self.p.generation(conn) != proj.generation:
                    raise _Restart  # never answer from a projection a deletion has overtaken
                total, uncovered, oldest, newest = self._uncovered(conn, grants, filters, proj)
        hits = []
        for rank, (row, score, snippet, score_kind) in enumerate(rows, start=1):
            message = _message_from_dict(json.loads(row["body"]), row["text"])
            flags = []
            if score_kind == SCORE_WEAK:
                flags.append(FLAG_WEAK)
            if message.message_id in corrected:
                flags.append(FLAG_SUPERSEDED)
            hits.append(HistoryHit(message=message, rank=rank, score=float(score), score_kind=score_kind,
                                   snippet=_bounded_snippet(snippet), handle=message.message_id,
                                   flags=tuple(flags)))
        missing: tuple[str, ...] = ()
        if uncovered:
            missing = (f"messages at or before {_iso(newest)} not yet indexed"
                       f" ({uncovered} authorized messages, oldest {_iso(oldest)})",)
        partial = tuple(reasons) if uncovered else ()
        coverage = Coverage(total=total, searched=searched, index_ready=not uncovered,
                            missing=missing, partial_reasons=partial)
        if not coverage.complete:
            status = ResultStatus.PARTIAL
        elif raw_query_empty or any(FLAG_WEAK not in hit.flags for hit in hits):
            status = ResultStatus.COMPLETE  # an empty query is a recency listing, not a search
        else:
            status = ResultStatus.INSUFFICIENT_EVIDENCE  # no hit, or only weak hits (still returned)
        if exclude_corrected and corrected:
            self.ctx.metrics.incr("history.search.exclude_corrected")
        return HistorySearchResult(hits=tuple(hits), status=status, coverage=coverage)

    def corrected_message_ids(self, conn: sqlite3.Connection, grants: ScopeGrants) -> frozenset[str]:
        """Archived message ids superseded by a content correction of a memory ``grants`` may see.

        A MESSAGE source flags that message; a SESSION source flags every message of the
        session at or before the correction time. Corrections of memories outside the
        caller's grants are not revealed (they flag nothing for this caller).
        """
        rows = conn.execute(
            "SELECT m.id, c.record_id FROM history_corrections c"
            " JOIN history_messages m ON m.source_token = c.source_token"
            " UNION SELECT m.id, c.record_id FROM history_corrections c"
            " JOIN history_messages m ON m.session_token = c.session_token AND m.occurred_at <= c.corrected_at"
            " WHERE c.session_token IS NOT NULL").fetchall()
        if not rows:
            return frozenset()
        visible = self.records.visible_ids(conn, grants, {str(r[1]) for r in rows})
        return frozenset(str(r[0]) for r in rows if str(r[1]) in visible)

    def _hydrate(self, proj: _Projection, grants: ScopeGrants, deadline: Any, cancel: Any) -> list[str] | None:
        """Hydrate batches newest-first; returns partial reasons, or None when cancelled."""
        config = self.ctx.config
        cap = max(0, int(config.max_history_messages_hydrated))
        byte_cap = max(0, int(config.max_projection_bytes))
        reasons: list[str] = []
        progressed = False
        while not proj.exhausted:
            if self._is_cancelled(cancel):
                return None
            if proj.hydrated >= cap:
                reasons.append(f"hydration cap reached (max_history_messages_hydrated={cap})")
                break
            if proj.bytes >= byte_cap:
                reasons.append(f"projection memory cap reached (max_projection_bytes={byte_cap})")
                break
            if progressed and deadline.expired:
                reasons.append("deadline reached before the archive was fully indexed; a later search resumes")
                break
            self._hydrate_batch(proj, grants, min(max(1, int(config.history_hydration_batch)),
                                                  cap - proj.hydrated))
            progressed = True
        return reasons

    def _hydrate_batch(self, proj: _Projection, grants: ScopeGrants, batch: int) -> None:
        clause, params = self._auth_clause(grants, "hs")
        sql = (
            "SELECT m.* FROM history_messages m JOIN history_sessions hs ON hs.session_token=m.session_token"
            f" WHERE {clause}"
        )
        if proj.boundary is not None:
            sql += " AND (m.occurred_at < ? OR (m.occurred_at = ? AND m.id < ?))"
            params += [proj.boundary[0], proj.boundary[0], proj.boundary[1]]
        sql += " ORDER BY m.occurred_at DESC, m.id DESC LIMIT ?"
        params.append(batch)
        loaded: list[tuple[str, HistoryMessage]] = []
        with self.p.db.read() as conn:
            if self.p.generation(conn) != proj.generation:
                raise _Restart
            rows = conn.execute(sql, params).fetchall()
            for row in rows:
                session = proj.sessions.get(row["session_token"])
                if session is None:
                    session = self._authorized_session(conn, grants, row["session_token"])
                    if session is None:  # the join said authorized; the payload must agree
                        raise IntegrityError("history session authorization changed mid-read")
                    proj.sessions[session.token] = session
                loaded.append((row["session_token"], self._open_message(row, session)))
        proj.add_many(loaded)
        if rows:
            proj.boundary = (float(rows[-1]["occurred_at"]), rows[-1]["id"])
        if len(rows) < batch:
            proj.exhausted = True

    def _query_projection(self, proj: _Projection, compiled: CompiledQuery, filters: _Filters,
                          limit: int, raw_query_empty: bool, exclude: frozenset[str] = frozenset()
                          ) -> list[tuple[sqlite3.Row, float, str, str]]:
        """(row, score, snippet, score_kind) best-first.

        Strong hits (every content term) first, then weak any-term hits to fill ``limit``;
        message ids in ``exclude`` never appear (each stage over-fetches by their number).
        """
        fsql, fparams = filters.sql("m")
        conn = proj.conn
        if compiled.empty and not raw_query_empty:
            return []  # e.g. only punctuation: nothing can match
        spare = len(exclude)
        out: list[tuple[sqlite3.Row, float, str, str]] = []
        seen: set[str] = set()

        def take(rows: Iterable[sqlite3.Row], score: Callable[[sqlite3.Row], float],
                 snippet: Callable[[sqlite3.Row], str], kind: str) -> None:
            for row in rows:
                if len(out) >= limit:
                    return
                message_id = row["message_id"]
                if message_id in seen or message_id in exclude:
                    continue
                seen.add(message_id)
                out.append((row, score(row), snippet(row), kind))

        if compiled.empty:
            rows = conn.execute(
                f"SELECT m.* FROM msgs m WHERE {fsql} ORDER BY m.occurred_at DESC, m.seq DESC, m.message_id"
                " LIMIT ?", [*fparams, limit + spare]).fetchall()
            take(rows, lambda _r: 0.0, lambda r: _snippet_around(r["text"], ()), SCORE_RECENCY)
            return out
        if proj.fts:
            content = compiled.content_fts_terms
            expressions = [(" AND ".join(content), SCORE_STRONG)]
            if len(content) > 1:
                expressions.append((" OR ".join(content), SCORE_WEAK))
            for expression, kind in expressions:
                if len(out) >= limit:
                    break
                try:
                    rows = conn.execute(
                        "SELECT m.*, -bm25(fts) AS score,"
                        f" snippet(fts, 0, '', '', '…', {FTS_SNIPPET_TOKENS}) AS snip"
                        f" FROM fts JOIN msgs m ON m.id = fts.rowid WHERE fts MATCH ? AND {fsql}"
                        " ORDER BY bm25(fts), m.occurred_at DESC, m.message_id LIMIT ?",
                        [expression, *fparams, limit + spare + len(out)],
                    ).fetchall()
                except sqlite3.Error:
                    rows = []
                take(rows, lambda r: float(r["score"]), lambda r: r["snip"], kind)
            if out:
                return out
        # Substring fallback (e.g. CJK runs, partial identifiers): every content term must
        # occur (heuristic), ranked by recency.
        terms = compiled.content_plain_terms
        rows = conn.execute(
            f"SELECT m.* FROM msgs m WHERE lm_contains_all(m.text, ?) AND {fsql}"
            " ORDER BY m.occurred_at DESC, m.seq DESC, m.message_id LIMIT ?",
            [json.dumps(list(terms)), *fparams, limit + spare],
        ).fetchall()
        take(rows, lambda _r: 0.0, lambda r: _snippet_around(r["text"], terms), SCORE_SUBSTRING)
        return out

    def _uncovered(self, conn: sqlite3.Connection, grants: ScopeGrants, filters: _Filters,
                   proj: _Projection | None) -> tuple[int, int, float | None, float | None]:
        """(authorized total, not-yet-hydrated count, oldest, newest) for the filters."""
        clause, params = self._auth_clause(grants, "hs")
        fsql, fparams = filters.sql("m")
        base = (" FROM history_messages m JOIN history_sessions hs ON hs.session_token=m.session_token"
                f" WHERE {clause} AND {fsql}")
        total = int(conn.execute("SELECT COUNT(*)" + base, params + fparams).fetchone()[0])
        if proj is not None and proj.exhausted:
            return total, 0, None, None
        sql = "SELECT COUNT(*), MIN(m.occurred_at), MAX(m.occurred_at)" + base
        extra: list[Any] = []
        if proj is not None and proj.boundary is not None:
            sql += " AND (m.occurred_at < ? OR (m.occurred_at = ? AND m.id < ?))"
            extra = [proj.boundary[0], proj.boundary[0], proj.boundary[1]]
        count, oldest, newest = conn.execute(sql, params + fparams + extra).fetchone()
        return total, int(count or 0), oldest, newest

    # ------------------------------------------------------------------ scroll / browse
    def scroll(self, access: AccessContext, handle: str, *, before: int = 5, after: int = 5) -> dict[str, Any]:
        """Bounded window around a hit, in exact retained order with exact retained text."""
        policy.require(access, Operation.READ)
        v.check_int(before, "before", lo=0, hi=MAX_SCROLL)
        v.check_int(after, "after", lo=0, hi=MAX_SCROLL)
        if not isinstance(handle, str) or not _MESSAGE_ID.fullmatch(handle):
            raise NotFound("history message not found")
        with self.p.db.read() as conn:
            anchor = conn.execute("SELECT * FROM history_messages WHERE id=?", (handle,)).fetchone()
            session = (self._authorized_session(conn, access.grants, anchor["session_token"])
                       if anchor is not None else None)
            if anchor is None or session is None:
                raise NotFound("history message not found")
            seq = int(anchor["seq"])
            earlier = conn.execute(
                "SELECT * FROM history_messages WHERE session_token=? AND seq<? ORDER BY seq DESC LIMIT ?",
                (session.token, seq, before + 1)).fetchall()
            later = conn.execute(
                "SELECT * FROM history_messages WHERE session_token=? AND seq>? ORDER BY seq ASC LIMIT ?",
                (session.token, seq, after + 1)).fetchall()
            has_more_before = len(earlier) > before
            has_more_after = len(later) > after
            window = list(reversed(earlier[:before])) + [anchor] + list(later[:after])
            messages = [self._open_message(row, session) for row in window]
            lo = int(earlier[before]["seq"]) + 1 if has_more_before else 0
            hi = int(later[after]["seq"]) - 1 if has_more_after else None
            gaps = self._gaps_in(conn, session.token, lo, hi, messages)
        return {"anchor": handle, "session_ref": session.session_ref, "messages": messages,
                "has_more_before": has_more_before, "has_more_after": has_more_after, "gaps": gaps}

    def browse(self, access: AccessContext, session_ref: str, *, from_seq: int = 0, limit: int = 50
               ) -> dict[str, Any]:
        policy.require(access, Operation.READ)
        v.check_ref(session_ref, "session_ref")
        v.check_int(from_seq, "from_seq", lo=0)
        v.check_int(limit, "limit", lo=1, hi=MAX_BROWSE)
        with self.p.db.read() as conn:
            session = self._authorized_session(conn, access.grants, self.session_token(session_ref))
            if session is None:
                raise NotFound("history session not found")
            rows = conn.execute(
                "SELECT * FROM history_messages WHERE session_token=? AND seq>=? ORDER BY seq LIMIT ?",
                (session.token, from_seq, limit + 1)).fetchall()
            has_more = len(rows) > limit
            messages = [self._open_message(row, session) for row in rows[:limit]]
            next_seq = int(rows[limit]["seq"]) if has_more else None
            gaps = self._gaps_in(conn, session.token, from_seq, next_seq - 1 if next_seq is not None else None,
                                 messages)
        return {"session": session.to_dict(), "messages": messages, "has_more": has_more,
                "next_seq": next_seq, "gaps": gaps}

    def _gaps_in(self, conn: sqlite3.Connection, s_token: str, lo: int, hi: int | None,
                 messages: list[HistoryMessage]) -> list[dict[str, Any]]:
        upper = _SEQ_MAX if hi is None else hi
        out: list[dict[str, Any]] = []
        if upper >= lo:
            for row in conn.execute(
                "SELECT from_seq, to_seq, reason FROM history_gaps WHERE session_token=? AND to_seq>=?"
                " AND from_seq<=? ORDER BY from_seq", (s_token, lo, upper),
            ):
                out.append({"from_seq": int(row[0]), "to_seq": int(row[1]), "reason": row[2]})
            for row in conn.execute(
                "SELECT seq, reason FROM history_skipped WHERE session_token=? AND seq BETWEEN ? AND ?"
                " ORDER BY seq", (s_token, lo, upper),
            ):
                out.append({"from_seq": int(row[0]), "to_seq": int(row[0]), "reason": f"skipped_{row[1]}"})
        for message in messages:
            if message.redactions:
                out.append({"from_seq": message.sequence, "to_seq": message.sequence, "reason": "redacted",
                            "message_id": message.message_id, "categories": list(message.redactions)})
        out.sort(key=lambda item: (item["from_seq"], item["reason"]))
        return out

    def sessions(self, access: AccessContext, *, limit: int = 50) -> list[dict[str, Any]]:
        """Authorized sessions, most recent first."""
        policy.require(access, Operation.READ)
        v.check_int(limit, "limit", lo=1, hi=1_000)
        clause, params = self._auth_clause(access.grants, "hs")
        out = []
        with self.p.db.read() as conn:
            rows = conn.execute(
                f"SELECT hs.* FROM history_sessions hs WHERE {clause}"
                " ORDER BY COALESCE(hs.last_at, 0) DESC, hs.session_token LIMIT ?", [*params, limit],
            ).fetchall()
            for row in rows:
                session = self._open_session(row)
                if not access.grants.allows(session.scope):
                    raise IntegrityError("authorization index disagrees with history session scope")
                item = session.to_dict()
                item["skipped_events"] = int(conn.execute(
                    "SELECT COUNT(*) FROM history_skipped WHERE session_token=?", (session.token,)).fetchone()[0])
                item["gaps"] = int(conn.execute(
                    "SELECT COUNT(*) FROM history_gaps WHERE session_token=?", (session.token,)).fetchone()[0])
                out.append(item)
        return out

    def coverage_status(self, access: AccessContext) -> dict[str, Any]:
        """Authorized-only archive counts and search-projection coverage (does not hydrate)."""
        policy.require(access, Operation.READ)
        grants = access.grants
        clause, params = self._auth_clause(grants, "hs")
        with self.p.db.read() as conn:
            generation = self.p.generation(conn)
            sessions = int(conn.execute(f"SELECT COUNT(*) FROM history_sessions hs WHERE {clause}",
                                        params).fetchone()[0])
            with self._lock:
                proj = self._projections.get(grants.fingerprint())
            current = proj is not None and not proj.closed and proj.generation == generation
            if current:
                with proj.lock:
                    total, uncovered, oldest, newest = self._uncovered(conn, grants, _Filters(), proj)
                    hydrated = proj.hydrated if not proj.closed else 0
            else:
                total, uncovered, oldest, newest = self._uncovered(conn, grants, _Filters(), None)
                hydrated = 0
        missing: list[str] = []
        if uncovered:
            what = "not yet indexed" if current else "not indexed (the search projection is built on demand)"
            missing.append(f"messages at or before {_iso(newest)} {what}"
                           f" ({uncovered} authorized messages, oldest {_iso(oldest)})")
        return {
            "kind": "history_archive",
            "messages": total, "sessions": sessions, "hydrated": hydrated,
            "index_ready": not uncovered, "status": "partial" if uncovered else "complete",
            "missing": missing, "generation": generation, "fts5_available": self._fts,
            "max_history_messages_hydrated": self.ctx.config.max_history_messages_hydrated,
            "counts_kind": "measured",
        }

    # ------------------------------------------------------------------ hooks (core / forgetting)
    def verify_source(self, conn: sqlite3.Connection, access: AccessContext, source: SourceRef) -> bool | None:
        """MESSAGE: the archived message exists in an authorized session. SESSION: the
        session exists and is authorized. Anything else: None (not this service's kind)."""
        if source.kind == SourceKind.MESSAGE:
            if not _MESSAGE_ID.fullmatch(source.ref):
                return False
            row = conn.execute("SELECT session_token FROM history_messages WHERE id=?", (source.ref,)).fetchone()
            if row is None:
                return False
            return self._authorized_session(conn, access.grants, row[0]) is not None
        if source.kind == SourceKind.SESSION:
            return self._authorized_session(conn, access.grants, self.session_token(source.ref)) is not None
        return None

    def session_visible(self, conn: sqlite3.Connection, access: AccessContext, session_ref: str) -> bool | None:
        token = self.session_token(session_ref)
        if conn.execute("SELECT 1 FROM history_sessions WHERE session_token=?", (token,)).fetchone() is None:
            return None
        return self._authorized_session(conn, access.grants, token) is not None

    def message_source_visible(self, conn: sqlite3.Connection, access: AccessContext,
                               source_token: str) -> bool | None:
        tokens = [r[0] for r in conn.execute(
            "SELECT DISTINCT session_token FROM history_messages WHERE source_token=?", (source_token,))]
        if not tokens:
            return None
        return all(self._authorized_session(conn, access.grants, t) is not None for t in tokens)

    def source_tokens_for_session(self, conn: sqlite3.Connection, session_token: str) -> list[str]:
        """Source tokens of every archived message in the session (records citing the
        session itself are indexed under the session token by the record store)."""
        return [r[0] for r in conn.execute(
            "SELECT source_token FROM history_messages WHERE session_token=? ORDER BY seq", (session_token,))]

    def note_correction(self, conn: sqlite3.Connection, record: Any, cited: Iterable[SourceRef] = ()) -> int:
        """Core hook (``CoreService.correct``, inside its write transaction) for a content change.

        ``record`` is the revision whose content was corrected away; its MESSAGE and SESSION
        sources are recorded as superseded evidence, except sources the correction itself
        cites (``cited``), which are cleared for this memory instead. Stores keyed source /
        session tokens and the record id only. Returns the number of sources recorded.
        """
        now = float(self.ctx.clock())
        cited_tokens = sorted({self.records.source_token(s.identity()) for s in cited})
        recorded = 0
        for source in record.sources:
            if source.kind == SourceKind.MESSAGE:
                session_token = None
            elif source.kind == SourceKind.SESSION:
                session_token = self.session_token(source.ref)
            else:
                continue
            token = self.records.source_token(source.identity())
            if token in cited_tokens:
                continue
            conn.execute(
                "INSERT INTO history_corrections(source_token, record_id, session_token, corrected_at)"
                " VALUES(?,?,?,?) ON CONFLICT(source_token, record_id) DO UPDATE SET"
                " corrected_at=MAX(history_corrections.corrected_at, excluded.corrected_at)",
                (token, record.id, session_token, now))
            recorded += 1
        if cited_tokens:
            conn.execute(
                f"DELETE FROM history_corrections WHERE record_id=? AND source_token IN"
                f" ({','.join('?' * len(cited_tokens))})", [record.id, *cited_tokens])
        if recorded:
            self.ctx.metrics.incr("history.corrections_noted", recorded)
        return recorded

    def hidden_sessions_for_scope(self, conn: sqlite3.Connection, access: AccessContext, dim: str,
                                  value_token: str) -> int:
        """Sessions carrying ``dim=value`` that ``access`` may not read (for admin checks on
        broad forget targets; returns a count only to trusted callers, never to users)."""
        clause, params = self._auth_clause(access.grants, "hs")
        return int(conn.execute(
            "SELECT COUNT(*) FROM history_session_scopes x JOIN history_sessions hs"
            f" ON hs.session_token=x.session_token WHERE x.dim=? AND x.value_token=? AND NOT ({clause})",
            [dim, value_token, *params]).fetchone()[0])

    def purge(self, conn: sqlite3.Connection, target_kind: str, target_token: str,
              forget_policy: ForgetPolicy | None, *, access: AccessContext | None = None) -> dict[str, int]:
        """Remove archive data for a forget target, from the token alone (also used on replay).

        Counts never include sessions the caller may not read: with ``access`` they are
        filtered by its grants; without it, a ``scope:<dim>`` purge counts only sessions
        whose sole constraint is the forgotten value (everything matching is still deleted).
        """
        fp = forget_policy or ForgetPolicy()
        now = self.ctx.clock()
        counts: dict[str, int] = {}
        if target_kind == "session":
            counts = self._purge_sessions(conn, [target_token], suppress=fp.suppress_relearning, now=now,
                                          reportable=self._reporter(access, scope_purge=False))
        elif target_kind == "source":
            # Correction annotations on this source go whether or not the archive copy is kept.
            conn.execute("DELETE FROM history_corrections WHERE source_token=?", (target_token,))
            rows = conn.execute(
                "SELECT id, session_token, seq, event_token FROM history_messages WHERE source_token=?",
                (target_token,)).fetchall()
            report = self._reporter(access, scope_purge=False)
            reported = sum(1 for row in rows if report(conn, row["session_token"]))
            if rows and fp.delete_source_archive:
                for row in rows:
                    conn.execute("DELETE FROM history_messages WHERE id=?", (row["id"],))
                    self._insert_gap(conn, row["session_token"], int(row["seq"]), int(row["seq"]),
                                     GAP_FORGOTTEN, now)
                    if fp.suppress_relearning:
                        conn.execute("INSERT OR IGNORE INTO history_suppressed(kind, token, created_at)"
                                     " VALUES('event', ?, ?)", (row["event_token"], now))
                    self._refresh_session_stats(conn, row["session_token"])
                counts = {"messages": reported}
            elif rows:
                counts = {"retained_messages": reported}
        elif target_kind.startswith("scope:"):
            dim = target_kind.split(":", 1)[1]
            tokens = [r[0] for r in conn.execute(
                "SELECT session_token FROM history_session_scopes WHERE dim=? AND value_token=?",
                (dim, target_token))]
            counts = self._purge_sessions(conn, tokens, suppress=fp.suppress_relearning, now=now,
                                          reportable=self._reporter(access, scope_purge=True))
        elif target_kind == "profile":
            counts = {
                "messages": conn.execute("DELETE FROM history_messages").rowcount,
                "history_skipped_events": conn.execute("DELETE FROM history_skipped").rowcount,
                "history_gap_rows": conn.execute("DELETE FROM history_gaps").rowcount,
                "sessions": conn.execute("DELETE FROM history_sessions").rowcount,
            }
            conn.execute("DELETE FROM history_session_scopes")
            conn.execute("DELETE FROM history_suppressed")
            conn.execute("DELETE FROM history_corrections")
            conn.execute("DELETE FROM cursors WHERE source LIKE ?", (_CURSOR_PREFIX + "%",))
        counts = {k: v for k, v in counts.items() if v}
        if any(not k.startswith("retained_") for k in counts):
            self.drop_projections()
        return counts

    def _reporter(self, access: AccessContext | None, *, scope_purge: bool
                  ) -> Callable[[sqlite3.Connection, str], bool]:
        """Whether a purged session may be counted in the caller's receipt."""
        if access is not None:
            clause, params = self._auth_clause(access.grants, "hs")

            def granted(conn: sqlite3.Connection, token: str) -> bool:
                return conn.execute(f"SELECT 1 FROM history_sessions hs WHERE hs.session_token=? AND {clause}",
                                    [token, *params]).fetchone() is not None
            return granted
        if scope_purge:
            # Without the caller's grants, only sessions constrained by nothing but the
            # forgotten value (which the forgetting service checked is granted) are counted.
            def single(conn: sqlite3.Connection, token: str) -> bool:
                return conn.execute("SELECT COUNT(*) FROM history_session_scopes WHERE session_token=?",
                                    (token,)).fetchone()[0] == 1
            return single
        return lambda conn, token: True  # session / message targets are authorized before purge

    def _purge_sessions(self, conn: sqlite3.Connection, tokens: list[str], *, suppress: bool,
                        now: float, reportable: Callable[[sqlite3.Connection, str], bool]) -> dict[str, int]:
        messages = sessions = 0
        for token in tokens:
            report = reportable(conn, token)
            conn.execute(
                "DELETE FROM history_corrections WHERE session_token=? OR source_token IN"
                " (SELECT source_token FROM history_messages WHERE session_token=?)", (token, token))
            removed = conn.execute("DELETE FROM history_messages WHERE session_token=?", (token,)).rowcount
            conn.execute("DELETE FROM history_skipped WHERE session_token=?", (token,))
            conn.execute("DELETE FROM history_gaps WHERE session_token=?", (token,))
            conn.execute("DELETE FROM cursors WHERE stream_token=? AND source LIKE ?", (token, _CURSOR_PREFIX + "%"))
            conn.execute("DELETE FROM history_session_scopes WHERE session_token=?", (token,))
            gone = conn.execute("DELETE FROM history_sessions WHERE session_token=?", (token,)).rowcount
            if report:
                messages += removed
                sessions += gone
            if suppress:
                conn.execute("INSERT OR IGNORE INTO history_suppressed(kind, token, created_at)"
                             " VALUES('session', ?, ?)", (token, now))
        return {"messages": messages, "sessions": sessions}

    @staticmethod
    def _refresh_session_stats(conn: sqlite3.Connection, s_token: str) -> None:
        conn.execute(
            "UPDATE history_sessions SET"
            " message_count=(SELECT COUNT(*) FROM history_messages WHERE session_token=?),"
            " first_at=(SELECT MIN(occurred_at) FROM history_messages WHERE session_token=?),"
            " last_at=(SELECT MAX(occurred_at) FROM history_messages WHERE session_token=?)"
            " WHERE session_token=?", (s_token, s_token, s_token, s_token),
        )

    # ------------------------------------------------------------------ key rotation / lifecycle
    def reseal(self, conn: sqlite3.Connection, *, limit: int = 500) -> int:
        """Re-seal up to ``limit`` archive rows not under the current data key (caller holds a
        write transaction); returns rows re-sealed. A thin wrapper over :meth:`reencrypt`
        that retires every other DEK found in the archive tables."""
        current = self.p.keyring.current_dek_id
        old = frozenset(r[0] for r in conn.execute(
            f"SELECT DISTINCT dek_id FROM {SESSIONS} WHERE dek_id<>?"
            f" UNION SELECT DISTINCT dek_id FROM {MESSAGES} WHERE dek_id<>?", (current, current)))
        return self.reencrypt(conn, old, limit)

    def reencrypt(self, conn: sqlite3.Connection, old_dek_ids: frozenset[str], limit: int) -> int:
        """Data-key rotation hook (``admin.rotate_data_key``): re-seal up to ``limit`` archive
        rows still under a retiring DEK, authenticating each with its original AAD first."""
        from ..admin import reencrypt_table

        done = reencrypt_table(conn, self.p, SESSIONS, key_columns=("session_token",),
                               row_id=lambda r: r["session_token"], fields=lambda r: {"scope": r["scope_token"]},
                               old_dek_ids=old_dek_ids, limit=limit)
        done += reencrypt_table(
            conn, self.p, MESSAGES, key_columns=("id",), row_id=lambda r: r["id"],
            fields=lambda r: self._message_fields(r["session_token"], r["seq"], r["role"], r["event_token"],
                                                  r["occurred_at"]),
            old_dek_ids=old_dek_ids, limit=limit - done)
        return done

    def drop_projections(self) -> None:
        """Discard every in-memory projection (decrypted text leaves memory with it)."""
        with self._lock:
            projections, self._projections = list(self._projections.values()), OrderedDict()
        for proj in projections:
            with proj.lock:
                proj.close()

    def close(self) -> None:
        self.drop_projections()


__all__ = ["HistoryArchive", "CompiledQuery", "compile_query"]

