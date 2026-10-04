"""Format-compatible implementation of the Locus ``MemoryVault`` and ``ContinuityStore``.

Extracted from Locus ``agent/ollama_code/memory.py`` and ``continuity.py`` (Apache-2.0,
Locus commit b332e4554e72956f949506207ffa034749360d79) so Locus can delegate to the
package *without* migrating data: same SQLite tables, same AES-256-GCM associated
data (``memory-v1|...``, ``locus-context-v1|...``, ``locus-observation-v1|...``), same
JSON payloads, same ids, same public dict shapes and error messages.

Deliberate differences from the host original (each is a safety fix; see
docs/locus-compatibility.md "Defects and risks"):

1. No key custody here. The caller supplies the 32-byte key. ``open()`` verifies the
   key against existing rows and raises :class:`LegacyWrongKey` instead of silently
   operating a vault that mixes keys.
2. ``approve`` keeps a record's own target; it never re-targets a candidate into the
   caller's workspace. With ``enforce_target=True`` (adapter default), approve,
   feedback, delete and update refuse ids outside the caller's targets.
3. Non-finite confidence and timestamps are rejected; a string ``tags`` value is one
   tag rather than one tag per character.
4. ``write_guard`` (optional) is called before every mutation so a cutover can fence
   this writer once the package store becomes authoritative.
5. Semantic recall uses an injected ``embedder`` callable; nothing here performs
   network I/O.
6. Audit defects fixed without changing the format: an explicit empty ``scopes`` list
   returns nothing (D1), feedback is compare-and-swap (D23), editing title/content/tags
   drops the stale cached vector (D24), concurrent first-open column migration is
   tolerated (D25).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import MemoryEngineError, WrongKey

VALID_SCOPES = {"personal", "workspace", "agent"}
VALID_STATUSES = {"candidate", "approved"}
VALID_KINDS = {"preference", "fact", "decision", "procedure", "relationship"}
CANDIDATE_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_MEMORY_CONTENT = 32_000
LEGACY_MEMORY_VERSION = 2

SNAPSHOT_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_SNAPSHOTS_PER_WORKSPACE = 50
MAX_CHANGED_FILES = 100
VALID_OBSERVATION_STATUSES = {"OPEN", "ACTIONED", "DECLINED"}

Embedder = Callable[[str, str, list[str]], list[list[float]]]


class LegacyVaultError(MemoryEngineError):
    """Equivalent of Locus ``memory.MemoryError`` (messages preserved)."""

    code = "legacy_vault_error"


class LegacyContinuityError(MemoryEngineError):
    code = "legacy_continuity_error"


class LegacyWrongKey(WrongKey, LegacyVaultError):
    code = "wrong_key"


def legacy_workspace_hash(workspace: str) -> str:
    """sha256 of the resolved workspace path (the legacy ``workspace:`` target suffix)."""
    try:
        value = str(Path(workspace).expanduser().resolve())
    except (OSError, RuntimeError) as exc:
        raise LegacyVaultError("workspace memory target is invalid") from exc
    return hashlib.sha256(value.encode()).hexdigest()


def legacy_agent_hash(agent_id: str) -> str:
    return hashlib.sha256(agent_id.strip().encode()).hexdigest()


def legacy_target(scope: str, *, workspace: str = "", agent_id: str = "") -> str:
    if scope == "personal":
        return "personal"
    if scope == "workspace":
        if not workspace.strip():
            raise LegacyVaultError("workspace memory requires an active workspace")
        return "workspace:" + legacy_workspace_hash(workspace)
    if scope == "agent":
        if not agent_id.strip():
            raise LegacyVaultError("agent memory requires an agent id")
        return "agent:" + legacy_agent_hash(agent_id)
    raise LegacyVaultError("memory scope must be personal, workspace, or agent")


def _check_key(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise LegacyVaultError("memory encryption requires a 256-bit key")
    return bytes(key)


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or len(left) != len(right):
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    norm = math.sqrt(sum(a * a for a in left)) * math.sqrt(sum(b * b for b in right))
    return dot / norm if norm else 0.0


class LegacyMemoryVault:
    """Drop-in implementation of Locus ``MemoryVault`` over the same database file."""

    def __init__(self, path: Path, *, key: bytes, embedder: Embedder | None = None,
                 write_guard: Callable[[], None] | None = None, enforce_target: bool = False,
                 clock: Callable[[], float] = time.time, verify_key: bool = True) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cipher = AESGCM(_check_key(key))
        self._lock = threading.RLock()
        self._embedder = embedder
        self._write_guard = write_guard
        self.enforce_target = enforce_target
        self._clock = clock
        self._key_checked = not verify_key
        self._initialize()

    @classmethod
    def codec(cls, key: bytes) -> LegacyMemoryVault:
        """Decrypt/encrypt helper bound to no database file (for migration tooling)."""
        instance = cls.__new__(cls)
        instance._cipher = AESGCM(_check_key(key))
        instance._lock = threading.RLock()
        instance._embedder = None
        instance._write_guard = None
        instance.enforce_target = False
        instance._clock = time.time
        return instance

    # ------------------------------------------------------------------ storage
    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _guard(self) -> None:
        if self._write_guard is not None:
            self._write_guard()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS memories (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL CHECK(status IN ('candidate', 'approved')),
                    scope TEXT NOT NULL CHECK(scope IN ('personal', 'workspace', 'agent')),
                    target_hash TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    pinned INTEGER NOT NULL DEFAULT 0,
                    stale INTEGER NOT NULL DEFAULT 0,
                    revision INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    expires_at REAL
                );
                CREATE INDEX IF NOT EXISTS memories_lookup_idx
                    ON memories(status, scope, target_hash, pinned, updated_at);
                CREATE TABLE IF NOT EXISTS memory_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace_hash TEXT NOT NULL,
                    agent_hash TEXT NOT NULL,
                    session_id TEXT,
                    run_id TEXT,
                    stage TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    reason_code TEXT NOT NULL DEFAULT '',
                    memory_id TEXT,
                    occurred_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS memory_events_target_idx
                    ON memory_events(workspace_hash, agent_hash, occurred_at DESC);
                """
            )
            columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(memories)")}
            migrations = {
                "last_used_at": "ALTER TABLE memories ADD COLUMN last_used_at REAL",
                "use_count": "ALTER TABLE memories ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0",
                "superseded_by": "ALTER TABLE memories ADD COLUMN superseded_by TEXT",
            }
            for name, statement in migrations.items():
                if name not in columns:
                    try:
                        connection.execute(statement)
                    except sqlite3.OperationalError as exc:  # D25: concurrent first open won the race
                        if "duplicate column" not in str(exc):
                            raise
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def _ensure_key(self) -> None:
        """Verify the key once, before the first operation (reads or writes)."""
        if not self._key_checked:
            self.verify_key()
            self._key_checked = True

    def verify_key(self) -> None:
        """Fail closed when the supplied key does not open existing rows.

        Runs lazily before the first operation so a wrong key can never add rows
        sealed under a different key (the host original let such writes commit).
        """
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM memories ORDER BY rowid LIMIT 3").fetchall()
        if not rows:
            return
        for row in rows:
            try:
                self._open_payload(row)
                return
            except LegacyVaultError:
                continue
        raise LegacyWrongKey("a memory record could not be decrypted with the supplied key")

    @staticmethod
    def _aad(identifier: str, status: str, scope: str, target_hash: str, revision: int) -> bytes:
        return f"memory-v1|{identifier}|{status}|{scope}|{target_hash}|{revision}".encode()

    def _seal(self, payload: dict[str, Any], *, identifier: str, status: str, scope: str,
              target_hash: str, revision: int) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        return nonce, self._cipher.encrypt(nonce, plaintext,
                                           self._aad(identifier, status, scope, target_hash, revision))

    def _open_payload(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            plaintext = self._cipher.decrypt(
                bytes(row["nonce"]), bytes(row["ciphertext"]),
                self._aad(row["id"], row["status"], row["scope"], row["target_hash"], int(row["revision"])),
            )
            payload = json.loads(plaintext)
        except Exception as exc:  # authentication failure must stay generic
            raise LegacyVaultError("a memory record could not be decrypted") from exc
        if not isinstance(payload, dict):
            raise LegacyVaultError("a memory record is malformed")
        return payload

    def _open(self, row: sqlite3.Row) -> dict[str, Any]:
        payload = self._open_payload(row)
        return {
            "id": row["id"], "status": row["status"], "scope": row["scope"],
            "title": str(payload.get("title") or "Memory"),
            "content": str(payload.get("content") or ""),
            "tags": list(payload.get("tags") or []),
            "reason": str(payload.get("reason") or ""),
            "source_session_id": payload.get("source_session_id"),
            "source_run_id": payload.get("source_run_id"),
            "provenance": payload.get("provenance") or {},
            "kind": str(payload.get("kind") or "fact"),
            "confidence": float(payload.get("confidence", 1.0)),
            "valid_from": payload.get("valid_from"),
            "valid_until": payload.get("valid_until"),
            "last_confirmed_at": payload.get("last_confirmed_at"),
            "supersedes": list(payload.get("supersedes") or []),
            "embedding_model": str(payload.get("embedding_model") or ""),
            "pinned": bool(row["pinned"]), "stale": bool(row["stale"]),
            "last_used_at": row["last_used_at"],
            "use_count": int(row["use_count"] or 0),
            "superseded_by": row["superseded_by"],
            "revision": int(row["revision"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
            "expires_at": row["expires_at"],
        }

    def raw_rows(self) -> list[sqlite3.Row]:
        """All memory rows (for migration tooling); ciphertext stays sealed."""
        with self._connect() as connection:
            return connection.execute("SELECT * FROM memories ORDER BY created_at, id").fetchall()

    def open_row(self, row: sqlite3.Row, *, include_private: bool = False) -> dict[str, Any]:
        """Public dict for a raw row; ``include_private`` adds embedding/feedback for migration."""
        value = self._open(row)
        if include_private:
            payload = self._open_payload(row)
            value["embedding"] = payload.get("embedding") or []
            value["feedback"] = payload.get("feedback")
            value["target_hash"] = row["target_hash"]
        return value

    def _allowed_targets(self, workspace: str, agent_id: str) -> set[str]:
        targets = {"personal"}
        for scope in ("workspace", "agent"):
            try:
                targets.add(legacy_target(scope, workspace=workspace, agent_id=agent_id))
            except LegacyVaultError:
                continue
        return targets

    def _check_target(self, row: sqlite3.Row | None, workspace: str, agent_id: str) -> None:
        if self.enforce_target and row is not None and row["target_hash"] not in self._allowed_targets(workspace, agent_id):
            raise LegacyVaultError("memory not found")

    # ------------------------------------------------------------------ writes
    def save(self, value: dict[str, Any], memory_id: str = "", *, workspace: str = "",
             agent_id: str = "", default_status: str = "approved",
             _target_override: str | None = None, _created_at: float | None = None) -> dict[str, Any]:
        self._guard()
        self._ensure_key()
        identifier = memory_id or uuid.uuid4().hex
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier):
            raise LegacyVaultError("memory id is invalid")
        status = str(value.get("status") or default_status).lower()
        scope = str(value.get("scope") or "workspace").lower()
        if status not in VALID_STATUSES or scope not in VALID_SCOPES:
            raise LegacyVaultError("memory status or scope is invalid")
        target_hash = _target_override or legacy_target(scope, workspace=workspace, agent_id=agent_id)
        content = str(value.get("content") or "").strip()[:MAX_MEMORY_CONTENT]
        if not content:
            raise LegacyVaultError("memory content cannot be empty")
        title = str(value.get("title") or "Memory").strip()[:160] or "Memory"
        raw_tags = value.get("tags") or []
        if isinstance(raw_tags, str):
            raw_tags = [raw_tags]
        tags = sorted({str(item).strip().lower()[:40] for item in raw_tags if str(item).strip()})[:24]
        kind = str(value.get("kind") or "fact").strip().lower()
        if kind not in VALID_KINDS:
            raise LegacyVaultError("memory type must be preference, fact, decision, procedure, or relationship")
        try:
            confidence = float(value.get("confidence", 1.0))
        except (TypeError, ValueError) as exc:
            raise LegacyVaultError("memory confidence must be between 0 and 1") from exc
        if math.isnan(confidence):
            raise LegacyVaultError("memory confidence must be between 0 and 1")
        confidence = min(max(confidence, 0.0), 1.0)

        def timestamp(name: str) -> float | None:
            raw = value.get(name)
            if raw in (None, ""):
                return None
            try:
                number = float(raw)
            except (TypeError, ValueError) as exc:
                raise LegacyVaultError(f"memory {name} must be a Unix timestamp") from exc
            if not math.isfinite(number):
                raise LegacyVaultError(f"memory {name} must be a Unix timestamp")
            return number

        valid_from = timestamp("valid_from")
        valid_until = timestamp("valid_until")
        if valid_from is not None and valid_until is not None and valid_until <= valid_from:
            raise LegacyVaultError("memory valid-until date must be after its valid-from date")
        existing_embedding = value.get("embedding")
        embedding = [float(item) for item in existing_embedding] if isinstance(existing_embedding, list) else []
        payload = {
            "title": title, "content": content, "tags": tags,
            "reason": str(value.get("reason") or "")[:2_000],
            "source_session_id": str(value.get("source_session_id") or "") or None,
            "source_run_id": str(value.get("source_run_id") or "") or None,
            "provenance": value.get("provenance") if isinstance(value.get("provenance"), dict) else {},
            "kind": kind, "confidence": confidence,
            "valid_from": valid_from, "valid_until": valid_until,
            "last_confirmed_at": timestamp("last_confirmed_at"),
            "supersedes": [str(item)[:128] for item in value.get("supersedes") or []][:32],
            "embedding": embedding,
            "embedding_model": str(value.get("embedding_model") or "")[:256],
        }
        if "feedback" in value and isinstance(value.get("feedback"), dict):
            payload["feedback"] = value["feedback"]
        now = self._clock()
        with self._lock, self._connect() as connection:
            previous = connection.execute("SELECT * FROM memories WHERE id=?", (identifier,)).fetchone()
            if previous is not None:
                self._check_target(previous, workspace, agent_id)
                previous_payload = self._open_payload(previous)
                for key in ("reason", "source_session_id", "source_run_id", "provenance",
                            "last_confirmed_at", "supersedes", "embedding", "embedding_model", "feedback"):
                    if key not in value:
                        payload[key] = previous_payload.get(key)
                embedded = ("title", "content", "tags")
                if any(payload.get(k) != previous_payload.get(k) for k in embedded) and "embedding" not in value:
                    # D24: a vector of the old text would keep matching the old content.
                    payload["embedding"], payload["embedding_model"] = [], ""
            revision = int(previous["revision"]) + 1 if previous else 1
            created_at = float(previous["created_at"]) if previous else (_created_at or now)
            expires_at = now + CANDIDATE_TTL_SECONDS if status == "candidate" else None
            nonce, ciphertext = self._seal(payload, identifier=identifier, status=status, scope=scope,
                                           target_hash=target_hash, revision=revision)
            connection.execute(
                """INSERT INTO memories(
                    id, status, scope, target_hash, nonce, ciphertext, pinned, stale,
                    revision, created_at, updated_at, expires_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET status=excluded.status, scope=excluded.scope,
                    target_hash=excluded.target_hash, nonce=excluded.nonce,
                    ciphertext=excluded.ciphertext, pinned=excluded.pinned,
                    stale=excluded.stale, revision=excluded.revision,
                    updated_at=excluded.updated_at, expires_at=excluded.expires_at""",
                (identifier, status, scope, target_hash, nonce, ciphertext,
                 int(bool(value.get("pinned"))), int(bool(value.get("stale"))),
                 revision, created_at, now, expires_at),
            )
            row = connection.execute("SELECT * FROM memories WHERE id=?", (identifier,)).fetchone()
        result = self._open(row)
        result["conflicts"] = self.conflicts_for(result, workspace=workspace, agent_id=agent_id)
        return result

    def approve(self, memory_id: str, *, workspace: str = "", agent_id: str = "",
                resolution: str = "keep_both") -> dict[str, Any]:
        self._guard()
        self._ensure_key()
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM memories WHERE id=?", (memory_id,)).fetchone()
        if row is None:
            raise LegacyVaultError("memory candidate not found")
        try:
            self._check_target(row, workspace, agent_id)
        except LegacyVaultError as exc:
            raise LegacyVaultError("memory candidate not found") from exc
        if resolution not in {"keep_both", "replace"}:
            raise LegacyVaultError("memory conflict resolution must be keep_both or replace")
        value = self._open(row)
        value["status"] = "approved"
        value["last_confirmed_at"] = self._clock()
        conflicts = self.conflicts_for(value, workspace=workspace, agent_id=agent_id)
        # Keep the record's own target (the host original re-targeted it to the caller).
        result = self.save(value, memory_id, workspace=workspace, agent_id=agent_id,
                           default_status="approved", _target_override=row["target_hash"])
        if resolution == "replace" and conflicts:
            conflict_ids = [str(item["id"]) for item in conflicts]
            result = self.save({**result, "supersedes": conflict_ids}, memory_id, workspace=workspace,
                               agent_id=agent_id, default_status="approved",
                               _target_override=row["target_hash"])
            with self._connect() as connection:
                connection.executemany("UPDATE memories SET stale=1, superseded_by=? WHERE id=?",
                                       ((memory_id, identifier) for identifier in conflict_ids))
            result["supersedes"] = conflict_ids
            result["conflicts"] = []
        else:
            result["conflicts"] = conflicts
        return result

    def expire_candidates(self, *, workspace: str = "", agent_id: str = "") -> int:
        now = self._clock()
        with self._connect() as connection:
            identifiers = [str(row[0]) for row in connection.execute(
                "SELECT id FROM memories WHERE status='candidate' AND expires_at < ?", (now,)).fetchall()]
            count = connection.execute(
                "DELETE FROM memories WHERE status='candidate' AND expires_at < ?", (now,)).rowcount
        for identifier in identifiers:
            self.record_event("expiration", "expired", workspace=workspace, agent_id=agent_id,
                              memory_id=identifier)
        return count

    def list(self, *, workspace: str = "", agent_id: str = "", status: str = "",
             scopes: list[str] | tuple[str, ...] | None = None) -> list[dict[str, Any]]:
        self._ensure_key()
        self.expire_candidates(workspace=workspace, agent_id=agent_id)
        if scopes is not None and len(scopes) == 0:
            return []  # D1: an empty scope list never means "all scopes"
        selected = tuple(s for s in (scopes or ("personal", "workspace", "agent")) if s in VALID_SCOPES)
        targets: list[tuple[str, str]] = []
        for scope in selected:
            try:
                targets.append((scope, legacy_target(scope, workspace=workspace, agent_id=agent_id)))
            except LegacyVaultError:
                continue
        if not targets:
            return []
        clauses = " OR ".join("(scope=? AND target_hash=?)" for _ in targets)
        parameters: list[Any] = [item for pair in targets for item in pair]
        status_clause = ""
        if status in VALID_STATUSES:
            status_clause = " AND status=?"
            parameters.append(status)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM memories WHERE ({clauses}){status_clause} ORDER BY pinned DESC, updated_at DESC",
                parameters,
            ).fetchall()
        values = [self._open(row) for row in rows]
        if status == "candidate":
            for value in values:
                value["conflicts"] = self.conflicts_for(value, workspace=workspace, agent_id=agent_id)
        return values

    @staticmethod
    def _topic_tokens(memory: dict[str, Any]) -> set[str]:
        text = " ".join((memory.get("title") or "", " ".join(memory.get("tags") or [])))
        return {token for token in re.findall(r"[a-z0-9_.-]+", text.lower()) if len(token) > 2}

    def conflicts_for(self, memory: dict[str, Any], *, workspace: str = "", agent_id: str = "") -> list[dict[str, Any]]:
        topic = self._topic_tokens(memory)
        if not topic:
            return []
        normalized = re.sub(r"\s+", " ", str(memory.get("content") or "").strip().lower())
        conflicts: list[dict[str, Any]] = []
        for candidate in self.list(workspace=workspace, agent_id=agent_id, status="approved",
                                   scopes=[str(memory.get("scope") or "workspace")]):
            if candidate["id"] == memory.get("id") or candidate.get("stale"):
                continue
            candidate_topic = self._topic_tokens(candidate)
            overlap = len(topic & candidate_topic) / max(min(len(topic), len(candidate_topic)), 1)
            other = re.sub(r"\s+", " ", candidate["content"].strip().lower())
            if overlap >= 0.5 and normalized != other:
                conflicts.append({"id": candidate["id"], "title": candidate["title"],
                                  "content": candidate["content"], "kind": candidate.get("kind", "fact"),
                                  "confidence": candidate.get("confidence", 1.0)})
        return conflicts[:12]

    def _store_embedding(self, row: sqlite3.Row, payload: dict[str, Any], model: str, vector: list[float]) -> None:
        payload = dict(payload)
        payload["embedding"] = [float(value) for value in vector]
        payload["embedding_model"] = model[:256]
        nonce, ciphertext = self._seal(payload, identifier=row["id"], status=row["status"], scope=row["scope"],
                                       target_hash=row["target_hash"], revision=int(row["revision"]))
        with self._lock, self._connect() as connection:
            connection.execute(
                """UPDATE memories SET nonce=?, ciphertext=?
                WHERE id=? AND revision=? AND nonce=? AND ciphertext=?""",
                (nonce, ciphertext, row["id"], int(row["revision"]), row["nonce"], row["ciphertext"]),
            )

    def search(self, query: str, *, workspace: str = "", agent_id: str = "",
               scopes: list[str] | tuple[str, ...] | None = None, limit: int = 8,
               approved_only: bool = True, embedding_model: str = "",
               ollama_host: str = "http://127.0.0.1:11434") -> list[dict[str, Any]]:
        value = query.strip().lower()[:2_000]
        if not value:
            raise LegacyVaultError("memory search requires a query")
        terms = [term for term in re.findall(r"[\w.-]+", value) if len(term) > 1][:24]
        candidates = self.list(workspace=workspace, agent_id=agent_id,
                               status="approved" if approved_only else "", scopes=scopes)
        semantic: dict[str, float] = {}
        model = embedding_model.strip()[:256]
        if model and candidates and self._embedder is not None:
            try:
                with self._connect() as connection:
                    placeholders = ",".join("?" for _ in candidates)
                    rows = {str(row["id"]): row for row in connection.execute(
                        f"SELECT * FROM memories WHERE id IN ({placeholders})",
                        [item["id"] for item in candidates]).fetchall()}
                missing = []
                payloads: dict[str, dict[str, Any]] = {}
                for item in candidates:
                    payload = self._open_payload(rows[item["id"]])
                    payloads[item["id"]] = payload
                    if payload.get("embedding_model") != model or not payload.get("embedding"):
                        missing.append(item)
                inputs = [value] + [f"{item['title']}\n{item['content']}\n{' '.join(item['tags'])}"
                                    for item in missing]
                vectors = self._embedder(model, ollama_host, inputs)
                if len(vectors) != len(inputs):
                    raise LegacyVaultError("embedding count mismatch")
                query_vector = vectors[0]
                for item, vector in zip(missing, vectors[1:]):
                    if not all(math.isfinite(float(x)) for x in vector):
                        continue
                    self._store_embedding(rows[item["id"]], payloads[item["id"]], model, vector)
                    payloads[item["id"]] = {**payloads[item["id"]], "embedding": vector, "embedding_model": model}
                for item in candidates:
                    vector = payloads[item["id"]].get("embedding") or []
                    if len(vector) == len(query_vector):
                        semantic[item["id"]] = max(cosine_similarity(query_vector, vector), 0.0)
            except Exception:  # semantic recall is optional; lexical recall remains available
                semantic = {}
        ranked: list[tuple[float, dict[str, Any]]] = []
        now = self._clock()
        for memory in candidates:
            haystack = " ".join((memory["title"], memory["content"], " ".join(memory["tags"]))).lower()
            phrase = 4.0 if value in haystack else 0.0
            matches = sum(haystack.count(term) for term in terms)
            semantic_score = semantic.get(memory["id"], 0.0)
            if not phrase and not matches and semantic_score < 0.2:
                continue
            age_days = max((now - memory["updated_at"]) / 86_400, 0)
            confidence = float(memory.get("confidence", 1.0))
            score = (phrase + min(matches, 8) * 0.8 + semantic_score * 5.0
                     + (2.0 if memory["pinned"] else 0) + confidence + 1 / (1 + age_days / 30))
            valid_from = memory.get("valid_from")
            valid_until = memory.get("valid_until")
            if valid_from is not None and float(valid_from) > now:
                continue
            if valid_until is not None and float(valid_until) < now:
                score *= 0.15
            if memory["stale"]:
                score *= 0.4
            reasons: list[str] = []
            if phrase:
                reasons.append("exact phrase")
            elif matches:
                reasons.append(f"{matches} matching term{'s' if matches != 1 else ''}")
            if semantic_score:
                reasons.append(f"semantic similarity {semantic_score:.0%}")
            if memory["pinned"]:
                reasons.append("pinned")
            reasons.append(f"{confidence:.0%} confidence")
            ranked.append((score, {**memory, "retrieval_reason": ", ".join(reasons)}))
        ranked.sort(key=lambda item: (-item[0], item[1]["id"]))
        selected = [{**memory, "score": score} for score, memory in ranked[:min(max(limit, 1), 20)]]
        if selected:
            with self._connect() as connection:
                connection.executemany("UPDATE memories SET last_used_at=?, use_count=use_count+1 WHERE id=?",
                                       ((now, item["id"]) for item in selected))
        return selected

    def delete(self, memory_id: str, *, workspace: str = "", agent_id: str = "") -> bool:
        self._guard()
        self._ensure_key()
        with self._connect() as connection:
            if self.enforce_target:
                row = connection.execute("SELECT * FROM memories WHERE id=?", (memory_id,)).fetchone()
                if row is None or row["target_hash"] not in self._allowed_targets(workspace, agent_id):
                    return False
            return connection.execute("DELETE FROM memories WHERE id=?", (memory_id,)).rowcount == 1

    def delete_all(self, *, workspace: str = "", agent_id: str = "", scopes: list[str] | None = None) -> int:
        self._guard()
        identifiers = [item["id"] for item in self.list(workspace=workspace, agent_id=agent_id, scopes=scopes)]
        if not identifiers:
            return 0
        with self._connect() as connection:
            return connection.executemany("DELETE FROM memories WHERE id=?",
                                          ((item,) for item in identifiers)).rowcount

    def feedback(self, memory_id: str, outcome: str, *, workspace: str = "", agent_id: str = "") -> dict[str, Any]:
        self._guard()
        if outcome not in {"helpful", "ignored", "incorrect"}:
            raise LegacyVaultError("memory feedback must be helpful, ignored, or incorrect")
        self._ensure_key()
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT * FROM memories WHERE id=?", (memory_id,)).fetchone()
            if row is None:
                raise LegacyVaultError("memory not found")
            self._check_target(row, workspace, agent_id)
            payload = self._open_payload(row)
            feedback = payload.get("feedback")
            feedback = dict(feedback) if isinstance(feedback, dict) else {}
            feedback[outcome] = int(feedback.get(outcome) or 0) + 1
            payload["feedback"] = feedback
            nonce, ciphertext = self._seal(payload, identifier=row["id"], status=row["status"], scope=row["scope"],
                                           target_hash=row["target_hash"], revision=int(row["revision"]))
            stale = 1 if outcome == "incorrect" else int(row["stale"])
            changed = connection.execute(
                "UPDATE memories SET nonce=?, ciphertext=?, stale=? WHERE id=? AND revision=? AND nonce=?",
                (nonce, ciphertext, stale, memory_id, int(row["revision"]), row["nonce"]),
            ).rowcount
            if changed != 1:
                # D23: a concurrent save moved the revision; never write ciphertext sealed for the old one.
                raise LegacyVaultError("memory changed concurrently; retry feedback")
            updated = connection.execute("SELECT * FROM memories WHERE id=?", (memory_id,)).fetchone()
        return self._open(updated)

    def record_event(self, stage: str, outcome: str, *, workspace: str = "", agent_id: str = "",
                     session_id: str = "", run_id: str = "", reason_code: str = "", memory_id: str = "") -> None:
        workspace_hash = hashlib.sha256(workspace.encode()).hexdigest() if workspace else ""
        agent_hash = hashlib.sha256(agent_id.encode()).hexdigest() if agent_id else ""
        now = self._clock()
        with self._lock, self._connect() as connection:
            connection.execute(
                """INSERT INTO memory_events(workspace_hash, agent_hash, session_id, run_id, stage, outcome,
                    reason_code, memory_id, occurred_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (workspace_hash, agent_hash, session_id[:160] or None, run_id[:160] or None,
                 stage[:64], outcome[:64], reason_code[:128], memory_id[:128] or None, now),
            )
            connection.execute("DELETE FROM memory_events WHERE occurred_at < ?", (now - 90 * 24 * 60 * 60,))
            connection.execute(
                """DELETE FROM memory_events WHERE id IN (
                    SELECT id FROM memory_events WHERE workspace_hash=? AND agent_hash=?
                    ORDER BY occurred_at DESC LIMIT -1 OFFSET 5000)""",
                (workspace_hash, agent_hash),
            )

    def diagnostics(self, *, workspace: str = "", agent_id: str = "") -> dict[str, Any]:
        workspace_hash = hashlib.sha256(workspace.encode()).hexdigest() if workspace else ""
        agent_hash = hashlib.sha256(agent_id.encode()).hexdigest() if agent_id else ""
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT session_id, run_id, stage, outcome, reason_code, memory_id, occurred_at
                   FROM memory_events WHERE workspace_hash=? AND agent_hash=?
                   ORDER BY occurred_at DESC LIMIT 100""", (workspace_hash, agent_hash)).fetchall()
        events = [dict(row) for row in rows]
        counts: dict[str, int] = {}
        for event in events:
            key = f"{event['stage']}:{event['outcome']}"
            counts[key] = counts.get(key, 0) + 1
        status = self.status(workspace=workspace, agent_id=agent_id)
        last_proposal = next((e for e in events if e["stage"] == "proposal"), None)
        last_approval = next((e for e in events if e["stage"] == "approval" and e["outcome"] == "accepted"), None)
        return {**status, "events": events, "counts": counts, "last_proposal": last_proposal,
                "last_approval": last_approval, "history_available": bool(events)}

    def maintain(self, *, workspace: str = "", agent_id: str = "") -> dict[str, Any]:
        self._guard()
        now = self._clock()
        items = self.list(workspace=workspace, agent_id=agent_id)
        expired_ids = [item["id"] for item in items if item.get("valid_until") is not None
                       and float(item["valid_until"]) < now and not item["stale"]]
        if expired_ids:
            with self._connect() as connection:
                connection.executemany("UPDATE memories SET stale=1 WHERE id=?", ((i,) for i in expired_ids))
            for identifier in expired_ids:
                self.record_event("expiration", "expired", workspace=workspace, agent_id=agent_id,
                                  memory_id=identifier)
        conflicts = {item["id"]: self.conflicts_for(item, workspace=workspace, agent_id=agent_id)
                     for item in items if item["status"] == "approved" and not item["stale"]}
        conflicts = {key: value for key, value in conflicts.items() if value}
        return {"ok": True, "expired_marked_stale": len(expired_ids),
                "conflict_count": sum(len(v) for v in conflicts.values()) // 2, "conflicts": conflicts}

    def status(self, *, workspace: str = "", agent_id: str = "") -> dict[str, Any]:
        items = self.list(workspace=workspace, agent_id=agent_id)
        now = self._clock()
        conflict_ids = {item["id"] for item in items if item["status"] == "approved"
                        and self.conflicts_for(item, workspace=workspace, agent_id=agent_id)}
        return {
            "encrypted": True, "cipher": "AES-256-GCM",
            "approved_count": sum(item["status"] == "approved" for item in items),
            "candidate_count": sum(item["status"] == "candidate" for item in items),
            "candidate_ttl_days": 30,
            "stale_count": sum(bool(item["stale"]) for item in items),
            "expired_count": sum(item.get("valid_until") is not None and float(item["valid_until"]) < now
                                 for item in items),
            "conflict_count": len(conflict_ids), "semantic_encrypted": True,
            "memory_version": LEGACY_MEMORY_VERSION,
        }

    def export(self, *, workspace: str = "", agent_id: str = "") -> dict[str, Any]:
        return {"format": "locus-memory-export", "version": 2, "exported_at": self._clock(),
                "memories": self.list(workspace=workspace, agent_id=agent_id)}

    def import_values(self, document: dict[str, Any], *, workspace: str = "", agent_id: str = "") -> int:
        self._ensure_key()
        if document.get("format") != "locus-memory-export" or document.get("version") not in {1, 2}:
            raise LegacyVaultError("memory import format is not supported")
        values = document.get("memories")
        if not isinstance(values, list) or len(values) > 10_000:
            raise LegacyVaultError("memory import is malformed or too large")
        imported = 0
        for raw in values:
            if not isinstance(raw, dict):
                continue
            self.save(raw, str(raw.get("id") or ""), workspace=workspace, agent_id=agent_id,
                      default_status=str(raw.get("status") or "approved"))
            imported += 1
        return imported

    # ------------------------------------------------------------------ legacy plaintext notes
    def import_legacy_note(self, note: dict[str, Any], *, workspace: str) -> tuple[str, str]:
        """Crash-safe replacement for the host's legacy-note migration step.

        Returns (memory_id, outcome) where outcome is 'migrated' or 'already_migrated'.
        Unlike the host original, a re-run never overwrites a vault record that was
        edited after the first migration, and the note's original created_at is kept.
        """
        self._ensure_key()
        identifier = "legacy-" + hashlib.sha256(
            f"{Path(workspace).resolve()}|{note['id']}".encode()).hexdigest()[:40]
        with self._connect() as connection:
            existing = connection.execute("SELECT id FROM memories WHERE id=?", (identifier,)).fetchone()
        if existing is not None:
            return identifier, "already_migrated"
        self.save({**note, "scope": "workspace", "status": "approved"}, identifier, workspace=workspace,
                  _created_at=float(note.get("created_at") or self._clock()))
        return identifier, "migrated"


def format_memory_results(results: list[dict[str, Any]]) -> str:
    if not results:
        return "No approved memory matched that query."
    lines = ["Approved memory results (local user-controlled context):"]
    for item in results:
        stale = " · stale" if item.get("stale") else ""
        reason = str(item.get("retrieval_reason") or "matched the request")
        lines.append(f"\n## {item['title']} [{item.get('kind', 'fact')} · {item['scope']}{stale}]"
                     f"\nWhy recalled: {reason}\n{item['content']}")
    return "\n".join(lines)[:30_000]


# ====================================================================== continuity
def _continuity_target(workspace: str) -> str:
    if not str(workspace).strip():
        raise LegacyContinuityError("cross-chat context requires an active workspace")
    try:
        resolved = str(Path(workspace).expanduser().resolve())
    except (OSError, RuntimeError) as exc:
        raise LegacyContinuityError("workspace path is invalid") from exc
    return hashlib.sha256(resolved.encode()).hexdigest()


def _bounded(value: Any, limit: int = 8_000) -> str:
    return str(value or "").strip()[:limit]


def _ctokens(value: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9_./-]{2,}", value.lower())
            if t not in {"the", "and", "for", "with", "from", "this", "that", "into"}}


class LegacyContinuityStore:
    """Drop-in implementation of Locus ``ContinuityStore`` (same tables, AAD and payloads)."""

    def __init__(self, path: Path, *, key: bytes, write_guard: Callable[[], None] | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cipher = AESGCM(_check_key(key))
        self._lock = threading.RLock()
        self._write_guard = write_guard
        self._clock = clock
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _guard(self) -> None:
        if self._write_guard is not None:
            self._write_guard()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS context_snapshots (
                    id TEXT PRIMARY KEY, session_id TEXT NOT NULL, workspace_hash TEXT NOT NULL,
                    nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, pinned INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL, expires_at REAL,
                    UNIQUE(session_id, workspace_hash)
                );
                CREATE INDEX IF NOT EXISTS context_snapshots_lookup_idx
                    ON context_snapshots(workspace_hash, pinned, updated_at DESC);
                CREATE TABLE IF NOT EXISTS skill_observations (
                    id TEXT PRIMARY KEY, number INTEGER NOT NULL, workspace_hash TEXT NOT NULL,
                    status TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL, UNIQUE(workspace_hash, number)
                );
                CREATE INDEX IF NOT EXISTS skill_observations_lookup_idx
                    ON skill_observations(workspace_hash, status, number DESC);
                """
            )
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _snapshot_aad(identifier: str, session_id: str, target: str) -> bytes:
        return f"locus-context-v1|{identifier}|{session_id}|{target}".encode()

    @staticmethod
    def _observation_aad(identifier: str, number: int, target: str, status: str) -> bytes:
        return f"locus-observation-v1|{identifier}|{number}|{target}|{status}".encode()

    def _decrypt_snapshot(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            raw = self._cipher.decrypt(bytes(row["nonce"]), bytes(row["ciphertext"]),
                                       self._snapshot_aad(str(row["id"]), str(row["session_id"]),
                                                          str(row["workspace_hash"])))
            payload = json.loads(raw)
        except Exception as exc:  # corrupt encrypted rows must be isolated
            raise LegacyContinuityError("a context snapshot could not be decrypted") from exc
        return {**payload, "id": str(row["id"]), "session_id": str(row["session_id"]),
                "pinned": bool(row["pinned"]), "created_at": float(row["created_at"]),
                "updated_at": float(row["updated_at"]),
                "expires_at": float(row["expires_at"]) if row["expires_at"] is not None else None}

    def save_snapshot(self, workspace: str, session_id: str, payload: dict[str, Any], *,
                      pinned: bool = False) -> dict[str, Any]:
        self._guard()
        target = _continuity_target(workspace)
        session_id = _bounded(session_id, 160)
        if not session_id:
            raise LegacyContinuityError("context snapshot requires a session id")
        now = self._clock()
        document = {
            "goal": _bounded(payload.get("goal"), 4_000),
            "outcome": _bounded(payload.get("outcome"), 8_000),
            "mode": _bounded(payload.get("mode"), 32),
            "plan": payload.get("plan") if isinstance(payload.get("plan"), dict) else None,
            "todos": [{"content": _bounded(item.get("content"), 1_000), "status": _bounded(item.get("status"), 32)}
                      for item in (payload.get("todos") or [])[:100]
                      if isinstance(item, dict) and _bounded(item.get("content"), 1_000)],
            "checkpoint": payload.get("checkpoint") if isinstance(payload.get("checkpoint"), dict) else None,
            "changed_files": [_bounded(item, 1_000) for item in (payload.get("changed_files") or [])[:MAX_CHANGED_FILES]
                              if _bounded(item, 1_000)],
            "pending": _bounded(payload.get("pending"), 4_000),
        }
        with self._lock, self._connect() as connection:
            existing = connection.execute(
                "SELECT id, created_at, pinned FROM context_snapshots WHERE session_id=? AND workspace_hash=?",
                (session_id, target)).fetchone()
            identifier = str(existing["id"]) if existing else uuid.uuid4().hex
            created_at = float(existing["created_at"]) if existing else now
            is_pinned = bool(existing["pinned"]) if existing else pinned
            nonce = secrets.token_bytes(12)
            ciphertext = self._cipher.encrypt(nonce, json.dumps(document, separators=(",", ":")).encode(),
                                              self._snapshot_aad(identifier, session_id, target))
            expires_at = None if is_pinned else now + SNAPSHOT_TTL_SECONDS
            connection.execute(
                """INSERT INTO context_snapshots(id, session_id, workspace_hash, nonce, ciphertext, pinned,
                    created_at, updated_at, expires_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, workspace_hash) DO UPDATE SET nonce=excluded.nonce,
                    ciphertext=excluded.ciphertext, pinned=excluded.pinned, updated_at=excluded.updated_at,
                    expires_at=excluded.expires_at""",
                (identifier, session_id, target, nonce, ciphertext, int(is_pinned), created_at, now, expires_at))
            self._prune(connection, target, now)
            row = connection.execute("SELECT * FROM context_snapshots WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise LegacyContinuityError("context snapshot could not be stored")
        return self._decrypt_snapshot(row)

    @staticmethod
    def _prune(connection: sqlite3.Connection, target: str, now: float) -> None:
        connection.execute(
            "DELETE FROM context_snapshots WHERE pinned=0 AND expires_at IS NOT NULL AND expires_at < ?", (now,))
        overflow = connection.execute(
            "SELECT id FROM context_snapshots WHERE workspace_hash=? AND pinned=0 ORDER BY updated_at DESC"
            " LIMIT -1 OFFSET ?", (target, MAX_SNAPSHOTS_PER_WORKSPACE)).fetchall()
        if overflow:
            connection.executemany("DELETE FROM context_snapshots WHERE id=?", [(str(r["id"]),) for r in overflow])

    def list_snapshots(self, workspace: str, *, exclude_session: str = "", limit: int = 50) -> list[dict[str, Any]]:
        target = _continuity_target(workspace)
        now = self._clock()
        with self._lock, self._connect() as connection:
            self._prune(connection, target, now)
            rows = connection.execute(
                "SELECT * FROM context_snapshots WHERE workspace_hash=? AND session_id<>?"
                " ORDER BY pinned DESC, updated_at DESC LIMIT ?",
                (target, exclude_session, max(1, min(int(limit), 100)))).fetchall()
        results = []
        for row in rows:
            try:
                results.append(self._decrypt_snapshot(row))
            except LegacyContinuityError:
                continue
        return results

    def search_snapshots(self, query: str, workspace: str, *, exclude_session: str = "",
                         limit: int = 2) -> list[dict[str, Any]]:
        candidates = self.list_snapshots(workspace, exclude_session=exclude_session,
                                         limit=MAX_SNAPSHOTS_PER_WORKSPACE)
        query_tokens = _ctokens(query)
        now = self._clock()

        def score(item: dict[str, Any]) -> tuple[float, float]:
            searchable = " ".join([str(item.get("goal") or ""), str(item.get("outcome") or ""),
                                   str(item.get("pending") or ""), " ".join(item.get("changed_files") or [])])
            overlap = len(query_tokens & _ctokens(searchable))
            age_days = max((now - float(item.get("updated_at") or now)) / 86_400, 0)
            return (overlap * 10 + (4 if item.get("pinned") else 0) - min(age_days, 30) / 30,
                    float(item.get("updated_at") or 0))

        candidates.sort(key=score, reverse=True)
        return candidates[:max(0, min(int(limit), 10))]

    def delete_snapshot(self, identifier: str, workspace: str) -> bool:
        self._guard()
        target = _continuity_target(workspace)
        with self._lock, self._connect() as connection:
            result = connection.execute("DELETE FROM context_snapshots WHERE id=? AND workspace_hash=?",
                                        (identifier, target))
        return bool(result.rowcount)

    def set_snapshot_pinned(self, identifier: str, workspace: str, pinned: bool) -> dict[str, Any]:
        self._guard()
        target = _continuity_target(workspace)
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT * FROM context_snapshots WHERE id=? AND workspace_hash=?",
                                     (identifier, target)).fetchone()
            if row is None:
                raise LegacyContinuityError("context snapshot not found")
            now = self._clock()
            connection.execute("UPDATE context_snapshots SET pinned=?, expires_at=?, updated_at=? WHERE id=?",
                               (int(pinned), None if pinned else now + SNAPSHOT_TTL_SECONDS, now, identifier))
            updated = connection.execute("SELECT * FROM context_snapshots WHERE id=?", (identifier,)).fetchone()
        if updated is None:
            raise LegacyContinuityError("context snapshot not found")
        return self._decrypt_snapshot(updated)

    def clear_snapshots(self, workspace: str) -> int:
        self._guard()
        target = _continuity_target(workspace)
        with self._lock, self._connect() as connection:
            return int(connection.execute("DELETE FROM context_snapshots WHERE workspace_hash=?", (target,)).rowcount)

    def _decrypt_observation(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            raw = self._cipher.decrypt(bytes(row["nonce"]), bytes(row["ciphertext"]),
                                       self._observation_aad(str(row["id"]), int(row["number"]),
                                                             str(row["workspace_hash"]), str(row["status"])))
            payload = json.loads(raw)
        except Exception as exc:
            raise LegacyContinuityError("a skill observation could not be decrypted") from exc
        return {**payload, "id": str(row["id"]), "number": int(row["number"]), "status": str(row["status"]),
                "created_at": float(row["created_at"]), "updated_at": float(row["updated_at"])}

    def record_observation(self, workspace: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._guard()
        target = _continuity_target(workspace)
        checkpoint_only = payload.get("checkpoint_only") is True
        document = {
            "title": _bounded(payload.get("title"), 200) or (
                "Observation checkpoint" if checkpoint_only else "Skill observation"),
            "session_context": _bounded(payload.get("session_context"), 2_000),
            "skill": _bounded(payload.get("skill"), 200) or "All skills",
            "type": "internal" if str(payload.get("type")).lower() == "internal" else "open-source",
            "phase_area": _bounded(payload.get("phase_area"), 500),
            "issue": _bounded(payload.get("issue"), 4_000),
            "suggested_improvement": _bounded(payload.get("suggested_improvement"), 4_000),
            "principle": _bounded(payload.get("principle"), 4_000),
            "checkpoint_only": checkpoint_only,
            "source_session_id": _bounded(payload.get("source_session_id"), 160),
            "source_run_id": _bounded(payload.get("source_run_id"), 160),
        }
        if not checkpoint_only and not all(document[f] for f in ("issue", "suggested_improvement", "principle")):
            raise LegacyContinuityError("skill observations require issue, suggested improvement, and principle")
        now = self._clock()
        identifier = uuid.uuid4().hex
        status = "OPEN"
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT COALESCE(MAX(number), 0) AS maximum FROM skill_observations WHERE workspace_hash=?",
                (target,)).fetchone()
            number = int(row["maximum"] if row else 0) + 1
            nonce = secrets.token_bytes(12)
            ciphertext = self._cipher.encrypt(nonce, json.dumps(document, separators=(",", ":")).encode(),
                                              self._observation_aad(identifier, number, target, status))
            connection.execute(
                "INSERT INTO skill_observations(id, number, workspace_hash, status, nonce, ciphertext, created_at,"
                " updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (identifier, number, target, status, nonce, ciphertext, now, now))
            stored = connection.execute("SELECT * FROM skill_observations WHERE id=?", (identifier,)).fetchone()
        if stored is None:
            raise LegacyContinuityError("skill observation could not be stored")
        return self._decrypt_observation(stored)

    def list_observations(self, workspace: str, *, status: str = "", limit: int = 200) -> list[dict[str, Any]]:
        target = _continuity_target(workspace)
        normalized = status.upper()
        if normalized and normalized not in VALID_OBSERVATION_STATUSES:
            raise LegacyContinuityError("invalid observation status")
        query = "SELECT * FROM skill_observations WHERE workspace_hash=?"
        values: list[Any] = [target]
        if normalized:
            query += " AND status=?"
            values.append(normalized)
        query += " ORDER BY number DESC LIMIT ?"
        values.append(max(1, min(int(limit), 1_000)))
        with self._lock, self._connect() as connection:
            rows = connection.execute(query, values).fetchall()
        results = []
        for row in rows:
            try:
                results.append(self._decrypt_observation(row))
            except LegacyContinuityError:
                continue
        return results

    def set_observation_status(self, identifier: str, workspace: str, status: str) -> dict[str, Any]:
        self._guard()
        target = _continuity_target(workspace)
        normalized = status.upper()
        if normalized not in VALID_OBSERVATION_STATUSES:
            raise LegacyContinuityError("invalid observation status")
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT * FROM skill_observations WHERE id=? AND workspace_hash=?",
                                     (identifier, target)).fetchone()
            if row is None:
                raise LegacyContinuityError("skill observation not found")
            payload = self._decrypt_observation(row)
            document = {k: v for k, v in payload.items() if k not in {"id", "number", "status", "created_at", "updated_at"}}
            now = self._clock()
            nonce = secrets.token_bytes(12)
            ciphertext = self._cipher.encrypt(nonce, json.dumps(document, separators=(",", ":")).encode(),
                                              self._observation_aad(identifier, int(row["number"]), target, normalized))
            connection.execute("UPDATE skill_observations SET status=?, nonce=?, ciphertext=?, updated_at=? WHERE id=?",
                               (normalized, nonce, ciphertext, now, identifier))
            updated = connection.execute("SELECT * FROM skill_observations WHERE id=?", (identifier,)).fetchone()
        if updated is None:
            raise LegacyContinuityError("skill observation not found")
        return self._decrypt_observation(updated)

    def delete_observation(self, identifier: str, workspace: str) -> bool:
        self._guard()
        target = _continuity_target(workspace)
        with self._lock, self._connect() as connection:
            return bool(connection.execute("DELETE FROM skill_observations WHERE id=? AND workspace_hash=?",
                                           (identifier, target)).rowcount)

    def export_observations(self, workspace: str) -> dict[str, Any]:
        return {"format": "locus-skill-observations", "version": 1, "exported_at": self._clock(),
                "observations": self.list_observations(workspace, limit=1_000)}


def format_context_snapshots(results: list[dict[str, Any]], max_tokens: int) -> str:
    if not results or max_tokens <= 0:
        return ""
    sections = ["Cross-chat workspace context (local encrypted session snapshots; verify against the current workspace):"]
    for item in results:
        lines = [f"\n## Prior session {item.get('session_id', '')}"]
        if item.get("goal"):
            lines.append("Goal: " + str(item["goal"]))
        if item.get("outcome"):
            lines.append("Outcome: " + str(item["outcome"]))
        if item.get("pending"):
            lines.append("Pending: " + str(item["pending"]))
        files = item.get("changed_files") or []
        if files:
            lines.append("Changed files: " + ", ".join(str(v) for v in files[:30]))
        todos = [str(t.get("content") or "") for t in item.get("todos") or []
                 if isinstance(t, dict) and t.get("status") != "completed"]
        if todos:
            lines.append("Open steps: " + "; ".join(todos[:20]))
        sections.append("\n".join(lines))
    return "\n".join(sections)[:max_tokens * 4]


__all__ = [
    "LegacyMemoryVault", "LegacyContinuityStore", "LegacyVaultError", "LegacyContinuityError",
    "LegacyWrongKey", "format_memory_results", "format_context_snapshots", "legacy_target",
    "legacy_workspace_hash", "legacy_agent_hash", "cosine_similarity",
]
