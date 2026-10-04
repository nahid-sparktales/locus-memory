"""One security partition: its database, keyring, deletion ledger and shared helpers.

Deletion-state invariant: every ledger entry whose generation is at or below the
main database's ``deletion_generation`` has been applied to the main database.
``deletion_generation`` therefore only moves forward, and ``reconcile`` (run on
open and whenever :meth:`Partition.needs_reconcile` says so) applies the rest.
"""
from __future__ import annotations

import dataclasses
import functools
import hmac
import inspect
import json
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..crypto import KeyProvider, PartitionKeyring
from ..errors import (
    AccessDenied,
    IdempotencyConflict,
    IntegrityError,
    NotFound,
    ReconciliationRequired,
    ValidationError,
)
from ..models import AccessContext, ForgetPolicy, Operation, PartitionRef, Receipt, canonical_json
from . import schema
from .db import Database
from .ledger import DeletionLedger, LedgerEntry, LedgerMirror

# (conn, target_kind, target_token, generation[, forget_policy]) -> Any ; the forgetting
# service's ``apply_tombstone``. The policy argument is passed only when the ledger
# entry recorded one.
TombstoneApplier = Callable[..., Any]

# Ledger/tombstone kind recording that an operator acknowledged a deletion-state gap
# (the host mirror knew a newer generation than the restored store and ledger).
# Appliers must treat it as a no-op.
GAP_ACKNOWLEDGED_KIND = "gap_acknowledged"
# Policy column of a tombstone that a forget wrote for a record dying *with* its target (e.g. an
# episode lesson only the forgotten attempt proposed). It shares the generation of the ledger
# entry that caused it and is re-derived whenever that entry is applied, so it is never adopted
# into the ledger as if it were the entry itself. Decodes as the default policy.
DERIVED_TOMBSTONE_POLICY = '{"derived":true}'


def encode_forget_policy(policy: ForgetPolicy | None) -> str:
    """Ledger/tombstone encoding of a forget policy ('' means the default policy).

    Only a :class:`ForgetPolicy` (or None) is encodable: the ledger is append-only and
    MAC-chained, so an entry :func:`decode_forget_policy` could not read back would be
    permanent."""
    if policy is None or policy == ForgetPolicy():
        return ""
    if not isinstance(policy, ForgetPolicy):
        raise ValidationError("a forget policy must be a ForgetPolicy")
    return canonical_json(policy)


def decode_forget_policy(raw: str | None) -> ForgetPolicy | None:
    """The policy a ledger entry or tombstone recorded (None: the default policy).

    An entry whose recorded policy is valid JSON but not a policy object was written by an
    earlier build that did not validate the argument (``policy=True``); the ledger authenticated
    it, so it is applied with the default policy (the one that deletes derived data and
    suppresses relearning) instead of wedging every later reconcile. Unparseable JSON is not
    something any build wrote and stays an integrity failure."""
    if not raw:
        return None
    try:
        values = json.loads(raw)
    except ValueError as exc:
        raise IntegrityError("a recorded forget policy is malformed") from exc
    if not isinstance(values, dict):
        return ForgetPolicy()
    known = {f.name for f in dataclasses.fields(ForgetPolicy)}
    # ForgetPolicy refuses non-bools now, so only an earlier build can have recorded e.g. "false".
    # That build applied the value by truthiness (it deleted / suppressed); a replay must do what
    # the forget did - every field set this way errs toward deleting more - and must not wedge
    # reconciliation on an authenticated entry.
    return ForgetPolicy(**{k: bool(v) for k, v in values.items() if k in known})


def new_id(prefix: str = "") -> str:
    return prefix + secrets.token_hex(12)


def caller_binding(access: AccessContext | None, *, grants: bool = False) -> str:
    """Identity an idempotency record is bound to (``''`` = unbound, internal callers).

    A stored receipt is replayed only to the same principal acting as the same actor;
    with ``grants=True`` (forget receipts, whose counts are scoped to the caller's
    grants) also only under the same grants and admin standing.
    """
    if access is None:
        return ""
    parts = [access.principal, access.actor.value]
    if grants:
        parts += [access.grants.fingerprint(), "admin" if Operation.ADMIN in access.operations else ""]
    return canonical_json(parts)


def require_partition(access: Any, partition: Partition) -> None:
    """A service bound to one partition serves only access contexts of that partition.

    ``engine.services(access)`` returns the services of ``access.partition``; that object
    can be kept and handed a context for another partition (another security domain).
    """
    if not isinstance(access, AccessContext):
        raise AccessDenied("a trusted AccessContext is required")
    if access.partition.partition_id != partition.partition_id:
        raise AccessDenied("the access context belongs to a different partition")


# Every class decorated with :func:`partition_bound` (a meta-test walks them).
PARTITION_BOUND_CLASSES: list[type] = []


def _may_take_access(func: Callable[..., Any]) -> bool:
    """Whether a method can be handed an AccessContext: a parameter whose name says so
    (``access``, ``conn_or_access``, ...) or whose annotation is AccessContext (``report_to``)."""
    try:
        params = inspect.signature(func).parameters.values()
    except (TypeError, ValueError):
        return True  # unknown shape: check at run time
    return any("access" in p.name.lower() or "AccessContext" in str(p.annotation) for p in params)


def partition_bound(cls: type) -> type:
    """Class decorator: every public method that can receive an access context checks that the
    context belongs to the service's partition.

    A method whose ``access`` parameter comes first (or right after ``conn``) requires one there.
    Any other public method that can be handed a context - whatever its parameter is called
    (``conn_or_access``, ``report_to``, a keyword ``access``) - checks every AccessContext it
    receives at run time, so a renamed parameter can never silently skip the check.
    """
    for name, func in list(vars(cls).items()):
        if name.startswith("_") or not inspect.isfunction(func):
            continue
        try:
            params = list(inspect.signature(func).parameters)
        except (TypeError, ValueError):
            params = []
        if len(params) >= 2 and params[1] == "access":
            setattr(cls, name, _bind_partition(func, 0))
        elif len(params) >= 3 and params[1] == "conn" and params[2] == "access":
            setattr(cls, name, _bind_partition(func, 1))
        elif _may_take_access(func):
            setattr(cls, name, _bind_partition_any(func))
    if cls not in PARTITION_BOUND_CLASSES:
        PARTITION_BOUND_CLASSES.append(cls)
    return cls


def _bound_partition(service: Any) -> Partition:
    return getattr(service, "p", None) or service.ctx.partition


def _bind_partition(func: Callable[..., Any], position: int) -> Callable[..., Any]:
    @functools.wraps(func)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        access = args[position] if len(args) > position else kwargs.get("access")
        require_partition(access, _bound_partition(self))
        return func(self, *args, **kwargs)
    wrapper.__partition_check__ = "required"  # type: ignore[attr-defined]
    return wrapper


def _bind_partition_any(func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(func)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        for value in (*args, *kwargs.values()):
            if isinstance(value, AccessContext):
                require_partition(value, _bound_partition(self))
        return func(self, *args, **kwargs)
    wrapper.__partition_check__ = "any"  # type: ignore[attr-defined]
    return wrapper


_MISSING_DB_WITH_LEDGER = ("deletion ledger present but main database missing; restore the database"
                           " (the ledger must not be deleted: it prevents forgotten data from returning)")


def _ledger_has_entries(path: Path) -> bool:
    """Whether a deletion ledger file records any deletion (read-only, no key needed)."""
    if not path.is_file():
        return False
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return True  # unreadable: assume it matters (never initialize over it)
    try:
        exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ledger'").fetchone()
        if not exists:
            return False
        return conn.execute("SELECT 1 FROM ledger LIMIT 1").fetchone() is not None
    except sqlite3.Error:
        return True
    finally:
        conn.close()


class Partition:
    DB_NAME = "memory.sqlite3"
    LEDGER_NAME = "deletion-ledger.sqlite3"

    def __init__(self, root: Path, ref: PartitionRef, provider: KeyProvider, *,
                 mirror: LedgerMirror | None = None, clock: Callable[[], float] = time.time,
                 busy_timeout_ms: int = 5_000, create: bool = True) -> None:
        """Open the partition's vault under ``root``.

        With ``create=False`` only an existing, initialized vault is opened: a missing
        database (or one that holds no schema yet) raises :class:`NotFound` before any
        directory, database or key is created, so a mistyped profile can never yield a
        fresh, empty vault with new keys.
        """
        self.ref = ref
        self.partition_id = ref.partition_id
        self.dir = Path(root) / self.partition_id
        self.clock = clock
        self.mirror = mirror
        self.keyring = PartitionKeyring(self.partition_id, provider)
        db_path = self.dir / self.DB_NAME
        db_existed = db_path.is_file()
        if not create and not db_existed:
            raise NotFound("no vault exists for this partition (partition creation is disabled)")
        if not db_existed and _ledger_has_entries(self.dir / self.LEDGER_NAME):
            # A vault exists (its deletion ledger records forgets) but its database is missing -
            # being restored, evicted by sync, moved. Initializing fresh keys here would leave a
            # database whose keys can never authenticate that ledger; refuse before creating anything.
            raise IntegrityError(_MISSING_DB_WITH_LEDGER)
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        if not db_existed:
            try:
                self._create_vault(db_path, busy_timeout_ms)
            except BaseException:
                self.keyring.close()
                raise
        self.db = Database(self.dir / self.DB_NAME, busy_timeout_ms=busy_timeout_ms)
        self._lock = threading.RLock()
        self.ledger: DeletionLedger | None = None
        self.reconciled = False
        self.last_reconcile: dict[str, Any] = {}
        self.pending_reconciliation: list[Any] = []
        # A forget whose WAL checkpoint could not complete (a concurrent reader), or a deletion
        # applied without one (reconcile after a crash, a failed apply, another process): the
        # purged pages may still be on disk. Persisted in meta and retried until it completes.
        self.pending_purge_checkpoint = False
        try:
            with self.db.write() as conn:
                if not create and schema.current_version(conn) == 0:
                    # An empty or schema-less file is not a vault; never initialize keys for it.
                    raise NotFound("no vault exists for this partition (partition creation is disabled)")
                if schema.current_version(conn) == 0 and _ledger_has_entries(self.dir / self.LEDGER_NAME):
                    raise IntegrityError("deletion ledger present but main database is empty; restore the"
                                         " database (the ledger must not be deleted)")
                before, _ = schema.migrate(conn, partition_id=self.partition_id)
                if before == 0:
                    self.keyring.initialize(conn)
            with self.db.read() as conn:
                self.keyring.unlock(conn)
                # Also pending: deletions committed but never covered by a completed checkpoint
                # (a process died between its purge and its checkpoint).
                self.pending_purge_checkpoint = (schema.get_meta(conn, "pending_purge_checkpoint") == "1"
                                                 or self.deletion_generation(conn)
                                                 > self.purge_checkpointed_generation(conn))
            self.ledger = DeletionLedger(self.dir / self.LEDGER_NAME,
                                         lambda s: self.keyring.token("ledger", s), clock=self.clock)
            self.ledger.verify()
        except BaseException:
            # Wrong/missing key, tampered ledger, foreign or newer store: release every handle.
            # Nothing is deleted: the database at ``db_path`` may be another opener's vault (it
            # can be created and written between any check here and this failure), and a vault
            # this opener created was published fully keyed (``_create_vault``), so the next open
            # with the right key simply uses it.
            self.close()
            raise

    def _create_vault(self, db_path: Path, busy_timeout_ms: int) -> None:
        """Create a new vault without ever exposing a half-initialized database.

        The schema and keys are written to a private staging file first, which is then published
        at ``db_path`` with an atomic hard link that fails if a database already exists there. A
        concurrent first opener therefore either publishes its own fully keyed vault or finds the
        other one and opens it; a failure here removes only this opener's staging file, never a
        database someone else may already be using.
        """
        staging = db_path.with_name(f".{db_path.name}.{secrets.token_hex(8)}.creating")
        store = Database(staging, busy_timeout_ms=busy_timeout_ms, wal=False)
        try:
            with store.write() as conn:
                schema.migrate(conn, partition_id=self.partition_id)
                self.keyring.initialize(conn)
            store.close()
            if not db_path.exists() and _ledger_has_entries(self.dir / self.LEDGER_NAME):
                raise IntegrityError(_MISSING_DB_WITH_LEDGER)  # a vault's ledger appeared meanwhile
            try:
                os.link(staging, db_path)
            except FileExistsError:
                pass  # another opener published its vault first: open that one
            except OSError:
                if not db_path.exists():  # no hard links on this filesystem
                    os.rename(staging, db_path)
        finally:
            store.close()
            for suffix in ("", "-journal", "-wal", "-shm"):
                try:
                    Path(str(staging) + suffix).unlink()
                except OSError:
                    pass

    # ------------------------------------------------------------------ crypto helpers
    def seal_json(self, table: str, row_id: str, fields: dict[str, Any], value: Any
                  ) -> tuple[str, bytes, bytes]:
        """Seal under the database's *current* DEK (call inside the write transaction).

        Another process may have rotated the data key; sealing with a stale cached
        DEK could later strand rows under a retired key, so the current DEK id is
        re-read (a primary-key lookup) and the keyring reloaded when it changed.
        """
        current = schema.get_meta(self.db.conn, "current_dek_id")
        if current and current != self.keyring.current_dek_id:
            self.reload_keys()
        plaintext = canonical_json(value).encode()
        return self.keyring.seal(table, row_id, fields, plaintext)

    def open_json(self, table: str, row_id: str, fields: dict[str, Any], dek_id: str,
                  nonce: bytes, ciphertext: bytes) -> Any:
        if dek_id and not self.keyring.has_dek(dek_id):
            self.reload_keys()  # a DEK created by another process since we unlocked
            if not self.keyring.has_dek(dek_id):
                known = self.db.conn.execute(
                    "SELECT 1 FROM key_wraps WHERE dek_id=? AND purpose='data' LIMIT 1", (dek_id,)
                ).fetchone()
                if known is None:
                    raise IntegrityError("a stored record references a data key this vault does not have")
        plaintext = self.keyring.open(table, row_id, fields, dek_id, nonce, ciphertext)
        try:
            return json.loads(plaintext)
        except ValueError as exc:
            raise IntegrityError("a stored record is malformed") from exc

    def token(self, purpose: str, value: str) -> str:
        return self.keyring.token(purpose, value)

    def reload_keys(self) -> None:
        """Re-read key wraps (after a rotation by this or another process)."""
        self.keyring.unlock(self.db.conn)

    # ------------------------------------------------------------------ meta
    def generation(self, conn: sqlite3.Connection | None = None) -> int:
        conn = conn or self.db.conn
        return int(schema.get_meta(conn, "generation", "0") or 0)

    def deletion_generation(self, conn: sqlite3.Connection | None = None) -> int:
        conn = conn or self.db.conn
        return int(schema.get_meta(conn, "deletion_generation", "0") or 0)

    def bump(self, conn: sqlite3.Connection) -> int:
        return schema.bump(conn, "generation")

    def event(self, conn: sqlite3.Connection, stage: str, outcome: str, reason: str = "") -> None:
        now = self.clock()
        conn.execute(
            "INSERT INTO events(stage, outcome, reason_code, occurred_at) VALUES(?,?,?,?)",
            (stage[:64], outcome[:64], reason[:128], now),
        )
        conn.execute("DELETE FROM events WHERE occurred_at < ?", (now - 90 * 86_400,))
        conn.execute(
            "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id DESC LIMIT -1 OFFSET 20000)"
        )

    # ------------------------------------------------------------------ receipts
    def make_receipt(self, conn: sqlite3.Connection, operation: str, status: str, *,
                     record_ids: tuple[str, ...] = (), revisions: tuple[int, ...] = (),
                     details: dict[str, Any] | None = None,
                     limitations: tuple[str, ...] = (), persist: bool = True) -> Receipt:
        receipt = Receipt(
            receipt_id=new_id("r"), operation=operation, status=status,
            created_at=self.clock(), partition_id=self.partition_id,
            record_ids=record_ids, revisions=revisions, generation=self.generation(conn),
            details=dict(details or {}), limitations=limitations,
        )
        if persist:
            self.save_receipt(conn, receipt)
        return receipt

    def save_receipt(self, conn: sqlite3.Connection, receipt: Receipt) -> None:
        fields = {"operation": receipt.operation}
        dek, nonce, ct = self.seal_json("receipts", receipt.receipt_id, fields, receipt.to_dict())
        conn.execute(
            "INSERT OR REPLACE INTO receipts(id, operation, created_at, dek_id, nonce, ciphertext)"
            " VALUES(?,?,?,?,?,?)",
            (receipt.receipt_id, receipt.operation, receipt.created_at, dek, nonce, ct),
        )

    def load_receipt(self, conn: sqlite3.Connection, receipt_id: str) -> dict[str, Any] | None:
        row = conn.execute("SELECT * FROM receipts WHERE id=?", (receipt_id,)).fetchone()
        if row is None:
            return None
        return self.open_json("receipts", row["id"], {"operation": row["operation"]},
                              row["dek_id"], row["nonce"], row["ciphertext"])

    # ------------------------------------------------------------------ idempotency
    # Rows hold only keyed tokens: ``key_token`` binds operation, caller and key;
    # ``request_hash`` is a keyed HMAC of the request (an unkeyed digest would let anyone
    # holding the file confirm guessed content offline - even after it was forgotten).
    # ``idempotency_records`` links a row to the records its receipt created so forgetting
    # can detach it (the row then replays as "no longer exists").
    FORGOTTEN_RECEIPT = ""

    def _idempotency_token(self, operation: str, key: str, caller: str) -> str:
        return self.token("idempotency", f"{operation}|{key}" if not caller else
                          canonical_json(["v2", operation, caller, key]))

    def _request_hash(self, operation: str, request: Any) -> str:
        return self.token("idempotency-request", f"{operation}|" + canonical_json(request))

    def idempotency_lookup(self, conn: sqlite3.Connection, key: str | None, operation: str,
                           request: Any, *, caller: str = "") -> dict[str, Any] | None:
        if not key:
            return None
        token = self._idempotency_token(operation, key, caller)
        row = conn.execute("SELECT * FROM idempotency WHERE key_token=?", (token,)).fetchone()
        if row is None:
            return None
        if row["operation"] != operation or not hmac.compare_digest(
                str(row["request_hash"]), self._request_hash(operation, request)):
            raise IdempotencyConflict("idempotency key was already used for a different request")
        if row["receipt_id"] == self.FORGOTTEN_RECEIPT:
            raise NotFound("the memory created by this idempotency key no longer exists")
        return self.load_receipt(conn, row["receipt_id"])

    def idempotency_token(self, operation: str, key: str | None, *, caller: str = "") -> str | None:
        return self._idempotency_token(operation, key, caller) if key else None

    def request_hash(self, operation: str, request: Any) -> str:
        return self._request_hash(operation, request)

    def idempotency_store(self, conn: sqlite3.Connection, key: str | None, operation: str,
                          request: Any, receipt: Receipt, *, caller: str = "") -> None:
        if not key:
            return
        self.idempotency_store_token(conn, self._idempotency_token(operation, key, caller), operation,
                                     self._request_hash(operation, request), receipt)

    def idempotency_store_token(self, conn: sqlite3.Connection, token: str, operation: str,
                                request_hash: str, receipt: Receipt) -> None:
        """Store an idempotency row from precomputed keyed tokens (ledger replay)."""
        conn.execute(
            "INSERT OR IGNORE INTO idempotency(key_token, operation, request_hash, receipt_id, created_at)"
            " VALUES(?,?,?,?,?)",
            (token, operation, request_hash, receipt.receipt_id, self.clock()),
        )
        conn.executemany("INSERT OR IGNORE INTO idempotency_records(key_token, record_id) VALUES(?,?)",
                         [(token, rid) for rid in dict.fromkeys(receipt.record_ids)])

    # ------------------------------------------------------------------ in-flight forget requests
    # A forget records its request (sealed: the caller's access, the target's kind - never its
    # ref -, policy, keyed idempotency tokens) in the ledger file *before* its write-ahead append, then binds it to the appended
    # generation. Whoever applies that entry - the forget itself, a concurrent forget replaying
    # earlier entries, or reconciliation in any process after a failed/contended apply - applies
    # it with the original caller's access and records the receipt (and idempotency row) for it,
    # so the caller (or its retry) gets the real receipt. Rows are dropped once applied.
    _REQUESTS_DDL = (
        "CREATE TABLE IF NOT EXISTS forget_requests(marker_id TEXT PRIMARY KEY, generation INTEGER UNIQUE,"
        " target_kind TEXT NOT NULL, target_token TEXT NOT NULL, policy TEXT NOT NULL, key_token TEXT,"
        " created_at REAL NOT NULL, dek_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL)",
        "CREATE INDEX IF NOT EXISTS forget_requests_key ON forget_requests(key_token)",
        "CREATE INDEX IF NOT EXISTS forget_requests_target ON forget_requests(target_kind, target_token)",
    )
    _REQUEST_COLUMNS = "marker_id, generation, target_kind, target_token, policy, key_token, dek_id, nonce, ciphertext"

    def _requests_conn(self) -> sqlite3.Connection | None:
        if self.ledger is None:
            return None
        conn = self.ledger.db.conn
        if not getattr(self, "_requests_ready", False):
            for statement in self._REQUESTS_DDL:
                conn.execute(statement)
            self._requests_ready = True
        return conn

    def record_forget_request(self, kind: str, token: str, policy: str, key_token: str | None,
                              payload: dict[str, Any]) -> str | None:
        """Record a forget request before its ledger append; returns the marker id."""
        conn = self._requests_conn()
        if conn is None:
            return None
        marker = new_id("q")
        dek, nonce, ct = self.seal_json("forget_requests", marker, {"kind": kind, "token": token,
                                                                     "key": key_token or ""}, payload)
        conn.execute("INSERT INTO forget_requests(marker_id, generation, target_kind, target_token, policy,"
                     " key_token, created_at, dek_id, nonce, ciphertext) VALUES(?,NULL,?,?,?,?,?,?,?,?)",
                     (marker, kind, token, policy or "", key_token, self.clock(), dek, nonce, ct))
        return marker

    def bind_forget_request(self, marker: str | None, generation: int) -> None:
        conn = self._requests_conn()
        if conn is not None and marker:
            conn.execute("UPDATE forget_requests SET generation=? WHERE marker_id=? AND generation IS NULL",
                         (int(generation), marker))

    def _open_request(self, row: sqlite3.Row | tuple) -> dict[str, Any] | None:
        marker, _generation, kind, token, _policy, key_token, dek, nonce, ct = tuple(row)
        try:
            value = self.open_json("forget_requests", marker, {"kind": kind, "token": token,
                                                               "key": key_token or ""}, dek, nonce, ct)
        except Exception:  # a request that no longer opens degrades to an unattributed replay
            return None
        return value if isinstance(value, dict) else None

    def forget_request(self, generation: int, kind: str, token: str, policy: str = "") -> dict[str, Any] | None:
        """The request that wrote ledger entry ``generation`` (claiming a not-yet-bound request
        for the same target when the writer had not bound it yet)."""
        conn = self._requests_conn()
        if conn is None:
            return None
        row = conn.execute(f"SELECT {self._REQUEST_COLUMNS} FROM forget_requests WHERE generation=?",
                           (int(generation),)).fetchone()
        if row is None:
            row = conn.execute(
                f"SELECT {self._REQUEST_COLUMNS} FROM forget_requests WHERE generation IS NULL AND target_kind=?"
                " AND target_token=? AND policy=? ORDER BY created_at, marker_id LIMIT 1",
                (kind, token, policy or "")).fetchone()
            if row is None:
                return None
            try:
                claimed = conn.execute("UPDATE forget_requests SET generation=? WHERE marker_id=? AND"
                                       " generation IS NULL", (int(generation), row[0])).rowcount
            except sqlite3.Error:
                claimed = 0
            if not claimed:
                return None
        return self._open_request(row)

    def pending_forget_request(self, key_token: str | None) -> tuple[int, dict[str, Any]] | None:
        """The newest bound request carrying ``key_token`` (an earlier attempt of a retry)."""
        conn = self._requests_conn()
        if conn is None or not key_token:
            return None
        row = conn.execute(f"SELECT {self._REQUEST_COLUMNS} FROM forget_requests WHERE key_token=?"
                           " AND generation IS NOT NULL ORDER BY generation DESC LIMIT 1", (key_token,)).fetchone()
        if row is None:
            return None
        value = self._open_request(row)
        return None if value is None else (int(row[1]), value)

    # An unbound request older than this was left by a forget whose ledger append never happened
    # (failed or crashed); an in-flight one is bound within the store's bounded busy wait.
    UNBOUND_REQUEST_TTL_S = 600.0

    def drop_forget_requests(self, *, upto: int) -> None:
        """Drop requests whose entries are applied (and unbound ones a failed append left behind).

        The sealed request names the caller's grants: the ledger WAL frames that still hold it
        are folded and truncated by the next :meth:`flush_purged` (which every forget and
        reconcile runs after this)."""
        conn = self._requests_conn()
        if conn is not None:
            try:
                conn.execute("DELETE FROM forget_requests WHERE generation<=? OR"
                             " (generation IS NULL AND created_at < ?)",
                             (int(upto), self.clock() - self.UNBOUND_REQUEST_TTL_S))
            except sqlite3.OperationalError:
                pass  # busy: dropped by a later forget or reconcile

    def detach_forgotten_idempotency(self, conn: sqlite3.Connection) -> int:
        """Unlink idempotency rows from records that no longer exist (inside a forget)."""
        tokens = [r[0] for r in conn.execute(
            "SELECT DISTINCT key_token FROM idempotency_records WHERE record_id NOT IN (SELECT id FROM records)")]
        if not tokens:
            return 0
        for start in range(0, len(tokens), 500):
            chunk = tokens[start:start + 500]
            marks = ",".join("?" * len(chunk))
            conn.execute(f"UPDATE idempotency SET receipt_id=? WHERE key_token IN ({marks})",
                         [self.FORGOTTEN_RECEIPT, *chunk])
            conn.execute(f"DELETE FROM idempotency_records WHERE key_token IN ({marks})", chunk)
        return len(tokens)

    # ------------------------------------------------------------------ deletion reconciliation
    def record_tombstone(self, conn: sqlite3.Connection, kind: str, token: str, generation: int,
                         created_at: float, policy: str = "") -> None:
        """Insert or advance a tombstone; never moves its generation backwards."""
        conn.execute(
            "INSERT OR IGNORE INTO tombstones(target_kind, target_token, generation, created_at, policy)"
            " VALUES(?,?,?,?,?)", (kind, token, generation, created_at, policy),
        )
        conn.execute(
            "UPDATE tombstones SET generation=?, created_at=?, policy=?"
            " WHERE target_kind=? AND target_token=? AND generation<?",
            (generation, created_at, policy, kind, token, generation),
        )

    def advance_deletion_generation(self, conn: sqlite3.Connection, generation: int) -> int:
        """Set ``deletion_generation`` to ``max(current, generation)``; returns the new value."""
        value = max(self.deletion_generation(conn), int(generation))
        schema.set_meta(conn, "deletion_generation", str(value))
        return value

    def apply_ledger_entries(self, conn: sqlite3.Connection, apply: TombstoneApplier,
                             entries: list[LedgerEntry]) -> int:
        """Apply ledger entries (with their recorded policy) inside the caller's write tx."""
        for entry in entries:
            policy = decode_forget_policy(entry.policy)
            if policy is None:
                apply(conn, entry.target_kind, entry.target_token, entry.generation)
            else:
                apply(conn, entry.target_kind, entry.target_token, entry.generation, policy)
            self.record_tombstone(conn, entry.target_kind, entry.target_token, entry.generation,
                                  entry.created_at, entry.policy)
        if entries:
            self.advance_deletion_generation(conn, max(e.generation for e in entries))
        return len(entries)

    def needs_reconcile(self) -> bool:
        """True when this handle must reconcile before serving (cheap: two indexed lookups).

        Covers a failed apply in this process and a crash of another process between
        its ledger append and its main-database apply.
        """
        if not self.reconciled or self.ledger is None:
            return True
        return self.ledger.head()[0] > self.deletion_generation()

    def reconcile(self, apply: TombstoneApplier, *, acknowledge_mirror_gap: bool = False) -> dict[str, Any]:
        """Bring the main database up to the newest known deletion state before serving."""
        report: dict[str, Any] = {"reapplied": 0, "adopted_into_ledger": 0}
        if self.ledger is None:
            raise IntegrityError("the deletion ledger is not open")
        with self._lock:
            self.reconciled = False
            ledger_gen, ledger_mac = self.ledger.head()
            main_gen = self.deletion_generation()
            if ledger_gen > main_gen:
                with self.db.write() as conn:
                    # Re-read inside the transaction: another process may have applied some.
                    entries = self.ledger.since(self.deletion_generation(conn))
                    applied = self.apply_ledger_entries(conn, apply, entries)
                    if applied:
                        self.bump(conn)
                        self.event(conn, "reconcile", "reapplied", f"{applied}")
                report["reapplied"] = applied
            elif main_gen > ledger_gen:
                rows = self.db.conn.execute(
                    "SELECT generation, target_kind, target_token, created_at, policy FROM tombstones"
                    " WHERE generation > ? AND policy <> ?", (ledger_gen, DERIVED_TOMBSTONE_POLICY),
                ).fetchall()
                self.ledger.adopt([(int(r[0]), r[1], r[2], float(r[3]), r[4] or "") for r in rows])
                report["adopted_into_ledger"] = len(rows)
            head_gen, head_mac = self.ledger.head()
            self.drop_forget_requests(upto=self.deletion_generation())
            # Entries applied here (a crashed or failed forget, another process's, a restore)
            # purged rows: their pages must leave the disk exactly as after a live forget.
            self.ensure_purged()
            if self.mirror is not None:
                mirrored = self.mirror.read(self.partition_id)
                if mirrored is not None and mirrored[0] > head_gen:
                    if not acknowledge_mirror_gap:
                        raise ReconciliationRequired(
                            "this store and its ledger are older than the newest recorded deletion state;"
                            " restore the newer ledger or explicitly acknowledge the gap",
                            details={"known_generation": mirrored[0], "local_generation": head_gen},
                        )
                    # Persist the acknowledgement: advance ledger and store past the mirrored
                    # generation, otherwise every later open would raise again.
                    marker = self.ledger.append([(GAP_ACKNOWLEDGED_KIND, "acknowledged")],
                                                min_generation=mirrored[0] - 1)[0]
                    with self.db.write() as conn:
                        self.record_tombstone(conn, marker.target_kind, marker.target_token,
                                              marker.generation, marker.created_at)
                        self.advance_deletion_generation(conn, marker.generation)
                        self.event(conn, "reconcile", "gap_acknowledged")
                    self.ensure_purged()
                    report["acknowledged_gap"] = {"known_generation": mirrored[0],
                                                  "local_generation": head_gen}
                    head_gen, head_mac = self.ledger.head()
                self.mirror.write(self.partition_id, head_gen, head_mac)
            report["deletion_generation"] = head_gen
            self.last_reconcile = dict(report)
            self.reconciled = True
        return report

    # ------------------------------------------------------------------ physical purge
    def purge_checkpointed_generation(self, conn: sqlite3.Connection | None = None) -> int:
        """The deletion generation up to which a completed checkpoint removed purged pages from
        the disk (``meta.purge_checkpointed_generation``)."""
        conn = conn or self.db.conn
        try:
            return int(schema.get_meta(conn, "purge_checkpointed_generation", "0") or 0)
        except ValueError:
            return 0

    def _checkpoint_all(self, *, wait: bool) -> bool:
        """Fold and truncate the WALs of the main database and of the ledger file (which holds
        the sealed forget requests until they are dropped)."""
        main = self.db.checkpoint(wait=wait)
        ledger = self.ledger is None or self.ledger.db.checkpoint(wait=wait)
        return main and ledger

    def flush_purged(self, *, attempts: int = 2, wait: bool = True) -> bool:
        """Checkpoint the WALs after a purge so purged pages leave the disk.

        Retries a busy checkpoint (a concurrent reader) with bounded backoff. When it
        still cannot complete, the partition records ``pending_purge_checkpoint`` (in
        memory and durably in meta) and :meth:`retry_purge_checkpoint` keeps trying on
        later calls, on open and on close. A completed checkpoint records the deletion
        generation it covered (``purge_checkpointed_generation``), so a replayed receipt
        can tell whether its purge has reached the disk. Returns whether it completed.
        """
        try:
            covered = self.deletion_generation()  # read first: what a checkpoint now covers
        except Exception:
            covered = 0
        for attempt in range(max(1, attempts)):
            # Only the first attempt waits for readers (busy_timeout); retries never block.
            if self._checkpoint_all(wait=wait and attempt == 0):
                self._record_purge_state(pending=False, covered=covered)
                return True
            if attempt + 1 < attempts:
                time.sleep(min(0.02 * (2 ** attempt), 0.2))
        self._record_purge_state(pending=True)
        return False

    def _record_purge_state(self, *, pending: bool, covered: int = 0) -> None:
        was_pending, self.pending_purge_checkpoint = self.pending_purge_checkpoint, pending
        try:
            if pending:
                if not was_pending:
                    with self.db.write() as conn:
                        schema.set_meta(conn, "pending_purge_checkpoint", "1")
                return
            if not was_pending and covered <= self.purge_checkpointed_generation():
                return
            with self.db.write() as conn:
                conn.execute("DELETE FROM meta WHERE key='pending_purge_checkpoint'")
                if covered > self.purge_checkpointed_generation(conn):
                    schema.set_meta(conn, "purge_checkpointed_generation", str(int(covered)))
        except Exception:  # the in-memory flag still drives retries in this process
            return
        if not pending:
            # Recording the state wrote a frame; fold it in too (best effort, never waits).
            self.db.checkpoint(wait=False)

    def ensure_purged(self) -> bool:
        """Checkpoint (without waiting for readers) when deletions were committed that no
        completed checkpoint covers yet; a reader leaves it pending (retried on later calls,
        on open and on close). True when nothing is left to flush."""
        try:
            behind = self.deletion_generation() > self.purge_checkpointed_generation()
        except Exception:
            behind = True
        if not behind and not self.pending_purge_checkpoint:
            return True
        return self.flush_purged(attempts=2, wait=False)

    def purge_complete(self, generation: int) -> bool:
        """Whether the physical purge of the deletion at ``generation`` reached the disk (for a
        replayed receipt). Tries a non-blocking checkpoint when it has not yet."""
        try:
            if int(generation) <= self.purge_checkpointed_generation():
                return True
        except Exception:
            pass
        return self.flush_purged(attempts=1, wait=False)

    def retry_purge_checkpoint(self) -> bool:
        """Cheap, non-blocking retry of a pending post-forget checkpoint."""
        if not self.pending_purge_checkpoint:
            return True
        return self.flush_purged(attempts=1, wait=False)

    def close(self) -> None:
        if self.pending_purge_checkpoint and self.ledger is not None:
            try:
                self.flush_purged(attempts=1)
            except Exception:
                pass
        self.keyring.close()
        self.db.close()
        if self.ledger is not None:
            self.ledger.close()
