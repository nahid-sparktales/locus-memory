"""One security partition: its database, keyring, deletion ledger and shared helpers.

Deletion-state invariant: every ledger entry whose generation is at or below the
main database's ``deletion_generation`` has been applied to the main database.
``deletion_generation`` therefore only moves forward, and ``reconcile`` (run on
open and whenever :meth:`Partition.needs_reconcile` says so) applies the rest.
"""
from __future__ import annotations

import dataclasses
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
from ..errors import IdempotencyConflict, IntegrityError, ReconciliationRequired
from ..models import ForgetPolicy, PartitionRef, Receipt, canonical_json, content_hash
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


def encode_forget_policy(policy: ForgetPolicy | None) -> str:
    """Ledger/tombstone encoding of a forget policy ('' means the default policy)."""
    if policy is None or policy == ForgetPolicy():
        return ""
    return canonical_json(policy)


def decode_forget_policy(raw: str | None) -> ForgetPolicy | None:
    if not raw:
        return None
    try:
        values = json.loads(raw)
    except ValueError as exc:
        raise IntegrityError("a recorded forget policy is malformed") from exc
    if not isinstance(values, dict):
        raise IntegrityError("a recorded forget policy is malformed")
    known = {f.name for f in dataclasses.fields(ForgetPolicy)}
    return ForgetPolicy(**{k: bool(v) for k, v in values.items() if k in known})


def new_id(prefix: str = "") -> str:
    return prefix + secrets.token_hex(12)


class Partition:
    DB_NAME = "memory.sqlite3"
    LEDGER_NAME = "deletion-ledger.sqlite3"

    def __init__(self, root: Path, ref: PartitionRef, provider: KeyProvider, *,
                 mirror: LedgerMirror | None = None, clock: Callable[[], float] = time.time,
                 busy_timeout_ms: int = 5_000) -> None:
        self.ref = ref
        self.partition_id = ref.partition_id
        self.dir = Path(root) / self.partition_id
        self.clock = clock
        self.mirror = mirror
        self.keyring = PartitionKeyring(self.partition_id, provider)
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        self.db = Database(self.dir / self.DB_NAME, busy_timeout_ms=busy_timeout_ms)
        self._lock = threading.RLock()
        self.ledger: DeletionLedger | None = None
        self.reconciled = False
        self.last_reconcile: dict[str, Any] = {}
        self.pending_reconciliation: list[Any] = []
        try:
            with self.db.write() as conn:
                before, _ = schema.migrate(conn, partition_id=self.partition_id)
                if before == 0:
                    self.keyring.initialize(conn)
            with self.db.read() as conn:
                self.keyring.unlock(conn)
            self.ledger = DeletionLedger(self.dir / self.LEDGER_NAME,
                                         lambda s: self.keyring.token("ledger", s))
            self.ledger.verify()
        except BaseException:
            # Wrong/missing key, tampered ledger, foreign or newer store: release every handle.
            self.close()
            raise

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
    def idempotency_lookup(self, conn: sqlite3.Connection, key: str | None, operation: str,
                           request: Any) -> dict[str, Any] | None:
        if not key:
            return None
        token = self.token("idempotency", f"{operation}|{key}")
        row = conn.execute("SELECT * FROM idempotency WHERE key_token=?", (token,)).fetchone()
        if row is None:
            return None
        if row["operation"] != operation or row["request_hash"] != content_hash(request):
            raise IdempotencyConflict("idempotency key was already used for a different request")
        return self.load_receipt(conn, row["receipt_id"])

    def idempotency_store(self, conn: sqlite3.Connection, key: str | None, operation: str,
                          request: Any, receipt: Receipt) -> None:
        if not key:
            return
        token = self.token("idempotency", f"{operation}|{key}")
        conn.execute(
            "INSERT INTO idempotency(key_token, operation, request_hash, receipt_id, created_at)"
            " VALUES(?,?,?,?,?)",
            (token, operation, content_hash(request), receipt.receipt_id, self.clock()),
        )

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
                    " WHERE generation > ?", (ledger_gen,),
                ).fetchall()
                self.ledger.adopt([(int(r[0]), r[1], r[2], float(r[3]), r[4] or "") for r in rows])
                report["adopted_into_ledger"] = len(rows)
            head_gen, head_mac = self.ledger.head()
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
                    report["acknowledged_gap"] = {"known_generation": mirrored[0],
                                                  "local_generation": head_gen}
                    head_gen, head_mac = self.ledger.head()
                self.mirror.write(self.partition_id, head_gen, head_mac)
            report["deletion_generation"] = head_gen
            self.last_reconcile = dict(report)
            self.reconciled = True
        return report

    def close(self) -> None:
        self.keyring.close()
        self.db.close()
        if self.ledger is not None:
            self.ledger.close()
