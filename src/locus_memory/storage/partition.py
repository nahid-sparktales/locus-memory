"""One security partition: its database, keyring, deletion ledger and shared helpers."""
from __future__ import annotations

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
from ..models import PartitionRef, Receipt, canonical_json, content_hash
from . import schema
from .db import Database
from .ledger import DeletionLedger, LedgerMirror

# (conn, target_kind, target_token, generation) -> None ; registered by the forgetting service.
TombstoneApplier = Callable[[sqlite3.Connection, str, str, int], None]


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
        with self.db.write() as conn:
            before, _ = schema.migrate(conn, partition_id=self.partition_id)
            if before == 0:
                self.keyring.initialize(conn)
        with self.db.read() as conn:
            self.keyring.unlock(conn)
        self.ledger = DeletionLedger(self.dir / self.LEDGER_NAME, lambda s: self.keyring.token("ledger", s))
        self.ledger.verify()
        self.reconciled = False
        self.pending_reconciliation: list[Any] = []

    # ------------------------------------------------------------------ crypto helpers
    def seal_json(self, table: str, row_id: str, fields: dict[str, Any], value: Any
                  ) -> tuple[str, bytes, bytes]:
        plaintext = canonical_json(value).encode()
        return self.keyring.seal(table, row_id, fields, plaintext)

    def open_json(self, table: str, row_id: str, fields: dict[str, Any], dek_id: str,
                  nonce: bytes, ciphertext: bytes) -> Any:
        plaintext = self.keyring.open(table, row_id, fields, dek_id, nonce, ciphertext)
        try:
            return json.loads(plaintext)
        except ValueError as exc:
            raise IntegrityError("a stored record is malformed") from exc

    def token(self, purpose: str, value: str) -> str:
        return self.keyring.token(purpose, value)

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
    def reconcile(self, apply: TombstoneApplier, *, acknowledge_mirror_gap: bool = False) -> dict[str, Any]:
        """Bring the main database up to the newest known deletion state before serving."""
        report: dict[str, Any] = {"reapplied": 0, "adopted_into_ledger": 0}
        with self._lock:
            ledger_gen, ledger_mac = self.ledger.head()
            main_gen = self.deletion_generation()
            if ledger_gen > main_gen:
                entries = self.ledger.since(main_gen)
                with self.db.write() as conn:
                    for entry in entries:
                        apply(conn, entry.target_kind, entry.target_token, entry.generation)
                        conn.execute(
                            "INSERT OR REPLACE INTO tombstones(target_kind, target_token, generation, created_at)"
                            " VALUES(?,?,?,?)",
                            (entry.target_kind, entry.target_token, entry.generation, entry.created_at),
                        )
                    schema.set_meta(conn, "deletion_generation", str(ledger_gen))
                    self.bump(conn)
                    self.event(conn, "reconcile", "reapplied", f"{len(entries)}")
                report["reapplied"] = len(entries)
            elif main_gen > ledger_gen:
                rows = self.db.conn.execute(
                    "SELECT generation, target_kind, target_token, created_at FROM tombstones"
                    " WHERE generation > ?", (ledger_gen,),
                ).fetchall()
                self.ledger.adopt([(int(r[0]), r[1], r[2], float(r[3])) for r in rows])
                report["adopted_into_ledger"] = len(rows)
            head_gen, head_mac = self.ledger.head()
            if self.mirror is not None:
                mirrored = self.mirror.read(self.partition_id)
                if mirrored is not None and mirrored[0] > head_gen and not acknowledge_mirror_gap:
                    raise ReconciliationRequired(
                        "this store and its ledger are older than the newest recorded deletion state;"
                        " restore the newer ledger or explicitly acknowledge the gap",
                        details={"known_generation": mirrored[0], "local_generation": head_gen},
                    )
                self.mirror.write(self.partition_id, head_gen, head_mac)
            report["deletion_generation"] = head_gen
            self.reconciled = True
        return report

    def close(self) -> None:
        self.keyring.close()
        self.db.close()
        self.ledger.close()
