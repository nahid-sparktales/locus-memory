"""Append-only deletion ledger kept in a separate file from the partition database.

Deletions are written here *first* (write-ahead), then applied to the main
database. On open, the partition reconciles: any ledger generation newer than
the main database's ``deletion_generation`` is re-applied before data is served.
Restoring an old main-database backup therefore cannot resurrect forgotten data
as long as the ledger (or the host's ledger mirror) is newer.

Entries carry only keyed tokens and the forget policy flags - never content.
Each entry's MAC chains to the previous one and covers the policy, so edits or
holes in the middle are detected; tail truncation is detectable only with a
host-held high-water mark (:class:`LedgerMirror`). Replaying an entry (after a
crash or a restore) applies the same policy the user chose originally.
"""
from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..errors import IntegrityError
from .db import Database


@dataclass(frozen=True)
class LedgerEntry:
    generation: int
    target_kind: str
    target_token: str
    created_at: float
    mac: str
    policy: str = ""  # canonical JSON of the ForgetPolicy ('' = default policy)


@runtime_checkable
class LedgerMirror(Protocol):
    """Host-held high-water mark (e.g. stored in the Keychain) that survives file restores."""

    def read(self, partition_id: str) -> tuple[int, str] | None: ...

    def write(self, partition_id: str, generation: int, mac: str) -> None: ...


class MemoryLedgerMirror:
    def __init__(self) -> None:
        self.values: dict[str, tuple[int, str]] = {}

    def read(self, partition_id: str) -> tuple[int, str] | None:
        return self.values.get(partition_id)

    def write(self, partition_id: str, generation: int, mac: str) -> None:
        current = self.values.get(partition_id)
        if current is None or generation >= current[0]:
            self.values[partition_id] = (generation, mac)


class DeletionLedger:
    def __init__(self, path: Path, mac: Callable[[str], str], *, clock: Callable[[], float] = time.time) -> None:
        self.db = Database(path)
        self._mac = mac
        # Entry (and so tombstone) times use the same clock as the records they delete: a
        # tombstone's created_at is compared with record and legacy-row creation times.
        self._clock = clock
        with self.db.write() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ledger(
                    generation INTEGER PRIMARY KEY, target_kind TEXT NOT NULL,
                    target_token TEXT NOT NULL, created_at REAL NOT NULL, mac TEXT NOT NULL,
                    policy TEXT NOT NULL DEFAULT '')"""
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(ledger)")}
            if "policy" not in columns:  # ledger written before policies were recorded
                conn.execute("ALTER TABLE ledger ADD COLUMN policy TEXT NOT NULL DEFAULT ''")

    def _entry_mac(self, prev: str, generation: int, kind: str, token: str, created_at: float,
                   policy: str = "") -> str:
        base = f"{prev}|{generation}|{kind}|{token}|{created_at!r}"
        # Entries without a recorded policy keep the original MAC input (format compatibility).
        return self._mac(base + f"|{policy}" if policy else base)

    def head(self) -> tuple[int, str]:
        row = self.db.conn.execute(
            "SELECT generation, mac FROM ledger ORDER BY generation DESC LIMIT 1"
        ).fetchone()
        return (int(row[0]), str(row[1])) if row else (0, "")

    def append(self, entries: list[tuple[str, ...]], *, min_generation: int = 0) -> list[LedgerEntry]:
        """Durably append ``(kind, token)`` or ``(kind, token, policy)`` entries.

        Returns them with assigned generations (strictly above the current head and
        ``min_generation``).
        """
        out: list[LedgerEntry] = []
        with self.db.write() as conn:
            row = conn.execute(
                "SELECT generation, mac FROM ledger ORDER BY generation DESC LIMIT 1"
            ).fetchone()
            generation, prev = (int(row[0]), str(row[1])) if row else (0, "")
            generation = max(generation, min_generation)
            for item in entries:
                kind, token = item[0], item[1]
                policy = str(item[2]) if len(item) > 2 and item[2] else ""
                generation += 1
                now = float(self._clock())
                mac = self._entry_mac(prev, generation, kind, token, now, policy)
                conn.execute(
                    "INSERT INTO ledger(generation, target_kind, target_token, created_at, mac, policy)"
                    " VALUES(?,?,?,?,?,?)", (generation, kind, token, now, mac, policy),
                )
                out.append(LedgerEntry(generation, kind, token, now, mac, policy))
                prev = mac
        return out

    def since(self, generation: int) -> list[LedgerEntry]:
        rows = self.db.conn.execute(
            "SELECT generation, target_kind, target_token, created_at, mac, policy FROM ledger"
            " WHERE generation > ? ORDER BY generation", (generation,),
        ).fetchall()
        return [LedgerEntry(int(r[0]), r[1], r[2], float(r[3]), r[4], r[5] or "") for r in rows]

    def verify(self) -> int:
        """Verify the MAC chain; returns the number of entries. Raises IntegrityError."""
        prev = ""
        count = 0
        last_generation = 0
        for r in self.db.conn.execute(
            "SELECT generation, target_kind, target_token, created_at, mac, policy FROM ledger"
            " ORDER BY generation"
        ):
            generation = int(r[0])
            if generation <= last_generation:
                raise IntegrityError("deletion ledger order is corrupt")
            if self._entry_mac(prev, generation, r[1], r[2], float(r[3]), r[5] or "") != r[4]:
                raise IntegrityError("deletion ledger failed authentication")
            prev = r[4]
            last_generation = generation
            count += 1
        return count

    def adopt(self, entries: list[tuple]) -> None:
        """Re-append entries known only to the main database (ledger was rolled back).

        Each entry is ``(generation, kind, token, created_at[, policy])``.
        """
        with self.db.write() as conn:
            row = conn.execute(
                "SELECT generation, mac FROM ledger ORDER BY generation DESC LIMIT 1"
            ).fetchone()
            last, prev = (int(row[0]), str(row[1])) if row else (0, "")
            for item in sorted(entries, key=lambda e: e[0]):
                generation, kind, token, created_at = item[0], item[1], item[2], item[3]
                policy = str(item[4]) if len(item) > 4 and item[4] else ""
                if generation <= last:
                    continue
                mac = self._entry_mac(prev, generation, kind, token, created_at, policy)
                try:
                    conn.execute(
                        "INSERT INTO ledger(generation, target_kind, target_token, created_at, mac, policy)"
                        " VALUES(?,?,?,?,?,?)", (generation, kind, token, created_at, mac, policy),
                    )
                except sqlite3.IntegrityError:
                    continue
                prev, last = mac, generation

    def close(self) -> None:
        self.db.close()
