"""Append-only deletion ledger kept in a separate file from the partition database.

Deletions are written here *first* (write-ahead), then applied to the main
database. On open, the partition reconciles: any ledger generation newer than
the main database's ``deletion_generation`` is re-applied before data is served.
Restoring an old main-database backup therefore cannot resurrect forgotten data
as long as the ledger (or the host's ledger mirror) is newer.

Entries carry only keyed tokens - never content. Each entry's MAC chains to the
previous one so edits or holes in the middle are detected; tail truncation is
detectable only with a host-held high-water mark (:class:`LedgerMirror`).
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
    def __init__(self, path: Path, mac: Callable[[str], str]) -> None:
        self.db = Database(path)
        self._mac = mac
        with self.db.write() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ledger(
                    generation INTEGER PRIMARY KEY, target_kind TEXT NOT NULL,
                    target_token TEXT NOT NULL, created_at REAL NOT NULL, mac TEXT NOT NULL)"""
            )

    def _entry_mac(self, prev: str, generation: int, kind: str, token: str, created_at: float) -> str:
        return self._mac(f"{prev}|{generation}|{kind}|{token}|{created_at!r}")

    def head(self) -> tuple[int, str]:
        row = self.db.conn.execute(
            "SELECT generation, mac FROM ledger ORDER BY generation DESC LIMIT 1"
        ).fetchone()
        return (int(row[0]), str(row[1])) if row else (0, "")

    def append(self, entries: list[tuple[str, str]], *, min_generation: int = 0) -> list[LedgerEntry]:
        """Durably append (kind, token) entries; returns them with assigned generations."""
        out: list[LedgerEntry] = []
        with self.db.write() as conn:
            row = conn.execute(
                "SELECT generation, mac FROM ledger ORDER BY generation DESC LIMIT 1"
            ).fetchone()
            generation, prev = (int(row[0]), str(row[1])) if row else (0, "")
            generation = max(generation, min_generation)
            for kind, token in entries:
                generation += 1
                now = time.time()
                mac = self._entry_mac(prev, generation, kind, token, now)
                conn.execute(
                    "INSERT INTO ledger(generation, target_kind, target_token, created_at, mac)"
                    " VALUES(?,?,?,?,?)", (generation, kind, token, now, mac),
                )
                out.append(LedgerEntry(generation, kind, token, now, mac))
                prev = mac
        return out

    def since(self, generation: int) -> list[LedgerEntry]:
        rows = self.db.conn.execute(
            "SELECT generation, target_kind, target_token, created_at, mac FROM ledger"
            " WHERE generation > ? ORDER BY generation", (generation,),
        ).fetchall()
        return [LedgerEntry(int(r[0]), r[1], r[2], float(r[3]), r[4]) for r in rows]

    def verify(self) -> int:
        """Verify the MAC chain; returns the number of entries. Raises IntegrityError."""
        prev = ""
        count = 0
        last_generation = 0
        for r in self.db.conn.execute(
            "SELECT generation, target_kind, target_token, created_at, mac FROM ledger ORDER BY generation"
        ):
            generation = int(r[0])
            if generation <= last_generation:
                raise IntegrityError("deletion ledger order is corrupt")
            if self._entry_mac(prev, generation, r[1], r[2], float(r[3])) != r[4]:
                raise IntegrityError("deletion ledger failed authentication")
            prev = r[4]
            last_generation = generation
            count += 1
        return count

    def adopt(self, entries: list[tuple[int, str, str, float]]) -> None:
        """Re-append entries known only to the main database (ledger was rolled back)."""
        with self.db.write() as conn:
            row = conn.execute(
                "SELECT generation, mac FROM ledger ORDER BY generation DESC LIMIT 1"
            ).fetchone()
            last, prev = (int(row[0]), str(row[1])) if row else (0, "")
            for generation, kind, token, created_at in sorted(entries):
                if generation <= last:
                    continue
                mac = self._entry_mac(prev, generation, kind, token, created_at)
                try:
                    conn.execute(
                        "INSERT INTO ledger(generation, target_kind, target_token, created_at, mac)"
                        " VALUES(?,?,?,?,?)", (generation, kind, token, created_at, mac),
                    )
                except sqlite3.IntegrityError:
                    continue
                prev, last = mac, generation

    def close(self) -> None:
        self.db.close()
