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

Format 2 entries (every entry this build writes) also authenticate an ``extra``
mapping (e.g. that the legacy importer issued the forget only to propagate a legacy
deletion) under a domain-separated MAC; format 1 entries (earlier builds) still verify.

Outcomes: after an entry is applied, the main database's derived deletion state - the
ids of every record the deletion removed, the suppression keys and the source aliases
it recorded - is kept here too (``ledger_outcomes``, keyed tokens and opaque ids only),
each MACed and bound to its entry. The main database's copy is plaintext; on every
reconcile it is rebuilt from these, and a removed record found in the main database
again (an older backup mixed with newer deletion state) is removed again.
"""
from __future__ import annotations

import json
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
    extra: str = ""  # canonical JSON of authenticated entry attributes ('' = none; format 2 only)

    def extras(self) -> dict:
        """The authenticated ``extra`` mapping ({} when none or unreadable)."""
        if not self.extra:
            return {}
        try:
            value = json.loads(self.extra)
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def encode_extra(values: dict | None) -> str:
    """Canonical ``extra`` column value ('' for none)."""
    return _canonical(values) if values else ""


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
        # Set by verify(): the first generation written in format 2 (by a build that keeps the
        # authenticated deletion checkpoint in the main database), None when there is none.
        self.first_v2_generation: int | None = None
        with self.db.write() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ledger(
                    generation INTEGER PRIMARY KEY, target_kind TEXT NOT NULL,
                    target_token TEXT NOT NULL, created_at REAL NOT NULL, mac TEXT NOT NULL,
                    policy TEXT NOT NULL DEFAULT '', extra TEXT NOT NULL DEFAULT '')"""
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(ledger)")}
            if "policy" not in columns:  # ledger written before policies were recorded
                conn.execute("ALTER TABLE ledger ADD COLUMN policy TEXT NOT NULL DEFAULT ''")
            if "extra" not in columns:  # ledger written before format 2
                conn.execute("ALTER TABLE ledger ADD COLUMN extra TEXT NOT NULL DEFAULT ''")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ledger_outcomes(
                    generation INTEGER PRIMARY KEY, payload TEXT NOT NULL, mac TEXT NOT NULL)"""
            )

    def _entry_mac(self, prev: str, generation: int, kind: str, token: str, created_at: float,
                   policy: str = "", extra: str = "", *, version: int = 2) -> str:
        if version == 2:
            return self._mac("ledger-v2|" + _canonical([prev, generation, kind, token, repr(float(created_at)),
                                                         policy, extra]))
        base = f"{prev}|{generation}|{kind}|{token}|{created_at!r}"
        # Entries without a recorded policy keep the original MAC input (format compatibility).
        return self._mac(base + f"|{policy}" if policy else base)

    def _entry_version(self, prev: str, generation: int, kind: str, token: str, created_at: float,
                       policy: str, extra: str, mac: str) -> int | None:
        """2 or 1 when ``mac`` authenticates the entry in that format (format 1 cannot carry an
        ``extra``), else None."""
        if self._entry_mac(prev, generation, kind, token, created_at, policy, extra) == mac:
            return 2
        if not extra and self._entry_mac(prev, generation, kind, token, created_at, policy, version=1) == mac:
            return 1
        return None

    def head(self) -> tuple[int, str]:
        row = self.db.conn.execute(
            "SELECT generation, mac FROM ledger ORDER BY generation DESC LIMIT 1"
        ).fetchone()
        return (int(row[0]), str(row[1])) if row else (0, "")

    def append(self, entries: list[tuple[str, ...]], *, min_generation: int = 0) -> list[LedgerEntry]:
        """Durably append ``(kind, token)``, ``(kind, token, policy)`` or ``(kind, token, policy,
        extra)`` entries (format 2).

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
                extra = str(item[3]) if len(item) > 3 and item[3] else ""
                generation += 1
                now = float(self._clock())
                mac = self._entry_mac(prev, generation, kind, token, now, policy, extra)
                conn.execute(
                    "INSERT INTO ledger(generation, target_kind, target_token, created_at, mac, policy, extra)"
                    " VALUES(?,?,?,?,?,?,?)", (generation, kind, token, now, mac, policy, extra),
                )
                out.append(LedgerEntry(generation, kind, token, now, mac, policy, extra))
                prev = mac
        return out

    _COLUMNS = "generation, target_kind, target_token, created_at, mac, policy, extra"

    @staticmethod
    def _entry(r: sqlite3.Row | tuple) -> LedgerEntry:
        return LedgerEntry(int(r[0]), r[1], r[2], float(r[3]), r[4], r[5] or "", r[6] or "")

    def since(self, generation: int) -> list[LedgerEntry]:
        rows = self.db.conn.execute(
            f"SELECT {self._COLUMNS} FROM ledger WHERE generation > ? ORDER BY generation", (generation,),
        ).fetchall()
        return [self._entry(r) for r in rows]

    def verified_entries(self) -> list[LedgerEntry]:
        """Every entry, after verifying the whole MAC chain (raises IntegrityError like
        :meth:`verify`); also sets ``first_v2_generation``."""
        prev = ""
        last_generation = 0
        first_v2: int | None = None
        out: list[LedgerEntry] = []
        for r in self.db.conn.execute(f"SELECT {self._COLUMNS} FROM ledger ORDER BY generation"):
            entry = self._entry(r)
            if entry.generation <= last_generation:
                raise IntegrityError("deletion ledger order is corrupt")
            version = self._entry_version(prev, entry.generation, entry.target_kind, entry.target_token,
                                          entry.created_at, entry.policy, entry.extra, entry.mac)
            if version is None:
                raise IntegrityError("deletion ledger failed authentication")
            if version == 2 and first_v2 is None:
                first_v2 = entry.generation
            prev = entry.mac
            last_generation = entry.generation
            out.append(entry)
        self.first_v2_generation = first_v2
        return out

    def verify(self) -> int:
        """Verify the MAC chain; returns the number of entries. Raises IntegrityError."""
        return len(self.verified_entries())

    # ------------------------------------------------------------------ outcomes
    def _outcome_mac(self, generation: int, entry_mac: str, payload: str) -> str:
        return self._mac("ledger-outcome|" + _canonical([int(generation), entry_mac, payload]))

    def record_outcome(self, entry: LedgerEntry, outcome: dict) -> None:
        """Keep what applying ``entry`` removed and recorded (opaque ids, keyed tokens), bound to the
        entry. Inside a write transaction this thread already holds on the ledger (a rollback's
        append barrier) it is written there; otherwise in its own transaction."""
        payload = _canonical(outcome)
        row = (int(entry.generation), payload, self._outcome_mac(entry.generation, entry.mac, payload))
        sql = "INSERT OR REPLACE INTO ledger_outcomes(generation, payload, mac) VALUES(?,?,?)"
        conn = self.db.conn
        if conn.in_transaction:
            conn.execute(sql, row)
            return
        with self.db.write() as conn:
            conn.execute(sql, row)

    def outcomes(self, entries: list[LedgerEntry]) -> dict[int, dict]:
        """The authenticated outcomes of ``entries`` (generation -> outcome); rows that do not verify
        against their entry are ignored."""
        macs = {entry.generation: entry.mac for entry in entries}
        out: dict[int, dict] = {}
        for generation, payload, mac in self.db.conn.execute("SELECT generation, payload, mac FROM ledger_outcomes"):
            entry_mac = macs.get(int(generation))
            if entry_mac is None or self._outcome_mac(int(generation), entry_mac, payload) != mac:
                continue
            try:
                value = json.loads(payload)
            except ValueError:
                continue
            if isinstance(value, dict):
                out[int(generation)] = value
        return out

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
                        "INSERT INTO ledger(generation, target_kind, target_token, created_at, mac, policy, extra)"
                        " VALUES(?,?,?,?,?,?,'')", (generation, kind, token, created_at, mac, policy),
                    )
                except sqlite3.IntegrityError:
                    continue
                prev, last = mac, generation

    def close(self) -> None:
        self.db.close()
