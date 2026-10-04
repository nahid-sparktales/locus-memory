"""Durable canonical-ownership state machine with writer fencing.

One authoritative writer exists per (security partition, record family) at every
state. The control file lives beside the partition directories
(``<root>/control.sqlite3``) and is written with BEGIN IMMEDIATE + compare-and-swap
on ``ownership_generation`` so two migrators cannot both advance it.

    state                  authoritative   permitted writers   crash recovery
    legacy_authoritative   legacy          legacy              n/a
    shadow_prepared        legacy          legacy              re-run import (idempotent)
    validated              legacy          legacy              re-validate or abort
    cutover_in_progress    (quiesced)      none                finish (delta+verify) or abort to legacy
    package_authoritative  package         package             n/a
    rollback_in_progress   (quiesced)      none                finish reverse sync, then legacy
    legacy_retired         package         package             terminal

Reverting storage ownership is never a feature flag: it goes through
``rollback_in_progress`` and the reverse-sync protocol in ``migrations.rollback``.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..errors import OwnershipFenced, RevisionConflict, ValidationError
from ..storage.db import Database

STATES = (
    "legacy_authoritative", "shadow_prepared", "validated", "cutover_in_progress",
    "package_authoritative", "rollback_in_progress", "legacy_retired",
)
FAMILIES = ("memories", "context_snapshots", "skill_observations")

TRANSITIONS: dict[str, frozenset[str]] = {
    "legacy_authoritative": frozenset({"shadow_prepared"}),
    "shadow_prepared": frozenset({"validated", "legacy_authoritative"}),
    "validated": frozenset({"cutover_in_progress", "shadow_prepared", "legacy_authoritative"}),
    "cutover_in_progress": frozenset({"package_authoritative", "legacy_authoritative"}),
    "package_authoritative": frozenset({"rollback_in_progress", "legacy_retired"}),
    "rollback_in_progress": frozenset({"legacy_authoritative", "package_authoritative"}),
    "legacy_retired": frozenset(),
}

WRITERS: dict[str, frozenset[str]] = {
    "legacy_authoritative": frozenset({"legacy"}),
    "shadow_prepared": frozenset({"legacy"}),
    "validated": frozenset({"legacy"}),
    "cutover_in_progress": frozenset(),
    "package_authoritative": frozenset({"package"}),
    "rollback_in_progress": frozenset(),
    "legacy_retired": frozenset({"package"}),
}

AUTHORITATIVE: dict[str, str | None] = {
    "legacy_authoritative": "legacy", "shadow_prepared": "legacy", "validated": "legacy",
    "cutover_in_progress": None, "package_authoritative": "package",
    "rollback_in_progress": None, "legacy_retired": "package",
}


@dataclass(frozen=True)
class OwnershipRecord:
    partition_id: str
    family: str
    state: str
    generation: int
    updated_at: float
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def authoritative(self) -> str | None:
        return AUTHORITATIVE[self.state]

    @property
    def writers(self) -> frozenset[str]:
        return WRITERS[self.state]

    def to_dict(self) -> dict[str, Any]:
        return {"partition_id": self.partition_id, "family": self.family, "state": self.state,
                "generation": self.generation, "updated_at": self.updated_at,
                "authoritative": self.authoritative, "permitted_writers": sorted(self.writers),
                "details": self.details}


class OwnershipControl:
    FILE = "control.sqlite3"

    def __init__(self, root: Path | str, *, clock=time.time) -> None:
        self.db = Database(Path(root) / self.FILE)
        self.clock = clock
        with self.db.write() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ownership(
                    partition_id TEXT NOT NULL, family TEXT NOT NULL, state TEXT NOT NULL,
                    generation INTEGER NOT NULL, updated_at REAL NOT NULL, details TEXT NOT NULL,
                    PRIMARY KEY(partition_id, family))"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ownership_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, partition_id TEXT NOT NULL, family TEXT NOT NULL,
                    from_state TEXT NOT NULL, to_state TEXT NOT NULL, generation INTEGER NOT NULL,
                    at REAL NOT NULL, reason TEXT NOT NULL)"""
            )

    @staticmethod
    def _check(family: str, state: str | None = None) -> None:
        if family not in FAMILIES:
            raise ValidationError(f"unknown record family {family!r}")
        if state is not None and state not in STATES:
            raise ValidationError(f"unknown ownership state {state!r}")

    def get(self, partition_id: str, family: str = "memories") -> OwnershipRecord:
        self._check(family)
        row = self.db.conn.execute(
            "SELECT * FROM ownership WHERE partition_id=? AND family=?", (partition_id, family)
        ).fetchone()
        if row is None:
            return OwnershipRecord(partition_id, family, "legacy_authoritative", 0, 0.0, {})
        return OwnershipRecord(row["partition_id"], row["family"], row["state"], int(row["generation"]),
                               float(row["updated_at"]), json.loads(row["details"]))

    def transition(self, partition_id: str, family: str, target: str, *, expected_generation: int,
                   reason: str, details: dict[str, Any] | None = None) -> OwnershipRecord:
        self._check(family, target)
        with self.db.write() as conn:
            row = conn.execute(
                "SELECT state, generation, details FROM ownership WHERE partition_id=? AND family=?",
                (partition_id, family),
            ).fetchone()
            current = row["state"] if row else "legacy_authoritative"
            generation = int(row["generation"]) if row else 0
            if generation != expected_generation:
                raise RevisionConflict("ownership changed concurrently",
                                       details={"expected": expected_generation, "current": generation})
            if target not in TRANSITIONS[current]:
                raise ValidationError(f"ownership cannot move from {current} to {target}")
            merged = {**(json.loads(row["details"]) if row else {}), **(details or {})}
            now = self.clock()
            conn.execute(
                "INSERT OR REPLACE INTO ownership(partition_id, family, state, generation, updated_at, details)"
                " VALUES(?,?,?,?,?,?)",
                (partition_id, family, target, generation + 1, now, json.dumps(merged, sort_keys=True)),
            )
            conn.execute(
                "INSERT INTO ownership_log(partition_id, family, from_state, to_state, generation, at, reason)"
                " VALUES(?,?,?,?,?,?,?)", (partition_id, family, current, target, generation + 1, now, reason[:200]),
            )
        return self.get(partition_id, family)

    def update_details(self, partition_id: str, family: str, *, expected_generation: int,
                       details: dict[str, Any] | None = None,
                       append: dict[str, list[Any]] | None = None) -> OwnershipRecord:
        """Merge ``details`` into the record's details, and append the items of ``append`` (each
        key a list, items already present skipped), without a state change: compare-and-swap on the
        ownership generation (a concurrent transition wins and this raises RevisionConflict), the
        generation itself is unchanged (it fences writers, and no fence moved). What a step records
        *before* it acts (e.g. a migration snapshot about to be written) is known afterwards whatever
        happens to the step."""
        self._check(family)
        with self.db.write() as conn:
            row = conn.execute(
                "SELECT state, generation, updated_at, details FROM ownership WHERE partition_id=? AND family=?",
                (partition_id, family),
            ).fetchone()
            generation = int(row["generation"]) if row else 0
            if generation != expected_generation:
                raise RevisionConflict("ownership changed concurrently",
                                       details={"expected": expected_generation, "current": generation})
            merged = {**(json.loads(row["details"]) if row else {}), **(details or {})}
            for key, items in (append or {}).items():
                current = merged.get(key)
                values = list(current) if isinstance(current, list) else []
                values += [item for item in items if item not in values]
                merged[key] = values
            conn.execute(
                "INSERT OR REPLACE INTO ownership(partition_id, family, state, generation, updated_at, details)"
                " VALUES(?,?,?,?,?,?)",
                (partition_id, family, row["state"] if row else "legacy_authoritative", generation,
                 float(row["updated_at"]) if row else 0.0, json.dumps(merged, sort_keys=True)),
            )
        return self.get(partition_id, family)

    def assert_writer(self, partition_id: str, family: str, writer: str) -> OwnershipRecord:
        record = self.get(partition_id, family)
        if writer not in record.writers:
            raise OwnershipFenced(
                f"{writer} writes to {family} are fenced while ownership is {record.state}",
                details={"state": record.state, "generation": record.generation},
            )
        return record

    def writer_guard(self, partition_id: str, family: str, writer: str):
        """A zero-argument callable for LegacyMemoryVault(write_guard=...) and similar hooks."""
        def guard() -> None:
            self.assert_writer(partition_id, family, writer)
        return guard

    def history(self, partition_id: str, family: str = "memories") -> list[dict[str, Any]]:
        rows = self.db.conn.execute(
            "SELECT from_state, to_state, generation, at, reason FROM ownership_log"
            " WHERE partition_id=? AND family=? ORDER BY id", (partition_id, family)).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        self.db.close()
