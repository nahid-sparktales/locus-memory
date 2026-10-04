"""Shadow preparation, validation, cutover, crash recovery and rollback orchestration.

Protocol (memories family, one partition):

1. ``prepare_shadow``  legacy_authoritative -> shadow_prepared
   encrypted snapshot + manifest, import *from the snapshot* (live file untouched).
2. ``validate``        shadow_prepared -> validated
   delta import from the live legacy file (read-only), full decrypt/compare verify.
3. ``cutover``         validated -> cutover_in_progress -> package_authoritative
   fence legacy writers (durable state change; ``writer_guard`` now raises), drain
   in-flight host work via the host's ``quiesce`` hook, final delta, verify. Any
   failure before the final transition aborts to legacy_authoritative; no package
   write has been accepted yet, so nothing is lost.
4. ``resume``          finishes or aborts an interrupted cutover / rollback.
5. ``rollback``        package_authoritative -> rollback_in_progress -> legacy_authoritative
   reverse-sync representable records (keeping post-cutover corrections and
   deletions); refuses when records exist that the legacy format cannot represent
   unless ``allow_partial`` - then the package store is kept as a read-only
   recovery source and the report lists what stayed there.

There is no dual-write: exactly one writer is permitted at every state.
"""
from __future__ import annotations

import contextlib
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..compat.legacy_vault import LegacyMemoryVault, legacy_agent_hash
from ..errors import MigrationError
from ..models import AccessContext, Lifecycle, MemoryKind, MemoryRecord, Operation
from . import legacy as legacy_mod
from .state import OwnershipControl

LEGACY_KINDS = {MemoryKind.PREFERENCE, MemoryKind.FACT, MemoryKind.DECISION, MemoryKind.PROCEDURE,
                MemoryKind.RELATIONSHIP}


class SimulatedCrash(RuntimeError):
    """Raised by test crash points."""


class Migrator:
    FAMILY = "memories"

    def __init__(self, engine, control: OwnershipControl, access: AccessContext, legacy_db: Path, key: bytes,
                 mapping: legacy_mod.LegacyMapping | None = None, *, work_dir: Path,
                 project_workspaces: dict[str, str] | None = None) -> None:
        if Operation.ADMIN not in access.operations:
            raise MigrationError("migration requires an admin access context")
        self.engine = engine
        self.control = control
        self.access = access
        self.legacy_db = Path(legacy_db)
        self.key = key
        self.mapping = mapping or legacy_mod.LegacyMapping()
        self.work_dir = Path(work_dir)
        # project id -> workspace path, needed to write project memories back during rollback.
        self.project_workspaces = dict(project_workspaces or {})
        self.partition_id = access.partition.partition_id
        self.crash_at: str | None = None  # test hook

    # ------------------------------------------------------------------ helpers
    def _crash(self, point: str) -> None:
        if self.crash_at == point:
            raise SimulatedCrash(point)

    def state(self):
        return self.control.get(self.partition_id, self.FAMILY)

    def _move(self, target: str, reason: str, **details: Any):
        current = self.state()
        return self.control.transition(self.partition_id, self.FAMILY, target,
                                       expected_generation=current.generation, reason=reason, details=details)

    def _import(self, source: Path) -> dict[str, Any]:
        return legacy_mod.LegacyImporter(self.engine, self.access, source, self.key, self.mapping).run()

    # ------------------------------------------------------------------ steps
    def prepare_shadow(self) -> dict[str, Any]:
        if self.state().state != "legacy_authoritative":
            raise MigrationError(f"prepare_shadow requires legacy_authoritative, not {self.state().state}")
        snap_dir = self.work_dir / f"snapshot-{int(time.time() * 1000)}"
        manifest = legacy_mod.snapshot(self.legacy_db, snap_dir)
        self._crash("after_snapshot")
        report = self._import(snap_dir / manifest["snapshot_file"])
        self._crash("after_shadow_import")
        record = self._move("shadow_prepared", "shadow import complete", snapshot_dir=str(snap_dir),
                            snapshot_rows=manifest["rows"])
        return {"state": record.state, "manifest_rows": manifest["rows"], "import": report}

    def validate(self, *, queries: list[str] | None = None) -> dict[str, Any]:
        if self.state().state != "shadow_prepared":
            raise MigrationError(f"validate requires shadow_prepared, not {self.state().state}")
        delta = self._import(self.legacy_db)
        result = legacy_mod.verify(self.engine, self.access, self.legacy_db, self.key, self.mapping, queries=queries)
        if not result["ok"]:
            return {"state": self.state().state, "validated": False, "delta": delta, "verify": result}
        record = self._move("validated", "verification passed", verified_records=result["checked"])
        return {"state": record.state, "validated": True, "delta": delta, "verify": result}

    def cutover(self, *, quiesce: Callable[[], Any] | None = None, queries: list[str] | None = None
                ) -> dict[str, Any]:
        if self.state().state != "validated":
            raise MigrationError(f"cutover requires validated, not {self.state().state}")
        self._move("cutover_in_progress", "fencing legacy writers")
        self._crash("after_fence")
        return self._finish_cutover(quiesce=quiesce, queries=queries)

    def _finish_cutover(self, *, quiesce: Callable[[], Any] | None, queries: list[str] | None) -> dict[str, Any]:
        try:
            with (quiesce() if quiesce is not None else contextlib.nullcontext()):
                delta = self._import(self.legacy_db)
                self._crash("after_final_delta")
                result = legacy_mod.verify(self.engine, self.access, self.legacy_db, self.key, self.mapping,
                                           queries=queries)
        except legacy_mod.MigrationError as exc:
            self._move("legacy_authoritative", f"cutover aborted: {exc.code}")
            raise
        if not result["ok"]:
            record = self._move("legacy_authoritative", "cutover aborted: verification failed")
            return {"state": record.state, "cutover": False, "verify": result, "delta": delta}
        self._crash("before_authoritative")
        record = self._move("package_authoritative", "cutover complete", cutover_at=time.time())
        return {"state": record.state, "cutover": True, "verify": result, "delta": delta}

    def resume(self, *, quiesce: Callable[[], Any] | None = None) -> dict[str, Any]:
        state = self.state().state
        if state == "cutover_in_progress":
            return self._finish_cutover(quiesce=quiesce, queries=None)
        if state == "rollback_in_progress":
            return self._finish_rollback(allow_partial=bool(self.state().details.get("allow_partial")))
        return {"state": state, "resumed": False}

    # ------------------------------------------------------------------ rollback
    def _legacy_shape(self, record: MemoryRecord) -> tuple[str, str] | None:
        """(legacy scope, target hash) or None when the legacy format cannot represent it."""
        if record.kind not in LEGACY_KINDS:
            return None
        dims = record.scope.as_dict()
        if not dims:
            return "personal", "personal"
        if len(dims) != 1:
            return None
        (dim, value), = dims.items()
        if dim == "legacy_target":
            prefix = value.split(":", 1)[0]
            return (prefix, value) if prefix in {"workspace", "agent"} else None
        if dim == "agent":
            return "agent", "agent:" + legacy_agent_hash(value)
        if dim == "project":
            for digest, project in self.mapping.workspaces.items():
                if project == value:
                    return "workspace", "workspace:" + digest
        return None

    def plan_rollback(self) -> dict[str, Any]:
        ctx = self.engine.partition_context(self.access.partition)
        representable: list[str] = []
        unrepresentable: Counter[str] = Counter()
        with ctx.partition.db.read() as conn:
            for row in conn.execute("SELECT id FROM records").fetchall():
                record = ctx.records.get(conn, row[0])
                if record is None:
                    continue
                if record.lifecycle in (Lifecycle.REJECTED, Lifecycle.EXPIRED):
                    representable.append(record.id)  # represented as absence in the legacy store
                    continue
                if self._legacy_shape(record) is None:
                    unrepresentable[f"{record.kind.value}:{'+'.join(record.scope.as_dict()) or 'global'}"] += 1
                else:
                    representable.append(record.id)
            tombstones = conn.execute("SELECT COUNT(*) FROM tombstones WHERE target_kind='memory'").fetchone()[0]
            history = conn.execute("SELECT COUNT(*) FROM history_messages").fetchone()[0]
        if history:
            unrepresentable["session_history_messages"] = history
        return {"representable": len(representable), "unrepresentable": dict(unrepresentable),
                "memory_tombstones": tombstones, "safe": not unrepresentable}

    def rollback(self, *, allow_partial: bool = False) -> dict[str, Any]:
        if self.state().state != "package_authoritative":
            raise MigrationError(f"rollback requires package_authoritative, not {self.state().state}")
        plan = self.plan_rollback()
        if not plan["safe"] and not allow_partial:
            raise MigrationError(
                "rollback refused: the legacy store cannot represent some records; "
                "pass allow_partial to keep them in a read-only package recovery store",
                details={"unrepresentable": plan["unrepresentable"]},
            )
        self._move("rollback_in_progress", "reverse sync", allow_partial=allow_partial)
        self._crash("after_rollback_fence")
        return self._finish_rollback(allow_partial=allow_partial)

    def _finish_rollback(self, *, allow_partial: bool) -> dict[str, Any]:
        ctx = self.engine.partition_context(self.access.partition)
        vault = LegacyMemoryVault(self.legacy_db, key=self.key)  # migration actor: unguarded on purpose
        counts: Counter[str] = Counter()
        with ctx.partition.db.read() as conn:
            records = [r for r in (ctx.records.get(conn, row[0]) for row in conn.execute("SELECT id FROM records"))
                       if r is not None]
            tombstoned = {row[0] for row in conn.execute(
                "SELECT target_token FROM tombstones WHERE target_kind='memory'")}
        legacy_rows = {row["id"]: row for row in vault.raw_rows()}
        for record_id in tombstoned & set(legacy_rows):
            vault.delete(record_id)
            counts["deleted_forgotten"] += 1
        for record in records:
            if record.lifecycle in (Lifecycle.REJECTED, Lifecycle.EXPIRED):
                if record.id in legacy_rows and vault.delete(record.id):
                    counts["deleted_rejected_or_expired"] += 1
                continue
            shape = self._legacy_shape(record)
            if shape is None:
                counts["kept_in_package_only"] += 1
                continue
            scope, target = shape
            value = {
                "title": record.title, "content": record.content, "tags": list(record.tags),
                "scope": scope, "status": "candidate" if record.lifecycle == Lifecycle.CANDIDATE else "approved",
                "kind": record.kind.value, "reason": record.reason, "pinned": record.retention.pinned,
                "stale": record.lifecycle in (Lifecycle.STALE, Lifecycle.SUPERSEDED),
                "confidence": record.confidence.value if record.confidence.value is not None else 1.0,
                "valid_from": record.validity.valid_from, "valid_until": record.validity.valid_until,
                "supersedes": list(record.links.supersedes),
                "provenance": record.extra.get("legacy_provenance") or {},
            }
            existing = legacy_rows.get(record.id)
            if existing is not None:
                current = vault.open_row(existing)
                same = (current["content"] == record.content and current["title"] == record.title
                        and current["status"] == value["status"] and bool(current["stale"]) == value["stale"]
                        and current["superseded_by"] == record.links.superseded_by)
                if same:
                    counts["unchanged"] += 1
                    continue
            vault.save(value, record.id, _target_override=target,
                       _created_at=record.created_at if existing is None else None)
            if record.links.superseded_by:
                with vault._connect() as conn:  # column not settable through save()
                    conn.execute("UPDATE memories SET superseded_by=? WHERE id=?",
                                 (record.links.superseded_by, record.id))
            counts["written_back" if existing is not None else "restored"] += 1
        self._crash("before_rollback_complete")
        record = self._move("legacy_authoritative", "rollback complete",
                            package_readonly_recovery=bool(counts.get("kept_in_package_only")),
                            rolled_back_at=time.time())
        return {"state": record.state, "counts": dict(counts),
                "package_readonly_recovery": bool(counts.get("kept_in_package_only")),
                "limitations": ["records only the package can represent remain in the package store and are "
                                "not visible through the legacy API"] if counts.get("kept_in_package_only") else []}
