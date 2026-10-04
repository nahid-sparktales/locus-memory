"""Shadow preparation, validation, cutover, crash recovery and rollback orchestration.

Protocol (memories family, one partition):

1. ``prepare_shadow``  legacy_authoritative -> shadow_prepared
   encrypted snapshot + manifest, import *from the snapshot* (live file untouched).
2. ``validate``        shadow_prepared -> validated
   delta import from the live legacy file (read-only), full decrypt/compare verify.
3. ``cutover``         validated -> cutover_in_progress -> package_authoritative
   fence legacy writers (durable state change; ``writer_guard`` now raises), drain
   in-flight host work via the host's ``quiesce`` hook, then hold the legacy file's
   write lock (a built-in barrier: a legacy write that passed its guard either commits
   before it - and is in the final delta - or re-checks the guard inside its own
   transaction and is fenced), final delta, verify. Any failure before the final
   transition (of any kind) aborts to legacy_authoritative; no package write has been
   accepted yet, so nothing is lost. ``abort_cutover`` is the operator's escape hatch.
4. ``resume``          finishes or aborts an interrupted cutover / rollback.
5. ``rollback``        package_authoritative -> rollback_in_progress -> legacy_authoritative
   with the package store's write lock held (no package write or forget commits
   mid-sync; pending deletions are applied first and re-checked before the final
   transition), reverse-sync representable records: every legacy row without a live
   package record is deleted (whatever forget removed it), changed records are written
   back field by field, expired data stays absent. Refuses when records exist that the
   legacy format cannot represent (governed procedures, transient retention, ...)
   unless ``allow_partial`` - then the package store is kept as a read-only recovery
   source and the report lists what stayed there.

There is no dual-write: exactly one writer is permitted at every state.
"""
from __future__ import annotations

import contextlib
import dataclasses
import sqlite3
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..compat.legacy_vault import LegacyMemoryVault, legacy_agent_hash
from ..errors import IntegrityError, MigrationError, WrongKey
from ..models import (
    AccessContext,
    Actor,
    Lifecycle,
    MemoryKind,
    MemoryRecord,
    Operation,
    SourceKind,
    SourceRef,
)
from . import legacy as legacy_mod
from .state import OwnershipControl

LEGACY_KINDS = {MemoryKind.PREFERENCE, MemoryKind.FACT, MemoryKind.DECISION, MemoryKind.PROCEDURE,
                MemoryKind.RELATIONSHIP}


class SimulatedCrash(RuntimeError):
    """Raised by test crash points."""


def abort_cutover(control: OwnershipControl, partition_id: str, reason: str = "operator abort") -> dict[str, Any]:
    """Operator escape hatch: an interrupted cutover that cannot be resumed (the legacy file is gone or
    corrupt) goes back to legacy_authoritative. Safe: no package write is accepted before the final
    transition. Requires no legacy file."""
    current = control.get(partition_id, Migrator.FAMILY)
    if current.state not in ("cutover_in_progress", "validated"):
        raise MigrationError(f"abort requires cutover_in_progress or validated, not {current.state}")
    record = control.transition(partition_id, Migrator.FAMILY, "legacy_authoritative",
                                expected_generation=current.generation, reason=f"cutover aborted: {reason}"[:200])
    return {"state": record.state, "aborted": True}


def _legacy_status_never_approved(ctx: Any, conn: sqlite3.Connection, record: MemoryRecord) -> bool:
    """A superseded record that never went through approval (a candidate resolved by supersede)."""
    if record.lifecycle != Lifecycle.SUPERSEDED:
        return False
    if record.extra.get("legacy_status") == "approved":
        return False
    return not any(rev.lifecycle in (Lifecycle.APPROVED, Lifecycle.STALE) for rev in ctx.records.revisions(conn, record.id))


def _norm_tags(tags: Any) -> list[str]:
    raw = [tags] if isinstance(tags, str) else list(tags or ())
    return sorted({str(item).strip().lower()[:40] for item in raw if str(item).strip()})[:24]


def _comparable(value: dict[str, Any]) -> dict[str, Any]:
    """What the legacy store keeps of a value (its save() normalization), for change detection."""
    def number(raw: Any) -> float | None:
        return None if raw in (None, "") else float(raw)

    confidence = value.get("confidence")
    return {
        "title": str(value.get("title") or "Memory").strip()[:160] or "Memory",
        "content": str(value.get("content") or "").strip(),
        "tags": _norm_tags(value.get("tags")),
        "scope": value.get("scope"), "status": value.get("status"), "kind": value.get("kind"),
        "reason": str(value.get("reason") or "")[:2_000], "pinned": bool(value.get("pinned")),
        "stale": bool(value.get("stale")),
        "confidence": min(max(float(1.0 if confidence is None else confidence), 0.0), 1.0),
        "valid_from": number(value.get("valid_from")), "valid_until": number(value.get("valid_until")),
        "supersedes": [str(item)[:128] for item in value.get("supersedes") or []][:32],
    }


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

    @contextlib.contextmanager
    def _legacy_write_barrier(self):
        """Hold the legacy file's write lock: legacy writers re-check their ownership guard inside
        their own write transaction, so one that passed the guard before the fence either commits
        before this lock is granted (and is in the final delta) or is fenced after it."""
        # mode=rw: never create a file where the legacy vault is expected (a moved/missing file aborts).
        conn = sqlite3.connect(f"file:{self.legacy_db}?mode=rw", uri=True, timeout=30, isolation_level=None)
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            finally:
                conn.execute("ROLLBACK")
        finally:
            conn.close()

    def _finish_cutover(self, *, quiesce: Callable[[], Any] | None, queries: list[str] | None) -> dict[str, Any]:
        try:
            with (quiesce() if quiesce is not None else contextlib.nullcontext()), self._legacy_write_barrier():
                delta = self._import(self.legacy_db)
                self._crash("after_final_delta")
                result = legacy_mod.verify(self.engine, self.access, self.legacy_db, self.key, self.mapping,
                                           queries=queries)
                if not result["ok"]:
                    record = self._move("legacy_authoritative", "cutover aborted: verification failed")
                    return {"state": record.state, "cutover": False, "verify": result, "delta": delta}
                self._crash("before_authoritative")
                record = self._move("package_authoritative", "cutover complete", cutover_at=time.time())
                return {"state": record.state, "cutover": True, "verify": result, "delta": delta}
        except SimulatedCrash:
            raise  # models process death: the interrupted cutover is resumed (or aborted) later
        except Exception as exc:
            # Any failure before the final transition (an unreadable/corrupt/moved legacy file, a wrong
            # key, a malformed row, a failing quiesce hook) aborts back to legacy: never wedged with
            # no permitted writer. No package write has been accepted, so nothing is lost.
            if self.state().state == "cutover_in_progress":
                with contextlib.suppress(Exception):
                    self._move("legacy_authoritative",
                               f"cutover aborted: {getattr(exc, 'code', type(exc).__name__)}")
            raise

    def abort_cutover(self, reason: str = "operator abort") -> dict[str, Any]:
        return abort_cutover(self.control, self.partition_id, reason)

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
        if record.kind == MemoryKind.PROCEDURE and isinstance(record.extra.get("procedure"), dict):
            return None  # a governed procedure (state, findings, evidence) is not a legacy memory
        if record.retention.policy != "durable" or (
                record.lifecycle != Lifecycle.CANDIDATE and record.retention.expires_at is not None):
            return None  # transient/session retention would become a permanent legacy memory
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

    @staticmethod
    def _unrepresentable_key(record: MemoryRecord) -> str:
        if record.kind == MemoryKind.PROCEDURE and isinstance(record.extra.get("procedure"), dict):
            return "governed_procedure"
        if record.retention.policy != "durable" or (
                record.lifecycle != Lifecycle.CANDIDATE and record.retention.expires_at is not None):
            return f"retention:{record.retention.policy}"
        return f"{record.kind.value}:{'+'.join(record.scope.as_dict()) or 'global'}"

    def _package_records(self, ctx: Any, conn: sqlite3.Connection) -> tuple[dict[str, MemoryRecord], set[str]]:
        """(readable records by id, ids of rows that no longer authenticate)."""
        records: dict[str, MemoryRecord] = {}
        damaged: set[str] = set()
        for (record_id,) in conn.execute("SELECT id FROM records ORDER BY id").fetchall():
            try:
                record = ctx.records.get(conn, record_id)
            except (IntegrityError, WrongKey):
                damaged.add(record_id)
                continue
            if record is not None:
                records[record_id] = record
        return records, damaged

    def _absent_in_legacy(self, ctx: Any, conn: sqlite3.Connection, record: MemoryRecord, now: float) -> bool:
        """Represented as absence: rejected, expired (also at read time: TTL or retention passed),
        or superseded without ever having been approved."""
        effective = ctx.services.core.effective_lifecycle(record, now)
        return effective in (Lifecycle.REJECTED, Lifecycle.EXPIRED) or _legacy_status_never_approved(ctx, conn, record)

    def plan_rollback(self) -> dict[str, Any]:
        ctx = self.engine.partition_context(self.access.partition)
        representable: list[str] = []
        unrepresentable: Counter[str] = Counter()
        with ctx.partition.db.read() as conn:
            now = ctx.clock()
            records, _damaged = self._package_records(ctx, conn)
            for record in records.values():
                if self._absent_in_legacy(ctx, conn, record, now):
                    representable.append(record.id)  # represented as absence in the legacy store
                    continue
                if self._legacy_shape(record) is None:
                    unrepresentable[self._unrepresentable_key(record)] += 1
                else:
                    representable.append(record.id)
            tombstones = conn.execute("SELECT COUNT(*) FROM tombstones WHERE target_kind='memory'").fetchone()[0]
            all_tombstones = conn.execute("SELECT COUNT(*) FROM tombstones").fetchone()[0]
            history = conn.execute("SELECT COUNT(*) FROM history_messages").fetchone()[0]
        try:
            legacy_ids = {row["id"] for row in LegacyMemoryVault(self.legacy_db, key=self.key).raw_rows()}
        except Exception:
            legacy_ids = set()
        if history:
            unrepresentable["session_history_messages"] = history
        return {"representable": len(representable), "unrepresentable": dict(unrepresentable),
                "memory_tombstones": tombstones, "tombstones": all_tombstones,
                # Legacy rows with no live package record (forgotten by any target since import):
                # rollback deletes them.
                "legacy_rows_to_delete": len(legacy_ids - set(records)),
                "safe": not unrepresentable}

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

    @staticmethod
    def _apply_pending_deletions(ctx: Any, conn: sqlite3.Connection) -> int:
        """Apply ledger entries the store has not applied yet (a forget appended but waiting)."""
        partition = ctx.partition
        entries = partition.ledger.since(partition.deletion_generation(conn))
        if entries:
            partition.apply_ledger_entries(conn, ctx.services.forgetting.apply_tombstone, entries)
            partition.bump(conn)
        return len(entries)

    def _finish_rollback(self, *, allow_partial: bool) -> dict[str, Any]:
        ctx = self.engine.partition_context(self.access.partition)
        vault = LegacyMemoryVault(self.legacy_db, key=self.key)  # migration actor: unguarded on purpose
        counts: Counter[str] = Counter()
        # The package store's write lock is held for the whole reverse sync: no package write and no
        # forget commits until legacy is authoritative (they wait, then see the fence / apply to a
        # store that is no longer authoritative), so the snapshot written back is consistent.
        with ctx.partition.db.write() as conn:
            self._apply_pending_deletions(ctx, conn)
            now = ctx.clock()
            records, damaged = self._package_records(ctx, conn)
            legacy_rows = {row["id"]: row for row in vault.raw_rows()}
            self._delete_gone(vault, legacy_rows, records, damaged, counts)
            for record in records.values():
                if self._absent_in_legacy(ctx, conn, record, now):
                    if record.id in legacy_rows and vault.delete(record.id):
                        key = ("deleted_unapproved_superseded" if record.lifecycle == Lifecycle.SUPERSEDED
                               else "deleted_rejected_or_expired")
                        counts[key] += 1
                    continue
                shape = self._legacy_shape(record)
                if shape is None:
                    if (record.kind == MemoryKind.PROCEDURE and record.id in legacy_rows
                            and isinstance(record.extra.get("procedure"), dict) and vault.delete(record.id)):
                        counts["deleted_governed_procedures"] += 1  # written by an earlier rollback
                    counts["kept_in_package_only"] += 1
                    continue
                self._write_back(ctx, conn, vault, record, shape, legacy_rows.get(record.id), counts)
            # Deletions that arrived while syncing (a forget appended to the ledger meanwhile) win.
            while self._apply_pending_deletions(ctx, conn):
                records, damaged = self._package_records(ctx, conn)
                legacy_rows = {row["id"]: row for row in vault.raw_rows()}
                self._delete_gone(vault, legacy_rows, records, damaged, counts)
            self._checkpoint_legacy()
            self._crash("before_rollback_complete")
            record = self._move("legacy_authoritative", "rollback complete",
                                package_readonly_recovery=bool(counts.get("kept_in_package_only")),
                                rolled_back_at=time.time())
        return {"state": record.state, "counts": dict(counts),
                "package_readonly_recovery": bool(counts.get("kept_in_package_only")),
                "limitations": ["records only the package can represent remain in the package store and are "
                                "not visible through the legacy API"] if counts.get("kept_in_package_only") else []}

    @staticmethod
    def _delete_gone(vault: LegacyMemoryVault, legacy_rows: dict[str, Any], records: dict[str, MemoryRecord],
                     damaged: set[str], counts: Counter[str]) -> None:
        """After a successful cutover the package held every legacy row; a legacy row whose package
        record is gone was forgotten (by memory, project, agent, source, session or profile) or
        removed since: it must not come back when legacy is authoritative again."""
        for record_id in sorted(set(legacy_rows) - set(records) - damaged):
            try:
                vault.open_row(legacy_rows[record_id])
            except Exception:
                counts["legacy_unreadable_kept"] += 1  # cannot reason about it; left untouched
                continue
            if vault.delete(record_id):
                counts["deleted_forgotten"] += 1
        for record_id in list(legacy_rows):
            if record_id not in records and record_id not in damaged:
                legacy_rows.pop(record_id, None)

    def _write_back(self, ctx: Any, conn: sqlite3.Connection, vault: LegacyMemoryVault, record: MemoryRecord,
                    shape: tuple[str, str], existing: Any, counts: Counter[str]) -> None:
        scope, target = shape
        candidate = record.lifecycle == Lifecycle.CANDIDATE
        value = {
            "title": record.title, "content": record.content, "tags": list(record.tags),
            "scope": scope, "status": "candidate" if candidate else "approved",
            "kind": record.kind.value, "reason": record.reason, "pinned": record.retention.pinned,
            "stale": record.lifecycle in (Lifecycle.STALE, Lifecycle.SUPERSEDED),
            "confidence": record.confidence.value if record.confidence.value is not None else 1.0,
            "valid_from": record.validity.valid_from, "valid_until": record.validity.valid_until,
            "supersedes": list(record.links.supersedes),
            "provenance": record.extra.get("legacy_provenance") or {},
        }
        expires_at = record.retention.expires_at if candidate else None
        if existing is not None:
            current = vault.open_row(existing)
            same = (_comparable(current) == _comparable(value) and existing["target_hash"] == target
                    and current["superseded_by"] == record.links.superseded_by
                    and (current["expires_at"] == expires_at if candidate else True))
            if same:
                counts["unchanged"] += 1
                return
        vault.save(value, record.id, _target_override=target,
                   _created_at=record.created_at if existing is None else None)
        with contextlib.closing(vault._connect()) as legacy, legacy:  # columns not settable through save()
            legacy.execute("UPDATE memories SET superseded_by=? WHERE id=?", (record.links.superseded_by, record.id))
            if candidate:  # keep the package candidate's own TTL (save() would start a fresh one)
                legacy.execute("UPDATE memories SET expires_at=? WHERE id=?", (expires_at, record.id))
        counts["written_back" if existing is not None else "restored"] += 1
        if not record.extra.get("legacy") and not record.extra.get("legacy_round_trip"):
            # A package-native record now lives in the legacy store under its package id: mark it
            # as a legacy round trip so a later migration adopts it instead of refusing the id.
            source = SourceRef(SourceKind.LEGACY_IMPORT, f"legacy-vault:{record.id}", actor=Actor.SYSTEM)
            adopted = dataclasses.replace(
                record, revision=record.revision + 1, sources=tuple(record.sources) + (source,),
                extra={**record.extra, "legacy_round_trip": True})
            ctx.services.core.write_internal(conn, adopted, change="legacy_adopted", actor=Actor.SYSTEM,
                                             expected=record.revision)

    def _checkpoint_legacy(self) -> None:
        """Fold the legacy WAL so pre-delete page images of forgotten rows do not linger."""
        with contextlib.suppress(sqlite3.Error):
            conn = sqlite3.connect(f"file:{self.legacy_db}?mode=rw", uri=True, timeout=10, isolation_level=None)
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()
