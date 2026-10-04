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
   accepted yet, so nothing is lost. Forgetting is never fenced: an abort first applies the
   package deletions made since the fence to the legacy file (``abort_cutover`` with the
   partition context). ``abort_cutover`` is the operator's escape hatch.
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
from ..errors import IntegrityError, MemoryEngineError, MigrationError, WrongKey
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


def abort_cutover(control: OwnershipControl, partition_id: str, reason: str = "operator abort", *,
                  ctx: Any = None, legacy_db: Path | str | None = None) -> dict[str, Any]:
    """Operator escape hatch: an interrupted cutover that cannot be resumed (the legacy file is gone or
    corrupt) goes back to legacy_authoritative. Safe: no package write is accepted before the final
    transition. Requires no legacy file.

    Forgetting is never fenced, so a forget made while the cutover was in progress was applied to the
    package store only, while the legacy file - authoritative again after the abort - still holds the
    row. With ``ctx`` (the partition's context) the abort of a ``cutover_in_progress`` first deletes,
    from the legacy file (``legacy_db``, else the one recorded at the fence), the rows of every record
    a package deletion removed since the fence (see :func:`_abort_with_deletions`); a forget's receipt
    in that window says so (``forgetting._CUTOVER_PENDING``). Without ``ctx``, or when the legacy file
    cannot be updated, the abort still happens (never wedged) and the result says
    ``legacy_deletions.complete=False``."""
    current = control.get(partition_id, Migrator.FAMILY)
    if current.state not in ("cutover_in_progress", "validated"):
        raise MigrationError(f"abort requires cutover_in_progress or validated, not {current.state}")
    if ctx is not None and current.state == "cutover_in_progress":
        if ctx.partition.partition_id != partition_id:
            raise MigrationError("the partition context does not belong to this partition")
        return _abort_with_deletions(ctx, control, current, reason, legacy_db)
    record = control.transition(partition_id, Migrator.FAMILY, "legacy_authoritative",
                                expected_generation=current.generation, reason=f"cutover aborted: {reason}"[:200])
    return {"state": record.state, "aborted": True}


def _abort_with_deletions(ctx: Any, control: OwnershipControl, current: Any, reason: str,
                          legacy_db: Path | str | None) -> dict[str, Any]:
    """Abort a ``cutover_in_progress`` after applying the package deletions recorded since the fence
    to the legacy file (memory tombstones above ``fence_generation`` - every record a forget removed
    here, by any target, has one - except propagated legacy deletions; rows by id, ``secure_delete``,
    then a truncating checkpoint; no key is needed).

    Ordered like a rollback's final steps: under the package store's write lock pending ledger
    entries are applied, then the ledger's write lock (which every forget's append takes) is held
    from the last such check until the transition - a forget appending later is one made while
    legacy is authoritative (its receipt says so). The legacy step is best effort: a missing, busy or
    unwritable legacy file never blocks the abort."""
    partition = ctx.partition
    details = current.details if isinstance(current.details, dict) else {}
    raw_path = legacy_db if legacy_db is not None else details.get("legacy_db")
    path = Path(raw_path) if isinstance(raw_path, (str, Path)) else None
    try:
        fence: int | None = int(details["fence_generation"])
    except (KeyError, TypeError, ValueError):
        fence = None
    report = {"deleted": 0, "complete": True}
    deleted = 0
    try:
        with contextlib.ExitStack() as appends_barrier:
            with partition.db.write() as conn:
                Migrator._apply_pending_deletions(ctx, conn)
                appends_barrier.enter_context(partition.ledger.db.write())
                Migrator._apply_pending_deletions(ctx, conn)
                floor = fence if fence is not None else legacy_mod.rollback_watermark(conn)
                ids = legacy_mod.forgotten_since(conn, floor)
            if ids:
                if path is None or not path.is_file():
                    report["complete"] = False
                else:
                    try:
                        deleted, _folded = _delete_legacy_rows(path, lambda present: [i for i in present if i in ids],
                                                               LEGACY_BUSY_TIMEOUT_MS, checkpoint=False)
                    except sqlite3.Error:
                        report["complete"] = False
            record = control.transition(partition.partition_id, Migrator.FAMILY, "legacy_authoritative",
                                        expected_generation=current.generation,
                                        reason=f"cutover aborted: {reason}"[:200])
    except Exception:
        # Never wedged: whatever failed on the way, the abort itself still happens.
        if control.get(partition.partition_id, Migrator.FAMILY).state != "cutover_in_progress":
            raise
        record = control.transition(partition.partition_id, Migrator.FAMILY, "legacy_authoritative",
                                    expected_generation=current.generation, reason=f"cutover aborted: {reason}"[:200])
        report["complete"] = False
    report["deleted"] = deleted
    if deleted and path is not None:
        _checkpoint_legacy_file(path)  # outside the ledger lock: it may wait for legacy readers
    with contextlib.suppress(Exception):
        partition.drop_forget_requests(upto=partition.deletion_generation())
        partition.ensure_purged()
    return {"state": record.state, "aborted": True, "legacy_deletions": report}


def _checkpoint_legacy_file(path: Path) -> None:
    """Fold the legacy WAL so pre-delete page images of forgotten rows do not linger."""
    with contextlib.suppress(sqlite3.Error):
        conn = sqlite3.connect(f"file:{path}?mode=rw", uri=True, timeout=10, isolation_level=None)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()


def _legacy_status_never_approved(ctx: Any, conn: sqlite3.Connection, record: MemoryRecord) -> bool:
    """A superseded record that never went through approval (a candidate resolved by supersede)."""
    return ctx.services.core.never_approved(conn, record)


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


# Partition meta: the deletion generation up to which package deletions were applied to the copies a
# migration keeps for rollback (absent: nothing applied since the last cutover).
RESIDUE_KEY = "legacy_residue_generation"
# How long a forget waits for the legacy file's write lock before reporting the residue (retried later).
LEGACY_BUSY_TIMEOUT_MS = 2_000
_SNAPSHOT_FILES = ("legacy-snapshot.sqlite3", "legacy-snapshot.sqlite3-wal", "legacy-snapshot.sqlite3-shm",
                   "legacy-snapshot.sqlite3-journal", "manifest.json")


def _remove_snapshots(details: dict[str, Any]) -> tuple[int, bool]:
    """Remove the migration snapshots recorded in the ownership details (files the Migrator wrote,
    nothing else). Returns (snapshots removed, all gone)."""
    dirs = [str(item) for item in details.get("snapshot_dirs") or () if isinstance(item, str)]
    if isinstance(details.get("snapshot_dir"), str) and details["snapshot_dir"] not in dirs:
        dirs.append(details["snapshot_dir"])
    removed, complete = 0, True
    for raw in dirs:
        directory = Path(raw)
        if not directory.is_dir():
            continue
        for name in _SNAPSHOT_FILES:
            path = directory / name
            try:
                if path.is_file():
                    path.unlink()
                    removed += name == "legacy-snapshot.sqlite3"
            except OSError:
                complete = False
        with contextlib.suppress(OSError):
            directory.rmdir()  # only when empty: an operator's own files are never touched
    return removed, complete


def _delete_legacy_rows(path: Path, choose: Callable[[list[str]], list[str]], busy_timeout_ms: int, *,
                        checkpoint: bool = True) -> tuple[int, bool]:
    """Delete (secure_delete, then - with ``checkpoint`` - a truncating WAL checkpoint) the legacy
    rows whose ids ``choose`` picks from the ids in the file (read in the same write transaction).
    No key is needed: rows are deleted by id, never read. Returns (rows deleted, freed pages folded
    into the main file; True without ``checkpoint``)."""
    conn = sqlite3.connect(f"file:{path}?mode=rw", uri=True, timeout=busy_timeout_ms / 1000, isolation_level=None)
    try:
        conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            gone = list(choose([row[0] for row in conn.execute("SELECT id FROM memories")]))
            for start in range(0, len(gone), 500):
                chunk = gone[start:start + 500]
                conn.execute(f"DELETE FROM memories WHERE id IN ({','.join('?' * len(chunk))})", chunk)
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        folded = True
        if checkpoint:
            row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            folded = row is None or int(row[0]) == 0
    finally:
        conn.close()
    return len(gone), folded


def _purge_legacy_rows(ctx: Any, path: Path, live: set[str], verified: set[str], busy_timeout_ms: int
                       ) -> tuple[int, bool]:
    """Delete (secure_delete, then a truncating WAL checkpoint) the legacy rows of the cutover set
    whose package record is gone. Returns (rows deleted, freed pages folded into the main file)."""
    return _delete_legacy_rows(
        path, lambda ids: [i for i in ids if i not in live and legacy_mod.cutover_token(ctx, i) in verified],
        busy_timeout_ms)


def propagate_forgets_to_legacy(ctx: Any, control: Any, *, busy_timeout_ms: int | None = None) -> dict[str, Any]:
    """While the package is authoritative, apply its deletions to the copies a migration keeps.

    After a cutover the live legacy vault stays on disk (it is the rollback target, decryptable
    with the legacy key the host keeps) and the migration snapshots hold full ciphertext copies.
    So that a forget leaves nothing recoverable there: the snapshots recorded for this migration
    are removed, and every legacy row of the cutover set (:func:`legacy.record_cutover_set`) whose
    package record no longer exists is deleted with ``secure_delete`` and a truncating WAL
    checkpoint. Rollback keeps working: it reverse-syncs from the package store.

    Driven by the deletion generation (partition meta ``legacy_residue_generation``): idempotent,
    cheap when nothing is pending, and re-run after every forget, on open and at cutover, so a
    crash or a busy legacy file only delays it. Never raises for a legacy-side failure; returns
    ``complete=False`` (the caller reports the residue as a limitation) until it succeeds.
    """
    partition = ctx.partition
    record = control.get(partition.partition_id, Migrator.FAMILY)
    if record.state != "package_authoritative":
        return {"applicable": False, "complete": True}
    out: dict[str, Any] = {"applicable": True, "complete": True, "deleted": 0, "snapshots_removed": 0,
                           "pending": []}
    removed, snapshots_gone = _remove_snapshots(record.details)
    out["snapshots_removed"] = removed
    if not snapshots_gone:
        out["complete"] = False
        out["pending"].append("migration_snapshot")
    with partition.db.read() as conn:
        generation = partition.deletion_generation(conn)
        raw = conn.execute("SELECT value FROM meta WHERE key=?", (RESIDUE_KEY,)).fetchone()
        try:
            done = int(raw[0]) if raw is not None else -1
        except (TypeError, ValueError):
            done = -1
        if generation <= done:
            return out
        verified = legacy_mod.cutover_set(ctx, conn)
        live = {row[0] for row in conn.execute("SELECT id FROM records")}  # damaged rows count as live
    legacy_db = record.details.get("legacy_db")
    if verified is None or not isinstance(legacy_db, str) or not Path(legacy_db).is_file():
        out["complete"] = False
        out["pending"].append("legacy_store")  # unknown (cutover by an earlier build) or moved
        return out
    busy = LEGACY_BUSY_TIMEOUT_MS if busy_timeout_ms is None else int(busy_timeout_ms)
    try:
        deleted, folded = _purge_legacy_rows(ctx, Path(legacy_db), live, verified, busy)
    except sqlite3.Error:
        out["complete"] = False
        out["pending"].append("legacy_store")
        return out
    out["deleted"] = deleted
    if not folded:
        out["complete"] = False
        out["pending"].append("legacy_store")  # a reader kept the WAL busy: retried later
        return out
    with partition.db.write() as conn:
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (RESIDUE_KEY, str(generation)))
    return out


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

    def _import(self, source: Path, *, during_cutover: bool = False) -> dict[str, Any]:
        return legacy_mod.LegacyImporter(self.engine, self.access, source, self.key, self.mapping,
                                         ownership=self.control, during_cutover=during_cutover).run()

    # ------------------------------------------------------------------ steps
    def prepare_shadow(self) -> dict[str, Any]:
        if self.state().state != "legacy_authoritative":
            raise MigrationError(f"prepare_shadow requires legacy_authoritative, not {self.state().state}")
        self._repair_rollback_commit()  # a rollback left unadopted by an earlier build (idempotent)
        snap_dir = self.work_dir / f"snapshot-{int(time.time() * 1000)}"
        manifest = legacy_mod.snapshot(self.legacy_db, snap_dir)
        self._crash("after_snapshot")
        report = self._import(snap_dir / manifest["snapshot_file"])
        self._crash("after_shadow_import")
        # Every snapshot this migration wrote is listed: a successful cutover removes them (they are
        # full ciphertext copies of the legacy store that no later step reads).
        snapshots = [str(item) for item in self.state().details.get("snapshot_dirs") or () if str(item) != str(snap_dir)]
        record = self._move("shadow_prepared", "shadow import complete", snapshot_dir=str(snap_dir),
                            snapshot_dirs=[*snapshots, str(snap_dir)], snapshot_rows=manifest["rows"])
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
        # Read before the fence: every package deletion recorded after it may have been made while the
        # cutover was in progress (forgetting is never fenced) - an abort applies those to the legacy
        # file (see abort_cutover), which is recorded here for an abort that is not given one.
        fence_generation = self.engine.partition_context(self.access.partition).partition.deletion_generation()
        self._move("cutover_in_progress", "fencing legacy writers", fence_generation=fence_generation,
                   legacy_db=str(self.legacy_db))
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

    def _legacy_ids(self) -> list[str]:
        conn = legacy_mod._connect_ro(self.legacy_db)
        try:
            return [row[0] for row in conn.execute("SELECT id FROM memories")]
        finally:
            conn.close()

    def _abort(self, reason: str) -> dict[str, Any]:
        """Abort this partition's cutover, applying package deletions made since the fence to the
        legacy file first (see :func:`abort_cutover`)."""
        try:
            ctx = self.engine.partition_context(self.access.partition)
        except Exception:
            ctx = None  # the abort itself must still happen
        return abort_cutover(self.control, self.partition_id, reason, ctx=ctx, legacy_db=self.legacy_db)

    def _finish_cutover(self, *, quiesce: Callable[[], Any] | None, queries: list[str] | None) -> dict[str, Any]:
        try:
            failed: tuple[dict[str, Any], dict[str, Any]] | None = None
            with (quiesce() if quiesce is not None else contextlib.nullcontext()), self._legacy_write_barrier():
                delta = self._import(self.legacy_db, during_cutover=True)
                self._crash("after_final_delta")
                result = legacy_mod.verify(self.engine, self.access, self.legacy_db, self.key, self.mapping,
                                           queries=queries)
                if not result["ok"]:
                    failed = (result, delta)
                else:
                    self._crash("before_authoritative")
                    ctx = self.engine.partition_context(self.access.partition)
                    with ctx.partition.db.write() as conn:
                        # The verified legacy ids (the barrier keeps the file unchanged since verify).
                        legacy_mod.record_cutover_set(ctx, conn, self._legacy_ids())
                        conn.execute("DELETE FROM meta WHERE key=?", (RESIDUE_KEY,))
                    # The transition holds this store's write lock: a legacy import (or propagated
                    # legacy deletion) that checked the state before it either committed first or is
                    # fenced.
                    with ctx.partition.db.write():
                        record = self._move("package_authoritative", "cutover complete", cutover_at=time.time(),
                                            legacy_db=str(self.legacy_db))
            if failed is not None:
                # Outside the legacy write barrier (the abort deletes legacy rows): still no writer
                # is permitted until the abort's transition.
                aborted = self._abort("verification failed")
                return {"state": aborted["state"], "cutover": False, "verify": failed[0], "delta": failed[1],
                        "legacy_deletions": aborted.get("legacy_deletions")}
        except SimulatedCrash:
            raise  # models process death: the interrupted cutover is resumed (or aborted) later
        except Exception as exc:
            # Any failure before the final transition (an unreadable/corrupt/moved legacy file, a wrong
            # key, a malformed row, a failing quiesce hook) aborts back to legacy: never wedged with
            # no permitted writer. No package write has been accepted, so nothing is lost; package
            # deletions made meanwhile are applied to the legacy file first (best effort).
            if self.state().state == "cutover_in_progress":
                with contextlib.suppress(Exception):
                    self._abort(str(getattr(exc, "code", type(exc).__name__)))
            raise
        # Package deletions made while legacy was authoritative, and the migration snapshots, must
        # not outlive the cutover in the copies kept for rollback (outside the legacy barrier).
        residue = propagate_forgets_to_legacy(self.engine.partition_context(self.access.partition), self.control)
        return {"state": record.state, "cutover": True, "verify": result, "delta": delta, "legacy_residue": residue}

    def abort_cutover(self, reason: str = "operator abort") -> dict[str, Any]:
        return self._abort(reason)

    def resume(self, *, quiesce: Callable[[], Any] | None = None) -> dict[str, Any]:
        state = self.state().state
        if state == "cutover_in_progress":
            return self._finish_cutover(quiesce=quiesce, queries=None)
        if state == "rollback_in_progress":
            return self._finish_rollback(allow_partial=bool(self.state().details.get("allow_partial")))
        repaired = self._repair_rollback_commit()
        if repaired is not None:
            return {"state": state, "resumed": True, "repaired_rollback": repaired}
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
        package_only: list[str] = []
        with ctx.partition.db.read() as conn:
            now = ctx.clock()
            records, _damaged = self._package_records(ctx, conn)
            for record in records.values():
                if self._absent_in_legacy(ctx, conn, record, now):
                    representable.append(record.id)  # represented as absence in the legacy store
                    continue
                if self._legacy_shape(record) is None:
                    unrepresentable[self._unrepresentable_key(record)] += 1
                    package_only.append(record.id)
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
                # Earlier legacy versions of records only the package can represent now (an allow_partial
                # rollback deletes them; the package keeps the records for recovery).
                "stale_legacy_rows_to_delete": len(legacy_ids & set(package_only)),
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

    def _apply_late_deletions(self, ctx: Any, conn: sqlite3.Connection, vault: LegacyMemoryVault,
                              counts: Counter[str], now: float) -> int:
        """Deletions that arrived while syncing (a forget appended to the ledger meanwhile) win:
        applied to the package, then every legacy row they removed there is deleted. Returns the
        number of ledger entries applied."""
        applied = 0
        while True:
            entries = self._apply_pending_deletions(ctx, conn)
            if not entries:
                return applied
            applied += entries
            records, damaged = self._package_records(ctx, conn)
            legacy_rows = {row["id"]: row for row in vault.raw_rows()}
            self._delete_gone(ctx, conn, vault, legacy_rows, records, damaged, counts, now)

    def _finish_rollback(self, *, allow_partial: bool) -> dict[str, Any]:
        ctx = self.engine.partition_context(self.access.partition)
        vault = LegacyMemoryVault(self.legacy_db, key=self.key)  # migration actor: unguarded on purpose
        counts: Counter[str] = Counter()
        late = 0
        # Before any legacy write, and committed on its own: every id this rollback may write into
        # the legacy store joins the set of legacy ids the package held (``record_cutover_set``).
        # Legacy writes commit on their own while the package side (adoption, watermark) commits
        # later or - after a crash or failure - not at all; a forget that then removes such a
        # record (by cascade, as evidence-dependent, by any target) must still take its legacy copy
        # with it when this rollback (or its resumption) runs, whatever the legacy row says.
        legacy_mod.record_rollback_ids(ctx)
        # The package store's write lock is held for the whole reverse sync: no package write and no
        # forget commits until legacy is authoritative (they wait, then see the fence / apply to a
        # store that is no longer authoritative), so the snapshot written back is consistent.
        #
        # A forget is never fenced and appends its ledger entry (its durable decision) before it
        # waits for that lock. So that no append can fall between the last pending-deletion check
        # and the transition - and then be applied to the package only, while the now
        # authoritative legacy store keeps the row - the ledger's own write lock (which every
        # append takes, in this and any other process) is held from that last check until the
        # transition. A forget appending later is a forget made while legacy is authoritative (its
        # receipt says so). Lock order is the one every writer uses: package store first, then
        # ledger (the ownership control store is taken last, by the transition alone).
        #
        # The transition is the last durable step: it runs only after the package transaction
        # (adoptions of written-back records, the rollback watermark, applied deletions) has
        # committed. A crash or a failed commit before it leaves rollback_in_progress, which
        # ``resume`` finishes (idempotently); legacy is never authoritative without them.
        with contextlib.ExitStack() as appends_barrier:
            with ctx.partition.db.write() as conn:
                self._apply_pending_deletions(ctx, conn)
                now = ctx.clock()
                records, damaged = self._package_records(ctx, conn)
                legacy_rows = {row["id"]: row for row in vault.raw_rows()}
                self._delete_gone(ctx, conn, vault, legacy_rows, records, damaged, counts, now)
                package_only: list[str] = []
                for record in records.values():
                    if self._absent_in_legacy(ctx, conn, record, now):
                        if record.id in legacy_rows and vault.delete(record.id):
                            key = ("deleted_unapproved_superseded" if record.lifecycle == Lifecycle.SUPERSEDED
                                   else "deleted_rejected_or_expired")
                            counts[key] += 1
                        continue
                    shape = self._legacy_shape(record)
                    if shape is None:
                        # Kept in the package (read-only recovery). Its legacy row - imported, or written
                        # by an earlier rollback - is an earlier version the package changed since (a
                        # correction to transient retention, a governed procedure): left in place, the
                        # now authoritative legacy store would serve that version (a corrected-away
                        # statement, durable past the user's expiry) and a re-migration would take it
                        # back over the package record. It is deleted; the id joins the recovery set,
                        # so a re-migration never treats the missing row as a legacy deletion.
                        if record.id in legacy_rows and vault.delete(record.id):
                            governed = (record.kind == MemoryKind.PROCEDURE
                                        and isinstance(record.extra.get("procedure"), dict))
                            counts["deleted_governed_procedures" if governed
                                   else "deleted_stale_unrepresentable"] += 1
                        counts["kept_in_package_only"] += 1
                        package_only.append(record.id)
                        continue
                    self._write_back(ctx, conn, vault, record, shape, legacy_rows.get(record.id), counts)
                legacy_mod.record_rollback_recovery(ctx, conn, package_only)
                self._crash("after_reverse_sync")  # legacy written, package transaction not committed
                self._apply_late_deletions(ctx, conn, vault, counts, now)
                # Fold the legacy WAL (pre-delete page images of forgotten rows) while forgets can
                # still append: it may wait seconds for legacy readers.
                self._checkpoint_legacy()
                appends_barrier.enter_context(ctx.partition.ledger.db.write())
                late = self._apply_late_deletions(ctx, conn, vault, counts, now)
                # Every forget up to here is now applied to the legacy store: a legacy row created
                # after this rollback is live data a later re-migration imports (forgotten_check),
                # and a forget at or below this generation needs no legacy limitation. No ledger
                # entry can be appended until the transition below.
                generation = ctx.partition.deletion_generation(conn)
                legacy_mod.record_rollback_watermark(conn, generation)
            self._crash("before_rollback_complete")  # package committed, transition not yet made
            record = self._move("legacy_authoritative", "rollback complete",
                                package_readonly_recovery=bool(counts.get("kept_in_package_only")),
                                rolled_back_at=time.time(), rollback_deletion_generation=generation)
        if late:
            self._checkpoint_legacy()  # rows the final check deleted (never under the ledger lock)
        # Deletions applied above (pending ledger entries) purged package rows: their requests go
        # and their pages must leave the disk exactly as after a live forget (a reader leaves it
        # pending, retried on later calls).
        ctx.partition.drop_forget_requests(upto=ctx.partition.deletion_generation())
        ctx.partition.ensure_purged()
        kept = bool(counts.get("kept_in_package_only"))
        return {"state": record.state, "counts": dict(counts),
                "package_readonly_recovery": kept,
                # Opaque record ids (never content): what stayed in the package recovery store.
                "package_only_ids": sorted(package_only)[:200],
                "limitations": ["records only the package can represent remain in the package store (read-only"
                                " recovery; package_only_ids) and are not visible through the legacy API: the"
                                " earlier legacy copies of those that had one were deleted"
                                " (deleted_stale_unrepresentable, deleted_governed_procedures)"] if kept else []}

    def _delete_gone(self, ctx: Any, conn: sqlite3.Connection, vault: LegacyMemoryVault,
                     legacy_rows: dict[str, Any], records: dict[str, MemoryRecord], damaged: set[str],
                     counts: Counter[str], now: float) -> None:
        """A legacy row the last cutover verified (imported, or covered by a package forget) or this
        rollback wrote from a package record (:func:`legacy.record_rollback_ids`) whose package
        record is gone was forgotten (by memory, project, agent, source, session or profile, by
        cascade or with its evidence) or removed since: it must not come back when legacy is
        authoritative again. This holds on a resumed rollback too, after the record was purged.

        A legacy row the package never held (not in the cutover set - e.g. written to the fenced
        legacy file afterwards) is deleted only when a package-side forget covers it
        (:func:`legacy.forgotten_check`); otherwise it is live legacy data and is kept
        (``legacy_only_kept``). Without a recorded cutover set (a cutover by an earlier build)
        every legacy row without a package record is deleted, as before."""
        verified = legacy_mod.cutover_set(ctx, conn)
        for record_id in sorted(set(legacy_rows) - set(records) - damaged):
            try:
                value = vault.open_row(legacy_rows[record_id], include_private=True)
            except Exception:
                counts["legacy_unreadable_kept"] += 1  # cannot reason about it; left untouched
                continue
            if verified is not None and legacy_mod.cutover_token(ctx, record_id) not in verified:
                try:
                    mapped, _ = legacy_mod.map_record(value, self.mapping, now=now)
                except (MigrationError, KeyError, TypeError, ValueError, MemoryEngineError):
                    counts["legacy_only_kept"] += 1
                    continue
                if legacy_mod.forgotten_check(ctx, conn, mapped)[0] is not None:
                    counts["legacy_only_kept"] += 1  # never in the package and not forgotten there
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
        same = False
        if existing is not None:
            current = vault.open_row(existing)
            same = (_comparable(current) == _comparable(value) and existing["target_hash"] == target
                    and current["superseded_by"] == record.links.superseded_by
                    and (current["expires_at"] == expires_at if candidate else True))
        if same:
            counts["unchanged"] += 1
        else:
            vault.save(value, record.id, _target_override=target,
                       _created_at=record.created_at if existing is None else None)
            with contextlib.closing(vault._connect()) as legacy, legacy:  # columns not settable through save()
                legacy.execute("UPDATE memories SET superseded_by=? WHERE id=?",
                               (record.links.superseded_by, record.id))
                if candidate:  # keep the package candidate's own TTL (save() would start a fresh one)
                    legacy.execute("UPDATE memories SET expires_at=? WHERE id=?", (expires_at, record.id))
            counts["written_back" if existing is not None else "restored"] += 1
        if record.extra.get("legacy"):
            return  # an imported record: the next import's delta re-reads its (rewritten) legacy row
        # A package-native record now lives in the legacy store under its package id: mark it as a
        # legacy round trip (so a later migration adopts it instead of refusing the id, and a
        # legacy deletion of the row is propagated) and record the legacy revision and metadata
        # fingerprint of the row (so an unchanged row is no delta). Its own provenance - basis,
        # citations, derived_from - is kept, here and by every later delta.
        #
        # Done whether or not this pass changed the legacy row: legacy writes commit on their own,
        # while this adoption commits with the rollback's package transaction. A rollback
        # interrupted after the reverse sync (crash, failing transition) leaves the row in legacy
        # but the adoption rolled back; the resumed rollback finds the row unchanged and must still
        # adopt it, or every later migration refuses the id. Idempotent: an adopted record whose
        # marker, revision and fingerprint match is not rewritten.
        self._adopt(ctx, conn, vault, record, change="legacy_adopted")

    @staticmethod
    def _adopt(ctx: Any, conn: sqlite3.Connection, vault: LegacyMemoryVault, record: MemoryRecord, *,
               change: str) -> bool:
        """Mark a package-native record whose row is in the legacy store as a legacy round trip
        (see :meth:`_write_back`). True when the record was rewritten."""
        with contextlib.closing(vault._connect()) as legacy:
            row = legacy.execute("SELECT * FROM memories WHERE id=?", (record.id,)).fetchone()
        written = vault.open_row(row, include_private=True) if row is not None else None
        source = SourceRef(SourceKind.LEGACY_IMPORT, f"legacy-vault:{record.id}", actor=Actor.SYSTEM)
        sources = tuple(record.sources) + (() if any(s.identity() == source.identity() for s in record.sources)
                                           else (source,))
        extra = {**record.extra, "legacy_round_trip": True}
        if written is not None:
            extra.update({"legacy_revision": int(written["revision"]),
                          "legacy_fingerprint": legacy_mod.legacy_fingerprint(written)})
        if extra == record.extra and sources == tuple(record.sources):
            return False
        adopted = dataclasses.replace(record, revision=record.revision + 1, sources=sources, extra=extra)
        ctx.services.core.write_internal(conn, adopted, change=change, actor=Actor.SYSTEM, expected=record.revision)
        return True

    def _repair_rollback_commit(self) -> dict[str, Any] | None:
        """Repair a rollback whose package transaction was lost after its ownership transition.

        An earlier build made the transition to legacy_authoritative inside the rollback's package
        transaction: a crash or a failing commit after it left legacy authoritative without the
        adoptions of the records the rollback wrote back and without the rollback watermark, and
        nothing resumed it (every re-migration then refused the written-back ids). The control
        record still carries the deletion generation that rollback applied to the legacy store
        (``rollback_deletion_generation``); when the package recorded no watermark, or one below
        it, the package records whose ids are in the legacy file and that have no legacy origin are
        adopted and the watermark is recorded. Idempotent; None when nothing needs repair."""
        current = self.state()
        if current.state != "legacy_authoritative":
            return None
        try:
            claimed = int(current.details.get("rollback_deletion_generation"))
        except (TypeError, ValueError):
            return None
        ctx = self.engine.partition_context(self.access.partition)
        with ctx.partition.db.read() as conn:
            recorded = conn.execute("SELECT 1 FROM meta WHERE key=?",
                                    (legacy_mod.ROLLBACK_WATERMARK_KEY,)).fetchone() is not None
            if recorded and claimed <= legacy_mod.rollback_watermark(conn):
                return None
        vault = LegacyMemoryVault(self.legacy_db, key=self.key)
        legacy_ids = {row["id"] for row in vault.raw_rows()}
        adopted = 0
        with ctx.partition.db.write() as conn:
            records, _damaged = self._package_records(ctx, conn)
            for record in records.values():
                if record.id in legacy_ids and not legacy_mod._legacy_origin(record):
                    adopted += self._adopt(ctx, conn, vault, record, change="legacy_readopted")
            legacy_mod.record_rollback_watermark(conn, claimed)
        return {"adopted": adopted, "rollback_watermark": claimed}

    def _checkpoint_legacy(self) -> None:
        """Fold the legacy WAL so pre-delete page images of forgotten rows do not linger."""
        _checkpoint_legacy_file(self.legacy_db)
