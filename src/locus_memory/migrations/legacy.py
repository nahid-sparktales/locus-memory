"""Locus MemoryVault (format v2, "memory-v1" AAD) -> locus-memory partition migration.

Operations, all explicit and never run on import/installation:

* :func:`inventory` - read-only dry run; counts and compatibility classes, no content.
* :func:`snapshot`  - consistent copy of the (already encrypted) legacy database via the
  SQLite backup API plus a manifest of per-row fingerprints. No plaintext is written.
* :class:`LegacyImporter` - idempotent, resumable import preserving ids, revisions,
  lifecycle, scope, provenance and deletion state; a re-run applies only deltas and
  propagates legacy deletions as package tombstones. A delta is a new legacy revision,
  a change of the metadata the legacy vault edits *without* bumping its revision
  (``stale``/``superseded_by`` via feedback and ``approve(resolution="replace")``,
  ``pinned``, ``expires_at``, target), tracked as ``extra.legacy_fingerprint``, or a
  changed host mapping (the record is re-scoped).
* :func:`verify` - decrypts every destination record and compares it with the mapped
  source (content, lifecycle, scope and the metadata above), reports imported records
  whose legacy row is gone, then compares representative retrieval behaviour.

Code extraction (compat.legacy_vault) and physical migration are separate: Locus can
delegate to the package over the legacy file without running anything here.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import sqlite3
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..compat.legacy_vault import (
    VALID_KINDS,
    LegacyMemoryVault,
    legacy_agent_hash,
    legacy_workspace_hash,
)
from ..errors import IntegrityError, MemoryEngineError, MigrationError, WrongKey
from ..models import (
    AccessContext,
    Actor,
    Confidence,
    ForgetPolicy,
    ForgetTarget,
    Lifecycle,
    Links,
    MemoryKind,
    MemoryRecord,
    Operation,
    Retention,
    Scope,
    ScopeGrants,
    SourceKind,
    SourceRef,
    StatementBasis,
    Validity,
)
from ..validation import MAX_TIMESTAMP, MIN_TIMESTAMP

MANIFEST_FORMAT = "locus-memory.legacy-migration-manifest"
MANIFEST_VERSION = 1
LEGACY_FORMAT = "locus-memory-vault:memory-v1"

# Payload fields that have no first-class package equivalent and how they are handled.
UNSUPPORTED_FIELDS = {
    "embedding": "dropped; vectors are re-derivable and model-specific (re-embed under provider consent)",
    "use_count": "kept in extra.legacy_use_count; never used for ranking or confidence",
    "last_used_at": "kept in extra.legacy_last_used_at",
    "feedback": "kept in extra.legacy_feedback (user quality signal)",
    "provenance": "kept in extra.legacy_provenance (bounded)",
    "last_confirmed_at": "kept in extra.last_confirmed_at",
}
NOT_MIGRATED_TABLES = {
    "memory_events": "content-free diagnostics; retained in the legacy file, not copied",
    "context_snapshots": "separate record family (ownership.family=context_snapshots); not migrated by this importer",
    "skill_observations": "separate record family (ownership.family=skill_observations); not migrated by this importer",
}


@dataclass
class LegacyMapping:
    """Host-supplied identity mapping (legacy target hashes -> package scope values)."""

    workspaces: dict[str, str] = field(default_factory=dict)  # sha256(resolved path) -> project id
    agents: dict[str, str] = field(default_factory=dict)  # sha256(agent id) -> agent id

    @classmethod
    def from_known(cls, workspace_projects: dict[str, str] | None = None,
                   agent_ids: list[str] | None = None) -> LegacyMapping:
        return cls(
            workspaces={legacy_workspace_hash(path): project for path, project in (workspace_projects or {}).items()},
            agents={legacy_agent_hash(agent): agent for agent in (agent_ids or [])},
        )

    def scope_for(self, scope: str, target_hash: str) -> tuple[Scope, bool]:
        """Return (package scope, mapped?)."""
        if scope == "personal":
            return Scope.global_(), True
        prefix, _, digest = target_hash.partition(":")
        if scope == "workspace" and prefix == "workspace" and digest in self.workspaces:
            return Scope.of(project=self.workspaces[digest]), True
        if scope == "agent" and prefix == "agent" and digest in self.agents:
            return Scope.of(agent=self.agents[digest]), True
        return Scope.of(legacy_target=target_hash), False


def _connect_ro(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _row_fingerprint(row: sqlite3.Row) -> str:
    digest = hashlib.sha256()
    for name in ("id", "status", "scope", "target_hash", "revision"):
        digest.update(str(row[name]).encode() + b"\x00")
    digest.update(bytes(row["nonce"]) + bytes(row["ciphertext"]))
    return digest.hexdigest()


_FINGERPRINT_DOMAIN = "locus-memory/legacy-fingerprint/v1|"


def legacy_fingerprint(value: dict[str, Any]) -> str:
    """sha256 over the legacy row metadata that drives the mapped record.

    The legacy vault changes ``stale`` (feedback ``incorrect``), ``superseded_by`` and
    ``stale`` (``approve(resolution="replace")``) and can change ``pinned``/``expires_at``
    without bumping ``revision``; the revision alone therefore cannot detect a delta.
    Stored only inside the encrypted record payload (``extra.legacy_fingerprint``).
    """
    expires = value.get("expires_at")
    material = {
        "revision": int(value["revision"]),
        "status": str(value["status"]),
        "stale": bool(value.get("stale")),
        "superseded_by": value.get("superseded_by") or None,
        "pinned": bool(value.get("pinned")),
        "expires_at": None if expires is None else float(expires),
        "target_hash": str(value["target_hash"]),
        "scope": str(value["scope"]),
    }
    text = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((_FINGERPRINT_DOMAIN + text).encode()).hexdigest()


def _legacy_source_ref(record_id: str) -> str:
    return f"legacy-vault:{record_id}"


def _legacy_source_identity(record_id: str) -> str:
    """SourceRef.identity() of the LEGACY_IMPORT source every imported record carries."""
    return f"{SourceKind.LEGACY_IMPORT.value}:{_legacy_source_ref(record_id)}"


def lifecycle_for(row: dict[str, Any], *, now: float) -> Lifecycle:
    if row["status"] == "candidate":
        expires = row.get("expires_at")
        return Lifecycle.EXPIRED if expires is not None and float(expires) < now else Lifecycle.CANDIDATE
    if row.get("superseded_by"):
        return Lifecycle.SUPERSEDED
    if row.get("stale"):
        return Lifecycle.STALE
    return Lifecycle.APPROVED


def _legacy_time(value: dict[str, Any], name: str, notes: dict[str, Any], extra: dict[str, Any]) -> float | None:
    """A legacy timestamp the package can store. Locus accepts any finite number: an obvious
    millisecond value is normalized to seconds; anything else outside the supported range (or
    not a number) is dropped. The raw value is kept in ``extra.legacy_raw_<name>``."""
    raw = value.get(name)
    if raw is None or raw == "":
        return None
    try:
        number = float(raw)
    except (TypeError, ValueError):
        number = math.nan
    if math.isfinite(number) and MIN_TIMESTAMP <= number <= MAX_TIMESTAMP:
        return number
    extra[f"legacy_raw_{name}"] = raw if isinstance(raw, (int, float, str)) else str(raw)
    if math.isfinite(number) and MIN_TIMESTAMP <= number / 1000.0 <= MAX_TIMESTAMP and number > MAX_TIMESTAMP:
        notes["timestamp_milliseconds_normalized"] = True
        return number / 1000.0
    notes["timestamp_out_of_range"] = True
    return None


def map_record(value: dict[str, Any], mapping: LegacyMapping, *, now: float) -> tuple[MemoryRecord, dict[str, Any]]:
    """Map one decrypted legacy record (open_row(include_private=True)) to a package record.

    Every value the legacy vault (or Locus) can persist maps: out-of-range timestamps and
    non-finite confidences are normalized or dropped and noted, never a crash."""
    scope, mapped = mapping.scope_for(value["scope"], value["target_hash"])
    notes: dict[str, Any] = {"scope_mapped": mapped}
    sources = [SourceRef(SourceKind.LEGACY_IMPORT, _legacy_source_ref(value["id"]), actor=Actor.SYSTEM,
                         locator={"legacy_revision": int(value["revision"])})]
    if value.get("source_session_id"):
        sources.append(SourceRef(SourceKind.SESSION, _safe_ref(value["source_session_id"]), actor=Actor.HOST,
                                 locator={"legacy_field": "source_session_id"}, available=False))
    if value.get("source_run_id"):
        sources.append(SourceRef(SourceKind.TASK_ATTEMPT, _safe_ref(value["source_run_id"]), actor=Actor.HOST,
                                 locator={"legacy_field": "source_run_id"}, available=False))
    provenance = value.get("provenance") or {}
    provenance_json = json.dumps(provenance, sort_keys=True, default=str)
    extra: dict[str, Any] = {
        "legacy": True, "legacy_revision": int(value["revision"]), "legacy_target_hash": value["target_hash"],
        "legacy_scope": value["scope"], "legacy_status": value["status"],
        "legacy_stale": bool(value["stale"]), "legacy_use_count": int(value.get("use_count") or 0),
        "legacy_last_used_at": value.get("last_used_at"), "legacy_fingerprint": legacy_fingerprint(value),
    }
    if len(provenance_json) <= 8_000:
        extra["legacy_provenance"] = provenance
    else:
        extra["legacy_provenance_truncated"] = True
        notes["provenance_truncated"] = True
    if value.get("feedback"):
        extra["legacy_feedback"] = value["feedback"]
    if value.get("last_confirmed_at") is not None:
        extra["last_confirmed_at"] = value["last_confirmed_at"]
    if value.get("embedding"):
        notes["embedding_dropped"] = True
        extra["legacy_embedding_model"] = value.get("embedding_model") or ""
    kind = value["kind"] if value["kind"] in VALID_KINDS else "fact"
    if value["kind"] == "procedure":
        extra["legacy_ungoverned_procedure"] = True  # never passed procedural evaluation
    valid_from = _legacy_time(value, "valid_from", notes, extra)
    valid_until = _legacy_time(value, "valid_until", notes, extra)
    if valid_from is not None and valid_until is not None and valid_until <= valid_from:
        valid_until = None
        notes["invalid_validity_dropped"] = True
    expires_at = _legacy_time(value, "expires_at", notes, extra)
    raw_confidence = value.get("confidence")
    confidence = Confidence()
    if raw_confidence is not None:
        try:
            number = float(raw_confidence)
        except (TypeError, ValueError):
            number = math.nan
        if math.isfinite(number) and 0.0 <= number <= 1.0:
            confidence = Confidence(number, False, "legacy_unspecified")
        else:
            notes["invalid_confidence_dropped"] = True
    lifecycle = lifecycle_for({**value, "expires_at": expires_at}, now=now)
    record = MemoryRecord(
        id=value["id"], revision=int(value["revision"]), kind=MemoryKind(kind), lifecycle=lifecycle,
        scope=scope, title=value["title"], content=value["content"], tags=tuple(value.get("tags") or ()),
        basis=StatementBasis.LEGACY, confidence=confidence,
        sources=tuple(sources), validity=Validity(valid_from, valid_until),
        retention=Retention("durable", expires_at, bool(value["pinned"])),
        links=Links(supersedes=tuple(value.get("supersedes") or ()), superseded_by=value.get("superseded_by")),
        created_at=float(value["created_at"]), updated_at=float(value["updated_at"]),
        event_time=float(value["created_at"]), ingested_at=now, reason=value.get("reason") or "", extra=extra,
    )
    return record, notes


def _safe_ref(value: str) -> str:
    import re

    cleaned = re.sub(r"[^A-Za-z0-9_.:@/+=-]", "_", str(value))[:256] or "unknown"
    return cleaned.replace("..", "__")


# ---------------------------------------------------------------------- dry run
def inventory(legacy_db: Path, key: bytes, mapping: LegacyMapping | None = None, *,
              now: float | None = None) -> dict[str, Any]:
    """Read-only compatibility report. Contains counts and classes only - no content."""
    mapping = mapping or LegacyMapping()
    now = time.time() if now is None else now
    conn = _connect_ro(legacy_db)
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "memories" not in tables:
            raise MigrationError("not a Locus memory vault (no memories table)")
        columns = [r[1] for r in conn.execute("PRAGMA table_info(memories)")]
        rows = conn.execute("SELECT * FROM memories").fetchall()
        other_counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                        for t in NOT_MIGRATED_TABLES if t in tables}
    finally:
        conn.close()
    vault = LegacyMemoryVault.codec(key)
    counts: Counter[str] = Counter()
    unsupported: Counter[str] = Counter()
    unmapped_targets: Counter[str] = Counter()
    lifecycles: Counter[str] = Counter()
    for row in rows:
        counts[f"{row['scope']}:{row['status']}"] += 1
        try:
            value = vault.open_row(row, include_private=True)
        except Exception:
            counts["decrypt_failures"] += 1
            continue
        try:
            record, notes = map_record(value, mapping, now=now)
        except (MemoryEngineError, KeyError, TypeError, ValueError):
            counts["map_failures"] += 1
            continue
        lifecycles[record.lifecycle.value] += 1
        if not notes["scope_mapped"]:
            unmapped_targets[row["scope"]] += 1
        for name in UNSUPPORTED_FIELDS:
            if value.get(name):
                unsupported[name] += 1
    return {
        "format": LEGACY_FORMAT, "dry_run": True, "rows": len(rows), "columns": columns,
        "by_scope_status": dict(counts), "mapped_lifecycles": dict(lifecycles),
        "decrypt_failures": counts.get("decrypt_failures", 0),
        "map_failures": counts.get("map_failures", 0),
        "unmapped_scopes": dict(unmapped_targets),
        "unmapped_policy": "kept under scope {legacy_target: <legacy target hash>}; visible only to callers "
                           "granted that legacy target until the host supplies a mapping",
        "unsupported_fields": {k: {"records": unsupported.get(k, 0), "handling": v} for k, v in UNSUPPORTED_FIELDS.items()},
        "not_migrated_tables": {t: {"rows": other_counts.get(t, 0), "reason": r} for t, r in NOT_MIGRATED_TABLES.items()},
        "candidate_policy": "candidates stay candidates (never approved); expired candidates import as expired",
    }


def snapshot(legacy_db: Path, out_dir: Path, *, now: float | None = None) -> dict[str, Any]:
    """Consistent encrypted copy + manifest. The copy holds the same ciphertext as the source."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "legacy-snapshot.sqlite3"
    if target.exists():
        raise MigrationError("a snapshot already exists in this directory; use a new directory")
    src = sqlite3.connect(f"file:{Path(legacy_db)}?mode=ro", uri=True, timeout=10)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
        dst.execute("PRAGMA journal_mode=DELETE")
    finally:
        src.close()
        dst.close()
    try:
        target.chmod(0o600)
    except OSError:
        pass
    conn = _connect_ro(target)
    try:
        rows = conn.execute("SELECT * FROM memories ORDER BY id").fetchall()
        fingerprints = {row["id"]: _row_fingerprint(row) for row in rows}
    finally:
        conn.close()
    manifest = {
        "format": MANIFEST_FORMAT, "version": MANIFEST_VERSION, "source_format": LEGACY_FORMAT,
        "destination_schema": "locus-memory partition schema v1",
        "created_at": time.time() if now is None else now, "rows": len(rows),
        "row_fingerprints": fingerprints,
        "snapshot_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "snapshot_file": target.name,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest


def verify_snapshot(out_dir: Path) -> dict[str, Any]:
    out_dir = Path(out_dir)
    manifest = json.loads((out_dir / "manifest.json").read_text())
    target = out_dir / manifest["snapshot_file"]
    ok = hashlib.sha256(target.read_bytes()).hexdigest() == manifest["snapshot_sha256"]
    return {"ok": ok, "rows": manifest["rows"]}


# ---------------------------------------------------------------------- import
class LegacyImporter:
    """Idempotent, resumable import into one partition (requires an ADMIN access context)."""

    def __init__(self, engine, access: AccessContext, legacy_db: Path, key: bytes,
                 mapping: LegacyMapping | None = None, *, batch: int = 200) -> None:
        if Operation.ADMIN not in access.operations:
            raise MigrationError("migration requires an admin access context")
        self.engine = engine
        self.access = access
        self.legacy_db = Path(legacy_db)
        self.mapping = mapping or LegacyMapping()
        self.batch = max(1, batch)
        self.vault = LegacyMemoryVault.codec(key)
        # Test hook: called after each committed batch with the number of records imported so far.
        self.after_batch: Callable[[int], None] | None = None

    def _legacy_rows(self) -> list[sqlite3.Row]:
        conn = _connect_ro(self.legacy_db)
        try:
            return conn.execute("SELECT * FROM memories ORDER BY created_at, id").fetchall()
        finally:
            conn.close()

    def _preflight(self, ctx: Any, rows: list[sqlite3.Row]) -> None:
        """Refuse atomically (before any batch commits) when a legacy id is already used by a
        package record that is neither a legacy import nor a record a rollback wrote back."""
        ids = [row["id"] for row in rows]
        with ctx.partition.db.read() as conn:
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                taken = [r[0] for r in conn.execute(
                    f"SELECT id FROM records WHERE id IN ({','.join('?' * len(chunk))})", chunk)]
                for record_id in taken:
                    token = ctx.records.source_token(_legacy_source_identity(record_id))
                    if conn.execute("SELECT 1 FROM record_sources WHERE record_id=? AND source_token=?",
                                    (record_id, token)).fetchone():
                        continue
                    try:
                        existing = ctx.records.get(conn, record_id)
                    except (IntegrityError, WrongKey):
                        continue  # unreadable: the batch loop reports it
                    if existing is not None and not _legacy_origin(existing):
                        raise MigrationError("a non-legacy package record already uses a legacy id",
                                             details={"conflicting_ids": 1})

    def run(self) -> dict[str, Any]:
        ctx = self.engine.partition_context(self.access.partition)
        core, records, partition = ctx.services.core, ctx.records, ctx.partition
        now = ctx.clock()
        rows = self._legacy_rows()
        self._preflight(ctx, rows)
        report: Counter[str] = Counter()
        notes: Counter[str] = Counter()
        seen: set[str] = set()
        for start in range(0, len(rows), self.batch):
            chunk = rows[start:start + self.batch]
            with partition.db.write() as conn:
                for row in chunk:
                    seen.add(row["id"])
                    try:
                        value = self.vault.open_row(row, include_private=True)
                    except Exception:
                        report["decrypt_failures"] += 1
                        continue
                    try:
                        record, mapped_notes = map_record(value, self.mapping, now=now)
                    except (MemoryEngineError, KeyError, TypeError, ValueError):
                        report["map_failures"] += 1  # reported; verify() refuses to pass while it exists
                        continue
                    for name, flag in mapped_notes.items():
                        if flag is True and name != "scope_mapped":
                            notes[name] += 1
                    if not mapped_notes["scope_mapped"]:
                        notes["unmapped_scope"] += 1
                    existing = records.get(conn, record.id)
                    if existing is None:
                        # Never resurrect forgotten data, whatever forget removed it (memory, project,
                        # agent, repository, profile, source, session) or suppressed it.
                        record, _reason = forgotten_check(ctx, conn, record)
                        if record is None:
                            report["skipped_forgotten"] += 1
                            continue
                        core.write_internal(conn, record, change="imported", actor=Actor.SYSTEM, expected=None)
                        report["imported"] += 1
                        continue
                    if not _legacy_origin(existing):
                        raise MigrationError("a non-legacy package record already uses a legacy id")
                    reasons = delta_reasons(existing, record)
                    if not reasons:
                        report["unchanged"] += 1
                        continue
                    # A forgotten citation stays forgotten when the legacy row changes.
                    forgetting = ctx.services.forgetting
                    kept = tuple(src for src in record.sources if not forgetting.source_forgotten(conn, src))
                    # Compare-and-swap on the package revision: a concurrent writer loses cleanly.
                    updated = dataclasses.replace(record, revision=existing.revision + 1, sources=kept,
                                                  ingested_at=existing.ingested_at)
                    core.write_internal(conn, updated, change="legacy_delta", actor=Actor.SYSTEM,
                                        expected=existing.revision)
                    report["updated"] += 1
                    if "metadata" in reasons:
                        report["metadata_deltas"] += 1
                    if "scope" in reasons:
                        report["rescoped"] += 1
                    if "drift" in reasons:
                        report["drift_repaired"] += 1
                partition.event(conn, "migration", "batch", f"{len(chunk)}")
            if self.after_batch is not None:
                self.after_batch(start + len(chunk))
        deletions = self._propagate_deletions(seen)
        report["deleted_in_legacy"] = deletions["propagated"]
        return {"rows": len(rows), **dict(report), "deletion_propagation": deletions, "notes": dict(notes)}

    def _forget_access(self, scope: Scope) -> AccessContext:
        """The migration actor, authorized for exactly one record's scope - never wider.

        A copy of the importer's context (same principal and partition) whose grants are
        precisely ``scope``'s values, acting as HOST with only FORGET+ADMIN.
        """
        return dataclasses.replace(self.access, actor=Actor.HOST, grants=ScopeGrants.from_dict(scope.as_dict()),
                                   operations=frozenset({Operation.FORGET, Operation.ADMIN}))

    def _propagate_deletions(self, present: set[str]) -> dict[str, Any]:
        """Forget package records imported earlier whose legacy row has since been deleted.

        Each forget is authorized against that record's own scope (see :meth:`_forget_access`),
        so a record outside the importer's grants is still removed and nothing wider is ever
        authorized. One failure never aborts the rest: failures are counted by error code, the
        record stays, and :func:`verify` reports it, so a cutover cannot proceed past it. A
        re-run retries it.
        """
        ctx = self.engine.partition_context(self.access.partition)
        failed: Counter[str] = Counter()
        targets: list[tuple[str, Scope]] = []
        with ctx.partition.db.read() as conn:
            for record_id, record, error in _orphaned_legacy_records(ctx, conn, present):
                if record is None:
                    failed[error or IntegrityError.code] += 1  # unreadable: its scope is unknown
                else:
                    targets.append((record_id, record.scope))
        propagated = 0
        forget_policy = ForgetPolicy(suppress_relearning=False)
        for record_id, scope in targets:
            # Mark the forget as migration-origin first (a crash in between leaves an unbound mark,
            # which still reads as migration-origin), then bind it to the tombstone generation.
            with ctx.partition.db.write() as conn:
                conn.execute("INSERT OR REPLACE INTO migration_forgets(record_id, generation, created_at)"
                             " VALUES(?,NULL,?)", (record_id, ctx.clock()))
            try:
                receipt = ctx.services.forgetting.forget(self._forget_access(scope),
                                                         ForgetTarget("memory", record_id), forget_policy)
            except MemoryEngineError as exc:
                failed[exc.code] += 1
                continue
            except sqlite3.Error:
                failed["storage_error"] += 1
                continue
            with ctx.partition.db.write() as conn:
                conn.execute("UPDATE migration_forgets SET generation=? WHERE record_id=?",
                             (receipt.deletion_generation, record_id))
            propagated += 1
        return {"propagated": propagated, "failed": sum(failed.values()), "failed_by_code": dict(failed)}


def delta_reasons(existing: MemoryRecord, mapped: MemoryRecord) -> list[str]:
    """Why an already imported legacy record must be re-imported (empty: unchanged).

    ``revision``: the legacy row has a new revision. ``metadata``: same revision but the
    legacy metadata fingerprint differs - or the stored record predates fingerprints, in
    which case whether metadata changed is unknown and the record is re-imported once.
    ``scope``: the host mapping now maps the legacy target to a different package scope.
    """
    reasons = []
    if existing.extra.get("legacy_revision") != mapped.revision:
        reasons.append("revision")
    elif existing.extra.get("legacy_fingerprint") != mapped.extra.get("legacy_fingerprint"):
        reasons.append("metadata")
    if existing.scope != mapped.scope:
        reasons.append("scope")
    if not reasons and _drifted(existing, mapped):
        # The package changed an imported record while legacy is authoritative (e.g. maintenance
        # persisted an expiry): legacy wins, otherwise verification would fail on every run.
        reasons.append("drift")
    return reasons


def _drifted(existing: MemoryRecord, mapped: MemoryRecord) -> bool:
    for name in ("kind", "lifecycle", "title", "content", "tags", "basis", "created_at", "updated_at",
                 "validity"):
        if getattr(existing, name) != getattr(mapped, name):
            return True
    return bool(_metadata_mismatches(existing, mapped))


def _legacy_origin(record: MemoryRecord) -> bool:
    """Imported from the legacy store, or a package record a rollback wrote back into it."""
    return bool(record.extra.get("legacy") or record.extra.get("legacy_round_trip"))


def _migration_forget(conn: sqlite3.Connection, record_id: str, generation: int) -> bool:
    row = conn.execute("SELECT generation FROM migration_forgets WHERE record_id=?", (record_id,)).fetchone()
    return row is not None and (row[0] is None or int(row[0]) == generation)


def forgotten_check(ctx: Any, conn: sqlite3.Connection, record: MemoryRecord
                    ) -> tuple[MemoryRecord | None, str | None]:
    """(record to import, None), or (None, reason) when a package-side forget covers the legacy row.

    Covered: a memory tombstone for its id (unless it only propagated a legacy deletion and the
    row is back), a forgotten scope value of its mapped scope, a profile forget, a forgotten
    legacy-import source, or a suppression. A forgotten secondary citation (e.g. a session) is
    dropped and the row imported, as forgetting would have kept it with its other evidence.
    """
    forgetting = ctx.services.forgetting
    generation = forgetting.tombstone_generation(conn, "memory", record.id)
    if generation is not None and not _migration_forget(conn, record.id, generation):
        return None, "memory"
    kept = tuple(src for src in record.sources if not forgetting.source_forgotten(conn, src))
    if not any(src.kind == SourceKind.LEGACY_IMPORT for src in kept):
        return None, "source"
    if kept != record.sources:
        record = dataclasses.replace(record, sources=kept)
    # observed_generation=0: every scope/profile tombstone postdates the legacy data.
    reason = forgetting.blocked_reason(conn, record, observed_generation=0)
    if reason:
        return None, reason
    return record, None


def _orphaned_legacy_records(ctx, conn: sqlite3.Connection, present: set[str]
                             ) -> list[tuple[str, MemoryRecord | None, str | None]]:
    """(id, record, error code) of imported legacy records whose legacy row is gone.

    A row that no longer authenticates is included (record None, with its error code) only
    when the SQL source index shows it was a legacy import; nothing else is knowable about it.
    """
    out: list[tuple[str, MemoryRecord | None, str | None]] = []
    for (record_id,) in conn.execute("SELECT id FROM records ORDER BY id").fetchall():
        if record_id in present:
            continue
        try:
            record = ctx.records.get(conn, record_id)
        except (IntegrityError, WrongKey) as exc:
            token = ctx.records.source_token(_legacy_source_identity(record_id))
            if record_id in ctx.records.ids_for_source(conn, token):
                out.append((record_id, None, exc.code))
            continue
        if record is not None and record.extra.get("legacy"):
            out.append((record_id, record, None))
    return out


def verify(engine, access: AccessContext, legacy_db: Path, key: bytes, mapping: LegacyMapping | None = None,
           *, queries: list[str] | None = None, now: float | None = None) -> dict[str, Any]:
    """Decrypt and compare every record; compare representative retrieval behaviour.

    Besides content and lifecycle (which already reflects legacy ``stale``/``superseded_by``),
    the metadata the legacy vault edits without a revision bump is compared field by field
    (``pinned``, ``expires_at``, ``superseded_by``) together with the stored metadata
    fingerprint. Imported records whose legacy row is gone but which are still present in
    the package (a deletion that was not propagated) are mismatches too.
    """
    mapping = mapping or LegacyMapping()
    codec = LegacyMemoryVault.codec(key)
    ctx = engine.partition_context(access.partition)
    now = ctx.clock() if now is None else now
    conn_ro = _connect_ro(legacy_db)
    try:
        rows = conn_ro.execute("SELECT * FROM memories ORDER BY id").fetchall()
    finally:
        conn_ro.close()
    mismatches: list[dict[str, Any]] = []
    checked = 0
    missing = 0
    with ctx.partition.db.read() as conn:
        for row in rows:
            try:
                value = codec.open_row(row, include_private=True)
            except Exception:
                mismatches.append({"id": row["id"], "field": "undecryptable"})
                continue
            try:
                expected, _ = map_record(value, mapping, now=now)
            except (MemoryEngineError, KeyError, TypeError, ValueError):
                mismatches.append({"id": row["id"], "field": "unmappable"})
                continue
            got = ctx.records.get(conn, row["id"])  # decrypts and authenticates
            if got is None:
                if forgotten_check(ctx, conn, expected)[0] is not None:
                    # Not covered by any package-side forget: live legacy data is missing.
                    missing += 1
                    mismatches.append({"id": row["id"], "field": "missing"})
                continue
            checked += 1
            for name in ("kind", "lifecycle", "scope", "title", "content", "tags", "basis", "created_at",
                         "updated_at", "validity"):
                if getattr(got, name) != getattr(expected, name):
                    mismatches.append({"id": row["id"], "field": name})
            mismatches.extend({"id": row["id"], "field": name} for name in _metadata_mismatches(got, expected))
            if got.extra.get("legacy_revision") != int(row["revision"]):
                mismatches.append({"id": row["id"], "field": "legacy_revision"})
        present = {row["id"] for row in rows}
        for record_id, record, _error in _orphaned_legacy_records(ctx, conn, present):
            mismatches.append({"id": record_id, "field": "deleted_in_legacy" if record is not None else "unreadable"})
    behaviour: list[dict[str, Any]] = []
    for query in queries or []:
        legacy_ids = _legacy_search_ids(codec, rows, query, mapping, now)
        result = engine.search(access, query)
        package_ids = [hit.record.id for hit in result.hits]
        behaviour.append({
            "query_hash": hashlib.sha256(query.encode()).hexdigest()[:12],
            "legacy_hits": len(legacy_ids), "package_hits": len(package_ids),
            "legacy_hits_found_by_package": len(set(legacy_ids) & set(package_ids)),
        })
    return {"ok": not mismatches, "checked": checked, "missing": missing,
            "mismatches": mismatches[:200], "behaviour": behaviour}


def _metadata_mismatches(got: MemoryRecord, expected: MemoryRecord) -> list[str]:
    """Names of the metadata-derived fields on which ``got`` differs from the mapped source."""
    names = []
    if got.retention.pinned != expected.retention.pinned:
        names.append("pinned")
    if got.retention.expires_at != expected.retention.expires_at:
        names.append("expires_at")
    if got.retention.policy != expected.retention.policy:
        names.append("retention")
    if got.links.superseded_by != expected.links.superseded_by:
        names.append("superseded_by")
    if dataclasses.replace(got.links, superseded_by=None) != dataclasses.replace(expected.links, superseded_by=None):
        names.append("links")
    stored = got.extra.get("legacy_fingerprint")
    # Records imported before fingerprints existed carry none: unknown, not a mismatch (the
    # fields above are still compared one by one).
    if stored is not None and stored != expected.extra.get("legacy_fingerprint"):
        names.append("legacy_fingerprint")
    return names


def _legacy_search_ids(codec: LegacyMemoryVault, rows: list[sqlite3.Row], query: str, mapping: LegacyMapping,
                       now: float) -> list[str]:
    """Approved records the legacy lexical scorer would match (membership, not ranking)."""
    import re

    value = query.strip().lower()[:2_000]
    terms = [t for t in re.findall(r"[\w.-]+", value) if len(t) > 1][:24]
    ids = []
    for row in rows:
        if row["status"] != "approved":
            continue
        try:
            record = codec.open_row(row)
        except Exception:
            continue
        haystack = " ".join((record["title"], record["content"], " ".join(record["tags"]))).lower()
        if value in haystack or any(haystack.count(t) for t in terms):
            ids.append(record["id"])
    return ids
