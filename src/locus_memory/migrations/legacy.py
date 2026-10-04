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
import hmac
import json
import math
import sqlite3
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..compat.legacy_vault import (
    VALID_KINDS,
    LegacyMemoryVault,
    legacy_agent_hash,
    legacy_workspace_hash,
)
from ..core import CUTOVER_IMPORT
from ..errors import IntegrityError, MemoryEngineError, MigrationError, OwnershipFenced, WrongKey
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
    canonical_source,
)
from ..storage.partition import MIGRATION_ORIGIN
from ..validation import MAX_TIMESTAMP, MIN_TIMESTAMP, normalize_for_fingerprint

# Ownership states in which the legacy store is the authority and the importer may run.
IMPORT_STATES = frozenset({"legacy_authoritative", "shadow_prepared", "validated"})

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


def snapshot(legacy_db: Path, out_dir: Path, *, now: float | None = None, owner: str | None = None) -> dict[str, Any]:
    """Consistent encrypted copy + manifest. The copy holds the same ciphertext as the source.
    ``owner`` (the partition id of the migration that wrote it) is recorded in the manifest: the
    Migrator finds - and removes - its own snapshots by it."""
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
        **({"owner": str(owner)} if owner is not None else {}),
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
    """Idempotent, resumable import into one partition (requires an ADMIN access context).

    The importer only runs while the legacy store is the authority for the partition's
    memories (``legacy_authoritative``, ``shadow_prepared``, ``validated``; and
    ``cutover_in_progress`` for the :class:`~locus_memory.migrations.cutover.Migrator`'s own
    final delta, under its legacy write barrier). Once the package is authoritative (or a
    rollback is running) it refuses with :class:`OwnershipFenced`: re-importing then would
    overwrite authoritative package data with stale legacy rows, give writes to the fenced
    legacy file authority, and forget package records the legacy file no longer holds. The
    state is the engine host's ownership control unless ``ownership`` is given; with neither,
    no migration is being tracked and nothing is checked.
    """

    def __init__(self, engine, access: AccessContext, legacy_db: Path, key: bytes,
                 mapping: LegacyMapping | None = None, *, batch: int = 200, ownership: Any = None,
                 during_cutover: bool = False) -> None:
        if Operation.ADMIN not in access.operations:
            raise MigrationError("migration requires an admin access context")
        self.engine = engine
        self.access = access
        self.legacy_db = Path(legacy_db)
        self.mapping = mapping or LegacyMapping()
        self.batch = max(1, batch)
        self.vault = LegacyMemoryVault.codec(key)
        self.ownership = ownership
        self.during_cutover = bool(during_cutover)
        self._states = IMPORT_STATES | ({"cutover_in_progress"} if during_cutover else frozenset())
        # Test hook: called after each committed batch with the number of records imported so far.
        self.after_batch: Callable[[int], None] | None = None

    def _controls(self) -> list[Any]:
        controls = [self.ownership, getattr(getattr(self.engine, "host", None), "ownership", None)]
        out: list[Any] = []
        for control in controls:
            if control is not None and all(control is not c for c in out):
                out.append(control)
        return out

    def _require_legacy_authority(self) -> None:
        """Refuse unless the legacy store is still the authority (see the class docstring)."""
        pid = self.access.partition.partition_id
        for control in self._controls():
            state = control.get(pid, "memories").state
            if state not in self._states:
                raise OwnershipFenced(
                    f"the legacy importer is fenced while ownership is {state}: the legacy store is no"
                    " longer the authority for this partition's memories",
                    details={"state": state})

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
        conflicting: list[str] = []
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
                        conflicting.append(record_id)
        if conflicting:
            # The ids (opaque record ids, never content) make the refusal diagnosable.
            raise MigrationError("a non-legacy package record already uses a legacy id",
                                 details={"conflicting_ids": len(conflicting), "ids": sorted(conflicting)[:20]})

    def run(self) -> dict[str, Any]:
        # Checked up front (nothing is read or written otherwise) and again inside every write
        # transaction by CoreService (the inverse ownership fence of 'imported'/'legacy_delta').
        self._require_legacy_authority()
        token = CUTOVER_IMPORT.set(True) if self.during_cutover else None
        try:
            return self._run()
        finally:
            if token is not None:
                CUTOVER_IMPORT.reset(token)

    def _run(self) -> dict[str, Any]:
        ctx = self.engine.partition_context(self.access.partition)
        core, records, partition = ctx.services.core, ctx.records, ctx.partition
        now = ctx.clock()
        rows = self._legacy_rows()
        self._preflight(ctx, rows)
        report: Counter[str] = Counter()
        notes: Counter[str] = Counter()
        seen: set[str] = set()
        with partition.db.read() as conn:
            recovery = rollback_recovery_ids(ctx, conn)
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
                        record, _reason = forgotten_check(ctx, conn, record, record_cover=True)
                        if record is None:
                            report["skipped_forgotten"] += 1
                            continue
                        core.write_internal(conn, record, change="imported", actor=Actor.SYSTEM, expected=None)
                        report["imported"] += 1
                        continue
                    if not _legacy_origin(existing):
                        raise MigrationError("a non-legacy package record already uses a legacy id")
                    record = keep_known_scope(existing, record)
                    reasons = delta_reasons(existing, record)
                    if not reasons:
                        report["unchanged"] += 1
                        continue
                    if reasons == ["drift"] and existing.id in recovery:
                        # The legacy row is the very version a partial rollback replaced by the package
                        # record it kept for recovery (unchanged since: same legacy revision, metadata
                        # and scope): the package changes it lacks are the user's, made while the
                        # package was authoritative - never reverted by "legacy wins".
                        report["recovery_kept"] += 1
                        continue
                    # What the legacy format carries comes from the legacy row; provenance only the
                    # package holds (citations, derived_from, basis of a written-back package record)
                    # is kept, so forgetting an input still reaches the record.
                    merged = merge_delta(existing, record)
                    # A forgotten citation stays forgotten when the legacy row changes.
                    forgetting = ctx.services.forgetting
                    kept = tuple(src for src in merged.sources if not forgetting.source_forgotten(conn, src))
                    # derived_from is package provenance the legacy row never carries (merge_delta keeps
                    # it): a parent forgetting already removed - while it kept this record - is dropped,
                    # never a reason to refuse the legacy change (blocked_reason below).
                    parents = tuple(parent for parent in merged.links.derived_from
                                    if parent == existing.id or (
                                        forgetting.tombstone_generation(conn, "memory", parent) is None
                                        and records.get_row(conn, parent) is not None))
                    # Compare-and-swap on the package revision: a concurrent writer loses cleanly.
                    updated = dataclasses.replace(merged, revision=existing.revision + 1, sources=kept,
                                                  links=dataclasses.replace(merged.links, derived_from=parents),
                                                  ingested_at=existing.ingested_at)
                    blocked = forgetting.blocked_reason(conn, updated)
                    waived: frozenset[str] = frozenset()
                    if blocked is not None:
                        waived = edit_overrides_suppression(ctx, conn, existing, record)
                        if waived:
                            blocked = forgetting.blocked_reason(conn, updated, waive_suppression=waived)
                    if blocked is not None:
                        # A stale legacy row (not newer than what the package holds) never brings back a
                        # corrected-away, rejected or otherwise suppressed statement (nor one derived from
                        # forgotten data): the package record stays as it is and verify reports the
                        # difference until it is resolved.
                        report["skipped_suppressed"] += 1
                        continue
                    if waived:
                        # A newer authoritative edit restated it: the record's own suppression of that
                        # statement is lifted with it (later runs and verify agree on the record).
                        forgetting.lift_suppression(conn, updated.content, own_suppression_tokens(ctx, existing))
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
        self._require_legacy_authority()
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
            self._require_legacy_authority()
            try:
                # The ownership check runs again under this store's write lock, just before the
                # forget's ledger append: a cutover's final transition (which holds that lock) either
                # precedes it - and the legacy deletion is refused - or follows the durable append.
                # The entry itself authenticates that it only propagates a legacy deletion (see
                # _migration_forget); nothing outside the ledger can make a user's forget one.
                ctx.services.forgetting.forget(self._forget_access(scope), ForgetTarget("memory", record_id),
                                               forget_policy, precondition=self._require_legacy_authority,
                                               origin=MIGRATION_ORIGIN)
            except OwnershipFenced:
                raise  # nothing was appended
            except MemoryEngineError as exc:
                failed[exc.code] += 1
                continue
            except sqlite3.Error:
                failed["storage_error"] += 1
                continue
            propagated += 1
        return {"propagated": propagated, "failed": sum(failed.values()), "failed_by_code": dict(failed)}


def keep_known_scope(existing: MemoryRecord, mapped: MemoryRecord) -> MemoryRecord:
    """``mapped`` with ``existing``'s scope when the legacy row's target is that very scope's legacy
    target but the host mapping does not know it (an agent created after the mapping was built,
    whose record a rollback wrote back): a delta never replaces a concrete package scope with the
    unmapped ``legacy_target`` - the agent would lose the record and a forget of the agent would
    miss it."""
    target = mapped.scope.as_dict()
    current = existing.scope.as_dict()
    if set(target) != {"legacy_target"} or set(current) != {"agent"}:
        return mapped
    if target["legacy_target"] != "agent:" + legacy_agent_hash(current["agent"]):
        return mapped
    return dataclasses.replace(mapped, scope=existing.scope)


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
        # (Only reachable before cutover: the importer refuses once the package is authoritative.)
        reasons.append("drift")
    return reasons


def _drifted(existing: MemoryRecord, mapped: MemoryRecord) -> bool:
    return bool(_field_mismatches(existing, mapped, scope=False))


# What a legacy row carries, compared field by field (verify) and repaired by a delta (import).
_LEGACY_FIELDS = ("kind", "lifecycle", "title", "content", "tags", "created_at", "updated_at", "validity")


def _field_mismatches(got: MemoryRecord, expected: MemoryRecord, *, scope: bool = True) -> list[str]:
    """Names of the legacy-carried fields on which ``got`` differs from the mapped legacy row.

    A written-back package record (:func:`_round_trip`) keeps its own statement basis: the legacy
    format has none (every legacy row maps to ``legacy``), so it is not compared."""
    names = [name for name in (("scope",) if scope else ()) + _LEGACY_FIELDS
             if getattr(got, name) != getattr(expected, name)]
    if not _round_trip(got) and got.basis != expected.basis:
        names.append("basis")
    return names + _metadata_mismatches(got, expected)


def _legacy_origin(record: MemoryRecord) -> bool:
    """Imported from the legacy store, or a package record a rollback wrote back into it."""
    return bool(record.extra.get("legacy") or record.extra.get("legacy_round_trip"))


def _round_trip(record: MemoryRecord) -> bool:
    """A package-native record a rollback wrote into the legacy store (never imported from it)."""
    return bool(record.extra.get("legacy_round_trip")) and not record.extra.get("legacy")


def edit_overrides_suppression(ctx: Any, conn: sqlite3.Connection, existing: MemoryRecord,
                               mapped: MemoryRecord) -> frozenset[str]:
    """Suppression source tokens a legacy delta of ``existing`` (mapped from its legacy row) is not
    refused by - empty when the row is not newer than what the package holds.

    A correction (or rejection) of a record suppresses the corrected-away statement against the
    record's sources - for a legacy record the very sources a re-import of its row carries (its
    legacy-import identity, the session/run the legacy row cites) - so a *stale* legacy row (the
    pre-correction version, e.g. restored from a backup or left by a partial rollback) never reverts
    the correction. A legacy row with a *newer* revision than the one the package last held for this
    id (imported, or written there by a rollback and adopted) is not stale: it is an edit made in
    the authoritative legacy store after the package's change - the user restating the statement,
    exactly as ``correct`` in the package may (a correction is never refused by a suppression).
    Waived then:

    * the suppressions keyed on what the legacy row itself carries, on the record's own user
      actions (its creation and correction acts, never relearning provenance) and the source-less
      ``*`` row;
    * when the record itself stated this very statement in an earlier revision (the suppression is
      that of its own correction), those keyed on any source the record cites.

    Suppressions of a statement the record never made, keyed on its evidence (another record
    rejected or forgotten with relearning suppressed), forgotten sources and forgotten parents still
    refuse it. Legacy revisions are bound into the legacy ciphertext's authentication: a keyless
    edit cannot make a stale row look newer."""
    held = existing.extra.get("legacy_revision")
    if not isinstance(held, int) or isinstance(held, bool) or int(mapped.revision) <= held:
        return frozenset()
    tokens = {ctx.records.source_token(_legacy_source_identity(existing.id)), "*"}
    tokens.update(ctx.records.source_token(canonical_source(source).identity()) for source in mapped.sources
                  if _legacy_carried_source(source))
    tokens.update(_own_action_tokens(ctx, existing))
    if _stated_before(ctx, conn, existing, mapped.content):
        tokens.update(ctx.records.source_token(canonical_source(source).identity()) for source in existing.sources)
    return frozenset(tokens)


def _stated_before(ctx: Any, conn: sqlite3.Connection, record: MemoryRecord, content: str) -> bool:
    """Whether a stored revision of ``record`` (its authenticated payload; purged ones say nothing)
    states ``content`` (compared as suppression fingerprints compare it)."""
    wanted = normalize_for_fingerprint(content)
    if normalize_for_fingerprint(record.content) == wanted:
        return True
    for info in ctx.records.revisions(conn, record.id):
        if info.purged or info.revision >= record.revision:
            continue
        try:
            earlier = ctx.records.revision_record(conn, record.id, info.revision)
        except (IntegrityError, WrongKey):
            continue
        if earlier is not None and normalize_for_fingerprint(earlier.content) == wanted:
            return True
    return False


def own_suppression_tokens(ctx: Any, record: MemoryRecord) -> frozenset[str]:
    """The suppression source tokens that only ever match ``record`` itself: its legacy-import
    identity and its own user actions. An accepted newer legacy edit lifts the suppression of its
    statement keyed on these (never one keyed on shared evidence, nor the ``*`` row)."""
    return frozenset({ctx.records.source_token(_legacy_source_identity(record.id)), *_own_action_tokens(ctx, record)})


def _own_action_tokens(ctx: Any, record: MemoryRecord) -> set[str]:
    return {ctx.records.source_token(canonical_source(source).identity()) for source in record.sources
            if source.kind == SourceKind.USER_ACTION}


def _legacy_carried_source(source: SourceRef) -> bool:
    """A citation the legacy row itself produces (map_record): its import source and the
    session/run references of the legacy ``source_session_id``/``source_run_id`` fields."""
    return source.kind == SourceKind.LEGACY_IMPORT or (
        isinstance(source.locator, dict) and source.locator.get("legacy_field") in ("source_session_id",
                                                                                    "source_run_id"))


def merge_delta(existing: MemoryRecord, mapped: MemoryRecord) -> MemoryRecord:
    """The record a legacy delta writes over ``existing`` (revision/ingest time set by the caller).

    The fields the legacy format carries - kind, lifecycle, scope, title, content, tags, reason,
    validity, retention (pinned, expiry), supersedes/superseded_by, created/updated time and the
    ``legacy_*`` bookkeeping - come from the mapped legacy row. Provenance only the package holds
    is never dropped: citations the legacy row does not produce (memory, message, session,
    episode, task-attempt evidence) and ``links.derived_from``, so forgetting an input still
    cascades to the record. A package record a rollback wrote back (:func:`_round_trip`) also
    keeps its statement basis, conflict links and other ``extra`` entries (e.g.
    ``basis_attested_by``); it never becomes an "imported" record.
    """
    carried = {source.identity() for source in mapped.sources}
    package_sources = tuple(source for source in existing.sources
                            if not _legacy_carried_source(source) and source.identity() not in carried)
    sources = tuple(mapped.sources) + package_sources
    if not _round_trip(existing):
        links = dataclasses.replace(mapped.links, derived_from=existing.links.derived_from)
        return dataclasses.replace(mapped, sources=sources, links=links)
    links = dataclasses.replace(existing.links, supersedes=mapped.links.supersedes,
                                superseded_by=mapped.links.superseded_by)
    extra = {**existing.extra, **{k: v for k, v in mapped.extra.items() if k != "legacy"},
             "legacy_round_trip": True}
    return dataclasses.replace(
        existing, kind=mapped.kind, lifecycle=mapped.lifecycle, scope=mapped.scope, title=mapped.title,
        content=mapped.content, tags=mapped.tags, reason=mapped.reason, validity=mapped.validity,
        retention=mapped.retention, links=links, sources=sources, created_at=mapped.created_at,
        updated_at=mapped.updated_at, extra=extra)


def _migration_forget(ctx: Any, conn: sqlite3.Connection, record_id: str, generation: int) -> bool:
    """Whether the memory forget of ``record_id`` at ``generation`` only propagated a legacy deletion
    (the importer's, see ``LegacyImporter._propagate_deletions``) rather than being a user's.

    Decided by the authenticated deletion ledger: the importer's entries carry the migration origin
    under the ledger MAC. Only an entry written before that existed (format 1) falls back to the
    ``migration_forgets`` mark an earlier build recorded - and only to one bound to exactly that
    generation (an unbound row is what any tamperer could insert)."""
    verdict = ctx.partition.deletion_view().migration_forget(record_id, int(generation))
    if verdict is not None:
        return verdict
    row = conn.execute("SELECT generation FROM migration_forgets WHERE record_id=?", (record_id,)).fetchone()
    return row is not None and row[0] is not None and int(row[0]) == int(generation)


def forgotten_check(ctx: Any, conn: sqlite3.Connection, record: MemoryRecord, *, record_cover: bool = False
                    ) -> tuple[MemoryRecord | None, str | None]:
    """(record to import, None), or (None, reason) when a package-side forget covers the legacy row.

    ``record_cover`` (the importer, inside its write transaction): when a scope or profile forget
    covers the row, remember that by id (:func:`_scope_forget_cover`).

    Covered: a memory tombstone for its id (unless it only propagated a legacy deletion and the
    row is back), a forgotten scope value of its mapped scope, a profile forget, a forgotten
    legacy-import source, or a suppression. A forgotten secondary citation (e.g. a session) is
    handled exactly as forgetting handles it in a record the package holds: a record forgetting
    keeps with its other evidence (not evidence-dependent: an approved legacy memory) is imported
    with the citation dropped; an evidence-dependent one (a candidate, a derived kind or basis, an
    unattested record - ``ForgettingService.evidence_dependent``, judged on the mapped row before
    anything is dropped) is covered, as forgetting would have removed it.
    """
    forgetting = ctx.services.forgetting
    # The authenticated ledger first: a user's forget of this id, or any forget that removed it (its
    # outcome), covers it whatever the plaintext tombstone, suppression and mark tables say now.
    if ctx.partition.deletion_view().user_forgotten(record.id) is not None:
        return None, "memory"
    generation = forgetting.tombstone_generation(conn, "memory", record.id)
    if generation is not None and not _migration_forget(ctx, conn, record.id, generation):
        return None, "memory"
    kept = tuple(src for src in record.sources if not forgetting.source_forgotten(conn, src))
    if not any(src.kind == SourceKind.LEGACY_IMPORT for src in kept):
        return None, "source"
    if kept != record.sources:
        if forgetting.evidence_dependent(record):
            return None, "source"  # an evidence source was forgotten (an evidence-dependent record)
        record = dataclasses.replace(record, sources=kept)
    # Forgotten sources, derivation inputs and suppressions (not time-bound).
    reason = forgetting.blocked_reason(conn, record)
    if reason:
        return None, reason
    cover = _scope_forget_cover(ctx, conn, record)
    if cover is not None:
        if record_cover:
            conn.execute("INSERT OR IGNORE INTO migration_scope_covered(token, generation) VALUES(?, ?)",
                         (ctx.partition.token(_SCOPE_COVER_TOKEN, record.id), cover[1]))
        return None, cover[0]
    return record, None


def _scope_forget_reason(ctx: Any, conn: sqlite3.Connection, record: MemoryRecord) -> str | None:
    cover = _scope_forget_cover(ctx, conn, record)
    return None if cover is None else cover[0]


_SCOPE_COVER_TOKEN = "migration-scope-covered"


def _scope_forget_cover(ctx: Any, conn: sqlite3.Connection, record: MemoryRecord) -> tuple[str, int] | None:
    """(reason, forget generation) when a scope (project, agent, ...) or profile forget covers the
    legacy row: the forget covers the legacy rows that existed when it ran - never every later row
    of that workspace, agent or profile.

    Only consulted for legacy ids the package did not hold when the forget ran: a record the
    forget removed (an imported row, or one a rollback wrote back) got its own memory tombstone
    (``ForgettingService._apply``), which :func:`forgotten_check` honours by id whatever the
    legacy row's dates say.

    * A forget at or below the last rollback's deletion generation (:func:`rollback_watermark`,
      authenticated) was applied to the legacy store by that rollback, which deleted every row it
      covered: a legacy row present now was written afterwards and is live legacy data.
    * A later forget (made while legacy is authoritative, or after the last cutover) covers a row
      the importer already found it covering (``migration_scope_covered``, by id: decided once) and
      otherwise a row unless the row was created after the forget (the tombstone's time; ledger,
      records and the legacy vault all use the host clock). A row created at or before it stays
      forgotten, even if it was edited later; so does a row claiming a creation time later than now
      (no honest save writes one: it fails closed). The legacy ``created_at`` column is outside the
      legacy ciphertext's authentication: for a row the importer never saw before the forget, a
      keyless edit of it can still move the row from "before" to "after" the forget - a residual
      limited to rows written after the last import and before the forget (see
      docs/migrations-and-rollback.md).
    """
    watermark = rollback_watermark(conn, ctx)
    now = float(ctx.clock())
    view = ctx.partition.deletion_view()
    targets = [(f"scope:{dim}", ctx.records.scope_value_token(dim, value), f"the {dim} was forgotten")
               for dim, value in record.scope.constraints]
    targets.append(("profile", ctx.partition.partition_id, "the profile was forgotten"))
    covered = conn.execute("SELECT generation FROM migration_scope_covered WHERE token=?",
                           (ctx.partition.token(_SCOPE_COVER_TOKEN, record.id),)).fetchone()
    if covered is not None and int(covered[0]) > watermark:
        entry = view.by_generation.get(int(covered[0]))
        for kind, token, reason in targets:
            if entry is not None and (entry.target_kind, entry.target_token) == (kind, token):
                return f"{reason} after this legacy row was written", int(covered[0])
    for kind, token, reason in targets:
        # The forget's generation and time as the authenticated ledger states them (the plaintext
        # tombstone row only when the ledger has no entry for it).
        row = view.latest(kind, token) or conn.execute(
            "SELECT generation, created_at FROM tombstones WHERE target_kind=? AND target_token=?",
            (kind, token)).fetchone()
        if row is None or int(row[0]) <= watermark:
            continue
        if float(row[1]) < float(record.created_at) <= now:
            continue  # written after the forget: new legacy data
        return f"{reason} after this legacy row was written", int(row[0])
    return None


ROLLBACK_WATERMARK_KEY = "migration_rollback_generation"
CUTOVER_SET_KEY = "migration_cutover_set"
_CUTOVER_TOKEN = "migration-cutover-id"


ROLLBACK_WATERMARK_MAC_KEY = "migration_rollback_generation_mac"


def _watermark_mac(ctx: Any, value: int) -> str:
    return ctx.partition.token("migration-rollback-watermark", f"{ctx.partition.partition_id}|{int(value)}")


def rollback_watermark(conn: sqlite3.Connection, ctx: Any = None) -> int:
    """Deletion generation the last completed rollback applied to the legacy store (0: none).

    With ``ctx`` (every decision made on it): only a value bound to this partition's key by
    :func:`authenticate_rollback_watermark` counts, never above the store's (authenticated)
    deletion generation - a missing, edited or forged value is 0, which fails closed (every later
    forget is then treated as one the legacy store may still hold). Without ``ctx``: the recorded
    value as stored (diagnostics)."""
    row = conn.execute("SELECT value FROM meta WHERE key=?", (ROLLBACK_WATERMARK_KEY,)).fetchone()
    try:
        value = max(0, int(row[0])) if row is not None else 0
    except (TypeError, ValueError):
        return 0
    if ctx is None or value == 0:
        return value
    mac = conn.execute("SELECT value FROM meta WHERE key=?", (ROLLBACK_WATERMARK_MAC_KEY,)).fetchone()
    if mac is None or not hmac.compare_digest(str(mac[0]), _watermark_mac(ctx, value)):
        return 0
    return min(value, ctx.partition.deletion_generation(conn))


def record_rollback_watermark(conn: sqlite3.Connection, generation: int) -> None:
    """Inside the rollback's package write transaction, after its last deletion was applied (then
    :func:`authenticate_rollback_watermark`)."""
    value = max(rollback_watermark(conn), int(generation))
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (ROLLBACK_WATERMARK_KEY, str(value)))


def authenticate_rollback_watermark(ctx: Any, conn: sqlite3.Connection, generation: int) -> None:
    """Right after :func:`record_rollback_watermark`, in the same transaction: bind the watermark to
    this partition's key. The value bound is the larger of the authenticated previous watermark and
    ``generation`` - never a larger value an offline edit put into ``meta`` before (which would make
    every forget up to it look applied to the legacy store, and so stop covering the legacy rows it
    covers). Nothing is bound when no watermark of at least ``generation`` was recorded."""
    if rollback_watermark(conn) < int(generation):
        return
    value = max(rollback_watermark(conn, ctx), int(generation))
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (ROLLBACK_WATERMARK_KEY, str(value)))
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
                 (ROLLBACK_WATERMARK_MAC_KEY, _watermark_mac(ctx, value)))


def record_cutover_set(ctx: Any, conn: sqlite3.Connection, legacy_ids: Iterable[str]) -> int:
    """Remember (as keyed tokens) the legacy ids a successful cutover verified: every one of them
    was imported or covered by a package-side forget. Only these legacy rows are ever deleted for
    lack of a package record (rollback, post-cutover forget propagation); a legacy row the
    package never had is never deleted on that ground. Replaces the previous cutover's set."""
    conn.execute("DELETE FROM migration_cutover_ids")
    tokens = sorted({ctx.partition.token(_CUTOVER_TOKEN, str(i)) for i in legacy_ids})
    conn.executemany("INSERT OR IGNORE INTO migration_cutover_ids(token) VALUES(?)", [(t,) for t in tokens])
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, '1')", (CUTOVER_SET_KEY,))
    return len(tokens)


def record_rollback_ids(ctx: Any) -> int:
    """Before a rollback writes anything into the legacy store (its own committed transaction):
    add every package record id to the set of legacy ids the package held (the cutover set).

    A rollback writes package records into the legacy store under their package ids; legacy
    writes commit on their own, the rollback's package transaction later (or, after a crash or a
    failure, never). A record the package removes afterwards - while the rollback is still in
    progress, or by a deletion the rollback applies late - is then known to be the package's own,
    and its legacy copy is deleted like any other row of the set, never judged by what the legacy
    row carries (:func:`forgotten_check`). Every id added is one the package holds, so a legacy
    row the package never held is still never deleted on that ground. The next cutover replaces
    the set. Without a recorded set (a cutover by an earlier build) this changes nothing: every
    legacy row without a package record is deleted then anyway."""
    with ctx.partition.db.write() as conn:
        ids = [row[0] for row in conn.execute("SELECT id FROM records")]
        conn.executemany("INSERT OR IGNORE INTO migration_cutover_ids(token) VALUES(?)",
                         [(cutover_token(ctx, record_id),) for record_id in ids])
    return len(ids)


def forgotten_since(conn: sqlite3.Connection, generation: int, ctx: Any = None) -> set[str]:
    """Ids of package records a deletion above ``generation`` removed and that have no package
    record now: memory tombstones - a forget gives one to its memory target and to every record it
    removes, by any target, by cascade or with its evidence - and (with ``ctx``) the removals the
    authenticated deletion ledger proves, except deletions the importer made only to propagate a
    legacy deletion (:func:`_migration_forget`). What an aborted cutover applies to the legacy file."""
    out: set[str] = set()
    candidates = [(str(r[0]), int(r[1])) for r in conn.execute(
        "SELECT target_token, generation FROM tombstones WHERE target_kind='memory' AND generation > ?",
        (int(generation),)).fetchall()]
    if ctx is not None:
        # Removals the authenticated ledger proves (a tombstone row may have been deleted).
        candidates += [(record_id, removed_at) for record_id, (removed_at, _policy)
                       in ctx.partition.deletion_view().removed_records().items() if removed_at > int(generation)]
    for record_id, tombstone_generation in candidates:
        if record_id in out:
            continue
        if ctx is not None and _migration_forget(ctx, conn, record_id, tombstone_generation):
            continue
        if ctx is None and conn.execute("SELECT 1 FROM migration_forgets WHERE record_id=? AND generation=?",
                                        (record_id, tombstone_generation)).fetchone() is not None:
            continue
        if conn.execute("SELECT 1 FROM records WHERE id=?", (record_id,)).fetchone() is not None:
            continue
        out.add(record_id)
    return out


_RECOVERY_TOKEN = "migration-recovery-id"


def record_rollback_recovery(ctx: Any, conn: sqlite3.Connection, record_ids: Iterable[str]) -> int:
    """Inside the rollback's package write transaction: the ids it kept in the package only (records
    the legacy format cannot represent; their earlier legacy rows were deleted). Replaces the
    previous rollback's set. See :func:`rollback_recovery_ids`."""
    conn.execute("DELETE FROM migration_recovery_ids")
    tokens = sorted({ctx.partition.token(_RECOVERY_TOKEN, str(i)) for i in record_ids})
    conn.executemany("INSERT OR IGNORE INTO migration_recovery_ids(token) VALUES(?)", [(t,) for t in tokens])
    return len(tokens)


def rollback_recovery_ids(ctx: Any, conn: sqlite3.Connection) -> _RecoverySet:
    """The record ids the last rollback kept in the package only: their legacy row is missing on
    purpose (never a legacy deletion to propagate), and an unchanged earlier legacy row of one never
    wins over the package record (``id in`` the returned set)."""
    return _RecoverySet(ctx, {r[0] for r in conn.execute("SELECT token FROM migration_recovery_ids")})


class _RecoverySet:
    """Membership test over the keyed recovery tokens."""

    def __init__(self, ctx: Any, tokens: set[str]) -> None:
        self._ctx = ctx
        self._tokens = tokens

    def __contains__(self, record_id: object) -> bool:
        return bool(self._tokens) and isinstance(record_id, str) and \
            self._ctx.partition.token(_RECOVERY_TOKEN, record_id) in self._tokens

    def __bool__(self) -> bool:
        return bool(self._tokens)


def cutover_set(ctx: Any, conn: sqlite3.Connection) -> set[str] | None:
    """Tokens of the last cutover's legacy ids, or None when no set was recorded (a cutover made by
    an earlier build)."""
    if conn.execute("SELECT 1 FROM meta WHERE key=?", (CUTOVER_SET_KEY,)).fetchone() is None:
        return None
    return {r[0] for r in conn.execute("SELECT token FROM migration_cutover_ids")}


def cutover_token(ctx: Any, record_id: str) -> str:
    return ctx.partition.token(_CUTOVER_TOKEN, str(record_id))


def _orphaned_legacy_records(ctx, conn: sqlite3.Connection, present: set[str]
                             ) -> list[tuple[str, MemoryRecord | None, str | None]]:
    """(id, record, error code) of legacy-origin records whose legacy row is gone.

    Legacy origin (:func:`_legacy_origin`): imported from the legacy store, or a package record
    a rollback wrote into it (``extra.legacy_round_trip``) - once legacy is authoritative again,
    a user's deletion of that row is a legacy deletion like any other. A package-native record
    that never reached the legacy store has neither marker and is never selected.

    A row that no longer authenticates is included (record None, with its error code) only
    when the SQL source index shows a legacy-import source (imports and write-backs both carry
    one); nothing else is knowable about it. A record the last rollback kept in the package only
    (:func:`rollback_recovery_ids`) is never selected: that rollback deleted its legacy row.
    """
    out: list[tuple[str, MemoryRecord | None, str | None]] = []
    recovery = rollback_recovery_ids(ctx, conn)
    for (record_id,) in conn.execute("SELECT id FROM records ORDER BY id").fetchall():
        if record_id in present or record_id in recovery:
            continue
        try:
            record = ctx.records.get(conn, record_id)
        except (IntegrityError, WrongKey) as exc:
            token = ctx.records.source_token(_legacy_source_identity(record_id))
            if record_id in ctx.records.ids_for_source(conn, token):
                out.append((record_id, None, exc.code))
            continue
        if record is not None and _legacy_origin(record):
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
        recovery = rollback_recovery_ids(ctx, conn)
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
            expected = keep_known_scope(got, expected)
            if got.id in recovery and delta_reasons(got, expected) == ["drift"]:
                continue  # the package version a rollback kept over this unchanged legacy row (see _run)
            mismatches.extend({"id": row["id"], "field": name} for name in _field_mismatches(got, expected))
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
    # The legacy format carries supersedes/superseded_by only: derived_from (and a written-back
    # record's conflict links) are package provenance a delta keeps (see merge_delta).
    if tuple(got.links.supersedes) != tuple(expected.links.supersedes) or (
            not _round_trip(got) and tuple(got.links.conflicts_with) != tuple(expected.links.conflicts_with)):
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
