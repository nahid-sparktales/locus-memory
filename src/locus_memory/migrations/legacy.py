"""Locus MemoryVault (format v2, "memory-v1" AAD) -> locus-memory partition migration.

Operations, all explicit and never run on import/installation:

* :func:`inventory` - read-only dry run; counts and compatibility classes, no content.
* :func:`snapshot`  - consistent copy of the (already encrypted) legacy database via the
  SQLite backup API plus a manifest of per-row fingerprints. No plaintext is written.
* :class:`LegacyImporter` - idempotent, resumable import preserving ids, revisions,
  lifecycle, scope, provenance and deletion state; a re-run applies only deltas and
  propagates legacy deletions as package tombstones.
* :func:`verify` - decrypts every destination record and compares it with the mapped
  source, then compares representative retrieval behaviour.

Code extraction (compat.legacy_vault) and physical migration are separate: Locus can
delegate to the package over the legacy file without running anything here.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..compat.legacy_vault import (
    VALID_KINDS,
    LegacyMemoryVault,
    legacy_agent_hash,
    legacy_workspace_hash,
)
from ..errors import MigrationError
from ..models import (
    AccessContext,
    Actor,
    Confidence,
    Lifecycle,
    Links,
    MemoryKind,
    MemoryRecord,
    Operation,
    Retention,
    Scope,
    SourceKind,
    SourceRef,
    StatementBasis,
    Validity,
)

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


def lifecycle_for(row: dict[str, Any], *, now: float) -> Lifecycle:
    if row["status"] == "candidate":
        expires = row.get("expires_at")
        return Lifecycle.EXPIRED if expires is not None and float(expires) < now else Lifecycle.CANDIDATE
    if row.get("superseded_by"):
        return Lifecycle.SUPERSEDED
    if row.get("stale"):
        return Lifecycle.STALE
    return Lifecycle.APPROVED


def map_record(value: dict[str, Any], mapping: LegacyMapping, *, now: float) -> tuple[MemoryRecord, dict[str, Any]]:
    """Map one decrypted legacy record (open_row(include_private=True)) to a package record."""
    scope, mapped = mapping.scope_for(value["scope"], value["target_hash"])
    notes: dict[str, Any] = {"scope_mapped": mapped}
    sources = [SourceRef(SourceKind.LEGACY_IMPORT, f"legacy-vault:{value['id']}", actor=Actor.SYSTEM,
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
        "legacy_last_used_at": value.get("last_used_at"),
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
    valid_from, valid_until = value.get("valid_from"), value.get("valid_until")
    if valid_from is not None and valid_until is not None and valid_until <= valid_from:
        valid_until = None
        notes["invalid_validity_dropped"] = True
    lifecycle = lifecycle_for(value, now=now)
    record = MemoryRecord(
        id=value["id"], revision=int(value["revision"]), kind=MemoryKind(kind), lifecycle=lifecycle,
        scope=scope, title=value["title"], content=value["content"], tags=tuple(value.get("tags") or ()),
        basis=StatementBasis.LEGACY,
        confidence=Confidence(float(value["confidence"]), False, "legacy_unspecified")
        if value.get("confidence") is not None else Confidence(),
        sources=tuple(sources), validity=Validity(valid_from, valid_until),
        retention=Retention("durable", float(value["expires_at"]) if value.get("expires_at") is not None else None,
                            bool(value["pinned"])),
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
        record, notes = map_record(value, mapping, now=now)
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

    def run(self) -> dict[str, Any]:
        ctx = self.engine.partition_context(self.access.partition)
        core, records, partition = ctx.services.core, ctx.records, ctx.partition
        now = ctx.clock()
        rows = self._legacy_rows()
        report: Counter[str] = Counter()
        notes: Counter[str] = Counter()
        seen: set[str] = set()
        for start in range(0, len(rows), self.batch):
            chunk = rows[start:start + self.batch]
            with partition.db.write() as conn:
                for row in chunk:
                    seen.add(row["id"])
                    if ctx.services.forgetting.tombstone_generation(conn, "memory", row["id"]) is not None:
                        report["skipped_forgotten"] += 1  # never resurrect forgotten data
                        continue
                    try:
                        value = self.vault.open_row(row, include_private=True)
                    except Exception:
                        report["decrypt_failures"] += 1
                        continue
                    record, mapped_notes = map_record(value, self.mapping, now=now)
                    for name, flag in mapped_notes.items():
                        if flag is True and name != "scope_mapped":
                            notes[name] += 1
                    if not mapped_notes["scope_mapped"]:
                        notes["unmapped_scope"] += 1
                    existing = records.get(conn, record.id)
                    if existing is None:
                        core.write_internal(conn, record, change="imported", actor=Actor.SYSTEM, expected=None)
                        report["imported"] += 1
                    elif existing.extra.get("legacy_revision") == record.revision and existing.extra.get("legacy"):
                        report["unchanged"] += 1
                    elif not existing.extra.get("legacy"):
                        raise MigrationError("a non-legacy package record already uses a legacy id")
                    else:
                        updated = dataclasses.replace(record, revision=existing.revision + 1,
                                                      ingested_at=existing.ingested_at)
                        core.write_internal(conn, updated, change="legacy_delta", actor=Actor.SYSTEM,
                                            expected=existing.revision)
                        report["updated"] += 1
                partition.event(conn, "migration", "batch", f"{len(chunk)}")
            if self.after_batch is not None:
                self.after_batch(start + len(chunk))
        report["deleted_in_legacy"] = self._propagate_deletions(seen)
        return {"rows": len(rows), **dict(report), "notes": dict(notes)}

    def _propagate_deletions(self, present: set[str]) -> int:
        """Records imported earlier but deleted in the legacy store since: forget them in the package."""
        from ..models import ForgetPolicy, ForgetTarget

        ctx = self.engine.partition_context(self.access.partition)
        with ctx.partition.db.read() as conn:
            rows = conn.execute("SELECT id FROM records").fetchall()
            legacy_ids = [r[0] for r in rows
                          if (rec := ctx.records.get(conn, r[0])) is not None and rec.extra.get("legacy")]
        removed = 0
        admin = dataclasses.replace(self.access, actor=Actor.HOST,
                                    operations=self.access.operations | {Operation.FORGET})
        for record_id in legacy_ids:
            if record_id in present:
                continue
            ctx.services.forgetting.forget(admin, ForgetTarget("memory", record_id),
                                           ForgetPolicy(suppress_relearning=False))
            removed += 1
        return removed


def verify(engine, access: AccessContext, legacy_db: Path, key: bytes, mapping: LegacyMapping | None = None,
           *, queries: list[str] | None = None, now: float | None = None) -> dict[str, Any]:
    """Decrypt and compare every record; compare representative retrieval behaviour."""
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
            value = codec.open_row(row, include_private=True)
            expected, _ = map_record(value, mapping, now=now)
            got = ctx.records.get(conn, row["id"])  # decrypts and authenticates
            if got is None:
                if ctx.services.forgetting.tombstone_generation(conn, "memory", row["id"]) is None:
                    missing += 1
                    mismatches.append({"id": row["id"], "field": "missing"})
                continue
            checked += 1
            for name in ("kind", "lifecycle", "scope", "title", "content", "tags", "basis", "created_at",
                         "updated_at", "validity", "links"):
                if getattr(got, name) != getattr(expected, name):
                    mismatches.append({"id": row["id"], "field": name})
            if got.retention.pinned != expected.retention.pinned:
                mismatches.append({"id": row["id"], "field": "pinned"})
            if got.extra.get("legacy_revision") != int(row["revision"]):
                mismatches.append({"id": row["id"], "field": "legacy_revision"})
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
        record = codec.open_row(row)
        haystack = " ".join((record["title"], record["content"], " ".join(record["tags"]))).lower()
        if value in haystack or any(haystack.count(t) for t in terms):
            ids.append(record["id"])
    return ids
