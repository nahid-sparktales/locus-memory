"""Rollback preserves host provenance bindings, including explicit removal."""
from __future__ import annotations

import dataclasses

import pytest

from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.migrations.cutover import Migrator
from locus_memory.migrations.state import OwnershipControl
from locus_memory.models import Actor, RememberRequest, SourceKind, SourceRef


def test_rollback_keeps_new_record_source_bindings(engine, user_access, tmp_path):
    key = b"b" * 32
    legacy = LegacyMemoryVault(tmp_path / "legacy.sqlite3", key=key)
    control = OwnershipControl(tmp_path / "control")
    try:
        migrator = Migrator(engine, control, user_access, legacy.path, key, work_dir=tmp_path / "migration")
        migrator.prepare_shadow()
        assert migrator.validate()["validated"]
        assert migrator.cutover()["cutover"]
        record = engine.remember(user_access, RememberRequest("Violet source binding")).record
        ctx = engine.partition_context(user_access.partition)
        bindings = (
            SourceRef(SourceKind.SESSION, "session-new", actor=Actor.HOST,
                      locator={"legacy_field": "source_session_id"}, available=False),
            SourceRef(SourceKind.TASK_ATTEMPT, "run-new", actor=Actor.HOST,
                      locator={"legacy_field": "source_run_id"}, available=False),
        )
        with ctx.partition.db.write() as conn:
            ctx.services.core.write_internal(
                conn, dataclasses.replace(record, revision=record.revision + 1, sources=record.sources + bindings),
                change="host_sources", actor=Actor.USER, expected=record.revision,
            )
        assert migrator.rollback()["state"] == "legacy_authoritative"
        restored = legacy.list()[0]
        assert restored["source_session_id"] == "session-new"
        assert restored["source_run_id"] == "run-new"
    finally:
        control.close()


@pytest.mark.parametrize("metadata", [{"source_session_id": None, "source_run_id": None},
                                       {"source_session_id": "session-updated", "source_run_id": "run-updated"},
                                       None])
def test_source_only_change_is_written_and_removed_sources_stay_absent(engine, user_access, tmp_path, metadata):
    key = b"c" * 32
    legacy = LegacyMemoryVault(tmp_path / "legacy.sqlite3", key=key)
    original = legacy.save({"content": "Unchanged content", "scope": "personal", "source_session_id": "session-old",
                            "source_run_id": "run-old"})
    control = OwnershipControl(tmp_path / "control")
    try:
        migrator = Migrator(engine, control, user_access, legacy.path, key, work_dir=tmp_path / "migration")
        migrator.prepare_shadow()
        assert migrator.validate()["validated"]
        assert migrator.cutover()["cutover"]
        ctx = engine.partition_context(user_access.partition)
        with ctx.partition.db.write() as conn:
            record = ctx.records.get(conn, original["id"])
            updates = {"extra": {**record.extra, "locus": metadata}} if metadata is not None else {
                "sources": tuple(s for s in record.sources if not s.locator.get("legacy_field"))}
            ctx.services.core.write_internal(
                conn, dataclasses.replace(record, revision=record.revision + 1, **updates),
                change="host_sources", actor=Actor.USER, expected=record.revision,
            )
        assert migrator.rollback()["state"] == "legacy_authoritative"
        restored = legacy.list()[0]
        assert restored["content"] == "Unchanged content"
        assert restored["source_session_id"] == (metadata or {}).get("source_session_id")
        assert restored["source_run_id"] == (metadata or {}).get("source_run_id")
    finally:
        control.close()
