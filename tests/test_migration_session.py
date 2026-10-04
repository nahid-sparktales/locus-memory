"""Offline lifecycle works without importing or discovering any host app."""
from contextlib import contextmanager

import pytest

from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.crypto import StaticKeyProvider
from locus_memory.errors import MigrationError
from locus_memory.migrations.legacy import LegacyMapping
from locus_memory.migrations.session import LegacyMigrationSession
from locus_memory.models import PartitionRef


def test_session_holds_host_lease_through_cutover_and_rollback(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    key = b"k" * 32
    vault = LegacyMemoryVault(database, key=key)
    saved = vault.save({"scope": "personal", "content": "Prefer concise replies"})
    active = []

    @contextmanager
    def lease():
        active.append(True)
        try:
            yield
        finally:
            active.pop()

    def quiescent():
        assert active == [True]

    session = LegacyMigrationSession(
        tmp_path / "engine", database, StaticKeyProvider({"test": key}),
        partition=PartitionRef("test", "default"), legacy_key=lambda: key,
        mapping=LegacyMapping, lease=lease, assert_quiescent=quiescent,
    )
    with session as migration:
        assert migration.inventory()["rows"] == 1
        assert migration.snapshot()["state"] == "shadow_prepared"
        assert migration.validate()["validated"]
        assert migration.cutover()["cutover"]
        assert migration.engine.get(migration.access, saved["id"]).content == saved["content"]
        assert migration.rollback()["state"] == "legacy_authoritative"
    assert not active


def test_session_quiescence_failure_releases_lease_without_destination(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    LegacyMemoryVault(database, key=b"k" * 32)
    active = []

    @contextmanager
    def lease():
        active.append(True)
        try:
            yield
        finally:
            active.pop()

    def quiescent():
        raise MigrationError("host is busy")

    with pytest.raises(MigrationError, match="host is busy"), LegacyMigrationSession(
        tmp_path / "engine", database, StaticKeyProvider({"test": b"k" * 32}),
        partition=PartitionRef("test", "default"), legacy_key=lambda: b"k" * 32,
        mapping=LegacyMapping, lease=lease, assert_quiescent=quiescent,
    ):
        pytest.fail("must not acquire a migration session")
    assert not active
    assert not (tmp_path / "engine").exists()
