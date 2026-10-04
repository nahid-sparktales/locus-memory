"""Read-only selection and process exclusion do not require a host application."""
from __future__ import annotations

import sqlite3

import pytest

from locus_memory.compat.legacy_vault import LegacyVaultError
from locus_memory.errors import OwnershipFenced
from locus_memory.migrations.ownership import assert_legacy_writer, ownership_state, profile_lease
from locus_memory.migrations.state import OwnershipControl
from locus_memory.models import PartitionRef

PARTITION = PartitionRef("test-host", "profile-one")


def test_unmigrated_lookup_creates_no_profile_files(tmp_path):
    root = tmp_path / "uncreated"
    assert ownership_state(root, PARTITION) == "legacy_authoritative"
    assert_legacy_writer(root, PARTITION)
    assert not root.exists()


def test_lookup_uses_explicit_partition_and_fences_legacy(tmp_path):
    control = OwnershipControl(tmp_path)
    for generation, state in enumerate(("shadow_prepared", "validated", "cutover_in_progress",
                                        "package_authoritative")):
        control.transition(PARTITION.partition_id, "memories", state,
                           expected_generation=generation, reason="test")
    control.close()
    assert ownership_state(tmp_path, PARTITION) == "package_authoritative"
    assert ownership_state(tmp_path, PartitionRef("test-host", "other")) == "legacy_authoritative"
    with pytest.raises(OwnershipFenced, match="fenced"):
        assert_legacy_writer(tmp_path, PARTITION)


def test_missing_or_corrupt_control_refuses_stale_fallback(tmp_path):
    partition = tmp_path / PARTITION.partition_id
    partition.mkdir()
    (partition / "memory.sqlite3").touch()
    with pytest.raises(LegacyVaultError, match="missing"):
        ownership_state(tmp_path, PARTITION)
    (tmp_path / "control.sqlite3").write_bytes(b"corrupt database")
    with pytest.raises(LegacyVaultError, match="unavailable"):
        ownership_state(tmp_path, PARTITION)


def test_unknown_state_refuses_stale_fallback(tmp_path):
    control = OwnershipControl(tmp_path)
    control.close()
    with sqlite3.connect(tmp_path / "control.sqlite3") as connection:
        connection.execute("INSERT INTO ownership VALUES(?, 'memories', 'invalid', 1, 0, '{}')",
                           (PARTITION.partition_id,))
    with pytest.raises(LegacyVaultError, match="unavailable"):
        ownership_state(tmp_path, PARTITION)


def test_shared_leases_exclude_migration_and_release_after_error(tmp_path):
    lock = tmp_path / "profile" / "writers.lock"
    with profile_lease(lock), profile_lease(lock):
        with pytest.raises(LegacyVaultError, match="in use"), profile_lease(lock, exclusive=True):
            pytest.fail("exclusive migration lease must not be acquired")
    with profile_lease(lock, exclusive=True):
        with pytest.raises(LegacyVaultError, match="in use"), profile_lease(lock):
            pytest.fail("backend lease must not be acquired during migration")
    with pytest.raises(RuntimeError), profile_lease(lock, exclusive=True):
        raise RuntimeError("operator stopped migration")
    with profile_lease(lock, exclusive=True):
        assert lock.exists()
