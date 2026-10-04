"""Fresh profiles use package memory without pretending to migrate old data."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from locus_memory.bootstrap import initialize_fresh_profile
from locus_memory.compat.canonical_vault import CanonicalMemoryVault
from locus_memory.compat.legacy_vault import LegacyVaultError
from locus_memory.errors import VaultLocked
from locus_memory.migrations.ownership import ownership_state, profile_lease
from locus_memory.migrations.state import OwnershipControl
from locus_memory.models import PartitionRef

PARTITION = PartitionRef("test-host", "default")


@pytest.fixture
def bootstrap(tmp_path, keys):
    root, legacy = tmp_path / "engine", tmp_path / "legacy" / "memory.sqlite3"

    def initialize():
        return initialize_fresh_profile(
            root, legacy, keys, partition=PARTITION,
            initialization_lock=tmp_path / "initialize.lock",
            lease=lambda: profile_lease(tmp_path / "profile.lock", exclusive=True),
        )

    return initialize, root, legacy


def test_fresh_profile_is_canonical_and_can_be_reopened(bootstrap, keys):
    initialize, root, legacy = bootstrap
    assert initialize() == "package_authoritative"
    assert not legacy.exists()
    with CanonicalMemoryVault(root, keys, partition=PARTITION) as vault:
        item = vault.save({"content": "A fresh memory retains violet details.", "scope": "personal"})
    assert initialize() == "package_authoritative"
    with CanonicalMemoryVault(root, keys, partition=PARTITION) as vault:
        assert vault.search("violet")[0]["id"] == item["id"]
    assert not any(b"violet details" in path.read_bytes() for path in root.rglob("*") if path.is_file())


def test_existing_legacy_store_is_untouched_even_when_empty(bootstrap, keys):
    initialize, root, legacy = bootstrap
    legacy.parent.mkdir()
    legacy.touch()
    keys.locked = True  # Existing-state detection does not need key access.
    assert initialize() == "legacy_authoritative"
    assert legacy.read_bytes() == b"" and not root.exists()


def test_rolled_back_profile_is_not_bootstrapped_again(bootstrap):
    initialize, root, _ = bootstrap
    assert initialize() == "package_authoritative"
    control = OwnershipControl(root)
    try:
        control.transition(PARTITION.partition_id, "memories", "rollback_in_progress",
                           expected_generation=1, reason="test")
        control.transition(PARTITION.partition_id, "memories", "legacy_authoritative",
                           expected_generation=2, reason="test")
        history = control.history(PARTITION.partition_id)
        assert initialize() == "legacy_authoritative"
        assert control.history(PARTITION.partition_id) == history
    finally:
        control.close()


def test_missing_control_with_engine_residue_fails_closed(bootstrap):
    initialize, root, _ = bootstrap
    partition = root / PARTITION.partition_id
    partition.mkdir(parents=True)
    (partition / "memory.sqlite3").write_bytes(b"existing encrypted data")
    with pytest.raises(LegacyVaultError, match="ownership is missing"):
        initialize()
    assert not (root / "control.sqlite3").exists()


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_orphan_legacy_recovery_files_are_not_fresh(bootstrap, suffix):
    initialize, root, legacy = bootstrap
    legacy.parent.mkdir()
    Path(str(legacy) + suffix).write_bytes(b"recovery data")
    with pytest.raises(LegacyVaultError, match="recovery files remain"):
        initialize()
    assert not root.exists()


def test_locked_key_publishes_nothing_and_retry_succeeds(bootstrap, keys):
    initialize, root, _ = bootstrap
    keys.locked = True
    with pytest.raises(VaultLocked):
        initialize()
    assert not root.exists()
    keys.locked = False
    assert initialize() == "package_authoritative"


def test_failed_partition_build_publishes_nothing(bootstrap, monkeypatch):
    from locus_memory import bootstrap as module

    initialize, root, _ = bootstrap
    original = module.MemoryEngine.partition_context

    def fail(engine, partition):
        original(engine, partition)
        raise RuntimeError("interrupted before publication")

    monkeypatch.setattr(module.MemoryEngine, "partition_context", fail)
    with pytest.raises(RuntimeError, match="interrupted"):
        initialize()
    assert not root.exists()
    assert not list(root.parent.glob(".engine-initialize-*"))
    monkeypatch.setattr(module.MemoryEngine, "partition_context", original)
    assert initialize() == "package_authoritative"


def test_concurrent_first_launches_publish_one_profile(bootstrap):
    initialize, root, _ = bootstrap
    with ThreadPoolExecutor(max_workers=4) as executor:
        assert list(executor.map(lambda _: initialize(), range(4))) == ["package_authoritative"] * 4
    assert ownership_state(root, PARTITION) == "package_authoritative"
    control = OwnershipControl(root)
    try:
        assert len(control.history(PARTITION.partition_id)) == 1
    finally:
        control.close()


def test_active_writer_prevents_first_initialization(bootstrap):
    initialize, root, _ = bootstrap
    with profile_lease(root.parent / "profile.lock"):
        with pytest.raises(LegacyVaultError, match="in use"):
            initialize()
    assert not root.exists()
    assert initialize() == "package_authoritative"
