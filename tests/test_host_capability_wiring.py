"""Every package host entrypoint retains injected capabilities and ownership fences."""
from contextlib import nullcontext

from locus_memory.bootstrap import initialize_fresh_profile
from locus_memory.compat.canonical_vault import CanonicalMemoryVault
from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.host import HostCapabilities
from locus_memory.migrations.legacy import LegacyMapping
from locus_memory.migrations.session import LegacyMigrationSession
from locus_memory.models import PartitionRef
from locus_memory.runtime import RecallRuntime
from locus_memory.storage.ledger import MemoryLedgerMirror


def capabilities(clock):
    return HostCapabilities(clock=clock, ledger_mirror=MemoryLedgerMirror(), verification=object(),
                            evaluation_runner=object(), providers={"local": object()})


def assert_retained(actual, supplied):
    for name in ("ledger_mirror", "verification", "evaluation_runner", "providers", "clock"):
        assert getattr(actual, name) is getattr(supplied, name)
    assert supplied.ownership is None  # caller's capabilities were not mutated


def test_runtime_forwards_capabilities_without_overwriting_owner_input(tmp_path, keys, user_access, clock):
    host = capabilities(clock)
    runtime = RecallRuntime(root=tmp_path, partition=user_access.partition, key_provider=keys,
                            maintenance_access=user_access, host=host, clock=clock, mode="enabled")
    try:
        assert_retained(runtime.engine.host, host)
    finally:
        runtime.close()


def test_bootstrap_and_canonical_vault_retain_guard_and_ownership(tmp_path, keys, clock):
    partition = PartitionRef("test-host", "default")
    host = capabilities(clock)
    root = tmp_path / "engine"
    initialize_fresh_profile(root, tmp_path / "legacy", keys, partition=partition, host=host,
                             initialization_lock=tmp_path / "init.lock", lease=nullcontext)
    assert host.ledger_mirror.read(partition.partition_id) == (0, "")
    with CanonicalMemoryVault(root, keys, partition=partition, host=host) as vault:
        assert_retained(vault.engine.host, host)
        assert vault.engine.host.ownership is vault.control
        assert vault.control.get(partition.partition_id, "memories").state == "package_authoritative"


def test_migration_injects_capabilities_and_keeps_authoritative_control(tmp_path, keys, clock):
    database = tmp_path / "legacy.sqlite3"
    LegacyMemoryVault(database, key=b"k" * 32)
    host = capabilities(clock)
    with LegacyMigrationSession(tmp_path / "engine", database, keys, partition=PartitionRef("test", "default"),
                                legacy_key=lambda: b"k" * 32, mapping=LegacyMapping, lease=nullcontext,
                                assert_quiescent=lambda: None, host=host) as migration:
        assert_retained(migration.engine.host, host)
        assert migration.engine.host.ownership is migration.control
