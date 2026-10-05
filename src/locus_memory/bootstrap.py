"""Initialize an absent memory profile without migrating an existing store.

The host supplies every path, its keys, and an exclusive writer lease. An empty
partition and its ownership record are built privately, closed, then published
together. Readers can never mistake an unfinished bootstrap for a legacy vault.
"""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path

from . import MemoryEngine
from .compat.legacy_vault import LegacyVaultError
from .crypto import KeyProvider
from .host import HostCapabilities
from .migrations.ownership import ownership_state
from .migrations.state import OwnershipControl
from .models import PartitionRef


def _existing_state(root: Path, legacy_database: Path, partition: PartitionRef) -> str | None:
    if root.exists() or root.is_symlink():
        return ownership_state(root, partition)
    if legacy_database.exists() or legacy_database.is_symlink():
        return "legacy_authoritative"
    if any(Path(str(legacy_database) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise LegacyVaultError("legacy memory database is missing but recovery files remain")
    return None


def initialize_fresh_profile(
    root: Path | str, legacy_database: Path | str, keys: KeyProvider, *,
    partition: PartitionRef, initialization_lock: Path | str,
    lease: Callable[[], AbstractContextManager], host: HostCapabilities | None = None,
) -> str:
    """Return ownership, creating a package-owned store only when both stores are absent.

    Existing legacy, migrated, rolled-back and interrupted migration profiles are
    left untouched. A separate initialization lock serializes concurrent first
    launches; the host's exclusive profile lease excludes active legacy writers.
    The key provider remains responsible for host key creation and custody.
    """
    root, legacy_database = Path(root), Path(legacy_database)
    state = _existing_state(root, legacy_database, partition)
    if state is not None:
        return state
    lock = Path(initialization_lock)
    lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        state = _existing_state(root, legacy_database, partition)
        if state is not None:
            return state
        with lease():
            state = _existing_state(root, legacy_database, partition)
            if state is not None:
                return state
            # Resolve custody before creating any encrypted destination files.
            keys.get_key(keys.current_key_id())
            root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix=f".{root.name}-initialize-", dir=root.parent) as temporary:
                staged = Path(temporary)
                with MemoryEngine(staged, keys, host=host) as engine:
                    engine.partition_context(partition)
                control = OwnershipControl(staged)
                try:
                    now = time.time()
                    with control.db.write() as connection:
                        # This is initial ownership of an empty staged store, not
                        # a transition around the migration state machine.
                        connection.execute(
                            "INSERT INTO ownership VALUES(?, 'memories', 'package_authoritative', 1, ?, ?)",
                            (partition.partition_id, now, json.dumps({"initialized_empty": True})),
                        )
                        connection.execute(
                            "INSERT INTO ownership_log(partition_id, family, from_state, to_state, generation, at, reason)"
                            " VALUES(?, 'memories', 'uninitialized', 'package_authoritative', 1, ?, ?)",
                            (partition.partition_id, now, "initialize empty package profile"),
                        )
                finally:
                    control.close()
                staged.rename(root)
                parent_fd = os.open(root.parent, os.O_RDONLY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            return "package_authoritative"
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
