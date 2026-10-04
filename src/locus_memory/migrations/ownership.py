"""Read-only ownership lookup and process exclusion at host-supplied paths.

Ownership, rather than a recall rollout flag, selects the canonical vault.
Reading an unmigrated root does not create an engine store. The host selects
both the engine root and a stable lease path shared by all of its writers.
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path

from locus_memory.compat.legacy_vault import LegacyVaultError
from locus_memory.errors import OwnershipFenced
from locus_memory.migrations.state import STATES, WRITERS
from locus_memory.models import PartitionRef


def ownership_state(root: Path | str, partition: PartitionRef) -> str:
    database = Path(root) / "control.sqlite3"
    if not database.exists():
        if any(database.parent.glob("p*/*.sqlite3")):
            raise LegacyVaultError("memory ownership is missing for an existing engine; refusing legacy fallback")
        return "legacy_authoritative"
    try:
        with contextlib.closing(sqlite3.connect(
            database.resolve().as_uri() + "?mode=ro", uri=True, timeout=10,
        )) as connection:
            row = connection.execute(
                "SELECT state FROM ownership WHERE partition_id=? AND family='memories'",
                (partition.partition_id,),
            ).fetchone()
        state = row[0] if row else "legacy_authoritative"
        if state not in STATES:
            raise ValueError("unknown memory ownership state")
        return state
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise LegacyVaultError("memory ownership is unavailable; refusing legacy fallback") from exc


def assert_legacy_writer(root: Path | str, partition: PartitionRef) -> None:
    state = ownership_state(root, partition)
    if "legacy" not in WRITERS[state]:
        raise OwnershipFenced(f"legacy memory writes are fenced while ownership is {state}")


@contextlib.contextmanager
def profile_lease(lock_path: Path | str, *, exclusive: bool = False) -> Iterator[None]:
    """Backends hold shared leases; offline cutover requires an exclusive lease.

    Never wait for an active backend in the migrator: the operator must stop it
    and its turns first. Keep the file in place so all processes lock one inode.
    """
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LegacyVaultError(
                "memory profile is in use; stop its backends before migration and retry after migration"
            ) from exc
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
