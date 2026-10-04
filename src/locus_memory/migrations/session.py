"""Offline migration lifecycle with host-supplied keys and quiescence.

The host supplies exact paths, identity, source mapping and an exclusive lease.
No application discovery, key-file lookup or process control occurs here.
"""
from __future__ import annotations

import contextlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .. import MemoryEngine
from ..crypto import KeyProvider
from ..errors import MigrationError
from ..host import EngineConfig, HostCapabilities
from ..models import AccessContext, Actor, Operation, PartitionRef, ScopeGrants
from . import legacy
from .cutover import Migrator
from .state import OwnershipControl


class LegacyMigrationSession:
    """One offline operation held under the host's exclusive profile lease."""

    def __init__(self, root: Path, database: Path, keys: KeyProvider, *,
                 partition: PartitionRef, legacy_key: Callable[[], bytes],
                 mapping: Callable[[], legacy.LegacyMapping],
                 lease: Callable[[], contextlib.AbstractContextManager],
                 assert_quiescent: Callable[[], None],
                 principal: str = "memory-migration") -> None:
        self.root, self.database = Path(root), Path(database)
        self.keys, self.partition = keys, partition
        self.legacy_key, self._mapping = legacy_key, mapping
        self._lease, self.assert_quiescent = lease, assert_quiescent
        self.principal = principal
        self._stack = contextlib.ExitStack()

    def __enter__(self):
        if not self.database.is_file():
            raise MigrationError("the existing memory vault was not found")
        try:
            self._stack.enter_context(self._lease())
            self.assert_quiescent()
            self.mapping = self._mapping()
            # Resolve the legacy key before creating any destination files.
            self.legacy_key()
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.root.chmod(0o700)
            self.control = OwnershipControl(self.root)
            self._stack.callback(self.control.close)
            self.engine = MemoryEngine(
                self.root, self.keys, host=HostCapabilities(ownership=self.control),
                config=EngineConfig(serving_mode="enabled", canonical_backend="legacy"),
            )
            self._stack.callback(self.engine.close)
            self.access = AccessContext(
                principal=self.principal, partition=self.partition, actor=Actor.HOST,
                operations=frozenset({Operation.ADMIN, Operation.READ}),
                grants=ScopeGrants(projects=frozenset(self.mapping.workspaces.values())),
                purpose="offline migration",
            )
            self.migrator = Migrator(
                self.engine, self.control, self.access, self.database, self.legacy_key(),
                self.mapping, work_dir=self.root / "migration",
            )
            return self
        except BaseException:
            self._stack.close()
            raise

    def __exit__(self, *args):
        return self._stack.__exit__(*args)

    def inventory(self) -> dict[str, Any]:
        return legacy.inventory(self.database, self.legacy_key(), self.mapping)

    def snapshot(self) -> dict[str, Any]:
        report = self.inventory()
        if report["decrypt_failures"] or report["map_failures"]:
            raise MigrationError("inventory has unreadable or unmappable records; cutover refused")
        return self.migrator.prepare_shadow()

    def validate(self, queries: list[str] | None = None) -> dict[str, Any]:
        return self.migrator.validate(queries=queries)

    def cutover(self, queries: list[str] | None = None) -> dict[str, Any]:
        @contextlib.contextmanager
        def quiesce():
            self.assert_quiescent()
            yield
        if self.migrator.state().state == "cutover_in_progress":
            return self.migrator.resume(quiesce=quiesce)
        return self.migrator.cutover(quiesce=quiesce, queries=queries)

    def rollback(self) -> dict[str, Any]:
        self.assert_quiescent()
        ctx = self.engine.partition_context(self.partition)
        with ctx.partition.db.read() as connection:
            _, damaged = self.migrator._package_records(ctx, connection)
        if damaged:
            raise MigrationError("rollback refused: package records could not be authenticated")
        if self.migrator.state().state == "rollback_in_progress":
            return self.migrator.resume()
        # Deliberately no partial rollback: recovery copies require a separate decision.
        return self.migrator.rollback()
