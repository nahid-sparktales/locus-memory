"""MemoryEngine: the single public entry point.

The engine is an in-process library object. It does nothing at import time and
nothing on construction beyond remembering its root; a partition's database is
opened (and created on first use) when an operation for that partition arrives.

Every method takes a trusted :class:`AccessContext` built by the host. Scope,
operation and actor checks happen before any content is decrypted or ranked.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from .crypto import KeyProvider
from .errors import MemoryEngineError
from .host import EngineConfig, HostCapabilities
from .models import (
    AccessContext,
    CandidateProposal,
    ContextPacket,
    ContextRequest,
    Correction,
    EngineStatus,
    EpisodeReport,
    ForgetPolicy,
    ForgetReceipt,
    ForgetTarget,
    IngestionEvent,
    Lifecycle,
    MemoryKind,
    MemoryRecord,
    PartitionRef,
    Query,
    RememberRequest,
    Scope,
    SearchResult,
    WriteResult,
)
from .observability import Metrics
from .services import PartitionContext, Services, build_services
from .storage.partition import Partition
from .storage.records import RecordStore


class MemoryEngine:
    def __init__(self, root: Path | str, keys: KeyProvider, *, host: HostCapabilities | None = None,
                 config: EngineConfig | None = None) -> None:
        self.root = Path(root)
        self.keys = keys
        self.host = host or HostCapabilities()
        self.config = config or EngineConfig()
        self.metrics = Metrics()
        self._partitions: dict[str, PartitionContext] = {}
        self._lock = threading.RLock()
        self._closed = False

    # ------------------------------------------------------------------ lifecycle
    @classmethod
    def open(cls, root: Path | str, keys: KeyProvider, **kwargs: Any) -> MemoryEngine:
        return cls(root, keys, **kwargs)

    def __enter__(self) -> MemoryEngine:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            contexts, self._partitions = list(self._partitions.values()), {}
            self._closed = True
        for ctx in contexts:
            for service in ctx.services.all():
                closer = getattr(service, "close", None)
                if callable(closer):
                    closer()
            ctx.partition.close()

    def _ctx(self, access: AccessContext) -> PartitionContext:
        if not isinstance(access, AccessContext):
            raise MemoryEngineError("a trusted AccessContext is required")
        return self.partition_context(access.partition)

    def partition_context(self, ref: PartitionRef) -> PartitionContext:
        if self._closed:
            raise MemoryEngineError("engine is closed")
        pid = ref.partition_id
        with self._lock:
            ctx = self._partitions.get(pid)
            if ctx is not None:
                return ctx
            partition = Partition(self.root, ref, self.keys, mirror=self.host.ledger_mirror,
                                  clock=self.host.clock, busy_timeout_ms=self.config.busy_timeout_ms)
            try:
                ctx = PartitionContext(partition, RecordStore(partition), self.host, self.config, self.metrics)
                build_services(ctx)
                partition.reconcile(ctx.services.forgetting.apply_tombstone)
            except BaseException:
                partition.close()
                raise
            self._partitions[pid] = ctx
            return ctx

    def services(self, access: AccessContext) -> Services:
        """Sibling services for advanced/host use (repository, procedures, ...)."""
        return self._ctx(access).services

    # ------------------------------------------------------------------ memory records
    def get(self, access: AccessContext, memory_id: str) -> MemoryRecord:
        return self._ctx(access).services.core.get(access, memory_id)

    def list(self, access: AccessContext, *, lifecycles: tuple[Lifecycle, ...] | None = (Lifecycle.APPROVED,),
             kinds: tuple[MemoryKind, ...] = (), scope_filter: Scope | None = None,
             limit: int = 100, offset: int = 0) -> list[MemoryRecord]:
        return self._ctx(access).services.core.list(access, lifecycles=lifecycles, kinds=kinds,
                                                     scope_filter=scope_filter, limit=limit, offset=offset)

    def search(self, access: AccessContext, query: Query | str) -> SearchResult:
        query = query if isinstance(query, Query) else Query(text=query)
        return self._ctx(access).services.retrieval.search(access, query)

    def remember(self, access: AccessContext, request: RememberRequest, *,
                 idempotency_key: str | None = None) -> WriteResult:
        return self._ctx(access).services.core.remember(access, request, idempotency_key=idempotency_key)

    def propose(self, access: AccessContext, candidate: CandidateProposal, *,
                idempotency_key: str | None = None) -> WriteResult:
        return self._ctx(access).services.core.propose(access, candidate, idempotency_key=idempotency_key)

    def approve(self, access: AccessContext, memory_id: str, *, expected_revision: int | None,
                resolution: str = "keep_both") -> WriteResult:
        return self._ctx(access).services.core.approve(access, memory_id, expected_revision=expected_revision,
                                                        resolution=resolution)

    def reject(self, access: AccessContext, memory_id: str, *, expected_revision: int | None,
               reason: str = "") -> WriteResult:
        return self._ctx(access).services.core.reject(access, memory_id, expected_revision=expected_revision,
                                                       reason=reason)

    def correct(self, access: AccessContext, memory_id: str, correction: Correction, *,
                expected_revision: int | None) -> WriteResult:
        return self._ctx(access).services.core.correct(access, memory_id, correction,
                                                        expected_revision=expected_revision)

    def set_pinned(self, access: AccessContext, memory_id: str, pinned: bool, *,
                   expected_revision: int | None) -> WriteResult:
        return self._ctx(access).services.core.set_pinned(access, memory_id, pinned,
                                                           expected_revision=expected_revision)

    def supersede(self, access: AccessContext, old_id: str, new_id: str, *,
                  expected_revision: int | None) -> WriteResult:
        return self._ctx(access).services.core.supersede(access, old_id, new_id,
                                                          expected_revision=expected_revision)

    def forget(self, access: AccessContext, target: ForgetTarget, *, policy: ForgetPolicy | None = None,
               idempotency_key: str | None = None) -> ForgetReceipt:
        return self._ctx(access).services.forgetting.forget(access, target, policy or ForgetPolicy(),
                                                             idempotency_key=idempotency_key)

    def explain(self, access: AccessContext, memory_id: str) -> dict[str, Any]:
        return self._ctx(access).services.core.explain(access, memory_id)

    # ------------------------------------------------------------------ history
    def ingest_event(self, access: AccessContext, event: IngestionEvent):
        return self._ctx(access).services.history.ingest(access, event)

    def search_history(self, access: AccessContext, query: str, **kwargs: Any):
        return self._ctx(access).services.history.search(access, query, **kwargs)

    def scroll_history(self, access: AccessContext, handle: str, *, before: int = 5, after: int = 5):
        return self._ctx(access).services.history.scroll(access, handle, before=before, after=after)

    def browse_history(self, access: AccessContext, session_ref: str, *, from_seq: int = 0, limit: int = 50):
        return self._ctx(access).services.history.browse(access, session_ref, from_seq=from_seq, limit=limit)

    # ------------------------------------------------------------------ episodes / procedures
    def record_episode(self, access: AccessContext, report: EpisodeReport):
        """Returns (Episode, Receipt). Outcome is derived from host verification, not the claim."""
        return self._ctx(access).services.episodes.record(access, report)

    def get_episode(self, access: AccessContext, episode_id: str):
        return self._ctx(access).services.episodes.get(access, episode_id)

    def list_episodes(self, access: AccessContext, **filters: Any):
        return self._ctx(access).services.episodes.list(access, **filters)

    def nominate_procedure(self, access: AccessContext, draft):
        return self._ctx(access).services.procedures.nominate(access, draft)

    def evaluate_procedure(self, access: AccessContext, procedure_id: str, **kwargs: Any):
        return self._ctx(access).services.procedures.evaluate(access, procedure_id, **kwargs)

    def approve_procedure(self, access: AccessContext, procedure_id: str, *, expected_version: int | None):
        return self._ctx(access).services.procedures.approve(access, procedure_id, expected_version=expected_version)

    def reject_procedure(self, access: AccessContext, procedure_id: str, reason: str = ""):
        return self._ctx(access).services.procedures.reject(access, procedure_id, reason)

    def export_procedure(self, access: AccessContext, procedure_id: str, destination: Path | str):
        return self._ctx(access).services.procedures.export(access, procedure_id, Path(destination))

    def list_procedures(self, access: AccessContext, **filters: Any):
        return self._ctx(access).services.procedures.list(access, **filters)

    # ------------------------------------------------------------------ repository
    def register_repository(self, access: AccessContext, root: Path | str, *, repository_id: str,
                            scope: Scope | None = None):
        return self._ctx(access).services.repository.register(access, root, repository_id=repository_id,
                                                               scope=scope)

    def snapshot_repository(self, access: AccessContext, repository_id: str, **kwargs: Any):
        return self._ctx(access).services.repository.snapshot(access, repository_id, **kwargs)

    def repository_status(self, access: AccessContext, repository_id: str):
        return self._ctx(access).services.repository.status(access, repository_id)

    # ------------------------------------------------------------------ context
    def build_context(self, access: AccessContext, request: ContextRequest) -> ContextPacket:
        return self._ctx(access).services.context.build(access, request)

    def revalidate_context(self, access: AccessContext, packet: ContextPacket) -> ContextPacket:
        return self._ctx(access).services.context.revalidate(access, packet)

    def explain_context(self, access: AccessContext, receipt_id: str) -> dict[str, Any]:
        return self._ctx(access).services.context.explain(access, receipt_id)

    # ------------------------------------------------------------------ maintenance
    def consolidate(self, access: AccessContext, request: dict[str, Any] | None = None):
        return self._ctx(access).services.consolidation.run(access, request or {})

    def maintain(self, access: AccessContext) -> dict[str, Any]:
        return self._ctx(access).services.consolidation.maintain(access)

    def invalidate(self, access: AccessContext, reason: str) -> int:
        """Host signal: scope/consent changed. Bumps generation and cancels affected work."""
        return self._ctx(access).services.consolidation.invalidate(access, reason)

    def status(self, access: AccessContext) -> EngineStatus:
        from .status import build_status

        return build_status(self._ctx(access), access)
