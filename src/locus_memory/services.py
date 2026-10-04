"""Per-partition service wiring.

Every service is constructed with one :class:`PartitionContext` and may reach its
siblings through ``ctx.services`` (late-bound). A service that stores data
derived from forgettable inputs implements::

    def purge(self, conn, target_kind: str, target_token: str, policy) -> dict[str, int]

which the forgetting service calls inside the deletion transaction, both for live
``forget`` calls and for ledger reconciliation after a restore. A ``purge`` that
also accepts a keyword-only ``access`` receives the caller's AccessContext on live
calls (``None`` on replay) so its reported counts can exclude items the caller may
not see; everything matching the target is deleted either way.

A service that owns sealed tables (``dek_id``/``nonce``/``ciphertext`` columns)
takes part in data-key rotation by implementing::

    def reencrypt(self, conn, old_dek_ids: frozenset[str], limit: int) -> int

(usually via ``admin.reencrypt_table``); until it does, a rotation that finds rows
in its tables stays ``blocked`` and keeps the old key (see admin.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .host import EngineConfig, HostCapabilities
from .observability import Metrics
from .storage.partition import Partition
from .storage.records import RecordStore

if TYPE_CHECKING:  # pragma: no cover
    from .context.compiler import ContextCompiler
    from .core import CoreService
    from .forgetting import ForgettingService
    from .history.archive import HistoryArchive
    from .learning.consolidation import ConsolidationService
    from .learning.episodes import EpisodeService
    from .learning.procedures import ProcedureService
    from .providers.hub import ProviderHub
    from .repository.service import RepositoryService
    from .retrieval.service import RetrievalService


@dataclass
class Services:
    core: CoreService = None  # type: ignore[assignment]
    retrieval: RetrievalService = None  # type: ignore[assignment]
    context: ContextCompiler = None  # type: ignore[assignment]
    history: HistoryArchive = None  # type: ignore[assignment]
    forgetting: ForgettingService = None  # type: ignore[assignment]
    repository: RepositoryService = None  # type: ignore[assignment]
    episodes: EpisodeService = None  # type: ignore[assignment]
    procedures: ProcedureService = None  # type: ignore[assignment]
    consolidation: ConsolidationService = None  # type: ignore[assignment]
    providers: ProviderHub = None  # type: ignore[assignment]

    def all(self) -> list[Any]:
        return [getattr(self, name) for name in self.__dataclass_fields__ if getattr(self, name) is not None]


@dataclass
class PartitionContext:
    partition: Partition
    records: RecordStore
    host: HostCapabilities
    config: EngineConfig
    metrics: Metrics
    services: Services = field(default_factory=Services)

    @property
    def clock(self):
        return self.host.clock


def build_services(ctx: PartitionContext) -> Services:
    from .context.compiler import ContextCompiler
    from .core import CoreService
    from .forgetting import ForgettingService
    from .history.archive import HistoryArchive
    from .learning.consolidation import ConsolidationService
    from .learning.episodes import EpisodeService
    from .learning.procedures import ProcedureService
    from .providers.hub import ProviderHub
    from .repository.service import RepositoryService
    from .retrieval.service import RetrievalService

    services = ctx.services
    services.core = CoreService(ctx)
    services.providers = ProviderHub(ctx)
    services.retrieval = RetrievalService(ctx)
    services.history = HistoryArchive(ctx)
    services.context = ContextCompiler(ctx)
    services.forgetting = ForgettingService(ctx)
    services.repository = RepositoryService(ctx)
    services.episodes = EpisodeService(ctx)
    services.procedures = ProcedureService(ctx)
    services.consolidation = ConsolidationService(ctx)
    return services
