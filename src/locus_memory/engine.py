"""MemoryEngine: the single public entry point.

The engine is an in-process library object. It does nothing at import time and
nothing on construction beyond remembering its root; a partition's database is
opened when an operation for that partition arrives. By default a missing vault is
created on first use; with ``create_partitions=False`` (open-existing-only mode)
opening a partition that has no vault raises :class:`NotFound` and creates nothing,
so a mistyped profile can never silently yield an empty vault with fresh keys.

Every method takes a trusted :class:`AccessContext` built by the host. Scope,
operation and actor checks happen before any content is decrypted or ranked.

:meth:`MemoryEngine.export` returns a *plaintext* document of what the caller may
export; it never writes a file - where (and whether) that plaintext is stored is the
host's decision.

Before serving any call, the engine makes sure the partition's main database has
applied every deletion recorded in its deletion ledger (after a crash, a failed
forget, a restore, or a forget by another process that did not finish).
"""
from __future__ import annotations

import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import policy
from .crypto import KeyProvider
from .errors import AccessDenied, IntegrityError, MemoryEngineError, ValidationError
from .host import CancellationToken, EngineConfig, HostCapabilities
from .models import (
    AccessContext,
    Actor,
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
    Operation,
    PartitionRef,
    Query,
    Receipt,
    RememberRequest,
    Scope,
    SearchResult,
    WriteResult,
)
from .observability import Metrics
from .services import PartitionContext, Services, build_services
from .storage.partition import Partition
from .storage.records import RecordStore

EXPORT_FORMAT = "locus-memory.export"
EXPORT_VERSION = 1


class MemoryEngine:
    def __init__(self, root: Path | str, keys: KeyProvider, *, host: HostCapabilities | None = None,
                 config: EngineConfig | None = None, create_partitions: bool = True) -> None:
        self.root = Path(root)
        self.keys = keys
        self.host = host or HostCapabilities()
        self.config = config or EngineConfig()
        # False: open-existing-only mode - a partition without a vault raises NotFound.
        self.create_partitions = bool(create_partitions)
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

    def partition_context(self, ref: PartitionRef, *, acknowledge_mirror_gap: bool = False) -> PartitionContext:
        if self._closed:
            raise MemoryEngineError("engine is closed")
        pid = ref.partition_id
        ctx = self._partitions.get(pid)
        if ctx is None:
            with self._lock:
                if self._closed:
                    raise MemoryEngineError("engine is closed")
                ctx = self._partitions.get(pid)
                if ctx is None:
                    partition = Partition(self.root, ref, self.keys, mirror=self.host.ledger_mirror,
                                          clock=self.host.clock, busy_timeout_ms=self.config.busy_timeout_ms,
                                          create=self.create_partitions)
                    try:
                        ctx = PartitionContext(partition, RecordStore(partition), self.host, self.config,
                                               self.metrics)
                        build_services(ctx)
                        partition.reconcile(ctx.services.forgetting.apply_tombstone,
                                            acknowledge_mirror_gap=acknowledge_mirror_gap)
                    except BaseException:
                        partition.close()
                        raise
                    self._partitions[pid] = ctx
                    return ctx
        # Deletions recorded in the ledger but not (yet) applied - a failed forget here or a
        # crashed/unfinished forget in another process - are applied before serving anything.
        if acknowledge_mirror_gap or ctx.partition.needs_reconcile():
            ctx.partition.reconcile(ctx.services.forgetting.apply_tombstone,
                                    acknowledge_mirror_gap=acknowledge_mirror_gap)
        return ctx

    def _fence(self, access: AccessContext) -> None:
        """Canonical memory writes are refused unless the package is the authoritative writer."""
        control = self.host.ownership
        if control is not None:
            control.assert_writer(access.partition.partition_id, "memories", "package")

    def ownership_state(self, access: AccessContext) -> dict[str, Any] | None:
        control = self.host.ownership
        return None if control is None else control.get(access.partition.partition_id, "memories").to_dict()

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
        self._fence(access)
        return self._ctx(access).services.core.remember(access, request, idempotency_key=idempotency_key)

    def propose(self, access: AccessContext, candidate: CandidateProposal, *,
                idempotency_key: str | None = None) -> WriteResult:
        self._fence(access)
        return self._ctx(access).services.core.propose(access, candidate, idempotency_key=idempotency_key)

    def approve(self, access: AccessContext, memory_id: str, *, expected_revision: int | None,
                resolution: str = "keep_both") -> WriteResult:
        self._fence(access)
        return self._ctx(access).services.core.approve(access, memory_id, expected_revision=expected_revision,
                                                        resolution=resolution)

    def reject(self, access: AccessContext, memory_id: str, *, expected_revision: int | None,
               reason: str = "") -> WriteResult:
        self._fence(access)
        return self._ctx(access).services.core.reject(access, memory_id, expected_revision=expected_revision,
                                                       reason=reason)

    def correct(self, access: AccessContext, memory_id: str, correction: Correction, *,
                expected_revision: int | None) -> WriteResult:
        self._fence(access)
        return self._ctx(access).services.core.correct(access, memory_id, correction,
                                                        expected_revision=expected_revision)

    def set_pinned(self, access: AccessContext, memory_id: str, pinned: bool, *,
                   expected_revision: int | None) -> WriteResult:
        self._fence(access)
        return self._ctx(access).services.core.set_pinned(access, memory_id, pinned,
                                                           expected_revision=expected_revision)

    def supersede(self, access: AccessContext, old_id: str, new_id: str, *,
                  expected_revision: int | None) -> WriteResult:
        self._fence(access)
        return self._ctx(access).services.core.supersede(access, old_id, new_id,
                                                          expected_revision=expected_revision)

    def forget(self, access: AccessContext, target: ForgetTarget, *, policy: ForgetPolicy | None = None,
               idempotency_key: str | None = None) -> ForgetReceipt:
        return self._ctx(access).services.forgetting.forget(access, target, policy or ForgetPolicy(),
                                                             idempotency_key=idempotency_key)

    def preview_forget(self, access: AccessContext, target: ForgetTarget, policy: ForgetPolicy | None = None
                       ) -> dict[str, Any]:
        """Counts ``forget`` would delete/retain now; deletes nothing and writes no ledger entry."""
        return self._ctx(access).services.forgetting.preview(access, target, policy or ForgetPolicy())

    def explain(self, access: AccessContext, memory_id: str) -> dict[str, Any]:
        return self._ctx(access).services.core.explain(access, memory_id)

    # ------------------------------------------------------------------ export
    def export(self, access: AccessContext, *, include_history: bool = False) -> dict[str, Any]:
        """Plaintext export document of everything this caller may export (requires EXPORT).

        Returns ``{"format": "locus-memory.export", "version": 1, "exported_at",
        "partition_id", "records": [...]}``: every record the caller's scope grants
        authorize, in every lifecycle, as the caller would read it. With
        ``include_history=True`` (which additionally requires READ) the document also
        has ``"history"``: each authorized session with all of its retained messages
        and its known gaps; without it the document has no ``history`` key at all.

        Operation checks happen before the partition is opened, scope filtering before
        anything is decrypted, and everything is read from one consistent snapshot after
        pending deletions have been applied. The document is returned, never written:
        whether plaintext leaves the encrypted vault, and where to, is the host's
        decision, and a later forget cannot reach a copy the host made.
        """
        if not isinstance(access, AccessContext):
            raise MemoryEngineError("a trusted AccessContext is required")
        if not isinstance(include_history, bool):
            raise ValidationError("include_history must be a bool")
        policy.require(access, Operation.EXPORT)
        if include_history:
            policy.require(access, Operation.READ)
        ctx = self._ctx(access)
        partition = ctx.partition
        with partition.db.read() as conn:
            now = ctx.clock()
            stored = ctx.records.authorized(conn, access.grants, lifecycles=None, order="created_at, id")
            records = ctx.services.core.present(conn, access, stored, now)
            document: dict[str, Any] = {
                "format": EXPORT_FORMAT, "version": EXPORT_VERSION, "exported_at": now,
                "partition_id": partition.partition_id,
                "records": [record.to_dict() for record in records],
            }
            if include_history:
                document["history"] = self._export_history(ctx, conn, access)
        return document

    @staticmethod
    def _export_history(ctx: PartitionContext, conn: Any, access: AccessContext) -> list[dict[str, Any]]:
        """Every session the caller's grants authorize, with all retained messages and gaps.

        Runs inside the caller's read snapshot; sessions outside the grants are excluded
        by the authorization index before any payload is decrypted.
        """
        from .history.archive import MESSAGES, SESSIONS

        archive = ctx.services.history
        clause, params = archive._auth_clause(access.grants, "hs")
        rows = conn.execute(
            f"SELECT hs.* FROM {SESSIONS} hs WHERE {clause} ORDER BY COALESCE(hs.first_at, 0), hs.session_token",
            params,
        ).fetchall()
        sessions: list[dict[str, Any]] = []
        for row in rows:
            session = archive._open_session(row)
            if not access.grants.allows(session.scope):  # defense in depth: index must agree with payload
                raise IntegrityError("authorization index disagrees with history session scope")
            message_rows = conn.execute(
                f"SELECT * FROM {MESSAGES} WHERE session_token=? ORDER BY seq", (session.token,)
            ).fetchall()
            messages = [archive._open_message(item, session) for item in message_rows]
            sessions.append({
                **session.to_dict(),
                "messages": [message.to_dict() for message in messages],
                "gaps": archive._gaps_in(conn, session.token, 0, None, messages),
            })
        return sessions

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
                            scope: Scope | None = None, exclude_patterns: Iterable[str] = ()):
        return self._ctx(access).services.repository.register(access, root, repository_id=repository_id,
                                                               scope=scope, exclude_patterns=exclude_patterns)

    def snapshot_repository(self, access: AccessContext, repository_id: str, **kwargs: Any):
        return self._ctx(access).services.repository.snapshot(access, repository_id, **kwargs)

    def repository_observations(self, access: AccessContext, repository_id: str, *, path: str | None = None,
                                current_only: bool = True):
        return self._ctx(access).services.repository.observations(access, repository_id, path=path,
                                                                   current_only=current_only)

    def repository_history(self, access: AccessContext, repository_id: str, *, max_commits: int = 50,
                           path: str | None = None):
        return self._ctx(access).services.repository.history(access, repository_id, max_commits=max_commits,
                                                              path=path)

    def read_repository_file(self, access: AccessContext, repository_id: str, path: str, *,
                             max_bytes: int = 256 * 1024, commit: str | None = None):
        return self._ctx(access).services.repository.read_file(access, repository_id, path,
                                                                max_bytes=max_bytes, commit=commit)

    def export_repository_interchange(self, access: AccessContext, repository_id: str):
        return self._ctx(access).services.repository.export_interchange(access, repository_id)

    def import_repository_interchange(self, access: AccessContext, document: dict[str, Any]):
        return self._ctx(access).services.repository.import_interchange(access, document)

    def process_provider_outbox(self, access: AccessContext, **kwargs: Any):
        return self._ctx(access).services.providers.process_outbox(access, **kwargs)

    def provider_usage(self, access: AccessContext, **kwargs: Any):
        return self._ctx(access).services.providers.usage(access, **kwargs)

    def provider_status(self, access: AccessContext):
        return self._ctx(access).services.providers.status(access)

    def repository_status(self, access: AccessContext, repository_id: str):
        return self._ctx(access).services.repository.status(access, repository_id)

    # ------------------------------------------------------------------ context
    def build_context(self, access: AccessContext, request: ContextRequest, *,
                      cancel: CancellationToken | None = None) -> ContextPacket:
        return self._ctx(access).services.context.build(access, request, cancel=cancel)

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

    # ------------------------------------------------------------------ administration
    def rotate_master_key(self, access: AccessContext, new_key_id: str, *, drop_old: bool = True) -> Receipt:
        """Re-wrap the partition's keys under ``new_key_id`` (ADMIN; see admin.py)."""
        from .admin import require_admin, rotate_master_key

        require_admin(access)
        return rotate_master_key(self._ctx(access), access, new_key_id, drop_old=drop_old)

    def rotate_data_key(self, access: AccessContext, *, batch: int = 500) -> dict[str, Any]:
        """Start or continue a progressive data-key rotation; one bounded batch per call (ADMIN)."""
        from .admin import require_admin, rotate_data_key

        require_admin(access)
        return rotate_data_key(self._ctx(access), access, batch=batch)

    def data_key_rotation_status(self, access: AccessContext) -> dict[str, Any]:
        from .admin import data_key_rotation_status, require_admin

        require_admin(access)
        return data_key_rotation_status(self._ctx(access), access)

    def reconcile(self, access: AccessContext, *, acknowledge_mirror_gap: bool = False) -> dict[str, Any]:
        """Run deletion reconciliation now (ADMIN).

        ``acknowledge_mirror_gap=True`` is the explicit operator decision to open a
        store whose database *and* ledger are older than the host's ledger mirror
        (deletions after the backup cannot be replayed). It is recorded durably.
        """
        if not isinstance(access, AccessContext):
            raise MemoryEngineError("a trusted AccessContext is required")
        policy.require(access, Operation.ADMIN)
        if access.actor not in (Actor.USER, Actor.HOST):
            raise AccessDenied("reconciliation is a user or host action")
        ctx = self._partitions.get(access.partition.partition_id)
        if ctx is None:  # opening reconciles (and is where a mirror gap is detected)
            ctx = self.partition_context(access.partition, acknowledge_mirror_gap=acknowledge_mirror_gap)
            return dict(ctx.partition.last_reconcile)
        return ctx.partition.reconcile(ctx.services.forgetting.apply_tombstone,
                                       acknowledge_mirror_gap=acknowledge_mirror_gap)
