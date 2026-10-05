"""Host-independent recall, shadow rollout, archival and maintenance orchestration.

Hosts supply roots, keys, trusted access contexts, scheduling and opaque prompt slots.
This module never discovers an application, loads credentials, inspects a host core,
or rewrites a host prompt. Legacy synchronization is optional and uses an explicit
source database and key callback. All state belongs to this runtime instance.
"""
from __future__ import annotations

import dataclasses
import hashlib
import logging
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

from . import MemoryEngine
from .context import CONTEXT_WRAPPER_CLOSE, CONTEXT_WRAPPER_OPEN, contains_context_block
from .crypto import KeyProvider
from .errors import MemoryEngineError, MigrationError
from .host import EngineConfig, HostCapabilities
from .migrations.legacy import LegacyImporter, LegacyMapping
from .migrations.state import OwnershipControl
from .models import (
    AccessContext,
    ContextPacket,
    ContextRequest,
    IngestionEvent,
    MemoryKind,
    PartitionRef,
    Scope,
    SliceSpec,
)

logger = logging.getLogger(__name__)
MODES = ("disabled", "shadow", "enabled")
SHADOW_STATES = frozenset({"legacy_authoritative", "shadow_prepared", "validated"})
PACKAGE_STATES = frozenset({"package_authoritative", "legacy_retired"})
MAX_CONTEXT_CHARS = 24_000
LEGACY_RESULTS_HEADER = "Approved memory results (local user-controlled context):"
MAINTENANCE_INTERVAL_S = 6 * 3600
RECALL_DEADLINE_MS = 5_000
_UNHASHED_COLUMNS = frozenset({"ciphertext", "use_count", "last_used_at"})
_ENGINE_ERRORS = (MemoryEngineError, sqlite3.Error, OSError)
_REF_UNSAFE = re.compile(r"[^A-Za-z0-9_.:@/+=-]")

_K = MemoryKind
_SCOPED_DIMS = ("project", "repository", "worktree", "team", "agent", "legacy_target")
#: The package's default slices, plus the legacy kinds and the ``legacy_target``
#: dimension that imported Locus records can carry.
_SLICES = (
    SliceSpec("user_preferences", 500, (_K.PREFERENCE,), (), True),
    SliceSpec("profile_facts", 800, (_K.FACT, _K.CONSTRAINT, _K.RELATIONSHIP, _K.DECISION), (), True),
    SliceSpec("workspace", 1200, (_K.DECISION, _K.CONSTRAINT, _K.FACT, _K.PREFERENCE, _K.RELATIONSHIP,
                                  _K.REPOSITORY_OBSERVATION, _K.SUMMARY),
              ("project", "repository", "worktree", "team", "legacy_target"), True),
    SliceSpec("agent", 400, (), ("agent", "legacy_target"), True),
    SliceSpec("episodes", 600, (_K.EPISODE,), None, True),
    SliceSpec("procedures", 600, (_K.PROCEDURE,), None, True),
)
class LegacyRecall(NamedTuple):
    """What the Stage-1 recall produced: the injected text and the recalled ids."""

    text: str
    ids: tuple[str, ...] = ()


def project_id(workspace_hash: str) -> str:
    """Package project id for a workspace: ``'ws-' + sha256(resolved path)[:32]``."""
    return "ws-" + workspace_hash[:32]


def _outside_packets(text: str) -> str:
    """``text`` without its engine packets (wrapper open through close; a packet the host
    truncated runs to the end). What remains is what the host itself put around them."""
    parts: list[str] = []
    rest = text
    while CONTEXT_WRAPPER_OPEN in rest:
        before, _, after = rest.partition(CONTEXT_WRAPPER_OPEN)
        parts.append(before)
        _, closed, rest = after.partition(CONTEXT_WRAPPER_CLOSE)
        if not closed:
            rest = ""
    parts.append(rest)
    return "".join(parts)


def assert_single_memory_layer(text: str) -> None:
    """The engine packet replaces the legacy layer; both together is a defect.

    Structural only: stored memory text is never evidence of a second layer. A record whose
    title or content quotes the legacy results header (e.g. a copied ``search_memory`` tool
    output) is rendered inside the packet; the stored text cannot forge the wrapper itself
    (the package neutralizes ``<memory-context`` in it). So a legacy layer counts only outside
    every packet, and two packets count anywhere.
    """
    if text.count(CONTEXT_WRAPPER_OPEN) > 1 or (
            contains_context_block(text) and LEGACY_RESULTS_HEADER in _outside_packets(text)):
        raise AssertionError("memory was injected twice (engine packet and legacy layer)")


def _run_inline(task: Callable[[], None]) -> None:
    task()


def _ref(value: str) -> str:
    cleaned = _REF_UNSAFE.sub("_", str(value or ""))[:256].replace("..", "__")
    return cleaned or uuid.uuid4().hex


def _slices(personal: bool) -> tuple[SliceSpec, ...]:
    """Without the personal scope, profile-global (unscoped) records are not requested."""
    if personal:
        return _SLICES
    return tuple(
        spec if spec.scope_dims else dataclasses.replace(spec, scope_dims=_SCOPED_DIMS)
        for spec in _SLICES if spec.scope_dims != ()
    )


class _LegacyState(NamedTuple):
    digest: str
    #: Workspace target hashes present in the legacy rows (for the import mapping).
    workspaces: frozenset[str]


def _legacy_state(database: Path) -> _LegacyState | None:
    """Content-free change fingerprint of the legacy rows, plus their workspace hashes.

    Only a gate that skips the import when nothing changed; what a change means is the
    importer's business. Read-only; decrypts nothing. ``None`` when there is no vault
    (or no table).
    """
    if not database.is_file():
        return None
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=10)
    try:
        names = [row[1] for row in connection.execute("PRAGMA table_info(memories)")
                 if row[1] not in _UNHASHED_COLUMNS]
        if not names:
            return None
        columns = ", ".join('"' + name.replace('"', '""') + '"' for name in names)
        rows = connection.execute(f"SELECT {columns} FROM memories ORDER BY id").fetchall()
    finally:
        connection.close()
    digest = hashlib.sha256()
    workspaces: set[str] = set()
    for row in rows:
        values = dict(zip(names, row, strict=True))
        digest.update(repr(sorted(values.items())).encode())
        prefix, _, value = str(values.get("target_hash") or "").partition(":")
        if prefix == "workspace" and value:
            workspaces.add(value)
    return _LegacyState(digest.hexdigest(), frozenset(workspaces))


class RecallRuntime:
    """One explicit partition's memory orchestration, independent of any host UI.

    ``initial_state`` is the host's read-only ownership observation while holding its
    profile lease; only a supplied package ownership state overrides rollout mode.
    ``ownership`` is opened only on first engine use. Supplying no
    ``legacy_database`` selects package-only serving; otherwise ``legacy_access`` and
    ``legacy_key`` are required when the legacy source is authoritative.
    """

    def __init__(
        self, *, root: Path | str, partition: PartitionRef, key_provider: KeyProvider,
        mode: str = "disabled", initial_state: str | None = None,
        archive: bool = False, legacy_database: Path | None = None,
        legacy_key: Callable[[], bytes] | None = None,
        legacy_access: AccessContext | None = None,
        maintenance_access: AccessContext,
        schedule: Callable[[Callable[[], None]], None] | None = None,
        clock: Callable[[], float] = time.time,
        maintenance_interval_s: float = MAINTENANCE_INTERVAL_S,
        layer_validator: Callable[[str], None] = assert_single_memory_layer,
        log: logging.Logger | None = None,
        host: HostCapabilities | None = None,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"memory engine mode must be one of {', '.join(MODES)}")
        for access in (legacy_access, maintenance_access):
            if access is not None and access.partition != partition:
                raise ValueError("runtime access must match its partition")
        self.root = Path(root)
        self.partition = partition
        self.legacy_db = Path(legacy_database) if legacy_database is not None else None
        self._legacy_key = legacy_key
        self._legacy_access = legacy_access
        self._maintenance_context = maintenance_access
        self._keys = key_provider
        self._host_capabilities = host or HostCapabilities()
        self.mode = "enabled" if initial_state in PACKAGE_STATES else mode
        self._canonical_backend = (
            "package" if initial_state in PACKAGE_STATES or self.legacy_db is None else "legacy"
        )
        self.archive = bool(archive) and self.mode != "disabled"
        self.schedule = schedule or _run_inline
        self.clock = clock
        self.maintenance_interval_s = float(maintenance_interval_s)
        self._layer_validator = layer_validator
        self._log = log or logger
        self.last_shadow: dict[str, Any] | None = None
        self._lock = threading.RLock()
        self._engine: MemoryEngine | None = None
        self._control: OwnershipControl | None = None
        self._closed = False
        self._synced: str | None = None
        self._pending: dict[int, tuple[object, AccessContext, ContextPacket]] = {}
        self._sequence: dict[str, int] = {}
        self._maintained_at: float | None = None
        self._maintaining = False
        self._embedding_access: dict[str, AccessContext] = {}

    @property
    def engine(self) -> MemoryEngine:
        """Open lazily; a disabled runtime creates no store."""
        with self._lock:
            if self.mode == "disabled":
                raise MemoryEngineError("the memory engine is disabled")
            if self._closed:
                raise MemoryEngineError("the memory runtime is closed")
            if self._engine is None:
                self.root.mkdir(parents=True, exist_ok=True)
                try:
                    self.root.chmod(0o700)
                except OSError:
                    pass
                # A package-only runtime needs no migration ownership database.
                self._control = OwnershipControl(self.root) if self.legacy_db is not None else None
                try:
                    self._engine = MemoryEngine(
                        self.root, self._keys,
                        host=dataclasses.replace(self._host_capabilities,
                                                 ownership=self._control or self._host_capabilities.ownership,
                                                 clock=self.clock),
                        config=EngineConfig(serving_mode=self.mode, canonical_backend=self._canonical_backend),
                    )
                except BaseException:
                    if self._control is not None:
                        self._control.close()
                        self._control = None
                    raise
            return self._engine

    def ownership_state(self) -> dict[str, Any]:
        _ = self.engine
        if self._control is None:
            return {"state": "package_authoritative"}
        return self._control.get(self.partition.partition_id, "memories").to_dict()

    def close(self) -> None:
        with self._lock:
            engine, control = self._engine, self._control
            self._engine = self._control = None
            self._closed = True
            self._pending.clear()
        try:
            if engine is not None:
                engine.close()
        finally:
            if control is not None:
                control.close()

    def _sync(self) -> bool:
        """Bring the derived copy up to date with the canonical legacy vault.

        The package's ``LegacyImporter`` decides everything about each record (deltas,
        lifecycle, re-scoping, deletion propagation). The adapter supplies only the host
        mapping, a pure function of the legacy rows so it never flips between turns:
        each workspace hash maps to its project id; agent targets stay ``legacy_target``
        because a hash does not reveal the agent id. False when there is no canonical
        vault (nothing to serve). Raises when the importer reports a legacy change it
        could not apply; the next call retries.
        """
        with self._lock:
            ownership = self.ownership_state()
            if ownership["state"] not in SHADOW_STATES:
                # Neither side may serve while ownership is moving.
                return ownership["state"] in PACKAGE_STATES
            if self.legacy_db is None:
                return True
            state = _legacy_state(self.legacy_db)
            if state is None:
                self._synced = None
                return False
            if state.digest == self._synced:
                return True
            mapping = LegacyMapping(workspaces={ws: project_id(ws) for ws in state.workspaces})
            access = self._legacy_access
            if access is None or self._legacy_key is None:
                raise MigrationError("legacy synchronization requires an explicit access context and key")
            engine = self.engine
            started = time.perf_counter()
            report = LegacyImporter(engine, access, self.legacy_db, self._legacy_key(), mapping).run()
            deletions = report.get("deletion_propagation") or {}
            engine.metrics.observe_ms("adapter.sync", (time.perf_counter() - started) * 1000)
            engine.metrics.incr("adapter.sync.imported", int(report.get("imported", 0)) + int(report.get("updated", 0)))
            engine.metrics.incr("adapter.sync.deleted", int(deletions.get("propagated", 0)))
            unapplied = int(report.get("decrypt_failures", 0)) + int(deletions.get("failed", 0))
            if unapplied:
                engine.metrics.incr("adapter.sync.incomplete")
                raise MigrationError(f"{unapplied} legacy change(s) could not be applied to the derived copy")
            self._synced = state.digest
            return True

    def packet(self, access: AccessContext, query: str, *, max_tokens: int,
               max_items: int, include_personal: bool = True) -> tuple[AccessContext, ContextPacket] | None:
        """Compile a bounded packet from a trusted host-provided access context."""
        if access.partition != self.partition:
            raise ValueError("recall access must match the runtime partition")
        if max_tokens <= 0 or max_items <= 0 or not self._sync():
            return None
        with self._lock:
            self._embedding_access[repr(access.grants)] = access
            while len(self._embedding_access) > 8:
                self._embedding_access.pop(next(iter(self._embedding_access)))
        request = ContextRequest(
            token_allowance=int(max_tokens), max_items=int(max_items),
            query=str(query or "").replace("\x00", " ").strip()[:2_000],
            slices=_slices(include_personal), deadline_ms=RECALL_DEADLINE_MS,
            order="relevance", evidence_policy="conservative",
        )
        return access, self.engine.build_context(access, request)

    def _failed(self, stage: str, exc: BaseException) -> None:
        self._log.warning("memory engine %s failed: %s", stage, getattr(exc, "code", type(exc).__name__))
        if self._engine is not None:
            self._engine.metrics.incr(f"adapter.{stage}.failed")

    def _single_layer(self, stage: str, text: str) -> bool:
        """Check the single-layer invariant without ever failing the turn: a violation is
        logged (without content) and counted, and the caller serves no engine memory."""
        try:
            self._layer_validator(text)
            return True
        except AssertionError:
            self._log.error("memory engine %s: memory layer invariant violated; no engine memory injected", stage)
            if self._engine is not None:
                self._engine.metrics.incr("adapter.layer_violation")
            return False

    def recall(self, slot: object, *, build_packet: Callable[[], tuple[AccessContext, ContextPacket] | None],
               legacy: Callable[[], LegacyRecall]) -> str:
        """Serve exactly one memory layer and retain its packet under an opaque slot."""
        if self.mode == "disabled":
            return legacy().text
        if self.mode == "shadow":
            started = time.perf_counter()
            result = legacy()
            self._shadow(build_packet, result, (time.perf_counter() - started) * 1000)
            return result.text
        try:
            built = build_packet()
        except _ENGINE_ERRORS as exc:
            self._failed("recall", exc)
            built = None
        with self._lock:
            self._pending.pop(id(slot), None)
            if built is None or not built[1].items:
                return ""  # an empty packet injects no layer (D41)
            access, packet = built
            if not self._single_layer("recall", packet.text):
                return ""  # fail closed: no engine memory, the turn goes on
            self._pending[id(slot)] = (slot, access, packet)
        return packet.text

    def revalidate(self, slot: object, current: str, *, active: bool = True,
                   max_chars: int = MAX_CONTEXT_CHARS) -> str | None:
        """Return replacement text just before use, or None when the host text stays valid."""
        if self.mode != "enabled":
            return
        with self._lock:
            pending = self._pending.get(id(slot))
        if pending is None or pending[0] is not slot:
            return
        _, access, packet = pending
        if current != packet.text[:max_chars]:
            # The caller injected something else; nothing of ours is in use. Should it carry two
            # layers anyway, drop it rather than send it (or fail the turn).
            if not self._single_layer("revalidate", current):
                return ""
            return
        fresh: ContextPacket | None = None
        if active:
            try:
                if self._sync():
                    # The package recompiles the same request when anything it relied on changed.
                    fresh = self.engine.revalidate_context(access, packet)
            except _ENGINE_ERRORS as exc:
                self._failed("revalidate", exc)
        if fresh is packet:
            return
        text = (fresh.text if fresh is not None and fresh.items else "")[:max_chars]
        if not self._single_layer("revalidate", text):
            text = ""
        with self._lock:
            if fresh is not None:
                self._pending[id(slot)] = (slot, access, fresh)
            else:
                self._pending.pop(id(slot), None)
        if self._engine is not None:
            self._engine.metrics.incr("adapter.revalidate.changed")

        return text

    def _shadow(self, build_packet: Callable[[], tuple[AccessContext, ContextPacket] | None],
                result: LegacyRecall, legacy_ms: float) -> None:
        """Compare without touching the prompt. Records counts and timings, never content."""
        self.last_shadow = None
        started = time.perf_counter()
        try:
            built = build_packet()
        except _ENGINE_ERRORS as exc:
            self._failed("shadow", exc)
            return
        if built is None:
            return
        packet = built[1]
        engine_ms = (time.perf_counter() - started) * 1000
        legacy_ids = {item for item in result.ids if item}
        engine_ids = {item.record_id for item in packet.items}
        comparison = {
            "legacy_items": len(legacy_ids), "engine_items": len(engine_ids),
            "overlap": len(legacy_ids & engine_ids),
            "legacy_tokens": len(result.text) // 4, "legacy_token_kind": "estimated",
            "engine_tokens": packet.token_count, "engine_token_kind": packet.token_count_kind.value,
            "engine_status": packet.status.value,
            "legacy_ms": round(legacy_ms, 3), "engine_ms": round(engine_ms, 3),
        }
        metrics = self.engine.metrics
        metrics.incr("adapter.shadow.compared")
        if legacy_ids == engine_ids:
            metrics.incr("adapter.shadow.same_ids")
        metrics.observe_ms("adapter.shadow.legacy_recall", legacy_ms)
        metrics.observe_ms("adapter.shadow.engine_context", engine_ms)
        metrics.gauge("adapter.shadow.overlap", comparison["overlap"])
        metrics.gauge("adapter.shadow.engine_tokens", packet.token_count, packet.token_count_kind.value)
        self.last_shadow = comparison
        self._log.info(
            "memory engine shadow: legacy_items=%d engine_items=%d overlap=%d legacy_tokens~%d "
            "engine_tokens=%d(%s) legacy_ms=%.1f engine_ms=%.1f",
            comparison["legacy_items"], comparison["engine_items"], comparison["overlap"],
            comparison["legacy_tokens"], comparison["engine_tokens"], comparison["engine_token_kind"],
            legacy_ms, engine_ms,
        )

    def release_context(self, slot: object) -> None:
        """Drop the packet belonging to a completed temporary prompt."""
        with self._lock:
            self._pending.pop(id(slot), None)

    def archive_text(self, access: AccessContext, *, session_ref: str, role: str,
                     text: str, event_id: str = "", source: str = "host",
                     scope: Scope | None = None) -> None:
        """Archive eligible committed text; hosts exclude synthetic messages before calling.

        Hidden reasoning and recalled memory are excluded by package policy. The host
        supplies consent, trusted provenance and any prompt-decoration stripping.
        With multiple project grants the event needs an explicit scope; grants alone
        do not identify which project produced a message.
        """
        if not self.archive or self.mode == "disabled" or role not in ("user", "assistant"):
            return
        if access.partition != self.partition:
            raise ValueError("archive access must match the runtime partition")
        if scope is None:
            if len(access.grants.projects) > 1:
                raise ValueError("archive scope is required when more than one project is granted")
            scope = Scope.of(project=next(iter(access.grants.projects), None))
        text = text.strip()
        lowered = text.lower()
        if not text or "<think" in lowered:
            return
        injected = contains_context_block(text) or LEGACY_RESULTS_HEADER in text or "## approved memory" in lowered
        session = _ref(session_ref)
        try:
            self.engine.ingest_event(access, IngestionEvent(
                event_id=_ref(event_id), session_ref=session,
                sequence=self._next_sequence(session), role=role, text=text[:200_000],
                occurred_at=self.clock(), scope=scope,
                source=source, is_memory_injection=injected,
            ))
        except _ENGINE_ERRORS as exc:
            self._failed("archive", exc)

    def _next_sequence(self, session: str) -> int:
        with self._lock:
            value = max(self._sequence.get(session, -1) + 1, time.time_ns() // 1_000)
            self._sequence[session] = value
            return value

    def session_boundary(self, slot: object, *, active: bool = True) -> None:
        """Release the slot and schedule bounded maintenance (at most once per interval).

        The host must discard any prompt text copied from this slot.
        """
        with self._lock:
            self._pending.pop(id(slot), None)
            if not active or self._engine is None or self._maintaining:
                return
            now = self.clock()
            if self._maintained_at is not None and now - self._maintained_at < self.maintenance_interval_s:
                return
            self._maintaining = True
            self._maintained_at = now
        self.schedule(self._maintain)

    def _maintain(self) -> None:
        try:
            engine = self.engine
            with engine.metrics.timer("adapter.maintain"):
                engine.maintain(self._maintenance_context)
                with self._lock:
                    contexts = list(self._embedding_access.values())
                    self._embedding_access.clear()
                for access in contexts:
                    engine.index_embeddings(access, limit=32, deadline_ms=RECALL_DEADLINE_MS)
        except _ENGINE_ERRORS as exc:
            self._failed("maintain", exc)
        finally:
            with self._lock:
                self._maintaining = False

    def scope_change(self, slot: object, reason: str, *, active: bool = True) -> None:
        """Drop pending packets and invalidate caches after workspace or consent changes.

        The host must discard any prompt text copied from this slot.
        """
        with self._lock:
            self._pending.pop(id(slot), None)
            opened = self._engine is not None
            self._embedding_access.clear()
        if not opened or not active:
            return
        try:
            self.engine.invalidate(self._maintenance_context, str(reason)[:200])
        except _ENGINE_ERRORS as exc:
            self._failed("invalidate", exc)
