"""Engine status scoped to the caller's authorized namespace."""
from __future__ import annotations

from typing import Any

from . import policy
from .crypto import CIPHER_NAME
from .models import API_VERSION, AccessContext, EngineStatus, Operation
from .services import PartitionContext
from .storage import schema
from .storage.db import fts5_available


def build_status(ctx: PartitionContext, access: AccessContext) -> EngineStatus:
    policy.require(access, Operation.READ)
    p = ctx.partition
    with p.db.read() as conn:
        counts = ctx.records.count_authorized(conn, access.grants)
        generation = p.generation(conn)
        deletion_generation = p.deletion_generation(conn)
        version = int(schema.get_meta(conn, "schema_version", "0") or 0)
    index: dict[str, Any] = {}
    retrieval = ctx.services.retrieval
    if retrieval is not None and hasattr(retrieval, "index_status"):
        index["memory"] = retrieval.index_status(access)
    history = ctx.services.history
    if history is not None and hasattr(history, "coverage_status"):
        index["history"] = history.coverage_status(access)
    providers: dict[str, Any] = {}
    hub = ctx.services.providers
    if hub is not None and hasattr(hub, "status"):
        providers = hub.status(access)
    limitations = [
        "metadata outside ciphertext: ids, kinds, lifecycle, revisions, timestamps, keyed tokens",
        "protects app-managed data at rest; not a compromised running process, swap, or a stolen key",
    ]
    return EngineStatus(
        api_version=API_VERSION, partition_id=p.partition_id, schema_version=version,
        canonical_backend=ctx.config.canonical_backend, serving_mode=ctx.config.serving_mode,
        counts=counts, generation=generation, deletion_generation=deletion_generation,
        key_id=p.keyring.current_dek_id or "", cipher=CIPHER_NAME, fts5_available=fts5_available(),
        index=index, providers=providers, limitations=tuple(limitations),
    )
