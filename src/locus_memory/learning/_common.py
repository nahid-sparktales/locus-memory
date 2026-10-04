"""Small shared helpers for the learning services (no I/O of their own)."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from typing import TypeVar

from ..models import MemoryKind, MemoryRecord, ScopeGrants
from ..storage.records import RecordStore

T = TypeVar("T")
CHUNK = 500  # stays far below SQLite's bound-parameter limit


def chunked(items: Iterable[T], size: int = CHUNK) -> Iterator[list[T]]:
    batch: list[T] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def authorized_by_ids(records: RecordStore, conn: sqlite3.Connection, grants: ScopeGrants, ids: Sequence[str], *,
                      kinds: tuple[MemoryKind, ...] | None = None, limit: int | None = None) -> list[MemoryRecord]:
    """``RecordStore.authorized`` over an arbitrarily long id list, newest first."""
    out: list[MemoryRecord] = []
    for batch in chunked(dict.fromkeys(ids)):
        out += records.authorized(conn, grants, lifecycles=None, kinds=kinds, ids=batch, limit=limit,
                                  order="updated_at DESC, id")
    out.sort(key=lambda r: (-r.updated_at, r.id))
    return out if limit is None else out[:limit]


def existing_ids(conn: sqlite3.Connection, table: str, column: str, ids: Iterable[str]) -> set[str]:
    """Subset of ``ids`` present in ``table.column`` (table/column are trusted literals)."""
    found: set[str] = set()
    for batch in chunked(dict.fromkeys(ids)):
        found.update(r[0] for r in conn.execute(
            f"SELECT {column} FROM {table} WHERE {column} IN ({','.join('?' * len(batch))})", batch))
    return found
