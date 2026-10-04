"""Partition key administration: master-key rotation and progressive data-key rotation.

Both operations require an ``ADMIN`` access context from a user or host actor.

Master-key rotation (cheap): every data/HMAC key is re-wrapped under the new
master key inside one write transaction. With ``drop_old`` the wraps under other
master keys are removed only after every key has a new wrap, so once the rotation
commits the vault no longer *needs* the old master key. Master rotation does not
change the data or HMAC keys themselves, so the old master key keeps opening them
from any file that still holds an old wrap:

* the live database files, until a checkpoint folds the WAL (where the deletion
  was committed) back into the main file and truncates the WAL. Both rotations
  therefore checkpoint after committing and report the outcome as
  ``flushed`` (receipt details for master rotation, the returned report for a
  completed data-key rotation). A reader pinned to an older snapshot can block
  the checkpoint; after bounded retries the result is ``flushed: False`` and the
  host must treat the old key as still able to open this vault until
  :func:`flush_key_material` returns ``True`` (or a retried rotation reports
  ``flushed: True``). Only then is it safe to delete the old master key.
* backups or file copies taken before the rotation: rotation never reaches them,
  and they stay openable with the old master key for as long as they exist.

Data-key (DEK) rotation (progressive, resumable):

1. The first call creates a new DEK, makes it current (new writes use it at once)
   and records the rotation state in ``meta['dek_rotation']``.
2. Each call re-encrypts at most ``batch`` rows still sealed under a retiring DEK,
   authenticating each row with its original associated data first (a tampered
   row aborts the batch with ``IntegrityError``; it is never re-sealed).
3. When no row in *any* sealed table (a table with ``dek_id``, ``nonce`` and
   ``ciphertext`` columns) references a retiring DEK, the old DEKs are retired.
   Until then they stay available, so old data is readable throughout.
4. The completing call checkpoints, so the retired DEK's wrap and every
   ciphertext sealed under it leave the on-disk files (``secure_delete`` zeroes
   the freed cells), and reports ``flushed`` as above. Batches before completion
   do not checkpoint: the retiring DEK is still wrapped in the live vault then,
   so an earlier flush would not take anything out of reach.

Foundation tables (records, record_revisions, receipts) are handled here. A sibling
service that owns sealed tables takes part by implementing::

    def reencrypt(self, conn, old_dek_ids: frozenset[str], limit: int) -> int

usually by calling :func:`reencrypt_table` with its own associated-data fields.
Rows in a sealed table nobody re-encrypts keep the rotation ``blocked`` (reported
per table) and the old DEK is retained - rotation never strands data.
"""
from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable, Iterable
from dataclasses import replace
from typing import Any

from . import policy
from .errors import AccessDenied, IntegrityError, MemoryEngineError
from .models import AccessContext, Actor, Operation, Receipt
from .services import PartitionContext
from .storage import schema
from .storage.partition import Partition
from .validation import check_int

ROTATION_META = "dek_rotation"

# Checkpoint attempts after a rotation; each one already waits up to the connection's
# busy timeout for readers pinned to an older snapshot.
FLUSH_ATTEMPTS = 3

PRE_ROTATION_COPIES_LIMITATION = (
    "backups or file copies of this vault taken before the rotation are not changed by it and"
    " still open with the replaced key"
)
UNFLUSHED_LIMITATION = (
    "a concurrent reader blocked the checkpoint, so the replaced key material is still in the"
    " on-disk database files; treat the replaced key as able to open this vault until"
    " locus_memory.admin.flush_key_material() returns True"
)

RowFn = Callable[[sqlite3.Row], Any]


def require_admin(access: AccessContext) -> None:
    policy.require(access, Operation.ADMIN)
    if access.actor not in (Actor.USER, Actor.HOST):
        raise AccessDenied("key administration is a user or host action")


# ---------------------------------------------------------------------------- flushing
def _checkpoint(p: Partition) -> bool:
    """Fold the WAL into the main database file and truncate it. True only when confirmed.

    A committed DELETE of key material reaches the main file only when a checkpoint
    copies the newer page images over the old ones (``secure_delete`` has zeroed the
    freed cells in them); until the WAL is reset its older frames hold the old pages
    too. ``wal_checkpoint(TRUNCATE)`` reports ``busy`` when a reader pinned to an
    older snapshot prevents that; it is retried a bounded number of times and then
    reported as not flushed instead of being assumed.
    """
    db = p.db
    if not db.wal:
        return True  # rollback journal: committed changes are already in the main file
    conn = db.conn
    if conn.in_transaction:
        raise MemoryEngineError("cannot flush the database inside an open transaction")
    for attempt in range(FLUSH_ATTEMPTS):
        if attempt:
            time.sleep(0.05 * (2 ** attempt))
        try:
            row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        except sqlite3.OperationalError:
            continue
        # (busy, frames in the WAL, frames checkpointed); (0, 0, 0) once truncated.
        if row is not None and int(row[0]) == 0 and int(row[1]) == int(row[2]):
            return True
    return False


def _confirm_flush(p: Partition, receipt: Receipt) -> Receipt:
    """Checkpoint after a committed rotation and record the outcome on its receipt.

    The receipt was committed with ``flushed: False`` (and the matching limitation),
    which stays true if the checkpoint cannot complete. On a confirmed flush the
    stored copy is updated; if that small follow-up write fails the stored copy
    keeps the conservative value while the caller learns the confirmed one.
    """
    try:
        confirmed = _checkpoint(p)
    except (MemoryEngineError, sqlite3.Error):
        confirmed = False  # e.g. closed concurrently: the committed rotation stands, unconfirmed
    if not confirmed:
        return receipt
    flushed = replace(receipt, details={**receipt.details, "flushed": True},
                      limitations=tuple(x for x in receipt.limitations if x != UNFLUSHED_LIMITATION))
    try:
        with p.db.write() as conn:
            p.save_receipt(conn, flushed)
    except (MemoryEngineError, sqlite3.Error):
        pass  # the rotation and the flush both happened; only the receipt annotation is stale
    return flushed


def flush_key_material(ctx: PartitionContext, access: AccessContext) -> bool:
    """Checkpoint the partition database and confirm it (ADMIN; user or host).

    For a rotation that reported ``flushed: False``: returns ``True`` once the WAL
    has been folded into the main file and truncated, i.e. once key material that a
    committed rotation removed is gone from the live on-disk files. Call it from a
    thread with no open transaction on this partition.
    """
    require_admin(access)
    return _checkpoint(ctx.partition)


# ---------------------------------------------------------------------------- master key
def rotate_master_key(ctx: PartitionContext, access: AccessContext, new_key_id: str, *,
                      drop_old: bool = True) -> Receipt:
    """Re-wrap every partition key under ``new_key_id`` (which the provider must hold).

    The receipt's ``details["flushed"]`` says whether the superseded wraps have left
    the on-disk files (see the module docstring): delete the old master key only
    after it is ``True``, and remember that pre-rotation backups still open with it.
    """
    require_admin(access)
    p = ctx.partition
    with p.db.write() as conn:
        count = p.keyring.rewrap(conn, new_key_id, drop_old=drop_old)
        masters = p.keyring.wrapped_master_ids(conn)
        p.event(conn, "admin", "master_key_rotated")
        receipt = p.make_receipt(conn, "rotate_master_key", "ok", details={
            "wrapped_keys": count, "master_key_id": new_key_id, "dropped_old": bool(drop_old),
            "master_key_ids": sorted(masters), "flushed": False,
        }, limitations=(PRE_ROTATION_COPIES_LIMITATION, UNFLUSHED_LIMITATION))
    return _confirm_flush(p, receipt)


# ---------------------------------------------------------------------------- data key
def sealed_tables(conn: sqlite3.Connection) -> list[str]:
    """Every table holding sealed rows (has ``dek_id``, ``nonce`` and ``ciphertext``)."""
    out = []
    for (name,) in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall():
        if name == "key_wraps":
            continue
        columns = {row[1] for row in conn.execute(f'PRAGMA table_info("{_quote(name)}")')}
        if {"dek_id", "nonce", "ciphertext"} <= columns:
            out.append(name)
    return out


def _quote(identifier: str) -> str:
    return identifier.replace('"', '""')


def remaining_rows(conn: sqlite3.Connection, dek_ids: Iterable[str]) -> dict[str, int]:
    ids = sorted(set(dek_ids))
    if not ids:
        return {}
    marks = ",".join("?" * len(ids))
    out = {}
    for table in sealed_tables(conn):
        count = conn.execute(f'SELECT COUNT(*) FROM "{_quote(table)}" WHERE dek_id IN ({marks})', ids).fetchone()[0]
        if count:
            out[table] = int(count)
    return out


def reencrypt_table(conn: sqlite3.Connection, partition: Partition, table: str, *,
                    key_columns: tuple[str, ...], row_id: RowFn, fields: RowFn,
                    old_dek_ids: Iterable[str], limit: int, aad_table: str | None = None) -> int:
    """Re-seal up to ``limit`` rows of ``table`` that use a retiring DEK. Returns rows done.

    ``row_id(row)`` and ``fields(row)`` must reproduce exactly the row id and
    associated-data fields the owner passed to ``seal_json`` (``aad_table`` defaults
    to ``table``). Each row is authenticated with its old key before re-sealing.
    """
    ids = sorted(set(old_dek_ids))
    if not ids or limit <= 0:
        return 0
    keyring = partition.keyring
    label = aad_table or table
    marks = ",".join("?" * len(ids))
    rows = conn.execute(
        f'SELECT * FROM "{_quote(table)}" WHERE dek_id IN ({marks}) LIMIT ?', [*ids, int(limit)]
    ).fetchall()
    where = " AND ".join(f'"{_quote(c)}"=?' for c in key_columns)
    done = 0
    for row in rows:
        rid, aad_fields = str(row_id(row)), dict(fields(row))
        plaintext = keyring.open(label, rid, aad_fields, row["dek_id"], row["nonce"], row["ciphertext"])
        dek, nonce, ciphertext = keyring.seal(label, rid, aad_fields, plaintext)
        cursor = conn.execute(
            f'UPDATE "{_quote(table)}" SET dek_id=?, nonce=?, ciphertext=? WHERE {where} AND dek_id=?',
            (dek, nonce, ciphertext, *[row[c] for c in key_columns], row["dek_id"]),
        )
        if cursor.rowcount != 1:
            raise IntegrityError("a sealed row changed during key rotation")
        done += 1
    return done


def _foundation_handlers(conn: sqlite3.Connection, p: Partition, old: frozenset[str], limit: int) -> int:
    done = reencrypt_table(
        conn, p, "records", key_columns=("id",), row_id=lambda r: r["id"],
        fields=lambda r: {"kind": r["kind"], "lifecycle": r["lifecycle"], "revision": int(r["revision"]),
                          "scope": r["scope_token"]},
        old_dek_ids=old, limit=limit)
    done += reencrypt_table(
        conn, p, "record_revisions", key_columns=("record_id", "revision"),
        row_id=lambda r: f"{r['record_id']}#{int(r['revision'])}",
        fields=lambda r: {"lifecycle": r["lifecycle"], "change": r["change"]},
        old_dek_ids=old, limit=limit - done)
    done += reencrypt_table(
        conn, p, "receipts", key_columns=("id",), row_id=lambda r: r["id"],
        fields=lambda r: {"operation": r["operation"]}, old_dek_ids=old, limit=limit - done)
    return done


def _load_state(conn: sqlite3.Connection) -> dict[str, Any] | None:
    raw = schema.get_meta(conn, ROTATION_META)
    if not raw:
        return None
    try:
        state = json.loads(raw)
    except ValueError as exc:
        raise IntegrityError("the key-rotation state is malformed") from exc
    if not isinstance(state, dict) or not isinstance(state.get("retiring"), list):
        raise IntegrityError("the key-rotation state is malformed")
    return state


def _sync_keys(p: Partition, conn: sqlite3.Connection) -> None:
    if schema.get_meta(conn, "current_dek_id") != p.keyring.current_dek_id:
        p.reload_keys()


def rotate_data_key(ctx: PartitionContext, access: AccessContext, *, batch: int = 500) -> dict[str, Any]:
    """Start or continue a DEK rotation; one bounded batch per call (see module docstring)."""
    require_admin(access)
    check_int(batch, "batch", lo=1, hi=1_000_000)
    p = ctx.partition
    started = False
    try:
        with p.db.write() as conn:
            _sync_keys(p, conn)
            state = _load_state(conn)
            if state is None:
                retiring = sorted(r[0] for r in conn.execute(
                    "SELECT DISTINCT dek_id FROM key_wraps WHERE purpose='data'").fetchall())
                new_dek = p.keyring.new_data_key(conn)
                state = {"retiring": retiring, "target": new_dek, "started_at": ctx.clock(), "migrated": 0}
                schema.set_meta(conn, ROTATION_META, json.dumps(state, sort_keys=True))
                p.event(conn, "admin", "data_key_rotation_started")
                started = True
    except BaseException:
        p.reload_keys()  # drop an in-memory DEK whose creation was rolled back
        raise
    old = frozenset(state["retiring"])
    try:
        with p.db.write() as conn:
            _sync_keys(p, conn)
            state = _load_state(conn) or state
            migrated = _foundation_handlers(conn, p, old, batch)
            for service in ctx.services.all():
                if migrated >= batch:
                    break
                hook = getattr(type(service), "reencrypt", None)
                if callable(hook):
                    migrated += int(service.reencrypt(conn, old, batch - migrated) or 0)
            remaining = remaining_rows(conn, old)
            state["migrated"] = int(state.get("migrated", 0)) + migrated
            retired: list[str] = []
            if not remaining:
                for dek_id in sorted(old):
                    if dek_id != p.keyring.current_dek_id:
                        p.keyring.retire_data_key(conn, dek_id)
                        retired.append(dek_id)
                conn.execute("DELETE FROM meta WHERE key=?", (ROTATION_META,))
                outcome = "complete"
                p.event(conn, "admin", "data_key_rotation_complete")
            else:
                schema.set_meta(conn, ROTATION_META, json.dumps(state, sort_keys=True))
                # Budget left over while rows remain: nobody re-encrypts those tables.
                outcome = "blocked" if migrated < batch else "in_progress"
            complete = outcome == "complete"
            report = {
                "state": outcome, "started": started, "current_dek_id": p.keyring.current_dek_id,
                "retiring": sorted(old), "retired": retired, "migrated": migrated,
                "migrated_total": state["migrated"], "remaining": remaining,
                "blocked_tables": sorted(remaining) if outcome == "blocked" else [],
                # Only a completed rotation removes key material; see the module docstring.
                "flushed": False if complete else None,
            }
            receipt = p.make_receipt(
                conn, "rotate_data_key", "ok" if complete else "partial", details=report,
                limitations=(PRE_ROTATION_COPIES_LIMITATION, UNFLUSHED_LIMITATION) if complete else ())
    except BaseException:
        p.reload_keys()  # a rolled-back retirement must not leave the keyring without a DEK
        raise
    if complete:
        receipt = _confirm_flush(p, receipt)
    return {**receipt.details, "receipt_id": receipt.receipt_id}


def data_key_rotation_status(ctx: PartitionContext, access: AccessContext) -> dict[str, Any]:
    require_admin(access)
    p = ctx.partition
    with p.db.read() as conn:
        state = _load_state(conn)
        if state is None:
            return {"state": "idle", "current_dek_id": schema.get_meta(conn, "current_dek_id")}
        return {"state": "in_progress", "current_dek_id": schema.get_meta(conn, "current_dek_id"),
                "retiring": sorted(state["retiring"]), "migrated_total": int(state.get("migrated", 0)),
                "remaining": remaining_rows(conn, state["retiring"])}
