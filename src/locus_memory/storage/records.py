"""Encrypted canonical memory records with authorization applied inside the query.

Source index: every cited source is indexed under ``source_token(identity)``. A
``session`` source is additionally indexed under ``partition.token('session', ref)``
- the token a session forget carries - because forgetting must work from the
token alone (also during ledger replay after a restore).
"""
from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable, Iterator
from typing import Any

from ..errors import IntegrityError, RevisionConflict, ValidationError
from ..models import (
    Actor,
    Confidence,
    Lifecycle,
    Links,
    MemoryKind,
    MemoryRecord,
    Retention,
    RevisionInfo,
    Scope,
    ScopeGrants,
    SourceKind,
    SourceRef,
    StatementBasis,
    Validity,
    canonical_json,
)
from ..validation import check_depth, normalize_for_fingerprint
from .partition import Partition

# Records fetched (and decrypted) per query by RecordStore.iter_authorized.
_FETCH_CHUNK = 128
# ORDER BY terms accepted by RecordStore.authorized (the clause is interpolated into SQL).
_ORDER = re.compile(r"\s*(r\.)?[a-z_]+(\s+(asc|desc))?(\s*,\s*(r\.)?[a-z_]+(\s+(asc|desc))?)*\s*",
                    re.IGNORECASE)


# Served in place of a stored provenance locator / applicability mapping nested deeper than the
# validation bound (``validation.MAX_MAPPING_DEPTH``) - one a build without that bound accepted.
# The record stays readable; only that mapping is withheld.
UNREADABLE_MAPPING: dict[str, Any] = {"unavailable": "stored mapping exceeds the validation bounds"}


def _stored_mapping(raw: Any, key: str) -> Any:
    """``raw`` with ``raw[key]`` replaced by ``UNREADABLE_MAPPING`` when it is nested too deeply."""
    if not isinstance(raw, dict) or not isinstance(raw.get(key), dict):
        return raw
    try:
        check_depth(raw[key], key)
    except ValidationError:
        return {**raw, key: dict(UNREADABLE_MAPPING)}
    return raw


def record_from_dict(raw: dict[str, Any]) -> MemoryRecord:
    links = raw.get("links") or {}
    return MemoryRecord(
        id=raw["id"], revision=int(raw["revision"]), kind=MemoryKind(raw["kind"]),
        lifecycle=Lifecycle(raw["lifecycle"]), scope=Scope.from_dict(raw.get("scope")),
        title=raw.get("title") or "", content=raw.get("content") or "",
        tags=tuple(raw.get("tags") or ()), basis=StatementBasis(raw.get("basis") or "user_stated"),
        confidence=Confidence.from_dict(raw.get("confidence")),
        subject=raw.get("subject"), predicate=raw.get("predicate"),
        sources=tuple(SourceRef.from_dict(_stored_mapping(s, "locator")) for s in raw.get("sources") or ()),
        validity=Validity.from_dict(_stored_mapping(raw.get("validity"), "applicability")),
        retention=Retention.from_dict(raw.get("retention")),
        links=Links(
            supersedes=tuple(links.get("supersedes") or ()),
            superseded_by=links.get("superseded_by"),
            conflicts_with=tuple(links.get("conflicts_with") or ()),
            derived_from=tuple(links.get("derived_from") or ()),
        ),
        created_at=float(raw.get("created_at") or 0.0), updated_at=float(raw.get("updated_at") or 0.0),
        event_time=raw.get("event_time"), ingested_at=raw.get("ingested_at"),
        reason=raw.get("reason") or "", extra=dict(raw.get("extra") or {}),
        schema_version=int(raw.get("schema_version") or 1),
    )


class RecordStore:
    TABLE = "records"
    REV_TABLE = "record_revisions"

    def __init__(self, partition: Partition) -> None:
        self.p = partition

    # ------------------------------------------------------------------ tokens
    def scope_token(self, scope: Scope) -> str:
        return self.p.token("scope", scope.key())

    def scope_value_token(self, dim: str, value: str) -> str:
        return self.p.token("scope-value", f"{dim}\x00{value}")

    def allowed_pairs(self, grants: ScopeGrants) -> list[str]:
        pairs = []
        for dim in ScopeGrants._DIM_FIELDS:
            for value in grants.values_for(dim):
                pairs.append(f"{dim}:{self.scope_value_token(dim, value)}")
        return pairs

    def source_token(self, identity: str) -> str:
        return self.p.token("source", identity)

    def source_index_tokens(self, source: SourceRef) -> tuple[str, ...]:
        """Every token under which ``source`` is indexed (see the module docstring)."""
        tokens = [self.source_token(source.identity())]
        if source.kind == SourceKind.SESSION:
            tokens.append(self.p.token("session", source.ref))
        return tuple(tokens)

    def subject_token(self, record: MemoryRecord) -> str | None:
        if not record.subject or not record.predicate:
            return None
        subject, predicate = record.subject.casefold(), record.predicate.casefold()
        if "|" in subject or "|" in predicate:
            # "a|b"+"c" and "a"+"b|c" must not collide (false conflicts could let an approval
            # supersede an unrelated memory); other inputs keep their original token.
            return self.p.token("subject-v2", canonical_json([record.scope.key(), subject, predicate]))
        return self.p.token("subject", f"{record.scope.key()}|{subject}|{predicate}")

    def content_token(self, text: str) -> str:
        return self.p.token("content", normalize_for_fingerprint(text))

    # ------------------------------------------------------------------ write
    def _fields(self, record: MemoryRecord, scope_token: str) -> dict[str, Any]:
        return {"kind": record.kind.value, "lifecycle": record.lifecycle.value,
                "revision": record.revision, "scope": scope_token}

    def write(self, conn: sqlite3.Connection, record: MemoryRecord, *, change: str, actor: Actor,
              expected_revision: int | None, generation: int, reason: str = "") -> MemoryRecord:
        """Insert (expected_revision=None) or compare-and-swap update a record."""
        scope_token = self.scope_token(record.scope)
        fields = self._fields(record, scope_token)
        payload = record.to_dict()
        dek, nonce, ct = self.p.seal_json(self.TABLE, record.id, fields, payload)
        values = (
            record.kind.value, record.lifecycle.value, scope_token, record.revision,
            int(record.retention.pinned), record.created_at, record.updated_at,
            record.retention.expires_at, record.validity.valid_from, record.validity.valid_until,
            self.subject_token(record), self.content_token(record.content), generation,
            dek, nonce, ct,
        )
        if expected_revision is None:
            try:
                conn.execute(
                    """INSERT INTO records(kind, lifecycle, scope_token, revision, pinned, created_at,
                       updated_at, expires_at, valid_from, valid_until, subject_token, content_token,
                       write_generation, dek_id, nonce, ciphertext, id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    values + (record.id,),
                )
            except sqlite3.IntegrityError as exc:
                raise RevisionConflict("a memory with this id already exists") from exc
        else:
            if record.revision != expected_revision + 1:
                raise IntegrityError("revision must advance by exactly one")
            cursor = conn.execute(
                """UPDATE records SET kind=?, lifecycle=?, scope_token=?, revision=?, pinned=?,
                   created_at=?, updated_at=?, expires_at=?, valid_from=?, valid_until=?,
                   subject_token=?, content_token=?, write_generation=?, dek_id=?, nonce=?,
                   ciphertext=? WHERE id=? AND revision=?""",
                values + (record.id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise RevisionConflict("the memory changed since it was read",
                                       details={"expected_revision": expected_revision})
            conn.execute("DELETE FROM record_scopes WHERE record_id=?", (record.id,))
            conn.execute("DELETE FROM record_sources WHERE record_id=?", (record.id,))
        conn.executemany(
            "INSERT INTO record_scopes(record_id, dim, value_token) VALUES(?,?,?)",
            [(record.id, dim, self.scope_value_token(dim, value)) for dim, value in record.scope.constraints],
        )
        source_rows = [(record.id, token, s.kind.value)
                       for s in record.sources for token in self.source_index_tokens(s)]
        conn.executemany(
            "INSERT OR IGNORE INTO record_sources(record_id, source_token, kind) VALUES(?,?,?)",
            source_rows,
        )
        conn.execute("DELETE FROM derivations WHERE derived_id=? AND derived_kind='memory'", (record.id,))
        conn.executemany(
            "INSERT OR IGNORE INTO derivations(derived_id, derived_kind, input_token, input_kind) VALUES(?,?,?,?)",
            [(record.id, "memory", self.p.token("memory", parent), "memory") for parent in record.links.derived_from]
            + [(rid, "memory", token, kind) for rid, token, kind in source_rows],
        )
        rev_id = f"{record.id}#{record.revision}"
        rdek, rnonce, rct = self.p.seal_json(
            self.REV_TABLE, rev_id, {"lifecycle": record.lifecycle.value, "change": change}, payload
        )
        conn.execute(
            """INSERT OR REPLACE INTO record_revisions(record_id, revision, lifecycle, change, actor,
               created_at, purged, dek_id, nonce, ciphertext) VALUES(?,?,?,?,?,?,0,?,?,?)""",
            (record.id, record.revision, record.lifecycle.value, change[:32], actor.value,
             record.updated_at, rdek, rnonce, rct),
        )
        return record

    # ------------------------------------------------------------------ read
    def _decode(self, row: sqlite3.Row) -> MemoryRecord:
        fields = {"kind": row["kind"], "lifecycle": row["lifecycle"], "revision": int(row["revision"]),
                  "scope": row["scope_token"]}
        raw = self.p.open_json(self.TABLE, row["id"], fields, row["dek_id"], row["nonce"], row["ciphertext"])
        if not isinstance(raw, dict) or raw.get("id") != row["id"]:
            raise IntegrityError("a stored record is malformed")
        record = record_from_dict(raw)
        if (record.revision != int(row["revision"]) or record.lifecycle.value != row["lifecycle"]
                or record.kind.value != row["kind"] or self.scope_token(record.scope) != row["scope_token"]):
            raise IntegrityError("record metadata does not match its authenticated payload")
        return record

    def get_row(self, conn: sqlite3.Connection, record_id: str) -> sqlite3.Row | None:
        return conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()

    def get(self, conn: sqlite3.Connection, record_id: str) -> MemoryRecord | None:
        row = self.get_row(conn, record_id)
        return self._decode(row) if row is not None else None

    def authorized(self, conn: sqlite3.Connection, grants: ScopeGrants, *,
                   lifecycles: Iterable[Lifecycle] | None = None,
                   kinds: Iterable[MemoryKind] | None = None,
                   ids: Iterable[str] | None = None, limit: int | None = None,
                   order: str = "pinned DESC, updated_at DESC, id",
                   scope: Scope | None = None) -> list[MemoryRecord]:
        """Records whose every scope constraint is granted. Unauthorized rows are never decrypted."""
        return list(self.iter_authorized(conn, grants, lifecycles=lifecycles, kinds=kinds, ids=ids,
                                         limit=limit, order=order, scope=scope))

    def iter_authorized(self, conn: sqlite3.Connection, grants: ScopeGrants, *,
                        lifecycles: Iterable[Lifecycle] | None = None,
                        kinds: Iterable[MemoryKind] | None = None,
                        ids: Iterable[str] | None = None, limit: int | None = None,
                        order: str = "pinned DESC, updated_at DESC, id",
                        scope: Scope | None = None) -> Iterator[MemoryRecord]:
        """:meth:`authorized`, decrypting lazily: a caller that stops early (a deadline, a bound)
        never decrypts the rest. ``scope`` restricts to records of exactly that scope (in SQL,
        by its keyed token). Close the iterator (or exhaust it) inside the read snapshot."""
        if not _ORDER.fullmatch(order):
            raise ValidationError("unsupported ORDER BY clause")
        # Column conditions are written "{p}r.col" so the fetch phase can disable their indexes
        # ("+r.col"): it must look rows up by primary key, not scan an index of every match.
        conditions: list[str] = []
        params: list[Any] = []
        if lifecycles is not None:
            values = [lc.value for lc in lifecycles]
            if not values:
                return
            conditions.append(f"{{p}}r.lifecycle IN ({','.join('?' * len(values))})")
            params += values
        if kinds:
            values = [k.value for k in kinds]
            conditions.append(f"{{p}}r.kind IN ({','.join('?' * len(values))})")
            params += values
        id_values: list[str] | None = None
        if ids is not None:
            id_values = list(ids)
            if not id_values:
                return
        if scope is not None:
            conditions.append("{p}r.scope_token = ?")
            params.append(self.scope_token(scope))
        pairs = self.allowed_pairs(grants)
        if pairs:
            conditions.append(
                "NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id AND "
                f"(s.dim || ':' || s.value_token) NOT IN ({','.join('?' * len(pairs))}))"
            )
            params += pairs
        else:
            conditions.append("NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id)")
        # Two phases: order only the ids (sorting whole rows reads every ciphertext before the
        # first record is available), then fetch and decrypt in chunks by primary key - with the
        # same conditions, so a row that changed in between (outside a snapshot) is never served.
        select_where = " AND ".join(c.replace("{p}", "") for c in conditions)
        fetch_where = " AND ".join(c.replace("{p}", "+") for c in conditions)
        sql = f"SELECT r.id FROM records r WHERE {select_where}"
        id_params = list(params)
        if id_values is not None:
            sql += f" AND r.id IN ({','.join('?' * len(id_values))})"
            id_params += id_values
        sql += f" ORDER BY {order}"
        if limit is not None:
            sql += " LIMIT ?"
            id_params.append(int(limit))
        ordered = [row[0] for row in conn.execute(sql, id_params).fetchall()]
        for start in range(0, len(ordered), _FETCH_CHUNK):
            chunk = ordered[start:start + _FETCH_CHUNK]
            rows = {row["id"]: row for row in conn.execute(
                f"SELECT r.* FROM records r WHERE r.id IN ({','.join('?' * len(chunk))}) AND {fetch_where}",
                [*chunk, *params]).fetchall()}
            for record_id in chunk:
                row = rows.get(record_id)
                if row is None:
                    continue
                record = self._decode(row)
                if not grants.allows(record.scope):  # defense in depth
                    raise IntegrityError("authorization index disagrees with record scope")
                yield record

    def visible_ids(self, conn: sqlite3.Connection, grants: ScopeGrants, ids: Iterable[str]) -> set[str]:
        """Ids (of existing records) whose scope is granted - SQL only, nothing is decrypted.

        For filtering *references* (link ids) out of read results; use :meth:`authorized`
        to read the records themselves.
        """
        wanted = sorted({i for i in ids if i})
        if not wanted:
            return set()
        pairs = self.allowed_pairs(grants)
        if pairs:
            cond = ("NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id AND "
                    f"(s.dim || ':' || s.value_token) NOT IN ({','.join('?' * len(pairs))}))")
        else:
            cond = "NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id)"
        out: set[str] = set()
        for start in range(0, len(wanted), 500):
            chunk = wanted[start:start + 500]
            rows = conn.execute(
                f"SELECT r.id FROM records r WHERE r.id IN ({','.join('?' * len(chunk))}) AND {cond}",
                [*chunk, *pairs],
            ).fetchall()
            out.update(row[0] for row in rows)
        return out

    def count_authorized(self, conn: sqlite3.Connection, grants: ScopeGrants, *,
                         now: float | None = None) -> dict[str, int]:
        """Lifecycle counts of authorized records only. With ``now``, candidates past their
        TTL count as ``expired`` (the read-time view get/list present)."""
        pairs = self.allowed_pairs(grants)
        if pairs:
            cond = ("NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id AND "
                    f"(s.dim || ':' || s.value_token) NOT IN ({','.join('?' * len(pairs))}))")
        else:
            cond = "NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id)"
        if now is None:
            label, params = "r.lifecycle", list(pairs)
        else:
            label = ("CASE WHEN r.lifecycle='candidate' AND r.expires_at IS NOT NULL AND r.expires_at < ?"
                     " THEN 'expired' ELSE r.lifecycle END")
            params = [float(now), *pairs]
        rows = conn.execute(
            f"SELECT {label} AS lc, COUNT(*) FROM records r WHERE {cond} GROUP BY lc", params
        ).fetchall()
        return {row[0]: int(row[1]) for row in rows}

    def revisions(self, conn: sqlite3.Connection, record_id: str) -> list[RevisionInfo]:
        rows = conn.execute(
            "SELECT * FROM record_revisions WHERE record_id=? ORDER BY revision", (record_id,)
        ).fetchall()
        return [RevisionInfo(record_id, int(r["revision"]), Lifecycle(r["lifecycle"]), float(r["created_at"]),
                             r["change"], Actor(r["actor"]), purged=bool(r["purged"])) for r in rows]

    def revision_record(self, conn: sqlite3.Connection, record_id: str, revision: int) -> MemoryRecord | None:
        row = conn.execute(
            "SELECT * FROM record_revisions WHERE record_id=? AND revision=?", (record_id, revision)
        ).fetchone()
        if row is None or row["purged"] or row["ciphertext"] is None:
            return None
        raw = self.p.open_json(self.REV_TABLE, f"{record_id}#{revision}",
                               {"lifecycle": row["lifecycle"], "change": row["change"]},
                               row["dek_id"], row["nonce"], row["ciphertext"])
        return record_from_dict(raw)

    def ids_for_source(self, conn: sqlite3.Connection, source_token: str) -> list[str]:
        return [r[0] for r in conn.execute(
            "SELECT record_id FROM record_sources WHERE source_token=?", (source_token,))]

    def ids_derived_from(self, conn: sqlite3.Connection, input_token: str) -> list[str]:
        return [r[0] for r in conn.execute(
            "SELECT derived_id FROM derivations WHERE input_token=? AND derived_kind='memory'", (input_token,))]

    def ids_for_scope_value(self, conn: sqlite3.Connection, dim: str, value: str) -> list[str]:
        token = self.scope_value_token(dim, value)
        return [r[0] for r in conn.execute(
            "SELECT record_id FROM record_scopes WHERE dim=? AND value_token=?", (dim, token))]

    def purge(self, conn: sqlite3.Connection, record_id: str) -> dict[str, int]:
        """Remove a record, its revision payloads, vectors and derivation edges."""
        counts = {
            "revisions": conn.execute("DELETE FROM record_revisions WHERE record_id=?", (record_id,)).rowcount,
            "embeddings": conn.execute("DELETE FROM embeddings WHERE record_id=?", (record_id,)).rowcount,
        }
        conn.execute("DELETE FROM derivations WHERE derived_id=?", (record_id,))
        counts["memories"] = conn.execute("DELETE FROM records WHERE id=?", (record_id,)).rowcount
        return counts
