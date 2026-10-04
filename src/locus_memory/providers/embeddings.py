"""Versioned, encrypted embedding storage - a derived index, never canonical memory.

* Vector bytes (float32 little-endian, unit-normalized) live inside AES-256-GCM
  ciphertext, together with the record revision and a keyed token of the embedded
  text. Only ``record_id``, ``model_key``, ``revision`` and ``index_generation`` are
  clear metadata.
* ``model_key`` is a keyed token over (provider name, model, model version, dimensions,
  provider preprocessing version, hub preprocessing version). Vectors with different
  keys are stored side by side and never compared: a ranking loads exactly one key.
* Vectors that do not match their key (wrong dimensions, wrong key in the payload,
  non-finite values) are ignored as incompatible and recomputed.
* Writes are compare-and-swap on the record's revision: a slow embedding reply cannot
  overwrite a record that was edited (or forgotten) meanwhile.
* ``index_generation`` records the partition generation the vector was committed at.
  Writing vectors does not bump the generation: vectors only add an optional ranking
  signal and never change what is visible.
"""
from __future__ import annotations

import base64
import binascii
import math
import operator
import sqlite3
import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ..errors import ValidationError
from ..models import ScopeGrants, canonical_json
from ..storage.partition import Partition
from ..storage.records import RecordStore
from .base import ProviderDescriptor

_CHUNK = 500


@dataclass(frozen=True)
class StoredVector:
    record_id: str
    revision: int
    text_token: str
    vector: tuple[float, ...]
    index_generation: int


def pack_vector(vector: Sequence[float]) -> str:
    return base64.b64encode(struct.pack(f"<{len(vector)}f", *vector)).decode("ascii")


def unpack_vector(data: str, dimensions: int) -> tuple[float, ...] | None:
    try:
        raw = base64.b64decode(data.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None
    if len(raw) != 4 * dimensions:
        return None
    values = struct.unpack(f"<{dimensions}f", raw)
    # Any NaN/inf makes the sum non-finite; float32 magnitudes cannot overflow a float64 sum.
    if not math.isfinite(sum(values)):
        return None
    return values


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity in [-1, 1]. A geometric similarity - not a probability of relevance."""
    if len(a) != len(b):
        raise ValidationError("vectors from different models cannot be compared")
    na = math.hypot(*a)
    nb = math.hypot(*b)
    if na == 0.0 or nb == 0.0:
        return 0.0
    dot = sum(map(operator.mul, a, b))
    return max(-1.0, min(1.0, dot / (na * nb)))


def _check_vector(vector: Sequence[float], dimensions: int) -> tuple[float, ...]:
    if len(vector) != dimensions:
        raise ValidationError("the vector does not match the model's dimensions")
    values = tuple(float(x) for x in vector)
    if not all(math.isfinite(x) and abs(x) <= 3.0e38 for x in values):
        raise ValidationError("vector values must be finite float32 numbers")
    return values


class EmbeddingStore:
    TABLE = "embeddings"

    def __init__(self, partition: Partition) -> None:
        self.p = partition

    # ------------------------------------------------------------------ keys
    def model_key(self, descriptor: ProviderDescriptor, hub_preprocessing: str) -> str:
        material = canonical_json([descriptor.name, descriptor.model, descriptor.version,
                                   descriptor.dimensions, descriptor.preprocessing_version, hub_preprocessing])
        return "e" + self.p.token("embedding-model", material)[:32]

    def text_token(self, text: str) -> str:
        return self.p.token("embedding-text", text)

    @staticmethod
    def _row_id(record_id: str, model_key: str) -> str:
        return f"{record_id}|{model_key}"

    @staticmethod
    def _fields(model_key: str, revision: int, index_generation: int) -> dict[str, object]:
        return {"model_key": model_key, "revision": int(revision), "index_generation": int(index_generation)}

    # ------------------------------------------------------------------ read
    def load(self, conn: sqlite3.Connection, model_key: str, record_ids: Iterable[str], *,
             dimensions: int) -> dict[str, StoredVector]:
        """Vectors stored under ``model_key`` for these ids (incompatible payloads are skipped)."""
        wanted = sorted({i for i in record_ids if i})
        out: dict[str, StoredVector] = {}
        for start in range(0, len(wanted), _CHUNK):
            chunk = wanted[start:start + _CHUNK]
            rows = conn.execute(
                f"SELECT record_id, model_key, revision, index_generation, dek_id, nonce, ciphertext"
                f" FROM embeddings WHERE model_key=? AND record_id IN ({','.join('?' * len(chunk))})",
                [model_key, *chunk],
            ).fetchall()
            for row in rows:
                stored = self._decode(row, dimensions)
                if stored is not None:
                    out[stored.record_id] = stored
        return out

    def _decode(self, row: sqlite3.Row, dimensions: int) -> StoredVector | None:
        record_id, model_key = row[0], row[1]
        payload = self.p.open_json(  # authentication failure raises IntegrityError (tampering)
            self.TABLE, self._row_id(record_id, model_key), self._fields(model_key, row[2], row[3]),
            row[4], row[5], row[6],
        )
        if (not isinstance(payload, dict) or payload.get("model_key") != model_key
                or payload.get("record_id") != record_id or payload.get("dims") != dimensions
                or payload.get("revision") != int(row[2]) or not isinstance(payload.get("vector"), str)):
            return None  # incompatible with the expected model: ignored, recomputed lazily
        vector = unpack_vector(payload["vector"], dimensions)
        if vector is None:
            return None
        return StoredVector(record_id, int(row[2]), str(payload.get("text_token") or ""), vector, int(row[3]))

    # ------------------------------------------------------------------ write
    def put(self, conn: sqlite3.Connection, *, record_id: str, model_key: str, expected_revision: int,
            text_token: str, vector: Sequence[float], dimensions: int) -> bool:
        """Compare-and-swap write inside the caller's write transaction.

        Returns False (and writes nothing) when the record no longer exists or its
        revision is not ``expected_revision``. Raises ValidationError for a vector that
        does not match the model's dimensions.
        """
        values = _check_vector(vector, dimensions)
        row = conn.execute("SELECT revision FROM records WHERE id=?", (record_id,)).fetchone()
        if row is None or int(row[0]) != int(expected_revision):
            return False
        index_generation = self.p.generation(conn)
        payload = {
            "record_id": record_id, "model_key": model_key, "revision": int(expected_revision),
            "dims": dimensions, "text_token": text_token, "vector": pack_vector(values),
        }
        dek, nonce, ct = self.p.seal_json(self.TABLE, self._row_id(record_id, model_key),
                                          self._fields(model_key, expected_revision, index_generation), payload)
        conn.execute(
            "INSERT OR REPLACE INTO embeddings(record_id, model_key, revision, index_generation, dek_id, nonce,"
            " ciphertext) VALUES(?,?,?,?,?,?,?)",
            (record_id, model_key, int(expected_revision), index_generation, dek, nonce, ct),
        )
        return True

    # ------------------------------------------------------------------ data-key rotation
    def reencrypt(self, conn: sqlite3.Connection, old_dek_ids: frozenset[str], limit: int) -> int:
        """Re-seal up to ``limit`` vectors still under a retiring DEK (same AAD as ``put``)."""
        from ..admin import reencrypt_table

        return reencrypt_table(
            conn, self.p, self.TABLE, key_columns=("record_id", "model_key"),
            row_id=lambda r: self._row_id(r["record_id"], r["model_key"]),
            fields=lambda r: self._fields(r["model_key"], r["revision"], r["index_generation"]),
            old_dek_ids=old_dek_ids, limit=limit)

    # ------------------------------------------------------------------ deletion / hygiene
    def delete_record(self, conn: sqlite3.Connection, record_id: str) -> int:
        return conn.execute("DELETE FROM embeddings WHERE record_id=?", (record_id,)).rowcount

    def delete_orphans(self, conn: sqlite3.Connection) -> int:
        return conn.execute(
            "DELETE FROM embeddings WHERE NOT EXISTS (SELECT 1 FROM records r WHERE r.id=embeddings.record_id)"
        ).rowcount

    def delete_all(self, conn: sqlite3.Connection) -> int:
        return conn.execute("DELETE FROM embeddings").rowcount

    def delete_models_except(self, conn: sqlite3.Connection, keep: Iterable[str]) -> int:
        keys = sorted(set(keep))
        if not keys:
            return conn.execute("DELETE FROM embeddings").rowcount
        return conn.execute(
            f"DELETE FROM embeddings WHERE model_key NOT IN ({','.join('?' * len(keys))})", keys
        ).rowcount

    def count_authorized(self, conn: sqlite3.Connection, records: RecordStore, grants: ScopeGrants,
                         model_key: str) -> dict[str, int]:
        """Vector counts for records the caller may see (SQL only; nothing is decrypted)."""
        pairs = records.allowed_pairs(grants)
        if pairs:
            cond = ("NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id AND "
                    f"(s.dim || ':' || s.value_token) NOT IN ({','.join('?' * len(pairs))}))")
        else:
            cond = "NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id=r.id)"
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN e.revision = r.revision THEN 1 ELSE 0 END), 0)"
            f" FROM embeddings e JOIN records r ON r.id = e.record_id WHERE e.model_key=? AND {cond}",
            [model_key, *pairs],
        ).fetchone()
        return {"vectors": int(row[0]), "current_revision": int(row[1])}
