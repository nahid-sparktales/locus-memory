"""Portable repository-intelligence interchange format (``locus-memory.repository-interchange`` v1).

A document carries one repository's inventory and observations between tools::

    {
      "format": "locus-memory.repository-interchange",
      "version": 1,
      "producer": {"name": "...", "version": "...", "kind": "observer|tool|model", "models": [...]},
      "repository_id": "repo-a",
      "hash_algorithm": "sha1" | "sha256",
      "generated_at": 1800000000.0,          # optional
      "since_snapshot": null,                # optional
      "records": [ {"type": "repository" | "snapshot" | "file" | "symbol" | "import"
                             | "observation" | "summary", ...}, ... ]
    }

The machine-readable schema is ``interchange_schema.json`` next to this module; the
authoritative check is :func:`validate_document` (stdlib only, strict): unknown
format/versions, unknown keys, oversized documents, malformed hashes, paths that
escape the repository root and excluded (secret-bearing) paths are all rejected,
and error messages never echo document content.

Trust model: an imported document is untrusted data. It can never approve memory,
change access, or waive verification. ``summary`` records are model output - they
must carry ``source_hashes`` and producer/model labels, are stored with basis
``model_interpretation`` and are imported as unapproved candidates only.

Producers: :class:`RepositoryIntelligenceProvider` is the protocol an optional deep
producer (for example Agent Dispatcher) would implement. **No real Agent Dispatcher
exporter integration exists yet**; :class:`SyntheticRepositoryProducer` is a
deterministic stand-in used only by tests - it calls no model.
"""
from __future__ import annotations

import json
import math
import re
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from .. import validation as v
from ..errors import InterchangeInvalid, RepositoryAccessDenied, ValidationError
from .scanner import Exclusions, check_repo_path

FORMAT = "locus-memory.repository-interchange"
VERSION = 1
SUPPORTED_VERSIONS = (1,)
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_SOURCE_HASHES = 64
RECORD_TYPES = ("repository", "snapshot", "file", "symbol", "import", "observation", "summary")
PRODUCER_KINDS = ("observer", "tool", "model")
HASH_ALGORITHMS = ("sha1", "sha256")
SYMBOL_KINDS = ("class", "function", "async_function")
EXTRACTIONS = ("ast", "heuristic", "tool")
SUPPORT_LEVELS = ("parsed", "heuristic", "unsupported")
SNAPSHOT_STATES = ("complete", "partial")

_TOP_REQUIRED = frozenset({"format", "version", "producer", "repository_id", "hash_algorithm", "records"})
_TOP_OPTIONAL = frozenset({"generated_at", "since_snapshot"})
_PRODUCER_KEYS = frozenset({"name", "version", "kind", "models"})
RECORD_FIELDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "repository": (frozenset({"type", "repository_id", "object_format"}), frozenset({"initial_commit"})),
    "snapshot": (frozenset({"type", "snapshot_id", "state"}), frozenset({"head", "dirty", "created_at"})),
    "file": (frozenset({"type", "path", "blob"}), frozenset({"size", "language", "support"})),
    "symbol": (frozenset({"type", "path", "blob", "name", "symbol_kind"}), frozenset({"line", "extraction"})),
    "import": (frozenset({"type", "path", "blob", "module"}), frozenset({"names", "extraction"})),
    "observation": (frozenset({"type", "path", "blob", "text"}), frozenset({"extraction", "language"})),
    "summary": (frozenset({"type", "text", "source_hashes", "producer", "model", "basis"}),
                frozenset({"title"})),
}
_HASH = {"sha1": re.compile(r"[0-9a-f]{40}"), "sha256": re.compile(r"[0-9a-f]{64}")}
_SNAPSHOT_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")


def _invalid(message: str, index: int | None = None) -> InterchangeInvalid:
    where = f"record {index}: " if index is not None else ""
    return InterchangeInvalid(f"interchange document rejected: {where}{message}",
                              details={"record": index} if index is not None else {})


class _Budget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def take(self, value: str, index: int | None) -> None:
        self.used += len(value.encode("utf-8", "surrogatepass")) + 8
        if self.used > self.limit:
            raise _invalid("document exceeds the size limit", index)


def _label(value: Any, what: str, index: int | None, budget: _Budget, *, max_chars: int = 128) -> str:
    if not isinstance(value, str):
        raise _invalid(f"{what} must be text", index)
    budget.take(value, index)
    try:
        return v.check_label(value, what, max_chars=max_chars)
    except ValidationError as exc:
        raise _invalid(f"{what} is invalid", index) from exc


def _text(value: Any, what: str, index: int | None, budget: _Budget, *, max_chars: int) -> str:
    if not isinstance(value, str):
        raise _invalid(f"{what} must be text", index)
    budget.take(value, index)
    try:
        return v.check_text(value, what, max_chars=max_chars)
    except ValidationError as exc:
        raise _invalid(f"{what} is invalid or too long", index) from exc


def _hash(value: Any, algorithm: str, what: str, index: int | None, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not _HASH[algorithm].fullmatch(value):
        raise _invalid(f"{what} is not a valid {algorithm} object id", index)
    return value


def _int(value: Any, what: str, index: int | None, *, lo: int, optional: bool = True) -> int | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < lo or value > 2**53:
        raise _invalid(f"{what} must be an integer >= {lo}", index)
    return value


def _choice(value: Any, allowed: Sequence[str], what: str, index: int | None) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise _invalid(f"{what} must be one of: {', '.join(allowed)}", index)
    return value


def _path(value: Any, index: int, budget: _Budget, exclusions: Exclusions) -> str:
    if not isinstance(value, str):
        raise _invalid("path must be text", index)
    budget.take(value, index)
    try:
        path = check_repo_path(value)
    except RepositoryAccessDenied as exc:
        raise _invalid("path escapes the repository root or is malformed", index) from exc
    if exclusions.excluded(path):
        raise _invalid("path is excluded from repository memory", index)
    return path


def _keys(raw: dict, required: frozenset[str], optional: frozenset[str], what: str, index: int | None) -> None:
    keys = set(raw)
    unknown = keys - required - optional
    if unknown:
        raise _invalid(f"{what} has unknown fields", index)
    if required - keys:
        raise _invalid(f"{what} is missing required fields", index)


def _reject_constant(name: str) -> Any:
    raise ValueError("non-finite numbers are not allowed")


def load_document(document: Any) -> dict[str, Any]:
    """Parse text/bytes (bounded) or accept a mapping; never returns non-dict."""
    if isinstance(document, (bytes, bytearray)):
        if len(document) > MAX_DOCUMENT_BYTES:
            raise _invalid("document exceeds the size limit")
        try:
            document = bytes(document).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _invalid("document is not UTF-8") from exc
    if isinstance(document, str):
        if len(document.encode("utf-8", "surrogatepass")) > MAX_DOCUMENT_BYTES:
            raise _invalid("document exceeds the size limit")
        try:
            document = json.loads(document, parse_constant=_reject_constant)
        except (ValueError, RecursionError) as exc:
            raise _invalid("document is not valid JSON") from exc
    if not isinstance(document, dict):
        raise _invalid("document must be a JSON object")
    return document


def validate_document(document: Any, *, exclusions: Exclusions | None = None) -> dict[str, Any]:
    """Strictly validate a v1 document; returns a normalized copy. Raises :class:`InterchangeInvalid`."""
    raw = load_document(document)
    exclusions = exclusions or Exclusions()
    budget = _Budget(MAX_DOCUMENT_BYTES)
    if raw.get("format") != FORMAT:
        raise _invalid("unknown document format")
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version not in SUPPORTED_VERSIONS:
        raise _invalid("unsupported interchange version")
    _keys(raw, _TOP_REQUIRED, _TOP_OPTIONAL, "document", None)
    algorithm = _choice(raw["hash_algorithm"], HASH_ALGORITHMS, "hash_algorithm", None)
    try:
        repository_id = v.check_id(raw["repository_id"], "repository_id")
    except ValidationError as exc:
        raise _invalid("repository_id is invalid") from exc
    producer_raw = raw["producer"]
    if not isinstance(producer_raw, dict):
        raise _invalid("producer must be an object")
    _keys(producer_raw, frozenset({"name", "kind"}), _PRODUCER_KEYS - {"name", "kind"}, "producer", None)
    producer: dict[str, Any] = {
        "name": _label(producer_raw["name"], "producer name", None, budget),
        "kind": _choice(producer_raw["kind"], PRODUCER_KINDS, "producer kind", None),
    }
    if producer_raw.get("version") is not None:
        producer["version"] = _label(producer_raw["version"], "producer version", None, budget, max_chars=64)
    if producer_raw.get("models") is not None:
        models = producer_raw["models"]
        if not isinstance(models, list) or len(models) > 16:
            raise _invalid("producer models must be a list of at most 16 labels")
        producer["models"] = [_label(m, "model label", None, budget) for m in models]
    out: dict[str, Any] = {"format": FORMAT, "version": version, "producer": producer,
                           "repository_id": repository_id, "hash_algorithm": algorithm}
    if raw.get("generated_at") is not None:
        value = raw["generated_at"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise _invalid("generated_at must be a finite timestamp")
        try:
            out["generated_at"] = v.check_timestamp(value, "generated_at")
        except ValidationError as exc:
            raise _invalid("generated_at is out of range") from exc
    if raw.get("since_snapshot") is not None:
        since = raw["since_snapshot"]
        if not isinstance(since, str) or not _SNAPSHOT_ID.fullmatch(since):
            raise _invalid("since_snapshot is invalid")
        out["since_snapshot"] = since
    records = raw["records"]
    if not isinstance(records, list):
        raise _invalid("records must be a list")
    if len(records) > MAX_RECORDS:
        raise _invalid("document exceeds the record limit")
    normalized: list[dict[str, Any]] = []
    repository_records = snapshot_records = 0
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise _invalid("record must be an object", index)
        kind = record.get("type")
        if kind not in RECORD_FIELDS:
            raise _invalid("unknown record type", index)
        required, optional = RECORD_FIELDS[kind]
        _keys(record, required, optional, f"{kind} record", index)
        item: dict[str, Any] = {"type": kind}
        if kind == "repository":
            repository_records += 1
            if record["repository_id"] != repository_id:
                raise _invalid("repository record does not match the document repository_id", index)
            item["repository_id"] = repository_id
            if _choice(record["object_format"], HASH_ALGORITHMS, "object_format", index) != algorithm:
                raise _invalid("object_format does not match hash_algorithm", index)
            item["object_format"] = algorithm
            item["initial_commit"] = _hash(record.get("initial_commit"), algorithm, "initial_commit", index,
                                           optional=True)
        elif kind == "snapshot":
            snapshot_records += 1
            snapshot_id = record["snapshot_id"]
            if not isinstance(snapshot_id, str) or not _SNAPSHOT_ID.fullmatch(snapshot_id):
                raise _invalid("snapshot_id is invalid", index)
            item["snapshot_id"] = snapshot_id
            item["state"] = _choice(record["state"], SNAPSHOT_STATES, "state", index)
            item["head"] = _hash(record.get("head"), algorithm, "head", index, optional=True)
            dirty = record.get("dirty", False)
            if not isinstance(dirty, bool):
                raise _invalid("dirty must be a boolean", index)
            item["dirty"] = dirty
            created = record.get("created_at")
            if created is not None:
                if isinstance(created, bool) or not isinstance(created, (int, float)) or not math.isfinite(created):
                    raise _invalid("created_at must be a finite timestamp", index)
                try:
                    item["created_at"] = v.check_timestamp(created, "created_at")
                except ValidationError as exc:
                    raise _invalid("created_at is out of range", index) from exc
            else:
                item["created_at"] = None
        elif kind == "summary":
            item["text"] = _text(record["text"], "summary text", index, budget, max_chars=v.MAX_CONTENT_CHARS)
            if record.get("title") is not None:
                item["title"] = _text(record["title"], "summary title", index, budget,
                                      max_chars=v.MAX_TITLE_CHARS)
            item["producer"] = _label(record["producer"], "summary producer", index, budget)
            item["model"] = _label(record["model"], "summary model", index, budget)
            if record["basis"] != "model_interpretation":
                raise _invalid("summaries are model output: basis must be model_interpretation", index)
            item["basis"] = "model_interpretation"
            hashes = record["source_hashes"]
            if not isinstance(hashes, list) or not 1 <= len(hashes) <= MAX_SOURCE_HASHES:
                raise _invalid(f"source_hashes must list 1-{MAX_SOURCE_HASHES} [path, blob] pairs", index)
            pairs = []
            for pair in hashes:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    raise _invalid("each source hash must be a [path, blob] pair", index)
                pairs.append([_path(pair[0], index, budget, exclusions),
                              _hash(pair[1], algorithm, "source blob", index)])
            item["source_hashes"] = pairs
        else:  # file, symbol, import, observation
            item["path"] = _path(record["path"], index, budget, exclusions)
            item["blob"] = _hash(record["blob"], algorithm, "blob", index)
            if kind == "file":
                item["size"] = _int(record.get("size"), "size", index, lo=0)
                if record.get("language") is not None:
                    item["language"] = _label(record["language"], "language", index, budget, max_chars=64)
                if record.get("support") is not None:
                    item["support"] = _choice(record["support"], SUPPORT_LEVELS, "support", index)
            elif kind == "symbol":
                item["name"] = _label(record["name"], "symbol name", index, budget, max_chars=200)
                item["symbol_kind"] = _choice(record["symbol_kind"], SYMBOL_KINDS, "symbol_kind", index)
                item["line"] = _int(record.get("line"), "line", index, lo=1)
                if record.get("extraction") is not None:
                    item["extraction"] = _choice(record["extraction"], EXTRACTIONS, "extraction", index)
            elif kind == "import":
                item["module"] = _label(record["module"], "module", index, budget, max_chars=300)
                names = record.get("names")
                if names is not None:
                    if not isinstance(names, list) or len(names) > 32:
                        raise _invalid("names must be a list of at most 32 labels", index)
                    item["names"] = [_label(n, "imported name", index, budget, max_chars=200) for n in names]
                if record.get("extraction") is not None:
                    item["extraction"] = _choice(record["extraction"], EXTRACTIONS, "extraction", index)
            else:  # observation
                item["text"] = _text(record["text"], "observation text", index, budget,
                                     max_chars=v.MAX_CONTENT_CHARS)
                if record.get("extraction") is not None:
                    item["extraction"] = _choice(record["extraction"], EXTRACTIONS, "extraction", index)
                if record.get("language") is not None:
                    item["language"] = _label(record["language"], "language", index, budget, max_chars=64)
        normalized.append(item)
    if repository_records != 1:
        raise _invalid("a document must contain exactly one repository record")
    if snapshot_records > 1:
        raise _invalid("a document may contain at most one snapshot record")
    out["records"] = normalized
    return out


def new_document(*, repository_id: str, hash_algorithm: str, producer: dict[str, Any],
                 records: list[dict[str, Any]], generated_at: float | None = None,
                 since_snapshot: str | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = {"format": FORMAT, "version": VERSION, "producer": dict(producer),
                           "repository_id": repository_id, "hash_algorithm": hash_algorithm,
                           "records": records}
    if generated_at is not None:
        doc["generated_at"] = generated_at
    if since_snapshot is not None:
        doc["since_snapshot"] = since_snapshot
    return doc


# ---------------------------------------------------------------------- producers
@runtime_checkable
class RepositoryIntelligenceProvider(Protocol):
    """An optional deep producer of repository intelligence (e.g. Agent Dispatcher).

    ``describe()`` returns ``{"name", "version", "kind", "models"}``; ``export()``
    returns a v1 interchange document. Its output is untrusted: it is validated
    strictly and its summaries only ever become unapproved candidates. No real Agent
    Dispatcher exporter integration exists yet.
    """

    def describe(self) -> dict[str, Any]: ...

    def export(self, repository_id: str, since_snapshot: str | None) -> dict[str, Any]: ...


class SyntheticRepositoryProducer:
    """Deterministic stand-in producer FOR TESTS ONLY. It calls no model and reads no files.

    It labels its summaries with a synthetic model name so they can never be mistaken
    for real model output.
    """

    def __init__(self, *, files: Sequence[tuple[str, str]], hash_algorithm: str = "sha1",
                 summary: str = "Synthetic summary of the listed files.",
                 model: str = "synthetic-model-0", initial_commit: str | None = None) -> None:
        self.files = [(str(p), str(b)) for p, b in files]
        self.hash_algorithm = hash_algorithm
        self.summary = summary
        self.model = model
        self.initial_commit = initial_commit

    def describe(self) -> dict[str, Any]:
        return {"name": "synthetic-producer", "version": "0", "kind": "model", "models": [self.model]}

    def export(self, repository_id: str, since_snapshot: str | None) -> dict[str, Any]:
        records: list[dict[str, Any]] = [{"type": "repository", "repository_id": repository_id,
                                          "object_format": self.hash_algorithm,
                                          "initial_commit": self.initial_commit}]
        records += [{"type": "file", "path": p, "blob": b} for p, b in self.files]
        if self.files:
            records.append({"type": "summary", "text": self.summary,
                            "source_hashes": [[p, b] for p, b in self.files],
                            "producer": "synthetic-producer", "model": self.model,
                            "basis": "model_interpretation", "title": "Synthetic summary"})
        return new_document(repository_id=repository_id, hash_algorithm=self.hash_algorithm,
                            producer=self.describe(), records=records, since_snapshot=since_snapshot)
