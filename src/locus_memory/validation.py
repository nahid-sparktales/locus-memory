"""Bounded input validation shared by every public entry point."""
from __future__ import annotations

import math
import re
import unicodedata
from typing import Any

from .errors import ValidationError

# Opaque identifiers: compatible with Locus MemoryVault ids ([A-Za-z0-9_-]{1,128}).
ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}")
# Host references (session ids, task ids, commit ids, ...) may carry a few more
# separators but never whitespace, control characters or path traversal.
REF_PATTERN = re.compile(r"[A-Za-z0-9_.:@/+=-]{1,256}")

MAX_CONTENT_CHARS = 32_000  # same bound as Locus MemoryVault
MAX_TITLE_CHARS = 160
MAX_TAGS = 24
MAX_TAG_CHARS = 40
MAX_REASON_CHARS = 2_000
MAX_QUERY_CHARS = 2_000
MAX_MESSAGE_CHARS = 200_000
MAX_SOURCES = 64
MAX_LIST = 256
# Nesting bound for host/agent-supplied JSON mappings (locators, applicability, host_refs,
# attachments, environment, usage). Real values are a few levels deep.
MAX_MAPPING_DEPTH = 32
MIN_TIMESTAMP = 0.0
MAX_TIMESTAMP = 32_503_680_000.0  # year 3000


def check_id(value: Any, field: str = "id") -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise ValidationError(f"{field} must match [A-Za-z0-9_-]{{1,128}}")
    return value


def check_ref(value: Any, field: str = "reference") -> str:
    if not isinstance(value, str) or not REF_PATTERN.fullmatch(value) or ".." in value:
        raise ValidationError(f"{field} is not a valid opaque reference")
    return value


def check_text(value: Any, field: str, *, max_chars: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text")
    text = value.strip()
    if not text and not allow_empty:
        raise ValidationError(f"{field} cannot be empty")
    if len(text) > max_chars:
        raise ValidationError(f"{field} exceeds {max_chars} characters")
    if "\x00" in text:
        raise ValidationError(f"{field} contains a NUL character")
    return text


def check_label(value: Any, field: str, *, max_chars: int = 128) -> str:
    text = check_text(value, field, max_chars=max_chars)
    if any(unicodedata.category(ch).startswith("C") for ch in text):
        raise ValidationError(f"{field} contains control characters")
    return text


def check_tags(values: Any) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, (list, tuple, set, frozenset)):
        raise ValidationError("tags must be a list")
    tags = sorted({
        str(item).strip().lower()[:MAX_TAG_CHARS] for item in values if str(item).strip()
    })
    if len(tags) > MAX_TAGS:
        raise ValidationError(f"at most {MAX_TAGS} tags are allowed")
    return tuple(tags)


def check_timestamp(value: Any, field: str, *, optional: bool = True) -> float | None:
    if value is None or value == "":
        if optional:
            return None
        raise ValidationError(f"{field} is required")
    if isinstance(value, bool):
        raise ValidationError(f"{field} must be a Unix timestamp")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field} must be a Unix timestamp") from exc
    if not math.isfinite(number) or not (MIN_TIMESTAMP <= number <= MAX_TIMESTAMP):
        raise ValidationError(f"{field} is outside the supported time range")
    return number


def check_finite(value: Any, field: str, *, lo: float | None = None, hi: float | None = None) -> float:
    if isinstance(value, bool):
        raise ValidationError(f"{field} must be a number")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field} must be a number") from exc
    if not math.isfinite(number):
        raise ValidationError(f"{field} must be finite")
    if lo is not None and number < lo or hi is not None and number > hi:
        raise ValidationError(f"{field} is out of range")
    return number


def check_int(value: Any, field: str, *, lo: int = 0, hi: int = 2**62) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < lo or value > hi:
        raise ValidationError(f"{field} is out of range")
    return value


def check_depth(value: Any, field: str, *, max_depth: int = MAX_MAPPING_DEPTH) -> None:
    """Refuse containers (dicts, lists, tuples) nested deeper than ``max_depth`` levels.

    Iterative, so arbitrarily deep input is rejected with a ValidationError instead of
    exhausting the interpreter stack (json, ``models.to_jsonable`` and the redaction walkers
    recurse once per level; a deep value accepted here would fail in every later reader).
    The value itself counts as level 1; scalars do not add a level.
    """
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            children: Any = item.values()
        elif isinstance(item, (list, tuple)):
            children = item
        else:
            continue
        if depth > max_depth:
            raise ValidationError(f"{field} is nested too deeply (at most {max_depth} levels)")
        stack.extend((child, depth + 1) for child in children
                     if isinstance(child, (dict, list, tuple)))


def check_mapping(value: Any, field: str, *, max_keys: int = 64, max_bytes: int = 16_000) -> dict:
    """Validate a small JSON-compatible mapping (provenance locators, applicability...).

    Bounded in keys, encoded size and nesting depth (``MAX_MAPPING_DEPTH``); never lets a
    ``RecursionError`` escape (it is a ValidationError on every interpreter).
    """
    import json

    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError(f"{field} must be an object")
    if len(value) > max_keys:
        raise ValidationError(f"{field} has too many keys")
    check_depth(value, field)
    try:
        encoded = json.dumps(value, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValidationError(f"{field} must be JSON-compatible and finite") from exc
    if len(encoded.encode()) > max_bytes:
        raise ValidationError(f"{field} is too large")
    try:
        return json.loads(encoded)
    except (ValueError, RecursionError) as exc:  # pragma: no cover - bounded above
        raise ValidationError(f"{field} must be JSON-compatible and finite") from exc


def normalize_for_fingerprint(text: str) -> str:
    """Normalization used for duplicate detection and source-linked suppression."""
    folded = unicodedata.normalize("NFKC", text).casefold()
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", folded)).strip()
