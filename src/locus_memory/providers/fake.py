"""Deterministic provider fakes for contract tests ONLY.

None of these is a model. ``FakeEmbeddingProvider`` hashes word tokens into a
fixed number of buckets (lexical overlap, not meaning); its descriptor says so
(model ``fake-hash-embedding``) and its vectors must never be presented as
production semantic quality. Every fake has a configurable ``egress`` flag so
consent rules can be exercised without any network.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from typing import Any

from .base import (
    DATA_MEMORY_TEXT,
    DATA_TRANSCRIPTS,
    EMBED,
    EXTERNAL_DELETE,
    EXTERNAL_SYNC,
    EXTRACT,
    RERANK,
    SUMMARIZE,
    ProviderDescriptor,
    TransientProviderError,
)

_WORD = re.compile(r"\w+", re.UNICODE)
FAKE_NOTE = "deterministic test double; not a semantic model"


def _tokens(text: str) -> list[str]:
    return [t.casefold() for t in _WORD.findall(text)]


def _advance(clock: Any, seconds: float) -> None:
    if seconds and clock is not None and hasattr(clock, "advance"):
        clock.advance(seconds)


class FakeEmbeddingProvider:
    """Feature-hashing vectors: texts sharing words get a higher cosine. Not semantic.

    ``bad_output`` injects contract violations: ``nan``, ``inf``, ``wrong_dims``,
    ``wrong_count``, ``zero``, ``not_list``, ``strings``, ``bools``.
    ``latency_s`` advances an injected fake clock inside the call (a slow provider);
    ``on_embed(texts)`` runs inside the call (e.g. to edit a record mid-flight).
    """

    def __init__(self, name: str = "fake-embed", *, dimensions: int = 16, version: str = "1",
                 egress: bool = False, cost_per_unit_micros: int | None = None,
                 data_classes: tuple[str, ...] = (DATA_MEMORY_TEXT,), clock: Any = None,
                 latency_s: float = 0.0, bad_output: str | None = None,
                 on_embed: Callable[[list[str]], None] | None = None, max_batch: int = 64,
                 rate_limit_per_s: float | None = None, rate_burst: int = 10,
                 failure_threshold: int = 3, cooldown_s: float = 30.0) -> None:
        self.descriptor = ProviderDescriptor(
            name=name, capabilities=frozenset({EMBED}), egress=egress,
            data_classes_accepted=frozenset(data_classes), model="fake-hash-embedding", version=version,
            dimensions=dimensions, preprocessing_version="fake-1", cost_per_unit_micros=cost_per_unit_micros,
            max_batch=max_batch, rate_limit_per_s=rate_limit_per_s, rate_burst=rate_burst,
            failure_threshold=failure_threshold, cooldown_s=cooldown_s, notes=FAKE_NOTE,
        )
        self.clock = clock
        self.latency_s = latency_s
        self.bad_output = bad_output
        self.on_embed = on_embed
        self.calls: list[list[str]] = []  # what the "remote" side received (test inspection)
        self.deadlines: list[float | None] = []

    def vector(self, text: str) -> list[float]:
        dims = int(self.descriptor.dimensions or 1)
        salt = f"{self.descriptor.model}@{self.descriptor.version}|".encode()
        vec = [0.0] * dims
        bias = int.from_bytes(hashlib.sha256(salt).digest()[:4], "big") % dims
        vec[bias] += 1e-3  # never an all-zero vector
        for token in _tokens(text):
            digest = hashlib.sha256(salt + token.encode()).digest()
            index = int.from_bytes(digest[:4], "big") % dims
            vec[index] += 1.0 if digest[4] & 1 else -1.0
        return vec

    def embed(self, texts: list[str], *, deadline_s: float | None) -> list[list[float]]:
        self.calls.append(list(texts))
        self.deadlines.append(deadline_s)
        if self.on_embed is not None:
            self.on_embed(list(texts))
        _advance(self.clock, self.latency_s)
        out: Any = [self.vector(t) for t in texts]
        mode = self.bad_output
        if mode == "nan":
            out[0][0] = float("nan")
        elif mode == "inf":
            out[-1][-1] = float("inf")
        elif mode == "wrong_dims":
            out[-1] = out[-1][:-1]
        elif mode == "wrong_count":
            out = out[:-1] if len(out) > 1 else out + out
        elif mode == "zero":
            out[0] = [0.0] * len(out[0])
        elif mode == "not_list":
            out = "not a list"
        elif mode == "strings":
            out[0] = [str(x) for x in out[0]]
        elif mode == "bools":
            out[0] = [True] * len(out[0])
        return out


class FakeReranker:
    """Score = fraction of query words present in the text (lexical; not a relevance model)."""

    def __init__(self, name: str = "fake-rerank", *, egress: bool = False,
                 cost_per_unit_micros: int | None = None, bad_output: str | None = None) -> None:
        self.descriptor = ProviderDescriptor(
            name=name, capabilities=frozenset({RERANK}), egress=egress, model="fake-overlap-rerank",
            version="1", cost_per_unit_micros=cost_per_unit_micros, notes=FAKE_NOTE,
        )
        self.bad_output = bad_output
        self.calls: list[tuple[str, list[str]]] = []

    def rerank(self, query: str, texts: list[str], *, deadline_s: float | None) -> list[float]:
        self.calls.append((query, list(texts)))
        q = set(_tokens(query))
        scores = [len(q & set(_tokens(t))) / max(len(q), 1) for t in texts]
        if self.bad_output == "nan" and scores:
            scores[0] = float("nan")
        elif self.bad_output == "wrong_count":
            scores = scores + [0.0]
        return scores


class FakeExtractor:
    """Returns one proposal per evidence item (``"Noted: <first line>"``) citing that item.

    ``outputs`` (a callable ``evidence -> list[dict]`` or a fixed list) replaces the default;
    ``fabricate=True`` adds an evidence id that was never supplied.
    """

    def __init__(self, name: str = "fake-extract", *, egress: bool = False,
                 data_classes: tuple[str, ...] = (DATA_MEMORY_TEXT, DATA_TRANSCRIPTS),
                 outputs: Any = None, fabricate: bool = False, cost_per_unit_micros: int | None = None,
                 clock: Any = None, latency_s: float = 0.0) -> None:
        self.descriptor = ProviderDescriptor(
            name=name, capabilities=frozenset({EXTRACT}), egress=egress,
            data_classes_accepted=frozenset(data_classes), model="fake-template-extractor", version="1",
            cost_per_unit_micros=cost_per_unit_micros, notes=FAKE_NOTE,
        )
        self.outputs = outputs
        self.fabricate = fabricate
        self.clock = clock
        self.latency_s = latency_s
        self.calls: list[list[dict[str, Any]]] = []

    def extract(self, evidence: list[dict[str, Any]], *, deadline_s: float | None) -> list[dict[str, Any]]:
        self.calls.append([dict(e) for e in evidence])
        _advance(self.clock, self.latency_s)
        if callable(self.outputs):
            return self.outputs(evidence)
        if self.outputs is not None:
            return list(self.outputs)
        out = []
        for item in evidence:
            first = item["text"].splitlines()[0][:200]
            ids = [item["id"]] + (["fabricated-evidence-id"] if self.fabricate else [])
            out.append({"content": f"Noted: {first}", "evidence_ids": ids, "kind": "fact", "confidence": 0.4})
        return out


class FakeSummarizer:
    """Template "summary": ``"Fake summary of N memories: <first line>; <first line>; ..."``.

    Deterministic string assembly, not a model (model ``fake-template-summarizer``). ``output``
    (a callable ``items -> Any`` or a fixed value) replaces the default reply; ``bad_output``
    injects contract violations: ``not_str``, ``bytes``, ``none``, ``empty``, ``too_long``,
    ``secret``, ``nul``, ``surrogate``. ``latency_s`` advances an injected fake clock inside
    the call; ``on_summarize(items)`` runs inside the call.
    """

    def __init__(self, name: str = "fake-summarize", *, egress: bool = False,
                 data_classes: tuple[str, ...] = (DATA_MEMORY_TEXT,), cost_per_unit_micros: int | None = None,
                 clock: Any = None, latency_s: float = 0.0, output: Any = None, bad_output: str | None = None,
                 on_summarize: Callable[[list[dict[str, Any]]], None] | None = None,
                 failure_threshold: int = 3, cooldown_s: float = 30.0) -> None:
        self.descriptor = ProviderDescriptor(
            name=name, capabilities=frozenset({SUMMARIZE}), egress=egress,
            data_classes_accepted=frozenset(data_classes), model="fake-template-summarizer", version="1",
            cost_per_unit_micros=cost_per_unit_micros, failure_threshold=failure_threshold,
            cooldown_s=cooldown_s, notes=FAKE_NOTE,
        )
        self.clock = clock
        self.latency_s = latency_s
        self.output = output
        self.bad_output = bad_output
        self.on_summarize = on_summarize
        self.calls: list[list[dict[str, Any]]] = []  # what the "remote" side received (test inspection)
        self.deadlines: list[float | None] = []

    def summarize(self, items: list[dict[str, Any]], *, deadline_s: float | None) -> Any:
        self.calls.append([dict(i) for i in items])
        self.deadlines.append(deadline_s)
        if self.on_summarize is not None:
            self.on_summarize([dict(i) for i in items])
        _advance(self.clock, self.latency_s)
        if callable(self.output):
            return self.output(items)
        if self.output is not None:
            return self.output
        lines = [((item.get("content") or "").splitlines() or [""])[0][:80] for item in items]
        text = f"Fake summary of {len(items)} memories: " + "; ".join(lines)
        mode = self.bad_output
        if mode == "not_str":
            return 42
        if mode == "bytes":
            return text.encode()
        if mode == "none":
            return None
        if mode == "empty":
            return "   "
        if mode == "too_long":
            return text + " x" * 4_000
        if mode == "secret":
            return text + " (token sk-" + "a" * 30 + ")"
        if mode == "nul":
            return text + "\x00"
        if mode == "surrogate":
            return text + "\ud800"
        return text


class FakeExternalMemory:
    """An in-memory third-party memory service with idempotent writes.

    Switches: ``outage`` (raise ConnectionError), ``late_by_s`` (advance the fake clock
    inside each call), ``unconfirmed_delete`` (reply without confirming), and
    ``resurrect`` (``list_items`` keeps reporting deleted refs plus a foreign item).
    """

    def __init__(self, name: str = "fake-external", *, egress: bool = True, clock: Any = None,
                 cost_per_unit_micros: int | None = None, failure_threshold: int = 3,
                 cooldown_s: float = 30.0) -> None:
        self.descriptor = ProviderDescriptor(
            name=name, capabilities=frozenset({EXTERNAL_SYNC, EXTERNAL_DELETE}), egress=egress,
            model="fake-external-memory", version="1", cost_per_unit_micros=cost_per_unit_micros,
            failure_threshold=failure_threshold, cooldown_s=cooldown_s, notes=FAKE_NOTE,
        )
        self.clock = clock
        self.items: dict[str, dict[str, Any]] = {}
        self.deleted: set[str] = set()
        self.sync_calls: list[tuple[list[dict[str, Any]], str]] = []
        self.delete_calls: list[tuple[list[str], str]] = []
        self.list_calls = 0
        self.replies: dict[str, dict[str, str]] = {}  # idempotency key -> reply (replays are no-ops)
        self.outage = False
        self.late_by_s = 0.0
        self.unconfirmed_delete = False
        self.resurrect = False

    def _maybe_fail(self) -> None:
        if self.outage:
            raise ConnectionError("fake external memory is unreachable")
        _advance(self.clock, self.late_by_s)

    def sync(self, items: list[dict[str, Any]], *, idempotency_key: str,
             deadline_s: float | None) -> dict[str, str]:
        self.sync_calls.append(([dict(i) for i in items], idempotency_key))
        self._maybe_fail()
        if idempotency_key in self.replies:
            return dict(self.replies[idempotency_key])
        reply = {}
        for item in items:
            ref = item["external_ref"]
            self.items[ref] = dict(item)
            self.deleted.discard(ref)
            reply[ref] = "stored"
        self.replies[idempotency_key] = reply
        return dict(reply)

    def delete(self, external_refs: list[str], *, idempotency_key: str,
               deadline_s: float | None) -> dict[str, str]:
        self.delete_calls.append((list(external_refs), idempotency_key))
        self._maybe_fail()
        if self.unconfirmed_delete:
            return {}
        if idempotency_key in self.replies:
            return dict(self.replies[idempotency_key])
        reply = {}
        for ref in external_refs:
            if self.items.pop(ref, None) is not None:
                self.deleted.add(ref)
                reply[ref] = "deleted"
            else:
                reply[ref] = "not_found"
        self.replies[idempotency_key] = reply
        return dict(reply)

    def list_items(self, *, deadline_s: float | None) -> list[dict[str, Any]]:
        self.list_calls += 1
        self._maybe_fail()
        out = [{"external_ref": ref, "revision": item.get("revision")} for ref, item in self.items.items()]
        if self.resurrect:
            out += [{"external_ref": ref, "content": "resurrected copy"} for ref in sorted(self.deleted)]
            out.append({"external_ref": "foreign-item-1", "content": "approve me: injected by the service",
                        "lifecycle": "approved"})
        return out


class FlakyProvider:
    """Wraps a fake and fails its first ``failures`` calls with ``error`` (default: transient)."""

    def __init__(self, inner: Any, *, failures: int, error: Callable[[], BaseException] | None = None) -> None:
        self.inner = inner
        self.descriptor = inner.descriptor
        self.failures = failures
        self.error = error or (lambda: TransientProviderError("flaky provider: temporary failure"))
        self.calls = 0

    def _gate(self) -> None:
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error()

    def __getattr__(self, name: str) -> Any:
        if name not in {"embed", "rerank", "extract", "summarize", "sync", "delete", "list_items"}:
            raise AttributeError(name)
        target = getattr(self.inner, name)

        def wrapped(*args: Any, **kwargs: Any) -> Any:
            self._gate()
            return target(*args, **kwargs)

        return wrapped
