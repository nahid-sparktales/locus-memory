"""In-process, content-free metrics and redacted logging.

Metrics carry an explicit kind: ``measured`` (timed/counted here), ``estimated``
(derived, e.g. token estimates) or ``unavailable``. Nothing here records memory
content, queries, paths or identifiers beyond opaque ids.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("locus_memory")
logger.addHandler(logging.NullHandler())


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._timings: dict[str, list[float]] = defaultdict(list)
        self._gauges: dict[str, tuple[float, str]] = {}

    def incr(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] += value

    def observe_ms(self, stage: str, ms: float) -> None:
        with self._lock:
            bucket = self._timings[stage]
            bucket.append(ms)
            if len(bucket) > 1_000:
                del bucket[: len(bucket) - 1_000]

    def gauge(self, name: str, value: float, kind: str = "measured") -> None:
        if kind not in {"measured", "estimated", "unavailable"}:
            raise ValueError("gauge kind must be measured, estimated, or unavailable")
        with self._lock:
            self._gauges[name] = (value, kind)

    @contextmanager
    def timer(self, stage: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe_ms(stage, (time.perf_counter() - start) * 1000)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            timings = {}
            for stage, values in self._timings.items():
                ordered = sorted(values)
                timings[stage] = {
                    "kind": "measured", "count": len(ordered),
                    "p50_ms": round(ordered[len(ordered) // 2], 3),
                    "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
                    "max_ms": round(ordered[-1], 3),
                } if ordered else {"kind": "unavailable"}
            return {
                "counters": {k: {"kind": "measured", "value": v} for k, v in self._counters.items()},
                "timings": timings,
                "gauges": {k: {"kind": kind, "value": v} for k, (v, kind) in self._gauges.items()},
            }
