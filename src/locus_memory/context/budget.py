"""Token accounting for hot-context compilation.

* When the host supplies a tokenizer (``HostCapabilities.token_counter``) counts
  are labelled ``MEASURED``. Otherwise the conservative estimate
  ``ceil(len(text) / estimate_chars_per_token * estimate_margin)`` is used and
  labelled ``ESTIMATED`` - it is never presented as a measurement.
* Tokenizers are not additive across concatenation, so per-item counts are only
  used to *plan* a selection; the compiler re-counts the final rendered text as a
  whole and trims until it fits (see ``compiler.ContextCompiler``).
* Slice ``max_tokens`` values are caps, not fill targets. All slices draw from one
  shared total (the host-owned allowance minus the wrapper overhead).
"""
from __future__ import annotations

import math
from collections.abc import Iterable

from ..errors import ValidationError
from ..host import TokenCounter
from ..models import MeasureKind

BUDGET = "budget"
SLICE_CAP = "slice_cap"


class CounterFailure(Exception):
    """The host tokenizer raised or returned something that is not a token count."""


def estimate_tokens(text: str, chars_per_token: float, margin: float) -> int:
    """Conservative token estimate (heuristic, labelled ESTIMATED by callers)."""
    if not text:
        return 0
    return math.ceil(len(text) * margin / chars_per_token)


class TokenMeter:
    """Counts tokens with the host tokenizer when available, else a labelled estimate."""

    def __init__(self, counter: TokenCounter | None, *, chars_per_token: float, margin: float) -> None:
        if isinstance(chars_per_token, bool) or not isinstance(chars_per_token, (int, float)) \
                or not math.isfinite(chars_per_token) or chars_per_token <= 0:
            raise ValidationError("estimate_chars_per_token must be a positive number")
        if isinstance(margin, bool) or not isinstance(margin, (int, float)) or not math.isfinite(margin):
            raise ValidationError("estimate_margin must be a finite number")
        self._counter = counter
        self.chars_per_token = float(chars_per_token)
        # A margin below 1 would make the estimate optimistic; never allow that.
        self.margin = max(float(margin), 1.0)

    @property
    def kind(self) -> MeasureKind:
        return MeasureKind.MEASURED if self._counter is not None else MeasureKind.ESTIMATED

    @property
    def measured(self) -> bool:
        return self._counter is not None

    def count(self, text: str) -> int:
        if not text:
            return 0
        if self._counter is None:
            return estimate_tokens(text, self.chars_per_token, self.margin)
        try:
            value = self._counter(text)
        except Exception as exc:  # host code: any failure means "no trustworthy count"
            raise CounterFailure("the host token counter failed") from exc
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CounterFailure("the host token counter returned an invalid count")
        return value

    def estimator(self) -> TokenMeter:
        """The same meter without the host tokenizer (fallback after a counter failure)."""
        return TokenMeter(None, chars_per_token=self.chars_per_token, margin=self.margin)


class Budget:
    """One shared total for all slices plus a cap per slice.

    ``remaining`` starts at ``allowance - overhead`` (the wrapper is paid for first)
    and may be negative when the allowance cannot even hold the wrapper, in which
    case nothing fits.
    """

    def __init__(self, allowance: int, overhead: int, caps: dict[str, int]) -> None:
        self.allowance = int(allowance)
        self.overhead = int(overhead)
        self.remaining = self.allowance - self.overhead
        self.caps = dict(caps)
        self.used: dict[str, int] = {name: 0 for name in caps}

    def refusal(self, slice_name: str, tokens: int) -> str | None:
        """Why ``tokens`` more cannot be taken for ``slice_name`` (None = it fits).

        The shared total is checked first: an item larger than everything left is a
        ``budget`` omission even if it is also larger than its slice cap.
        """
        if tokens > self.remaining:
            return BUDGET
        if self.used[slice_name] + tokens > self.caps[slice_name]:
            return SLICE_CAP
        return None

    def take(self, slice_name: str, tokens: int) -> None:
        self.remaining -= tokens
        self.used[slice_name] += tokens

    def release(self, slice_name: str, tokens: int) -> None:
        self.remaining += tokens
        self.used[slice_name] -= tokens

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0

    def slice_usage(self, names: Iterable[str]) -> list[dict[str, int | str]]:
        return [{"name": name, "max_tokens": self.caps[name], "used_tokens": self.used[name]}
                for name in names]
