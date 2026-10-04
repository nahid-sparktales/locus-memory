"""Portable automatic-memory policy used by hosts and their saved agent settings.

The host still decides when a turn permits memory and supplies trusted scopes.
This policy owns the shared defaults, input limits and chat-only scope boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

VALID_MEMORY_SCOPES = frozenset({"personal", "workspace", "agent"})


def _bounded_int(value: Any, default: int, upper: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        number = default
    return min(max(number, 0), upper)


@dataclass(frozen=True)
class MemoryPolicy:
    recall_enabled: bool = True
    proposals_enabled: bool = True
    search_enabled: bool = True
    scopes: tuple[str, ...] = ("personal", "workspace", "agent")
    max_automatic_memories: int = 8
    max_automatic_tokens: int = 1_200
    cross_chat_context_enabled: bool = True
    max_automatic_context_snapshots: int = 2
    max_automatic_context_tokens: int = 1_200

    @classmethod
    def parse(cls, value: Any) -> MemoryPolicy:
        raw = value if isinstance(value, dict) else {}
        supplied_scopes = raw.get("scopes")
        if not isinstance(supplied_scopes, list):
            supplied_scopes = ["personal", "workspace", "agent"]
        scopes = tuple(dict.fromkeys(
            str(item).lower() for item in supplied_scopes
            if str(item).lower() in VALID_MEMORY_SCOPES
        ))
        return cls(
            recall_enabled=bool(raw.get("recall_enabled", True)),
            proposals_enabled=bool(raw.get("proposals_enabled", True)),
            search_enabled=bool(raw.get("search_enabled", True)),
            scopes=scopes,
            max_automatic_memories=_bounded_int(raw.get("max_automatic_memories"), 8, 20),
            max_automatic_tokens=_bounded_int(raw.get("max_automatic_tokens"), 1_200, 4_000),
            cross_chat_context_enabled=bool(raw.get("cross_chat_context_enabled", True)),
            max_automatic_context_snapshots=_bounded_int(
                raw.get("max_automatic_context_snapshots"), 2, 10,
            ),
            max_automatic_context_tokens=_bounded_int(
                raw.get("max_automatic_context_tokens"), 1_200, 4_000,
            ),
        )

    def recall_scopes(self, *, just_chat: bool = False) -> tuple[str, ...]:
        return tuple(scope for scope in self.scopes if not (just_chat and scope == "workspace"))

    @property
    def automatic_recall_enabled(self) -> bool:
        return bool(self.recall_enabled and self.max_automatic_memories and self.max_automatic_tokens)

    def automatic_continuity_enabled(self, *, just_chat: bool = False) -> bool:
        return bool(not just_chat and self.cross_chat_context_enabled
                    and self.max_automatic_context_snapshots and self.max_automatic_context_tokens)

    def bound_legacy_context(self, text: str) -> str:
        """Preserve the legacy four-character estimate until its recall path is retired."""
        return text[:max(0, self.max_automatic_tokens) * 4]
