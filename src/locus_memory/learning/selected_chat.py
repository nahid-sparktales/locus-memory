"""Review host-selected conversation evidence into unapproved memory candidates.

The host must remove prompt decoration, attachments and injected context before
calling this module. Only user messages are considered. This deterministic review
does not invoke a model, read sessions, grant scopes, or approve its suggestions.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, Protocol

from ..errors import MemoryEngineError

_CUES = re.compile(
    r"\b(?:remember|always|never|prefer|preference|decided|decision|"
    r"do not|don't|must|should use|confirmed|that worked|fixed|resolved)\b", re.IGNORECASE,
)
_SECRET = re.compile(r"(?i)(?:api[_-]?key|authorization|password|secret|bearer\s+[A-Za-z0-9])")


class ReviewVault(Protocol):
    """Legacy-shaped public API shared by the compatibility and canonical stores."""

    def list(self, *, workspace: str, agent_id: str) -> list[dict[str, Any]]: ...

    def save(self, value: dict[str, Any], *, workspace: str, agent_id: str,
             default_status: str) -> dict[str, Any]: ...

    def record_event(self, stage: str, outcome: str, **context: Any) -> Any: ...


def _normalized(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def review_selected_chat(
    vault: ReviewVault, messages: Iterable[Mapping[str, Any]], *, workspace: str,
    agent_id: str, session_id: str, run_id: str,
) -> list[dict[str, Any]]:
    """Save up to twenty review-only suggestions, preserving their source bindings.

    Validation failures isolate a single suggestion. Deduplication includes saved
    candidates and approved memories and is updated only after a successful save.
    Diagnostics contain identifiers and outcomes, never conversation content.
    """
    candidates: list[dict[str, Any]] = []
    existing_content = {
        _normalized(item.get("content")) for item in vault.list(workspace=workspace, agent_id=agent_id)
    }
    event_context = {
        "workspace": workspace, "agent_id": agent_id, "session_id": session_id, "run_id": run_id,
    }
    for message in messages:
        if message.get("role") != "user":
            continue
        text = str(message.get("content") or "").strip()
        if not text or len(text) > 4_000 or not _CUES.search(text) or _SECRET.search(text):
            continue
        content = re.sub(r"\s+", " ", text)[:2_000]
        normalized = content.casefold()
        if normalized in existing_content:
            vault.record_event("proposal", "deduplicated", reason_code="existing_memory", **event_context)
            continue
        try:
            candidate = vault.save(
                {
                    "title": "From selected chat", "content": content,
                    "reason": "Explicit durable wording found during selected-chat review.",
                    "scope": "workspace", "status": "candidate", "kind": "preference", "confidence": 0.8,
                    "source_session_id": session_id, "source_run_id": run_id,
                },
                workspace=workspace, agent_id=agent_id, default_status="candidate",
            )
        except MemoryEngineError:
            continue
        vault.record_event("proposal", "accepted", memory_id=candidate["id"], **event_context)
        candidates.append(candidate)
        existing_content.add(normalized)
        if len(candidates) >= 20:
            break
    return candidates
