"""Compose a continuity snapshot from evidence explicitly collected by a host.

No filesystem, model, session or run-store discovery occurs in this module.
The encrypted store applies the persisted field bounds when saving the payload.
"""
from __future__ import annotations

from typing import Any


def snapshot_payload(
    *, goal: Any = "", outcome: Any = "", mode: Any = "work",
    plan: dict[str, Any] | None = None, todos: list[dict[str, Any]] | None = None,
    checkpoint: dict[str, Any] | None = None, changed_files: list[str] | None = None,
    pending: Any = "",
) -> dict[str, Any]:
    active_todos = todos if todos is not None else []
    pending_text = str(pending or "").strip()
    if not pending_text:
        pending_text = "; ".join(
            str(item.get("content") or "") for item in active_todos
            if isinstance(item, dict) and item.get("status") != "completed" and item.get("content")
        )
    return {
        "goal": goal, "outcome": outcome, "mode": mode, "plan": plan,
        "todos": active_todos, "checkpoint": checkpoint,
        "changed_files": changed_files if changed_files is not None else [],
        "pending": pending_text,
    }
