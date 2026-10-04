from __future__ import annotations

from typing import Any

from ..services import PartitionContext


class HistoryArchive:
    """STUB - to be implemented."""

    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx

    def session_visible(self, conn, access, ref):
        return None

    def message_source_visible(self, conn, access, token):
        return None

    def source_tokens_for_session(self, conn, token):
        return []

    def verify_source(self, conn, access, source):
        return None

    def purge(self, conn, kind, token, policy):
        return {}

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(f"HistoryArchive.{name} is not implemented yet")
