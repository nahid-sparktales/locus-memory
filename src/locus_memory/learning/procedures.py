from __future__ import annotations

from typing import Any

from ..services import PartitionContext


class ProcedureService:
    """STUB - to be implemented."""

    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(f"ProcedureService.{name} is not implemented yet")
