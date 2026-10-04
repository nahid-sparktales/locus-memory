"""Hot-context compilation (see ``compiler.py``) and public markers of a rendered block."""
from .markers import (
    CONTEXT_PREAMBLE,
    CONTEXT_WRAPPER_CLOSE,
    CONTEXT_WRAPPER_OPEN,
    contains_context_block,
    is_context_block,
)

__all__ = ["CONTEXT_PREAMBLE", "CONTEXT_WRAPPER_CLOSE", "CONTEXT_WRAPPER_OPEN", "contains_context_block",
           "is_context_block"]
