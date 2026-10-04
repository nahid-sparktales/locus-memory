"""locus_memory: local-first, encrypted, scope-enforcing memory engine.

Importing this package has no side effects: no directories are scanned, no
databases opened, no network used. Construct :class:`MemoryEngine` explicitly.
"""
from __future__ import annotations

from .crypto import FileKeyProvider, KeyProvider, StaticKeyProvider
from .engine import EXPORT_FORMAT, EXPORT_VERSION, MemoryEngine
from .errors import *  # noqa: F401,F403 - typed public errors
from .host import CancellationToken, EngineConfig, HostCapabilities
from .models import *  # noqa: F401,F403 - public models

__version__ = "0.2.1"

__all__ = [
    "MemoryEngine", "KeyProvider", "StaticKeyProvider", "FileKeyProvider",
    "HostCapabilities", "EngineConfig", "CancellationToken", "EXPORT_FORMAT", "EXPORT_VERSION",
    "__version__",
]
