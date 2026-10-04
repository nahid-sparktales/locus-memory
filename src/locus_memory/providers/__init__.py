"""Optional providers (embeddings, reranking, extraction, external memory services).

Nothing is enabled by default: hosts register provider objects in
``HostCapabilities.providers`` and, for egress providers, a consent policy in
``HostCapabilities.consent``. See :mod:`locus_memory.providers.base`.
"""
from __future__ import annotations

from .base import (
    CAPABILITIES,
    DATA_CLASSES,
    DATA_MEMORY_TEXT,
    DATA_REPOSITORY_SOURCE,
    DATA_TRANSCRIPTS,
    EMBED,
    EXTERNAL_DELETE,
    EXTERNAL_SYNC,
    EXTRACT,
    RERANK,
    CircuitOpen,
    ConsentGrant,
    ConsentPolicy,
    EmbeddingProvider,
    ExternalMemoryService,
    Extractor,
    ProviderDescriptor,
    ProviderRateLimited,
    Reranker,
    StaticConsentPolicy,
    TransientProviderError,
)

__all__ = [
    "CAPABILITIES", "DATA_CLASSES", "DATA_MEMORY_TEXT", "DATA_REPOSITORY_SOURCE", "DATA_TRANSCRIPTS",
    "EMBED", "EXTERNAL_DELETE", "EXTERNAL_SYNC", "EXTRACT", "RERANK", "CircuitOpen", "ConsentGrant",
    "ConsentPolicy", "EmbeddingProvider", "ExternalMemoryService", "Extractor", "ProviderDescriptor",
    "ProviderRateLimited", "Reranker", "StaticConsentPolicy", "TransientProviderError",
]
