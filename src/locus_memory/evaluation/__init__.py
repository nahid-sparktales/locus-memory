"""Offline, chronological evaluation of cumulative memory usefulness on a synthetic corpus.

Importing this package does nothing; :func:`run_benchmark` runs the arms (see
:mod:`.arms`) over seeded corpora (:mod:`.corpus`) and writes a manifest, per-question
rows and a markdown report. No network, no model, no real user data.
"""
from __future__ import annotations

from .corpus import generate_corpus
from .runner import ChronologyViolation, run_benchmark

__all__ = ["run_benchmark", "generate_corpus", "ChronologyViolation"]
