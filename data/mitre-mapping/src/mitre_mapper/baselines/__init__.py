"""Offline baseline strategies for comparing MITRE ATT&CK mapping quality.

This package is intentionally self-contained. It reuses read-only helpers from
``mitre_mapper`` but does not modify the production mapper, API, or n8n
workflow. Two baselines are provided:

* :class:`~mitre_mapper.baselines.bm25_only.BM25OnlyStrategy`
* :class:`~mitre_mapper.baselines.gemini_only.GeminiOnlyStrategy`
"""

from .base import STRATEGY_SCHEMA_VERSION, MappingStrategy, StrategyResult
from .bm25_only import BM25OnlyStrategy
from .gemini_only import GeminiOnlyStrategy

__all__ = [
    "BM25OnlyStrategy",
    "GeminiOnlyStrategy",
    "MappingStrategy",
    "STRATEGY_SCHEMA_VERSION",
    "StrategyResult",
]
