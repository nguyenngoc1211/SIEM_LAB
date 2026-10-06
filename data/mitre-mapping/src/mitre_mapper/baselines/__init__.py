"""Offline baseline strategies for comparing MITRE ATT&CK mapping quality.

This package is intentionally self-contained. It reuses read-only helpers from
``mitre_mapper`` but does not modify the production mapper, API, or n8n
workflow. The two active baselines are:

* :class:`~mitre_mapper.baselines.bm25_only.BM25OnlyStrategy` (B1)
* :class:`~mitre_mapper.baselines.deepseek_only.DeepSeekOnlyStrategy` (B2)

``GeminiOnlyStrategy`` is kept only so the archived Gemini 2.5 Flash
experiment can still be reproduced; it is no longer the default B2 arm.
"""

from .base import STRATEGY_SCHEMA_VERSION, MappingStrategy, StrategyResult
from .bm25_only import BM25OnlyStrategy
from .deepseek_only import DeepSeekOnlyStrategy
from .gemini_only import GeminiOnlyStrategy

__all__ = [
    "BM25OnlyStrategy",
    "DeepSeekOnlyStrategy",
    "GeminiOnlyStrategy",
    "MappingStrategy",
    "STRATEGY_SCHEMA_VERSION",
    "StrategyResult",
]
