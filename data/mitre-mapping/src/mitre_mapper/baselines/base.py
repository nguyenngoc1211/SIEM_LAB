"""Shared contracts for the offline baseline strategies."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..database import read_json


STRATEGY_SCHEMA_VERSION = "1.0.0"


@dataclass
class StrategyResult:
    """A mapping result that mirrors the production mapper output contract."""

    strategy: str
    scenario_id: str | None
    mapping_status: str
    primary_mapping: dict[str, Any] | None
    alternative_candidates: list[dict[str, Any]] = field(default_factory=list)
    candidate_trace: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": STRATEGY_SCHEMA_VERSION,
            "strategy": self.strategy,
            "scenario_id": self.scenario_id,
            "mapping_status": self.mapping_status,
            "primary_mapping": self.primary_mapping,
            "alternative_candidates": self.alternative_candidates,
            "candidate_trace": self.candidate_trace,
            "latency_ms": self.latency_ms,
            "details": self.details,
        }


class MappingStrategy(Protocol):
    name: str
    version: str

    def map_alert(
        self, alert: dict[str, Any], scenario_id: str | None = None,
    ) -> StrategyResult:
        ...


def load_catalog(database_path: Path) -> list[dict[str, Any]]:
    """Load the supported ATT&CK subset used by both baselines."""

    records = read_json(database_path)
    catalog: list[dict[str, Any]] = []
    for item in records:
        tactics = [
            value.get("tactic_id") or value.get("name")
            for value in item.get("tactics", [])
            if isinstance(value, dict)
        ]
        catalog.append({
            "technique_id": item["technique_id"],
            "name": item.get("name", ""),
            "tactics": [value for value in tactics if value],
            "parent_id": (item.get("parent_technique") or {}).get("technique_id"),
            "behavioral_indicators": [
                str(value) for value in item.get("behavioral_indicators", [])[:6] if value
            ],
            "retrieval_keywords": [
                str(value) for value in item.get("retrieval_keywords", [])[:10] if value
            ],
            "retrieval_text": str(item.get("retrieval_text") or "").strip(),
            "description": " ".join(str(item.get("description") or "").split())[:400],
        })
    return catalog


def load_parent_map(database_path: Path) -> dict[str, str]:
    """Map each sub-technique to its parent technique id."""

    records = read_json(database_path)
    parents: dict[str, str] = {}
    for item in records:
        parent = (item.get("parent_technique") or {}).get("technique_id")
        if parent:
            parents[str(item["technique_id"])] = str(parent)
    return parents


def clamp_confidence(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    return round(max(0.0, min(1.0, number)), 6)


def alternative_from_ranking(
    ranking: list[dict[str, Any]], skip: str | None,
) -> list[dict[str, Any]]:
    alternatives: list[dict[str, Any]] = []
    for item in ranking:
        if item.get("technique_id") == skip:
            continue
        reason = item.get("reason") or "Lower ranked candidate."
        alternatives.append({
            "technique_id": item["technique_id"],
            "name": item.get("name", item["technique_id"]),
            "confidence": item.get("confidence", item.get("score_normalized", 0.0)),
            "rejection_reason": reason,
        })
    return alternatives
