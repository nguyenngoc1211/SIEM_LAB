"""Baseline B1: rank supported techniques with BM25 only."""

from __future__ import annotations

import math
import time
from pathlib import Path
from typing import Any

from ..database import build_query_vector, read_json, read_jsonl, tokenize
from ..normalization import build_retrieval_text
from .base import StrategyResult, load_catalog


class BM25OnlyStrategy:
    """Pure lexical baseline over the existing BM25 artifact.

    No Qdrant, embedding, reranker, evidence rule, fallback, or confusion guard
    is used. The score is the sparse dot product between the alert query
    vector and each technique's stored BM25 vector, which reproduces the
    sparse branch of the production hybrid retriever exactly.
    """

    name = "bm25_only"
    version = "1.0.0"

    def __init__(
        self,
        project_root: Path,
        *,
        variant: str = "threshold",
        min_score: float = 0.0,
        margin_ratio: float = 0.10,
        top_k: int = 5,
        trace_limit: int = 20,
    ) -> None:
        if variant not in {"top1", "threshold"}:
            raise ValueError("variant must be 'top1' or 'threshold'")
        self.project_root = Path(project_root)
        self.variant = variant
        self.min_score = float(min_score)
        self.margin_ratio = float(margin_ratio)
        self.top_k = int(top_k)
        self.trace_limit = int(trace_limit)
        self.documents = read_jsonl(self.project_root / "artifacts" / "retrieval" / "technique_documents.jsonl")
        self.by_id = {document["technique_id"]: document for document in self.documents}
        self.bm25 = read_json(self.project_root / "artifacts" / "retrieval" / "bm25_index.json")
        self.catalog = load_catalog(self.project_root / "artifacts" / "attack" / "attack_final.mapping.json")
        self.name_by_id = {item["technique_id"]: item["name"] for item in self.catalog}

    def query_text(self, alert: dict[str, Any]) -> str:
        derived = alert.get("derived") if isinstance(alert.get("derived"), dict) else {}
        text = derived.get("retrieval_text")
        if isinstance(text, str) and text.strip():
            return text
        return build_retrieval_text(alert)

    def rank(self, text: str) -> list[dict[str, Any]]:
        query_vector = build_query_vector(text, self.bm25)
        query_weights = dict(zip(query_vector["indices"], query_vector["values"]))
        query_terms = set(tokenize(text))
        rows: list[dict[str, Any]] = []
        for technique_id, vector in self.bm25["document_vectors"].items():
            raw = sum(
                value * query_weights.get(index, 0.0)
                for index, value in zip(vector["indices"], vector["values"])
            )
            document = self.by_id.get(technique_id, {})
            matched = sorted(query_terms & set(tokenize(document.get("sparse_text", ""))))[:12]
            rows.append({
                "technique_id": technique_id,
                "name": self.name_by_id.get(technique_id, document.get("name", technique_id)),
                "score_raw": round(raw, 6),
                "matched_terms": matched,
            })
        rows.sort(key=lambda item: (-item["score_raw"], item["technique_id"]))

        high = rows[0]["score_raw"] if rows else 0.0
        low = rows[-1]["score_raw"] if rows else 0.0
        for row in rows:
            if high <= 0.0:
                row["score_normalized"] = 0.0
            elif math.isclose(low, high):
                row["score_normalized"] = 1.0
            else:
                row["score_normalized"] = round((row["score_raw"] - low) / (high - low), 6)
        for rank, row in enumerate(rows, 1):
            row["rank"] = rank
        return rows

    def map_alert(
        self, alert: dict[str, Any], scenario_id: str | None = None,
    ) -> StrategyResult:
        started = time.perf_counter()
        text = self.query_text(alert)
        ranking = self.rank(text)
        status, primary, margin = self._decide(ranking)
        alternatives = self._alternatives(ranking, primary)
        trace = [
            {
                "technique_id": row["technique_id"],
                "name": row["name"],
                "rank": row["rank"],
                "score_raw": row["score_raw"],
                "score_normalized": row["score_normalized"],
                "matched_terms": row["matched_terms"],
            }
            for row in ranking[: self.trace_limit]
        ]
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        return StrategyResult(
            strategy=self.name,
            scenario_id=scenario_id,
            mapping_status=status,
            primary_mapping=primary,
            alternative_candidates=alternatives,
            candidate_trace=trace,
            latency_ms=elapsed_ms,
            details={
                "strategy_version": self.version,
                "variant": self.variant,
                "min_score": self.min_score,
                "margin_ratio": self.margin_ratio,
                "top1_margin_ratio": margin,
                "query_length": len(text),
                "candidate_count": len(ranking),
                "confidence_source": "per_query_minmax_bm25",
                "retrieval_source": "artifacts/retrieval/bm25_index.json",
                "document_source": "artifacts/retrieval/technique_documents.jsonl",
            },
        )

    def _decide(
        self, ranking: list[dict[str, Any]],
    ) -> tuple[str, dict[str, Any] | None, float]:
        if not ranking or ranking[0]["score_raw"] <= 0.0:
            return "insufficient_evidence", None, 0.0
        top = ranking[0]
        top1 = {
            "technique_id": top["technique_id"],
            "name": top["name"],
            "confidence": top["score_normalized"],
        }
        if self.variant == "top1":
            return "mapped", top1, 1.0
        first = float(top["score_raw"])
        second = float(ranking[1]["score_raw"]) if len(ranking) > 1 else 0.0
        margin = (first - second) / first if first > 0 else 0.0
        if first <= self.min_score:
            return "insufficient_evidence", None, round(margin, 6)
        if margin < self.margin_ratio:
            return "uncertain", top1, round(margin, 6)
        return "mapped", top1, round(margin, 6)

    def _alternatives(
        self, ranking: list[dict[str, Any]], primary: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        primary_id = primary["technique_id"] if primary else None
        alternatives: list[dict[str, Any]] = []
        for row in ranking:
            if row["technique_id"] == primary_id:
                continue
            if len(alternatives) >= self.top_k:
                break
            alternatives.append({
                "technique_id": row["technique_id"],
                "name": row["name"],
                "confidence": row["score_normalized"],
                "rejection_reason": (
                    "Lower BM25 score than the selected technique."
                    if primary_id else "No BM25 term overlapped with the alert query."
                ),
            })
        return alternatives
