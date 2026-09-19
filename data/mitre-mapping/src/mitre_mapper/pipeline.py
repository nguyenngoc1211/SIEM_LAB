from __future__ import annotations

import time
from typing import Any

from .clients import CrossEncoderReranker, HybridRetriever
from .database import read_json
from .evidence import evaluate_evidence
from .normalization import normalize_alert
from .settings import Settings


class MappingPipeline:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings.load()
        self.retriever = HybridRetriever(self.settings)
        self.reranker = CrossEncoderReranker(self.settings)
        self.manifest = read_json(self.settings.manifest_path)
        self.documents = self.retriever.by_id

    def map_alert(self, raw_alert: Any) -> dict[str, Any]:
        started = time.perf_counter()
        alert = normalize_alert(raw_alert)
        alert_text = (alert.get("derived") or {}).get("retrieval_text", "")
        if not alert_text.strip():
            raise ValueError("Normalized alert has no retrieval_text")
        candidates, degraded = self.retriever.retrieve(alert_text)
        top, reranker_degraded, reranker_version = self.reranker.rerank(alert_text, candidates)
        degraded.extend(reranker_degraded)

        evaluated: list[dict[str, Any]] = []
        for candidate in top:
            evaluation = self._evaluate_candidate(candidate, alert)
            evaluated.append(evaluation)
        self._add_parent_fallbacks(evaluated, alert)
        self._apply_confusion_guard(evaluated)
        evaluated.sort(key=lambda value: (-value["candidate_score"], value["technique_id"]))

        valid = [value for value in evaluated if value["valid"]]
        status = "insufficient_evidence"
        primary = None
        if valid:
            winner = valid[0]
            runner_up = valid[1] if len(valid) > 1 else None
            margin = winner["candidate_score"] - (runner_up["candidate_score"] if runner_up else 0.0)
            if winner["candidate_score"] >= self.settings.decision_threshold:
                status = "mapped" if margin >= self.settings.uncertainty_margin else "uncertain"
                primary = {
                    "technique_id": winner["technique_id"],
                    "name": winner["name"],
                    "confidence": winner["candidate_score"],
                }

        chosen = valid[0] if primary else None
        alternatives = []
        for value in evaluated:
            if chosen and value["technique_id"] == chosen["technique_id"]:
                continue
            reason = value["rejection_reason"]
            if not reason and primary:
                reason = "Lower final score than the primary mapping."
            elif not reason:
                reason = "Candidate did not satisfy the final decision threshold."
            alternatives.append({
                "technique_id": value["technique_id"],
                "name": value["name"],
                "confidence": value["candidate_score"],
                "rejection_reason": reason,
            })

        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        return {
            "mapping_status": status,
            "primary_mapping": primary,
            "supporting_evidence": chosen["supporting_evidence"] if chosen else [],
            "contradictory_evidence": chosen["contradictory_evidence"] if chosen else [],
            "alternative_candidates": alternatives,
            "candidate_trace": [self._trace(value) for value in evaluated],
            "normalized_alert": alert,
            "pipeline": {
                "retriever_version": "hybrid-bm25-attackbert-1.0.0",
                "reranker_version": reranker_version,
                "rule_engine_version": "1.0.0",
                "attack_index_version": self.manifest["index_version"],
                "attack_final_sha256": self.manifest["attack_final_sha256"],
                "collection": self.settings.collection_name,
                "degraded_modes": degraded,
                "latency_ms": elapsed_ms,
            },
        }

    def _evaluate_candidate(self, candidate: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
        payload = candidate["document"]["payload"]
        evidence = evaluate_evidence(payload, alert)
        score = (
            self.settings.retrieval_weight * candidate["fusion_score"]
            + self.settings.reranker_weight * candidate["reranker_score"]
            + self.settings.evidence_weight * evidence["evidence_score"]
        )
        return {
            **candidate,
            **evidence,
            "candidate_score": round(max(0.0, min(1.0, score)), 6),
            "rejection_reason": "; ".join(evidence["rejection_reasons"]),
            "fallback_from": None,
        }

    def _add_parent_fallbacks(self, evaluated: list[dict[str, Any]], alert: dict[str, Any]) -> None:
        present = {value["technique_id"] for value in evaluated}
        additions = []
        for candidate in list(evaluated):
            parent_id = candidate["document"]["payload"].get("parent_id")
            if candidate["valid"] or not parent_id or parent_id in present or parent_id not in self.documents:
                continue
            parent_document = self.documents[parent_id]
            inherited = {
                "technique_id": parent_id,
                "name": parent_document["name"],
                "dense_score": candidate["dense_score"],
                "bm25_score": candidate["bm25_score"],
                "fusion_score": round(candidate["fusion_score"] * 0.95, 6),
                "matched_terms": candidate["matched_terms"],
                "document": parent_document,
                "rank_before_rerank": candidate["rank_before_rerank"],
                "rank_after_rerank": candidate["rank_after_rerank"],
                "reranker_raw_score": candidate["reranker_raw_score"],
                "reranker_score": round(candidate["reranker_score"] * 0.95, 6),
            }
            result = self._evaluate_candidate(inherited, alert)
            result["fallback_from"] = candidate["technique_id"]
            additions.append(result)
            present.add(parent_id)
        evaluated.extend(additions)

    @staticmethod
    def _apply_confusion_guard(evaluated: list[dict[str, Any]]) -> None:
        by_id = {value["technique_id"]: value for value in evaluated}
        for candidate in evaluated:
            if not candidate["valid"]:
                continue
            relations = candidate["document"]["payload"].get("confusable_techniques", [])
            for relation in relations:
                other = by_id.get(relation.get("technique_id"))
                if not other or not other["valid"]:
                    continue
                if other["evidence_score"] >= candidate["evidence_score"] + 0.2:
                    penalty = 0.2 if relation.get("hard_negative") else 0.1
                    candidate["candidate_score"] = round(max(0.0, candidate["candidate_score"] - penalty), 6)
                    candidate["contradictory_evidence"].append({
                        "rule_id": "CONFUSION-GUARD",
                        "field": "candidate_comparison",
                        "value": other["technique_id"],
                        "weight": -penalty,
                        "reason": f"Confusable candidate {other['technique_id']} has materially stronger structured evidence.",
                    })

    @staticmethod
    def _trace(value: dict[str, Any]) -> dict[str, Any]:
        return {
            "technique_id": value["technique_id"],
            "name": value["name"],
            "bm25_score": value["bm25_score"],
            "dense_score": value["dense_score"],
            "fusion_score": value["fusion_score"],
            "matched_terms": value["matched_terms"],
            "rank_before_rerank": value["rank_before_rerank"],
            "reranker_raw_score": round(value["reranker_raw_score"], 6),
            "reranker_score": round(value["reranker_score"], 6),
            "rank_after_rerank": value["rank_after_rerank"],
            "required_passed": value["required_passed"],
            "excluded": value["excluded"],
            "evidence_score": value["evidence_score"],
            "candidate_score": value["candidate_score"],
            "fallback_from": value["fallback_from"],
            "rejection_reason": value["rejection_reason"],
        }
