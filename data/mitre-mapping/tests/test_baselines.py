from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.baselines.bm25_only import BM25OnlyStrategy  # noqa: E402
from mitre_mapper.baselines.dataset import (  # noqa: E402
    find_leakage,
    scenario_family,
    scenario_group,
)
from mitre_mapper.baselines.evaluate import evaluate_strategy  # noqa: E402
from mitre_mapper.baselines.gemini_only import GeminiOnlyStrategy  # noqa: E402
from mitre_mapper.baselines.sanitize import sanitize_alert  # noqa: E402


class SanitizeTests(unittest.TestCase):
    def test_removes_mitre_fields_and_inline_ids(self) -> None:
        alert = {
            "producer": {"rule_name": "ET SCAN T1046 suspicious", "rule_id": "1001"},
            "mitre": {"technique_ids": ["T1046"], "tactic_ids": ["TA0007"]},
            "mitre_technique_id": "T1046",
            "tactic": "Discovery",
            "tags": ["attack.t1046", "ids", "suricata"],
            "derived": {
                "retrieval_text": "Declared MITRE techniques: T1046\nRule: ET SCAN T1046 suspicious",
                "external_hints": {"wazuh_mitre": {"id": ["T1046"]}},
            },
            "rule": {"mitre": {"id": ["T1046"], "tactic": ["TA0007"]}},
        }
        clean, report = sanitize_alert(alert)
        self.assertNotIn("mitre", clean)
        self.assertNotIn("mitre_technique_id", clean)
        self.assertNotIn("tactic", clean)
        self.assertEqual(clean["tags"], ["ids", "suricata"])
        self.assertNotIn("wazuh_mitre", clean["derived"]["external_hints"])
        self.assertNotIn("T1046", clean["derived"]["retrieval_text"])
        self.assertNotIn("T1046", clean["producer"]["rule_name"])
        self.assertEqual(report["counts"]["removed_fields"], 6)
        self.assertEqual(find_leakage(clean), [])


class BM25Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.strategy = BM25OnlyStrategy(ROOT, variant="top1")

    def test_ranks_candidates_and_scores_deterministically(self) -> None:
        alert = {
            "derived": {
                "retrieval_text": (
                    "Rule: LAB Internal Common Service Sweep\n"
                    "Event type: network_scan\n"
                    "Action: scan\n"
                    "Target type: host\n"
                )
            }
        }
        result = self.strategy.map_alert(alert, scenario_id="unit-test")
        self.assertEqual(result.mapping_status, "mapped")
        self.assertGreater(result.latency_ms, 0)
        supported = {row["technique_id"] for row in self.strategy.catalog}
        self.assertIn(result.primary_mapping["technique_id"], supported)
        trace = result.candidate_trace
        self.assertEqual([row["score_raw"] for row in trace], sorted(
            (row["score_raw"] for row in trace), reverse=True,
        ))
        self.assertIn("T1046", [row["technique_id"] for row in trace[:3]])
        self.assertTrue(trace[0]["matched_terms"])

    def test_is_deterministic(self) -> None:
        alert = {"derived": {"retrieval_text": "Rule: periodic HTTP beacon"}}
        first = self.strategy.map_alert(alert).to_dict()
        second = self.strategy.map_alert(alert).to_dict()
        first.pop("latency_ms")
        second.pop("latency_ms")
        self.assertEqual(first, second)


class GeminiValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.strategy = GeminiOnlyStrategy(ROOT, dry_run=True)

    def _details(self) -> dict:
        return {"errors": [], "invalid_ids": []}

    def test_rejects_out_of_subset_primary(self) -> None:
        details = self._details()
        result = self.strategy._validate({
            "mapping_status": "mapped",
            "primary_technique_id": "T9999",
            "confidence": 0.9,
            "ranked_candidates": [{"technique_id": "T9999", "confidence": 0.9, "reason": "x"}],
        }, details)
        self.assertEqual(result.mapping_status, "invalid_output")
        self.assertIsNone(result.primary_mapping)
        self.assertIn("T9999", details["invalid_ids"])

    def test_accepts_supported_primary(self) -> None:
        details = self._details()
        result = self.strategy._validate({
            "mapping_status": "mapped",
            "primary_technique_id": "T1046",
            "confidence": 0.8,
            "ranked_candidates": [
                {"technique_id": "T1046", "confidence": 0.8, "reason": "internal scan"}
            ],
        }, details)
        self.assertEqual(result.mapping_status, "mapped")
        self.assertEqual(result.primary_mapping["technique_id"], "T1046")

    def test_dry_run_skips_without_network(self) -> None:
        result = self.strategy.map_alert({"derived": {"retrieval_text": "x"}}, scenario_id="s1")
        self.assertEqual(result.mapping_status, "skipped")
        self.assertIsNone(result.primary_mapping)


class EvaluationTests(unittest.TestCase):
    def test_partial_credit_for_parent_and_child(self) -> None:
        ground_truth = {"s1": {"technique_ids": ["T1595.002"], "group": "A2", "family": "T1595.002"}}
        parent_map = {"T1595.002": "T1595"}
        parent_result = {
            "s1": {
                "mapping_status": "mapped",
                "primary_mapping": {"technique_id": "T1595", "name": "Active Scanning", "confidence": 0.8},
                "alternative_candidates": [],
            }
        }
        metrics = evaluate_strategy("bm25_only", parent_result, ground_truth, parent_map)
        row = metrics["scenarios"][0]
        self.assertEqual(row["partial_credit"], 0.5)
        self.assertFalse(row["primary_hit"])
        exact_result = {
            "s1": {
                "mapping_status": "mapped",
                "primary_mapping": {"technique_id": "T1595.002", "name": "Vulnerability Scanning", "confidence": 0.9},
                "alternative_candidates": [],
            }
        }
        exact_metrics = evaluate_strategy("bm25_only", exact_result, ground_truth, parent_map)
        self.assertEqual(exact_metrics["scenarios"][0]["partial_credit"], 1.0)
        self.assertTrue(exact_metrics["scenarios"][0]["exact_top1"])

    def test_scenario_parsing(self) -> None:
        self.assertEqual(scenario_group("A2-T1071.001-03"), "A2")
        self.assertEqual(scenario_family("A2-T1071.001-03"), "T1071.001")


if __name__ == "__main__":
    unittest.main()
