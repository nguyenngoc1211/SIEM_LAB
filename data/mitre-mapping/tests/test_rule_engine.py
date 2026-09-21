from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.evidence import evaluate_evidence, rule_matches  # noqa: E402


class RuleEngineTests(unittest.TestCase):
    alert = {
        "producer": {"rule_name": "ET SCAN Suspicious inbound traffic"},
        "event": {"action": "scan", "count": 12},
        "target": {"port": 80},
    }

    def test_all_supported_operators(self) -> None:
        cases = [
            ({"field": "event.action", "operator": "equals", "value": "SCAN"}, True),
            ({"field": "producer.rule_name", "operator": "contains_any", "value": ["inbound", "other"]}, True),
            ({"field": "target.port", "operator": "exists", "value": True}, True),
            ({"field": "target.port", "operator": "in", "value": [80, 443]}, True),
            ({"field": "event.count", "operator": "greater_than_or_equal", "value": 10}, True),
            ({"field": "producer.rule_name", "operator": "matches_regex", "value": r"ET\s+SCAN"}, True),
            ({"field": "event.missing", "operator": "exists", "value": False}, True),
        ]
        for rule, expected in cases:
            with self.subTest(rule=rule):
                self.assertEqual(expected, rule_matches(rule, self.alert))

    def test_required_is_boolean_and_does_not_add_to_score(self) -> None:
        payload = {
            "required_evidence": [
                {
                    "rule_id": "REQ-001",
                    "field": "event.action",
                    "operator": "equals",
                    "value": "scan",
                    "weight": 1.0,
                }
            ],
            "positive_evidence": [
                {
                    "rule_id": "POS-001",
                    "field": "target.port",
                    "operator": "equals",
                    "value": 80,
                    "weight": 0.25,
                }
            ],
            "negative_evidence": [],
            "exclusion_indicators": [],
        }
        result = evaluate_evidence(payload, self.alert)
        self.assertTrue(result["required_passed"])
        self.assertEqual(0.25, result["raw_evidence_score"])
        self.assertEqual(1.0, result["evidence_score"])

    def test_event_fields_still_act_as_required_gates(self) -> None:
        payload = {
            "required_evidence": [
                {
                    "rule_id": "REQ-EVENT-001",
                    "field": "event.type",
                    "operator": "equals",
                    "value": "network_scan",
                    "weight": 0.0,
                }
            ],
            "positive_evidence": [],
            "negative_evidence": [],
            "exclusion_indicators": [],
        }
        result = evaluate_evidence(payload, self.alert)
        self.assertFalse(result["required_passed"])
        self.assertFalse(result["valid"])

    def test_candidate_requires_a_matching_event_signal(self) -> None:
        payload = {
            "required_evidence": [],
            "positive_evidence": [
                {
                    "rule_id": "POS-EVENT-001",
                    "field": "event.type",
                    "operator": "equals",
                    "value": "network_scan",
                    "weight": 0.4,
                }
            ],
            "negative_evidence": [],
            "exclusion_indicators": [],
        }
        result = evaluate_evidence(payload, self.alert)
        self.assertTrue(result["required_passed"])
        self.assertFalse(result["event_signal_present"])
        self.assertFalse(result["valid"])
        self.assertEqual(0.0, result["evidence_score"])

    def test_matching_positive_event_field_opens_candidate_gate(self) -> None:
        payload = {
            "required_evidence": [],
            "positive_evidence": [
                {
                    "rule_id": "POS-EVENT-001",
                    "field": "event.action",
                    "operator": "equals",
                    "value": "scan",
                    "weight": 0.4,
                }
            ],
            "negative_evidence": [],
            "exclusion_indicators": [],
        }

        result = evaluate_evidence(payload, self.alert)

        self.assertTrue(result["event_signal_present"])
        self.assertTrue(result["valid"])

    def test_other_required_fields_still_act_as_gates(self) -> None:
        payload = {
            "required_evidence": [
                {
                    "rule_id": "REQ-PROTOCOL-001",
                    "field": "network.application_protocol",
                    "operator": "equals",
                    "value": "dns",
                    "weight": 0.0,
                }
            ],
            "positive_evidence": [],
            "negative_evidence": [],
            "exclusion_indicators": [],
        }
        result = evaluate_evidence(payload, self.alert)
        self.assertFalse(result["required_passed"])
        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
