from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.normalization import normalize_alert  # noqa: E402


class NormalizationTests(unittest.TestCase):
    def test_input_is_not_modified_and_volatile_fields_are_not_rendered(self) -> None:
        source = {
            "alert_id": "volatile-id",
            "event_time": "2026-01-01T00:00:00Z",
            "producer": {"rule_name": "Internal port scan"},
            "event": {"type": "network_scan", "action": "scan"},
            "network": {"flow_id": "123"},
        }
        original = copy.deepcopy(source)
        result = normalize_alert(source)
        text = result["derived"]["retrieval_text"]
        self.assertEqual(source, original)
        self.assertNotIn("volatile-id", text)
        self.assertNotIn("2026-01-01", text)
        self.assertNotIn("123", text)

    def test_n8n_body_wrapper_is_accepted(self) -> None:
        result = normalize_alert({"body": {"producer": {"rule_name": "Scan"}, "event": {"type": "network_scan"}}})
        self.assertIn("IDS rule: Scan", result["derived"]["retrieval_text"])

    def test_soc_v2_wazuh_alert_gets_behavior_semantics(self) -> None:
        payload = {
            "_source": {
                "rule": {"description": "SOC v2 detection"},
                "data": {
                    "event_type": "alert",
                    "direction": "to_server",
                    "app_proto": "http",
                    "alert": {"signature": "SOC LAB V2 periodic HTTP beacon"},
                    "http": {"http_method": "POST", "url": "/telemetry", "status": 200},
                },
            }
        }
        result = normalize_alert(payload)
        self.assertIn("SOC LAB V2 periodic HTTP beacon", result["producer"]["rule_name"])
        self.assertEqual(result["event"]["type"], "network_communication")
        self.assertEqual(result["event"]["action"], "connect")
        self.assertEqual(result["network"]["direction"], "to_server")
        self.assertEqual(result["target"]["type"], "application")

    def test_suricata_rule_identity_and_mitre_metadata_are_preserved(self) -> None:
        payload = {
            "rule": {"id": "86601", "description": "Generic Suricata ingestion"},
            "data": {
                "app_proto": "http",
                "alert": {
                    "signature_id": 1002036,
                    "signature": "LAB Repeated JSON Credential Guesses",
                    "metadata": {
                        "mitre_tactic_id": ["TA0006"],
                        "mitre_technique_id": ["T1110.001"],
                    },
                },
            },
        }

        result = normalize_alert(payload)

        self.assertEqual(1002036, result["producer"]["rule_id"])
        self.assertEqual("86601", result["producer"]["collector_rule_id"])
        self.assertEqual(["TA0006"], result["mitre"]["tactic_ids"])
        self.assertEqual(["T1110.001"], result["mitre"]["technique_ids"])
        self.assertEqual("sensor_rule_metadata", result["mitre"]["source"])


if __name__ == "__main__":
    unittest.main()
