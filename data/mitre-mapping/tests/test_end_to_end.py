from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.pipeline import MappingPipeline  # noqa: E402
from mitre_mapper.settings import Settings  # noqa: E402


class EndToEndTests(unittest.TestCase):
    @staticmethod
    def offline_pipeline() -> MappingPipeline:
        settings = replace(
            Settings.load(ROOT),
            qdrant_url="http://127.0.0.1:1",
            embedding_url="http://127.0.0.1:1",
            reranker_url="http://127.0.0.1:1",
            request_timeout=0.1,
            local_fallback=True,
        )
        return MappingPipeline(settings)

    def test_scan_alert_maps_to_active_scanning(self) -> None:
        payload = json.loads((ROOT.parent / "test alert scan CH.txt").read_text(encoding="utf-8-sig"))
        result = self.offline_pipeline().map_alert(payload)
        self.assertIn(result["mapping_status"], {"mapped", "uncertain"})
        self.assertEqual("T1595", result["primary_mapping"]["technique_id"])
        self.assertTrue(result["pipeline"]["degraded_modes"])

    def test_internal_scan_maps_to_service_discovery(self) -> None:
        payload = {
            "producer": {"rule_name": "SOC internal port scan"},
            "data_source": {"category": "network_traffic"},
            "event": {"type": "network_scan", "action": "scan", "outcome": "unknown"},
            "network": {"direction": "lateral"},
            "target": {"type": "service", "port": 445},
        }
        result = self.offline_pipeline().map_alert(payload)
        self.assertEqual("mapped", result["mapping_status"])
        self.assertEqual("T1046", result["primary_mapping"]["technique_id"])

    def test_benign_dns_alert_is_not_confidently_mapped(self) -> None:
        payload = {
            "producer": {"rule_name": "Benign DNS response"},
            "data_source": {"category": "network_traffic"},
            "event": {"type": "dns", "action": "query", "outcome": "success"},
        }
        result = self.offline_pipeline().map_alert(payload)
        self.assertIn(result["mapping_status"], {"insufficient_evidence", "uncertain"})

    def test_missing_or_undeclared_parent_does_not_create_fallback(self) -> None:
        pipeline = MappingPipeline.__new__(MappingPipeline)
        pipeline.documents = {}
        evaluated = [
            {
                "technique_id": "T1071.001",
                "valid": False,
                "document": {"payload": {"parent_id": "T1071"}},
            },
            {
                "technique_id": "T1046",
                "valid": False,
                "document": {"payload": {"parent_id": None}},
            },
        ]

        pipeline._add_parent_fallbacks(evaluated, {})

        self.assertEqual(["T1071.001", "T1046"], [item["technique_id"] for item in evaluated])


if __name__ == "__main__":
    unittest.main()
