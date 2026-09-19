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


if __name__ == "__main__":
    unittest.main()
