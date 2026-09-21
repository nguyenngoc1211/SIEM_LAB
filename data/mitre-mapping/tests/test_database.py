from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.database import read_jsonl, validate_database  # noqa: E402


class DatabaseTests(unittest.TestCase):
    def test_mapping_database_is_valid(self) -> None:
        records = json.loads((ROOT / "artifacts" / "attack" / "attack_final.mapping.json").read_text(encoding="utf-8"))
        result = validate_database(records)
        self.assertEqual([], result["errors"])
        self.assertEqual(len(records), len({value["technique_id"] for value in records}))

    def test_retrieval_documents_are_one_per_technique(self) -> None:
        records = json.loads((ROOT / "artifacts" / "attack" / "attack_final.mapping.json").read_text(encoding="utf-8"))
        documents = read_jsonl(ROOT / "artifacts" / "retrieval" / "technique_documents.jsonl")
        self.assertEqual(len(records), len(documents))
        self.assertTrue(all(value["dense_text"] and value["sparse_text"] for value in documents))

    def test_missing_parent_is_a_warning_not_an_error(self) -> None:
        records = [
            {
                "schema_version": "1.1.0",
                "technique_id": "T1071.001",
                "name": "Web Protocols",
                "description": "Uses web protocols for command and control.",
                "behavioral_indicators": ["HTTP command-and-control traffic"],
                "retrieval_keywords": [],
                "required_evidence": [],
                "positive_evidence": [],
                "negative_evidence": [],
                "exclusion_indicators": [],
                "parent_technique": {"technique_id": "T1071"},
                "source_metadata": {
                    "attack_version": "19.1",
                    "source_url": "https://attack.mitre.org/techniques/T1071/001",
                },
            }
        ]

        result = validate_database(records)

        self.assertEqual([], result["errors"])
        self.assertIn(
            "T1071.001: parent T1071 is outside the supported subset; "
            "parent fallback is disabled for this technique",
            result["warnings"],
        )


if __name__ == "__main__":
    unittest.main()
