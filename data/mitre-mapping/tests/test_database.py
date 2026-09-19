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


if __name__ == "__main__":
    unittest.main()
