from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.clients import _normalize  # noqa: E402
from mitre_mapper.pipeline import MappingPipeline  # noqa: E402


class RerankerScoringTests(unittest.TestCase):
    def test_per_query_minmax_scoring(self) -> None:
        self.assertEqual(
            {"low": 0.0, "middle": 0.5, "high": 1.0},
            _normalize({"low": 2.0, "middle": 3.0, "high": 4.0}),
        )

    def test_equal_scores_normalize_to_one(self) -> None:
        self.assertEqual({"a": 1.0, "b": 1.0}, _normalize({"a": 0.25, "b": 0.25}))


class FinalPoolTests(unittest.TestCase):
    def test_invalid_candidates_do_not_consume_top_five_slots(self) -> None:
        evaluated = [
            {
                "technique_id": f"T{index:04d}",
                "valid": index > 3,
                "rank_after_rerank": index,
                "rank_before_rerank": index,
            }
            for index in range(1, 14)
        ]

        selected = MappingPipeline._select_final_pool(evaluated, limit=5)

        self.assertEqual(5, len(selected))
        self.assertEqual(
            [f"T{index:04d}" for index in range(4, 9)],
            [item["technique_id"] for item in selected],
        )
        self.assertTrue(all(item["valid"] for item in selected))


if __name__ == "__main__":
    unittest.main()
