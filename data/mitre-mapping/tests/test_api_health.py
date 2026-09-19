from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

try:
    from mitre_mapper import api  # noqa: E402
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        raise unittest.SkipTest("FastAPI is not installed in the host test environment") from exc
    raise


class ApiHealthTests(unittest.TestCase):
    @staticmethod
    def body(response) -> dict:
        return json.loads(response.body)

    def test_health_is_503_while_pipeline_is_starting(self) -> None:
        with patch.object(api, "pipeline", None), patch.object(api, "_check_dependencies") as check:
            response = api.health()

        self.assertEqual(503, response.status_code)
        self.assertEqual("starting", self.body(response)["status"])
        check.assert_not_called()

    def test_health_is_200_when_all_dependencies_are_ready(self) -> None:
        dependency_status = {
            "qdrant": {"status": "green", "collection": "attack_techniques_v1", "points_count": 21},
            "embedding": {"status": "ok"},
            "reranker": {"status": "ok", "model": "test-model", "revision": "test-revision"},
        }
        with patch.object(api, "pipeline", object()), patch.object(
            api, "_check_dependencies", return_value=(dependency_status, {})
        ):
            response = api.health()

        body = self.body(response)
        self.assertEqual(200, response.status_code)
        self.assertEqual("ok", body["status"])
        self.assertEqual(dependency_status, body["dependencies"])
        self.assertEqual({}, body["failures"])

    def test_health_is_503_when_a_dependency_fails(self) -> None:
        with patch.object(api, "pipeline", object()), patch.object(
            api,
            "_check_dependencies",
            return_value=(
                {"qdrant": {"status": "green"}, "embedding": {"status": "ok"}},
                {"reranker": "connection refused"},
            ),
        ):
            response = api.health()

        body = self.body(response)
        self.assertEqual(503, response.status_code)
        self.assertEqual("unhealthy", body["status"])
        self.assertEqual("connection refused", body["failures"]["reranker"])


if __name__ == "__main__":
    unittest.main()
