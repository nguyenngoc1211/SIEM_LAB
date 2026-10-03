#!/usr/bin/env python3
"""Audit the current A1/A2 mapper results against the pre-change snapshot."""

from __future__ import annotations

import json
import math
import statistics
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "runtime" / "reports"
OUTPUT = REPORTS / "reranker_audit.json"
EXPECTED_FORMULA = "per_query_minmax(raw_reranker_score)"
EXPECTED_LIMIT = 5


def latest_baseline() -> Path:
    archive_root = REPORTS / "archive"
    candidates = [path for path in archive_root.iterdir() if path.is_dir()]
    if not candidates:
        raise FileNotFoundError("No archived A1/A2 baseline was found")
    return max(candidates, key=lambda path: path.stat().st_mtime)


BASELINE = latest_baseline()


def load_report_set(base: Path) -> dict[str, dict[str, Any]]:
    reports: dict[str, dict[str, Any]] = {}
    for group in ("a1", "a2"):
        for path in sorted((base / group).glob("A[12]-*.json")):
            report = json.loads(path.read_text(encoding="utf-8"))
            reports[str(report["scenario_id"])] = report
    return reports


def expected_ids(report: dict[str, Any]) -> set[str]:
    values = report.get("ground_truth", {}).get("technique_ids", [])
    if not values:
        values = report.get("mitre", {}).get("expected_techniques", [])
    return {str(value) for value in values}


def mapper_output(report: dict[str, Any]) -> dict[str, Any]:
    outputs = report.get("mapper_output", [])
    return outputs[0] if outputs and isinstance(outputs[0], dict) else {}


def output_candidates(output: dict[str, Any]) -> list[tuple[str, float]]:
    scores: dict[str, float] = {}
    primary = output.get("primary_mapping")
    values = ([primary] if isinstance(primary, dict) else []) + [
        item for item in output.get("alternative_candidates", []) if isinstance(item, dict)
    ]
    for item in values:
        technique_id = item.get("technique_id")
        confidence = item.get("confidence")
        if technique_id and confidence is not None:
            scores[str(technique_id)] = max(scores.get(str(technique_id), 0.0), float(confidence))
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def exact(report: dict[str, Any]) -> bool:
    expected = expected_ids(report)
    observed = {str(value) for value in report.get("mitre", {}).get("observed_techniques", [])}
    return bool(expected) and expected == observed


def candidate_hit(report: dict[str, Any], depth: int) -> bool:
    expected = expected_ids(report)
    actual = {item[0] for item in output_candidates(mapper_output(report))[:depth]}
    return bool(expected & actual)


def expected_reranker_rank(report: dict[str, Any]) -> int | None:
    expected = expected_ids(report)
    ranks = [
        int(item["rank_after_rerank"])
        for item in mapper_output(report).get("candidate_trace", [])
        if item.get("technique_id") in expected and item.get("rank_after_rerank") is not None
    ]
    return min(ranks) if ranks else None


def expected_trace(report: dict[str, Any]) -> dict[str, Any] | None:
    expected = expected_ids(report)
    matches = [
        item for item in mapper_output(report).get("candidate_trace", [])
        if item.get("technique_id") in expected
    ]
    if not matches:
        return None
    return min(matches, key=lambda item: int(item.get("rank_after_rerank", 10**9)))


def audit_scenario(report: dict[str, Any]) -> dict[str, Any]:
    output = mapper_output(report)
    pipeline = output.get("pipeline", {})
    trace = [item for item in output.get("candidate_trace", []) if isinstance(item, dict)]
    selected = [item for item in trace if item.get("selected_for_final_pool")]
    invalid_selected = [
        item.get("technique_id")
        for item in selected
        if not (
            item.get("required_passed")
            and item.get("event_signal_present")
            and not item.get("excluded")
        )
    ]
    formula_mismatches: list[str] = []
    direct = [item for item in trace if not item.get("fallback_from")]
    raw_scores = [float(item.get("reranker_raw_score", 0.0)) for item in direct]
    low = min(raw_scores) if raw_scores else 0.0
    high = max(raw_scores) if raw_scores else 0.0
    direct_scores: dict[str, float] = {}
    for item in direct:
        raw_score = float(item.get("reranker_raw_score", 0.0))
        expected_score = 1.0 if math.isclose(low, high) else (raw_score - low) / (high - low)
        direct_scores[str(item.get("technique_id"))] = expected_score
        if abs(float(item.get("reranker_score", 0.0)) - expected_score) > 2e-3:
            formula_mismatches.append(str(item.get("technique_id")))
    for item in trace:
        fallback_from = item.get("fallback_from")
        if not fallback_from:
            continue
        expected_score = direct_scores.get(str(fallback_from))
        if expected_score is None or abs(
            float(item.get("reranker_score", 0.0)) - expected_score * 0.95
        ) > 2e-3:
            formula_mismatches.append(str(item.get("technique_id")))

    expected = expected_ids(report)
    expected_trace = [item for item in trace if item.get("technique_id") in expected]
    expected_selected = [item for item in expected_trace if item.get("selected_for_final_pool")]
    backfilled = [
        item for item in selected
        if int(item.get("rank_after_rerank", 0)) > EXPECTED_LIMIT
    ]
    expected_backfilled = [item for item in backfilled if item.get("technique_id") in expected]
    candidates = output_candidates(output)
    return {
        "scenario_id": report.get("scenario_id"),
        "group": str(report.get("scenario_id", ""))[:2],
        "expected_techniques": sorted(expected),
        "observed_techniques": report.get("mitre", {}).get("observed_techniques", []),
        "mapping_status": report.get("mitre", {}).get("status"),
        "mapper_status": output.get("mapping_status"),
        "exact": exact(report),
        "expected_in_top3": candidate_hit(report, 3),
        "expected_in_trace": bool(expected_trace),
        "expected_in_final_pool": bool(expected_selected),
        "backfill_used": bool(backfilled),
        "expected_backfilled": bool(expected_backfilled),
        "expected_rank_after_rerank": expected_reranker_rank(report),
        "selected_count": len(selected),
        "invalid_selected": invalid_selected,
        "formula_matches": not formula_mismatches,
        "formula_mismatches": formula_mismatches,
        "pipeline_formula": pipeline.get("reranker_score_formula"),
        "pipeline_limit": pipeline.get("final_candidate_limit"),
        "top_candidates": [
            {"technique_id": technique_id, "confidence": confidence}
            for technique_id, confidence in candidates[:10]
        ],
    }


def main() -> None:
    current = load_report_set(REPORTS)
    baseline = load_report_set(BASELINE)
    scenarios = [audit_scenario(current[key]) for key in sorted(current)]
    common = sorted(set(current) & set(baseline))

    rank_movements: Counter[str] = Counter()
    rank_deltas: list[int] = []
    expected_score_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for scenario_id in common:
        before = expected_reranker_rank(baseline[scenario_id])
        after = expected_reranker_rank(current[scenario_id])
        if before is None or after is None:
            rank_movements["not_comparable"] += 1
        elif after < before:
            rank_movements["improved"] += 1
            rank_deltas.append(after - before)
        elif after > before:
            rank_movements["worsened"] += 1
            rank_deltas.append(after - before)
        else:
            rank_movements["unchanged"] += 1
            rank_deltas.append(0)
        before_trace = expected_trace(baseline[scenario_id])
        after_trace = expected_trace(current[scenario_id])
        if before_trace and after_trace:
            expected_score_pairs.append((before_trace, after_trace))

    exact_before = sum(exact(report) for report in baseline.values())
    exact_after = sum(item["exact"] for item in scenarios)
    top3_before = sum(candidate_hit(report, 3) for report in baseline.values())
    top3_after = sum(item["expected_in_top3"] for item in scenarios)
    missing_before = sum(
        report.get("mitre", {}).get("status") == "MISSING" for report in baseline.values()
    )
    missing_after = sum(item["mapping_status"] == "MISSING" for item in scenarios)
    exact_regressions = [
        scenario_id for scenario_id in common
        if exact(baseline[scenario_id]) and not exact(current[scenario_id])
    ]
    exact_improvements = [
        scenario_id for scenario_id in common
        if not exact(baseline[scenario_id]) and exact(current[scenario_id])
    ]
    top3_losses = [
        scenario_id for scenario_id in common
        if candidate_hit(baseline[scenario_id], 3) and not candidate_hit(current[scenario_id], 3)
    ]
    top3_gains = [
        scenario_id for scenario_id in common
        if not candidate_hit(baseline[scenario_id], 3) and candidate_hit(current[scenario_id], 3)
    ]
    expected_absent_from_baseline_trace = [
        scenario_id for scenario_id in common
        if expected_reranker_rank(baseline[scenario_id]) is None
    ]
    expected_not_in_final_pool = [
        item["scenario_id"] for item in scenarios if not item["expected_in_final_pool"]
    ]
    backfill_used = [item["scenario_id"] for item in scenarios if item["backfill_used"]]
    expected_backfilled = [
        item["scenario_id"] for item in scenarios if item["expected_backfilled"]
    ]

    summary = {
        "scenario_count": len(scenarios),
        "a1_count": sum(item["group"] == "A1" for item in scenarios),
        "a2_count": sum(item["group"] == "A2" for item in scenarios),
        "detection_pass": sum(
            report.get("detection", {}).get("status") == "PASS" for report in current.values()
        ),
        "siem_pass": sum(
            report.get("siem", {}).get("status") == "PASS" for report in current.values()
        ),
        "exact_before": exact_before,
        "exact_after": exact_after,
        "top3_before": top3_before,
        "top3_after": top3_after,
        "missing_before": missing_before,
        "missing_after": missing_after,
        "exact_regressions": exact_regressions,
        "exact_improvements": exact_improvements,
        "top3_losses": top3_losses,
        "top3_gains": top3_gains,
        "expected_in_trace": sum(item["expected_in_trace"] for item in scenarios),
        "expected_in_final_pool": sum(item["expected_in_final_pool"] for item in scenarios),
        "expected_not_in_final_pool": expected_not_in_final_pool,
        "backfill_used_scenarios": len(backfill_used),
        "backfill_used_scenario_ids": backfill_used,
        "expected_backfilled_scenario_ids": expected_backfilled,
        "formula_ok_scenarios": sum(item["formula_matches"] for item in scenarios),
        "pipeline_formula_ok": sum(
            item["pipeline_formula"] == EXPECTED_FORMULA for item in scenarios
        ),
        "pipeline_limit_ok": sum(item["pipeline_limit"] == EXPECTED_LIMIT for item in scenarios),
        "pool_size_at_most_limit": sum(
            item["selected_count"] <= EXPECTED_LIMIT for item in scenarios
        ),
        "invalid_selected_scenarios": sum(bool(item["invalid_selected"]) for item in scenarios),
        "invalid_selected_candidates": sum(len(item["invalid_selected"]) for item in scenarios),
        "selected_pool_size_distribution": dict(sorted(Counter(
            item["selected_count"] for item in scenarios
        ).items())),
        "expected_rank_movements": dict(rank_movements),
        "expected_absent_from_baseline_trace": expected_absent_from_baseline_trace,
        "mean_expected_rank_delta": (
            round(sum(rank_deltas) / len(rank_deltas), 4) if rank_deltas else None
        ),
        "expected_reranker_component_mean_before": round(statistics.mean(
            float(before["reranker_score"]) for before, _ in expected_score_pairs
        ), 6),
        "expected_reranker_component_mean_after": round(statistics.mean(
            float(after["reranker_score"]) for _, after in expected_score_pairs
        ), 6),
        "expected_reranker_component_median_before": round(statistics.median(
            float(before["reranker_score"]) for before, _ in expected_score_pairs
        ), 6),
        "expected_reranker_component_median_after": round(statistics.median(
            float(after["reranker_score"]) for _, after in expected_score_pairs
        ), 6),
        "expected_candidate_score_mean_before": round(statistics.mean(
            float(before["candidate_score"]) for before, _ in expected_score_pairs
        ), 6),
        "expected_candidate_score_mean_after": round(statistics.mean(
            float(after["candidate_score"]) for _, after in expected_score_pairs
        ), 6),
        "expected_candidate_score_median_before": round(statistics.median(
            float(before["candidate_score"]) for before, _ in expected_score_pairs
        ), 6),
        "expected_candidate_score_median_after": round(statistics.median(
            float(after["candidate_score"]) for _, after in expected_score_pairs
        ), 6),
    }
    result = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "baseline": str(BASELINE.relative_to(ROOT)).replace("\\", "/"),
        "expected_formula": EXPECTED_FORMULA,
        "expected_limit": EXPECTED_LIMIT,
        "summary": summary,
        "scenarios": scenarios,
    }
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
