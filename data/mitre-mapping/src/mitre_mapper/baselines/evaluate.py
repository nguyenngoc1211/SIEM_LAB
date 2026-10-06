"""Score baseline results against the frozen ground truth."""

from __future__ import annotations

import math
import re
import statistics
from collections import Counter, defaultdict
from typing import Any, Callable


FAMILY_RE = re.compile(r"^(A\d+)-(T[0-9]+(?:\.[0-9]+)?)-\d+$", re.IGNORECASE)
ANSWERED_STATUS = {"mapped", "uncertain"}
ABSTAIN_STATUS = {"insufficient_evidence", "skipped", "error", "invalid_output"}


def scenario_group(scenario_id: str | None) -> str | None:
    return str(scenario_id).split("-", 1)[0].upper() if scenario_id else None


def scenario_family(scenario_id: str | None) -> str | None:
    match = FAMILY_RE.match(str(scenario_id or ""))
    return match.group(2).upper() if match else None


def wilson_ci(successes: int, total: int, z: float = 1.96) -> list[float] | None:
    if total <= 0:
        return None
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(
        proportion * (1 - proportion) / total + z * z / (4 * total * total)
    ) / denominator
    return [round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4)]


def _rate(successes: int, total: int) -> dict[str, Any]:
    return {
        "count": successes,
        "total": total,
        "rate": round(successes / total, 4) if total else None,
        "wilson_95": wilson_ci(successes, total),
    }


def ranked_candidates(result: dict[str, Any], limit: int = 5) -> list[str]:
    values: list[str] = []
    primary = result.get("primary_mapping") if isinstance(result.get("primary_mapping"), dict) else None
    if primary and primary.get("technique_id"):
        values.append(str(primary["technique_id"]))
    for item in result.get("alternative_candidates") or []:
        if not isinstance(item, dict):
            continue
        technique_id = item.get("technique_id")
        if technique_id and str(technique_id) not in values:
            values.append(str(technique_id))
    return values[:limit]


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return round(ordered[index], 3)


def evaluate_strategy(
    strategy: str,
    results_by_scenario: dict[str, dict[str, Any]],
    ground_truth_by_scenario: dict[str, dict[str, Any]],
    parent_map: dict[str, str],
    *,
    partial_credit_parent: float = 0.5,
    top_n: int = 3,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for scenario_id, truth in sorted(ground_truth_by_scenario.items()):
        expected = {str(value) for value in truth.get("technique_ids") or []}
        if not expected:
            continue
        result = results_by_scenario.get(scenario_id) or {}
        status = str(result.get("mapping_status") or "not_run")
        primary = result.get("primary_mapping") if isinstance(result.get("primary_mapping"), dict) else None
        primary_id = str(primary["technique_id"]) if primary and primary.get("technique_id") else None
        candidates = ranked_candidates(result, 5)
        candidate_set = set(candidates[:top_n])

        is_parent = bool(primary_id) and any(parent_map.get(value) == primary_id for value in expected)
        is_child = bool(primary_id) and any(parent_map.get(primary_id) == value for value in expected)
        primary_hit = bool(primary_id) and primary_id in expected
        exact_top1 = primary_hit and len(expected) == 1
        top_n_hit = bool(expected & candidate_set)
        all_expected_top_n = expected.issubset(candidate_set)
        if primary_hit:
            partial = 1.0
        elif is_parent or is_child:
            partial = partial_credit_parent
        else:
            partial = 0.0
        answered = status in ANSWERED_STATUS and primary_id is not None
        wrong_primary = answered and not primary_hit and not is_parent and not is_child
        latency = result.get("latency_ms")
        try:
            latency_value = float(latency) if latency is not None else None
        except (TypeError, ValueError):
            latency_value = None

        rows.append({
            "scenario_id": scenario_id,
            "group": truth.get("group") or scenario_group(scenario_id),
            "family": truth.get("family") or scenario_family(scenario_id),
            "expected": sorted(expected),
            "status": status,
            "primary": primary_id,
            "candidates": candidates,
            "exact_top1": exact_top1,
            "primary_hit": primary_hit,
            "top_n_hit": top_n_hit,
            "all_expected_top_n": all_expected_top_n,
            "partial_credit": partial,
            "wrong_primary": wrong_primary,
            "abstain": status in ABSTAIN_STATUS or primary_id is None,
            "coverage": answered,
            "latency_ms": latency_value,
        })

    total = len(rows)
    latencies = [
        row["latency_ms"]
        for row in rows
        if row["latency_ms"] is not None
        and row["status"] not in {"skipped", "error", "not_run"}
    ]

    def count(predicate: Callable[[dict[str, Any]], bool]) -> int:
        return sum(1 for row in rows if predicate(row))

    status_counts = Counter(row["status"] for row in rows)
    summary = {
        "strategy": strategy,
        "n": total,
        "exact_top1": _rate(count(lambda row: row["exact_top1"]), total),
        "primary_hit": _rate(count(lambda row: row["primary_hit"]), total),
        f"top{top_n}_hit": _rate(count(lambda row: row["top_n_hit"]), total),
        f"all_expected_top{top_n}": _rate(count(lambda row: row["all_expected_top_n"]), total),
        "partial_credit_mean": round(
            sum(row["partial_credit"] for row in rows) / total, 4
        ) if total else None,
        "wrong_primary": _rate(count(lambda row: row["wrong_primary"]), total),
        "wrong_primary_over_answered": _rate(
            count(lambda row: row["wrong_primary"]),
            count(lambda row: row["coverage"]),
        ),
        "coverage": _rate(count(lambda row: row["coverage"]), total),
        "abstain": _rate(count(lambda row: row["abstain"]), total),
        "status_counts": dict(sorted(status_counts.items())),
        "latency_ms": {
            "count": len(latencies),
            "mean": round(statistics.mean(latencies), 3) if latencies else None,
            "median": round(statistics.median(latencies), 3) if latencies else None,
            "p95": _percentile(latencies, 0.95),
            "min": round(min(latencies), 3) if latencies else None,
            "max": round(max(latencies), 3) if latencies else None,
        },
    }
    return {
        "strategy": strategy,
        "summary": summary,
        "scenarios": rows,
        "breakdown": {
            "by_group": _breakdown(rows, lambda row: row["group"] or "unknown"),
            "by_family": _breakdown(rows, lambda row: row["family"] or "unknown"),
        },
    }


def _breakdown(
    rows: list[dict[str, Any]], key: Callable[[dict[str, Any]], str],
) -> dict[str, Any]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[key(row)].append(row)
    output: dict[str, Any] = {}
    for bucket, items in sorted(buckets.items()):
        total = len(items)
        output[bucket] = {
            "n": total,
            "exact_top1": round(sum(item["exact_top1"] for item in items) / total, 4),
            "primary_hit": round(sum(item["primary_hit"] for item in items) / total, 4),
            "top_n_hit": round(sum(item["top_n_hit"] for item in items) / total, 4),
            "partial_credit_mean": round(
                sum(item["partial_credit"] for item in items) / total, 4
            ),
            "wrong_primary": sum(item["wrong_primary"] for item in items),
            "coverage": round(sum(item["coverage"] for item in items) / total, 4),
        }
    return output


def mcnemar(
    first: dict[str, bool], second: dict[str, bool],
) -> dict[str, Any]:
    """Exact McNemar test over paired per-scenario successes."""

    common = sorted(set(first) & set(second))
    only_first = sum(1 for key in common if first[key] and not second[key])
    only_second = sum(1 for key in common if second[key] and not first[key])
    discordant = only_first + only_second
    if discordant == 0:
        p_value = 1.0
    else:
        tail = min(only_first, only_second)
        p_value = min(1.0, 2 * sum(
            math.comb(discordant, index) for index in range(tail + 1)
        ) / (2 ** discordant))
    return {
        "n": len(common),
        "only_first": only_first,
        "only_second": only_second,
        "discordant": discordant,
        "p_value": round(p_value, 6),
    }
