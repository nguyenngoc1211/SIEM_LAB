"""Write comparison artifacts for the baseline run."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..database import write_json
from .evaluate import mcnemar


def _scenario_success(metrics: dict[str, Any], field: str) -> dict[str, bool]:
    return {
        row["scenario_id"]: bool(row[field])
        for row in metrics["scenarios"]
    }


def build_comparison(
    metrics_by_strategy: dict[str, dict[str, Any]],
    *,
    dataset_manifest: dict[str, Any],
    config: dict[str, Any],
    primary_metric: str = "primary_hit",
) -> dict[str, Any]:
    pairs: dict[str, Any] = {}
    names = sorted(metrics_by_strategy)
    for index, first in enumerate(names):
        for second in names[index + 1:]:
            pairs[f"{first}__vs__{second}"] = mcnemar(
                _scenario_success(metrics_by_strategy[first], primary_metric),
                _scenario_success(metrics_by_strategy[second], primary_metric),
            )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "primary_metric": primary_metric,
        "dataset": {
            "dataset_version": dataset_manifest.get("dataset_version"),
            "created_at": dataset_manifest.get("created_at"),
            "counts": dataset_manifest.get("counts"),
            "attack_index": dataset_manifest.get("attack_index"),
            "alerts_sha256": (dataset_manifest.get("outputs") or {}).get("alerts", {}).get("sha256"),
            "ground_truth_sha256": (dataset_manifest.get("outputs") or {}).get("ground_truth", {}).get("sha256"),
        },
        "config": config,
        "summaries": {
            name: metrics_by_strategy[name]["summary"]
            for name in names
        },
        "paired_tests": pairs,
        "strategies": metrics_by_strategy,
    }


def write_reports(
    output_dir: Path,
    comparison: dict[str, Any],
    metrics_by_strategy: dict[str, dict[str, Any]],
) -> dict[str, str]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "comparison.json"
    csv_path = output_dir / "comparison.csv"
    md_path = output_dir / "comparison.md"

    write_json(json_path, comparison)

    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow([
            "strategy", "scenario_id", "group", "family", "expected", "status",
            "primary", "candidates_top3", "exact_top1", "primary_hit",
            "top3_hit", "partial_credit", "wrong_primary", "coverage", "latency_ms",
        ])
        for strategy in sorted(metrics_by_strategy):
            for row in metrics_by_strategy[strategy]["scenarios"]:
                writer.writerow([
                    strategy,
                    row["scenario_id"],
                    row["group"],
                    row["family"],
                    ";".join(row["expected"]),
                    row["status"],
                    row["primary"],
                    ";".join(row["candidates"][:3]),
                    int(row["exact_top1"]),
                    int(row["primary_hit"]),
                    int(row["top_n_hit"]),
                    row["partial_credit"],
                    int(row["wrong_primary"]),
                    int(row["coverage"]),
                    row["latency_ms"],
                ])

    md_path.write_text(_markdown(comparison), encoding="utf-8")
    return {
        "comparison_json": str(json_path),
        "comparison_csv": str(csv_path),
        "comparison_md": str(md_path),
    }


def _percent(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{100 * float(value):.1f}%"


def _number(value: Any) -> str:
    return "n/a" if value is None else str(value)


def _markdown(comparison: dict[str, Any]) -> str:
    summaries = comparison["summaries"]
    lines = [
        "# Baseline mapper comparison",
        "",
        f"- Generated at: `{comparison['generated_at']}`",
        f"- Primary paired metric: `{comparison['primary_metric']}`",
        f"- Dataset: `{comparison['dataset'].get('dataset_version')}` "
        f"({(comparison['dataset'].get('counts') or {}).get('alerts')} alerts)",
        f"- Alerts SHA-256: `{comparison['dataset'].get('alerts_sha256')}`",
        "",
        "## Overall metrics",
        "",
        "| Strategy | N | Exact top-1 | Primary hit | Top-3 hit | Partial credit | Wrong primary | Coverage | Abstain | Median latency (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for strategy in sorted(summaries):
        summary = summaries[strategy]
        top3_key = "top3_hit"
        lines.append(
            "| {strategy} | {n} | {exact} | {hit} | {top3} | {partial} | {wrong} | "
            "{coverage} | {abstain} | {latency} |".format(
                strategy=strategy,
                n=summary.get("n"),
                exact=_percent((summary.get("exact_top1") or {}).get("rate")),
                hit=_percent((summary.get("primary_hit") or {}).get("rate")),
                top3=_percent((summary.get(top3_key) or {}).get("rate")),
                partial=_percent(summary.get("partial_credit_mean")),
                wrong=_percent((summary.get("wrong_primary") or {}).get("rate")),
                coverage=_percent((summary.get("coverage") or {}).get("rate")),
                abstain=_percent((summary.get("abstain") or {}).get("rate")),
                latency=_number((summary.get("latency_ms") or {}).get("median")),
            )
        )

    lines.extend([
        "",
        "## Per-group breakdown",
        "",
        "| Strategy | Group | N | Exact top-1 | Primary hit | Top-3 hit | Partial credit |",
        "|---|---|---:|---:|---:|---:|---:|",
    ])
    for strategy in sorted(summaries):
        groups = comparison["strategies"][strategy]["breakdown"]["by_group"]
        for group in sorted(groups):
            row = groups[group]
            lines.append(
                f"| {strategy} | {group} | {row['n']} | {_percent(row['exact_top1'])} | "
                f"{_percent(row['primary_hit'])} | {_percent(row['top_n_hit'])} | "
                f"{_percent(row['partial_credit_mean'])} |"
            )

    lines.extend([
        "",
        "## Paired McNemar tests (primary hit)",
        "",
        "| Comparison | Only first | Only second | p-value |",
        "|---|---:|---:|---:|",
    ])
    for name, result in sorted(comparison["paired_tests"].items()):
        lines.append(
            f"| {name} | {result['only_first']} | {result['only_second']} | {result['p_value']} |"
        )

    warning_lines: list[str] = []
    for strategy in sorted(summaries):
        status_counts = summaries[strategy].get("status_counts") or {}
        incomplete = sum(
            count for status, count in status_counts.items()
            if status in {"skipped", "error", "invalid_output", "not_run"}
        )
        if incomplete:
            warning_lines.append(
                f"- `{strategy}`: {incomplete}/{summaries[strategy].get('n', 0)} runs did not "
                f"produce a mapping. Status counts: `{status_counts}`."
            )
    if warning_lines:
        lines.extend(["", "## Warnings", ""])
        lines.extend(warning_lines)

    lines.extend([
        "",
        "## Notes",
        "",
        "- `exact_top1` requires the single expected technique to be the primary mapping.",
        "- `primary_hit` accepts any expected technique as primary.",
        "- `partial_credit` gives 1.0 for an exact hit and 0.5 for a parent/child relation.",
        "- `hybrid_current` is read from archived reports and is a reference, not a re-run.",
        "- Status values `skipped` and `error` mean the strategy did not produce a mapping.",
        "",
    ])
    return "\n".join(lines)
