from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.baselines.base import load_parent_map  # noqa: E402
from mitre_mapper.baselines.compare import build_comparison, write_reports  # noqa: E402
from mitre_mapper.baselines.evaluate import evaluate_strategy  # noqa: E402
from mitre_mapper.database import read_json, read_jsonl, write_json, write_jsonl  # noqa: E402


SUCCESS_STATUSES = {"mapped", "uncertain", "insufficient_evidence"}


def latest_rows(path: Path) -> list[dict]:
    latest: dict[str, dict] = {}
    order: list[str] = []
    if not path.is_file():
        return []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        scenario_id = row.get("scenario_id")
        if not scenario_id:
            continue
        if scenario_id not in latest:
            order.append(scenario_id)
        latest[scenario_id] = row
    return [latest[key] for key in order]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Snapshot successful baseline runs and score the completed subset",
    )
    parser.add_argument("--dataset-dir", type=Path, default=ROOT / "benchmark")
    parser.add_argument("--run-dir", type=Path, default=ROOT / "reports" / "baselines")
    parser.add_argument("--arm", default="gemini_only")
    parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=ROOT / "reports" / "baselines" / "snapshots" / "gemini_only_2.5_flash_partial",
    )
    args = parser.parse_args()

    checkpoint = args.run_dir / "checkpoints" / f"{args.arm}.jsonl"
    rows = latest_rows(checkpoint)
    successful = [row for row in rows if row.get("mapping_status") in SUCCESS_STATUSES]
    failed = [row for row in rows if row.get("mapping_status") not in SUCCESS_STATUSES]
    if not successful:
        print(f"No successful rows found in {checkpoint}")
        return 1

    snapshot_dir = args.snapshot_dir
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(snapshot_dir / f"{args.arm}.successful.jsonl", successful)
    write_jsonl(snapshot_dir / f"{args.arm}.errors.jsonl", [
        {
            "scenario_id": row.get("scenario_id"),
            "mapping_status": row.get("mapping_status"),
            "errors": (row.get("details") or {}).get("errors", []),
            "model": (row.get("details") or {}).get("model"),
            "latency_ms": row.get("latency_ms"),
        }
        for row in failed
    ])

    ground_truth_all = {
        row["scenario_id"]: row
        for row in read_jsonl(args.dataset_dir / "ground_truth.jsonl")
        if row.get("scenario_id")
    }
    subset_ids = {row["scenario_id"] for row in successful}
    ground_truth_subset = {
        key: value for key, value in ground_truth_all.items() if key in subset_ids
    }
    write_jsonl(snapshot_dir / "ground_truth_subset.jsonl", [
        ground_truth_subset[key] for key in sorted(ground_truth_subset)
    ])

    result_maps: dict[str, dict[str, dict]] = {
        args.arm: {row["scenario_id"]: row for row in successful},
    }
    for other in ("bm25_only", "bm25_only_threshold", "gemini_only_pro31"):
        other_rows = latest_rows(args.run_dir / "checkpoints" / f"{other}.jsonl")
        selected = {row["scenario_id"]: row for row in other_rows if row["scenario_id"] in subset_ids}
        if selected:
            result_maps[other] = selected
    hybrid_path = args.dataset_dir / "archived_hybrid_results.jsonl"
    if hybrid_path.is_file():
        hybrid = {
            row["scenario_id"]: row
            for row in read_jsonl(hybrid_path)
            if row.get("scenario_id") in subset_ids
        }
        if hybrid:
            result_maps["hybrid_current"] = hybrid

    parent_map = load_parent_map(ROOT / "artifacts" / "attack" / "attack_final.mapping.json")
    metrics = {
        name: evaluate_strategy(name, result_map, ground_truth_subset, parent_map)
        for name, result_map in result_maps.items()
    }
    manifest = read_json(args.dataset_dir / "manifest.json")
    manifest = dict(manifest)
    manifest["counts"] = dict(manifest.get("counts") or {})
    manifest["counts"]["alerts"] = len(subset_ids)
    comparison = build_comparison(
        metrics,
        dataset_manifest=manifest,
        config={
            "note": "partial subset: only scenarios with a successful Gemini run",
            "arm": args.arm,
            "subset_size": len(subset_ids),
        },
    )
    comparison["subset"] = {
        "scenario_ids": sorted(subset_ids),
        "n": len(subset_ids),
        "unfinished_scenarios": sorted(set(ground_truth_all) - subset_ids),
    }
    report_paths = write_reports(snapshot_dir, comparison, metrics)

    snapshot = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "arm": args.arm,
        "checkpoint": str(checkpoint),
        "total_rows_latest": len(rows),
        "successful": len(successful),
        "failed": len(failed),
        "subset_scenario_ids": sorted(subset_ids),
        "report_paths": report_paths,
        "caveat": (
            "Partial results: the subset is not random and is skewed toward A1 scenarios. "
            "Do not treat these numbers as the final B2 evaluation."
        ),
    }
    write_json(snapshot_dir / "snapshot.json", snapshot)

    print(json.dumps({
        "snapshot_dir": str(snapshot_dir),
        "successful": len(successful),
        "failed": len(failed),
        "subset_size": len(subset_ids),
        "summaries": {
            name: {
                "n": metrics[name]["summary"]["n"],
                "primary_hit": metrics[name]["summary"]["primary_hit"]["rate"],
                "top3_hit": metrics[name]["summary"]["top3_hit"]["rate"],
                "wrong_primary": metrics[name]["summary"]["wrong_primary"]["rate"],
                "coverage": metrics[name]["summary"]["coverage"]["rate"],
            }
            for name in sorted(metrics)
        },
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
