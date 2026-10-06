from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.database import read_jsonl, write_json, write_jsonl  # noqa: E402


SUCCESS_STATUSES = {"mapped", "uncertain", "insufficient_evidence"}


def latest_rows(path: Path) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        scenario_id = row.get("scenario_id")
        if scenario_id:
            latest[scenario_id] = row
    return latest


def error_reason(row: dict) -> str:
    errors = (row.get("details") or {}).get("errors") or []
    text = " ".join(str(value) for value in errors)
    match = re.search(r"HTTP\s+(\d{3})", text)
    if match:
        return f"HTTP {match.group(1)}"
    if "json_parse_error" in text:
        return "json_parse_error"
    if "skipped" in text:
        return "skipped"
    if not errors:
        return "unknown"
    return text[:80]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Archive every Gemini baseline attempt into one self-contained snapshot",
    )
    parser.add_argument("--run-dir", type=Path, default=ROOT / "reports" / "baselines")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "reports" / "baselines" / "snapshots" / "gemini_attempts_20261005",
    )
    args = parser.parse_args()

    checkpoint_dir = args.run_dir / "checkpoints"
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    arms = sorted(
        path.stem
        for path in checkpoint_dir.glob("gemini_only*.jsonl")
        if not path.name.endswith(".meta.json")
    )
    summary: dict = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "All Gemini attempts were stopped by user request. This snapshot keeps the "
            "successful mappings and the failure reasons for audit."
        ),
        "arms": {},
    }
    all_successful: list[dict] = []
    for arm in arms:
        path = checkpoint_dir / f"{arm}.jsonl"
        rows = latest_rows(path)
        ordered = [rows[key] for key in sorted(rows)]
        successful = [row for row in ordered if row.get("mapping_status") in SUCCESS_STATUSES]
        failed = [row for row in ordered if row.get("mapping_status") not in SUCCESS_STATUSES]
        write_jsonl(output_dir / f"{arm}.latest.jsonl", ordered)
        write_jsonl(output_dir / f"{arm}.successful.jsonl", successful)
        error_rows = [
            {
                "scenario_id": row.get("scenario_id"),
                "mapping_status": row.get("mapping_status"),
                "reason": error_reason(row),
                "model": (row.get("details") or {}).get("model"),
                "latency_ms": row.get("latency_ms"),
                "errors": (row.get("details") or {}).get("errors", []),
            }
            for row in failed
        ]
        write_jsonl(output_dir / f"{arm}.errors.jsonl", error_rows)
        status_counts = Counter(row.get("mapping_status") for row in ordered)
        reason_counts = Counter(item["reason"] for item in error_rows)
        models = sorted({
            str((row.get("details") or {}).get("model"))
            for row in ordered
            if (row.get("details") or {}).get("model")
        })
        summary["arms"][arm] = {
            "checkpoint": str(path),
            "models": models,
            "attempted_scenarios": len(ordered),
            "successful": len(successful),
            "failed": len(failed),
            "status_counts": dict(sorted(status_counts.items())),
            "error_reasons": dict(sorted(reason_counts.items())),
            "successful_scenario_ids": [row["scenario_id"] for row in successful],
        }
        all_successful.extend(successful)

    summary["total_successful_rows"] = len(all_successful)
    summary["total_successful_unique_scenarios"] = len({
        row["scenario_id"] for row in all_successful
    })

    partial = args.run_dir / "snapshots" / "gemini_only_2.5_flash_partial"
    if partial.is_dir():
        copied = []
        for name in ("comparison.json", "comparison.csv", "comparison.md", "snapshot.json"):
            source = partial / name
            if source.is_file():
                shutil.copy2(source, output_dir / f"partial_2.5_flash_{name}")
                copied.append(f"partial_2.5_flash_{name}")
        summary["partial_evaluation_copied"] = copied

    write_json(output_dir / "summary.json", summary)
    lines = [
        "# Gemini baseline attempts archive",
        "",
        f"- Created at: `{summary['created_at']}`",
        f"- Total successful rows: {summary['total_successful_rows']}",
        f"- Unique scenarios with a successful Gemini mapping: "
        f"{summary['total_successful_unique_scenarios']}",
        "",
        "| Arm | Model | Attempted | Successful | Failed | Error reasons |",
        "|---|---|---:|---:|---:|---|",
    ]
    for arm in sorted(summary["arms"]):
        item = summary["arms"][arm]
        lines.append(
            f"| {arm} | {', '.join(item['models']) or 'n/a'} | {item['attempted_scenarios']} | "
            f"{item['successful']} | {item['failed']} | {item['error_reasons']} |"
        )
    lines.extend(["", "## Successful scenario ids", ""])
    for arm in sorted(summary["arms"]):
        item = summary["arms"][arm]
        if item["successful_scenario_ids"]:
            lines.append(f"- `{arm}`: {', '.join(item['successful_scenario_ids'])}")
    lines.append("")
    (output_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps(summary["arms"], ensure_ascii=False, indent=2))
    print(f"Wrote {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
