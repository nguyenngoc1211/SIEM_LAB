"""Build a frozen, leakage-free benchmark dataset from archived A1/A2 runs."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..database import read_json, sha256_file, write_json, write_jsonl
from .sanitize import (
    ATTACK_ID_IN_TEXT_RE,
    SANITIZER_VERSION,
    is_sensitive_key,
    sanitize_alert,
)


DATASET_VERSION = "1.0.0"
FAMILY_RE = re.compile(r"^(A\d+)-(T[0-9]+(?:\.[0-9]+)?)-\d+$", re.IGNORECASE)


def scenario_group(scenario_id: str | None) -> str | None:
    if not scenario_id:
        return None
    return str(scenario_id).split("-", 1)[0].upper()


def scenario_family(scenario_id: str | None) -> str | None:
    if not scenario_id:
        return None
    match = FAMILY_RE.match(str(scenario_id))
    return match.group(2).upper() if match else None


def find_leakage(value: Any, path: str = "") -> list[str]:
    """Return paths that still look like ATT&CK identifier leakage."""

    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            if is_sensitive_key(key):
                findings.append(child)
            findings.extend(find_leakage(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(find_leakage(item, f"{path}[{index}]"))
    elif isinstance(value, str) and ATTACK_ID_IN_TEXT_RE.search(value):
        findings.append(path or "<root>")
    return findings


def _report_files(reports_root: Path, groups: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for group in groups:
        directory = reports_root / group
        if not directory.is_dir():
            continue
        files.extend(sorted(directory.glob(f"{group.upper()}-*.json")))
    return files


def build_dataset(
    reports_root: Path,
    output_dir: Path,
    *,
    project_root: Path | None = None,
    groups: Iterable[str] = ("a1", "a2"),
    scrub_inline_ids: bool = True,
) -> dict[str, Any]:
    """Extract normalized alerts, ground truth, and archived hybrid results."""

    reports_root = Path(reports_root)
    output_dir = Path(output_dir)
    project_root = Path(project_root) if project_root else output_dir.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    alerts: list[dict[str, Any]] = []
    ground_truth: list[dict[str, Any]] = []
    archived_hybrid: list[dict[str, Any]] = []
    source_reports: list[dict[str, Any]] = []
    extraction_errors: list[dict[str, Any]] = []

    for path in _report_files(reports_root, groups):
        source_reports.append({
            "path": str(path).replace("\\", "/"),
            "sha256": sha256_file(path),
        })
        try:
            report = read_json(path)
        except (ValueError, OSError) as exc:
            extraction_errors.append({"path": str(path), "error": str(exc)})
            continue
        scenario_id = report.get("scenario_id")
        run_id = report.get("run_id")
        group = scenario_group(scenario_id)
        family = scenario_family(scenario_id)
        gt = report.get("ground_truth") if isinstance(report.get("ground_truth"), dict) else {}
        technique_ids = [
            str(value).strip().upper()
            for value in (gt.get("technique_ids") or [])
            if str(value).strip()
        ]
        tactic_ids = [
            str(value).strip().upper()
            for value in (gt.get("tactic_ids") or [])
            if str(value).strip()
        ]
        ground_truth.append({
            "scenario_id": scenario_id,
            "run_id": run_id,
            "group": group,
            "family": family,
            "scenario_name": report.get("scenario_name"),
            "technique_ids": technique_ids,
            "tactic_ids": tactic_ids,
            "expected_mapping_status": gt.get("expected_mapping_status"),
        })

        outputs = report.get("mapper_output") if isinstance(report.get("mapper_output"), list) else []
        hybrid = outputs[0] if outputs and isinstance(outputs[0], dict) else {}
        normalized = hybrid.get("normalized_alert")
        if not isinstance(normalized, dict):
            extraction_errors.append({
                "path": str(path),
                "scenario_id": scenario_id,
                "error": "mapper_output[0].normalized_alert is missing",
            })
            continue

        clean, sanitization = sanitize_alert(normalized, scrub_inline_ids=scrub_inline_ids)
        leakage = find_leakage(clean)
        alerts.append({
            "scenario_id": scenario_id,
            "run_id": run_id,
            "group": group,
            "family": family,
            "input_source": "archived_n8n_normalized_alert",
            "sanitization": sanitization,
            "leakage_paths": leakage,
            "input": clean,
        })
        pipeline = hybrid.get("pipeline") if isinstance(hybrid.get("pipeline"), dict) else {}
        archived_hybrid.append({
            "strategy": "hybrid_current",
            "scenario_id": scenario_id,
            "mapping_status": hybrid.get("mapping_status"),
            "primary_mapping": hybrid.get("primary_mapping"),
            "alternative_candidates": hybrid.get("alternative_candidates") or [],
            "candidate_trace": hybrid.get("candidate_trace") or [],
            "latency_ms": pipeline.get("latency_ms"),
            "details": {
                "source": "archived_report_mapper_output",
                "input_parity": "pre_sanitization_archived_run",
                "pipeline": pipeline,
            },
        })

    alerts_path = output_dir / "alerts.jsonl"
    ground_truth_path = output_dir / "ground_truth.jsonl"
    hybrid_path = output_dir / "archived_hybrid_results.jsonl"
    write_jsonl(alerts_path, alerts)
    write_jsonl(ground_truth_path, ground_truth)
    write_jsonl(hybrid_path, archived_hybrid)

    attack_manifest_path = project_root / "artifacts" / "attack" / "index_manifest.json"
    attack_manifest = read_json(attack_manifest_path) if attack_manifest_path.is_file() else {}

    manifest = {
        "dataset_version": DATASET_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sanitizer_version": SANITIZER_VERSION,
        "scrub_inline_ids": bool(scrub_inline_ids),
        "reports_root": str(reports_root).replace("\\", "/"),
        "groups": [str(group).lower() for group in groups],
        "counts": {
            "reports": len(source_reports),
            "alerts": len(alerts),
            "ground_truth": len(ground_truth),
            "archived_hybrid_results": len(archived_hybrid),
            "extraction_errors": len(extraction_errors),
            "alerts_with_leakage_after_sanitize": sum(1 for item in alerts if item["leakage_paths"]),
            "removed_fields": sum(item["sanitization"]["counts"]["removed_fields"] for item in alerts),
            "scrubbed_values": sum(item["sanitization"]["counts"]["scrubbed_values"] for item in alerts),
        },
        "attack_index": {
            "index_version": attack_manifest.get("index_version"),
            "attack_final_sha256": attack_manifest.get("attack_final_sha256"),
            "technique_count": attack_manifest.get("technique_count"),
            "attack_version": attack_manifest.get("attack_version"),
        },
        "outputs": {
            "alerts": {
                "path": alerts_path.name,
                "sha256": sha256_file(alerts_path),
            },
            "ground_truth": {
                "path": ground_truth_path.name,
                "sha256": sha256_file(ground_truth_path),
            },
            "archived_hybrid_results": {
                "path": hybrid_path.name,
                "sha256": sha256_file(hybrid_path),
            },
        },
        "source_reports": source_reports,
        "extraction_errors": extraction_errors,
    }
    write_json(output_dir / "manifest.json", manifest)
    return manifest
