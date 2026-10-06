"""Orchestrate baseline execution, scoring, and report generation."""

from __future__ import annotations

import json
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..database import read_json, read_jsonl, write_json, write_jsonl
from .base import load_parent_map
from .bm25_only import BM25OnlyStrategy
from .compare import build_comparison, write_reports
from .evaluate import evaluate_strategy
from .gemini_only import GeminiOnlyStrategy, QuotaExhausted


def load_dataset(dataset_dir: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, Any]]:
    dataset_dir = Path(dataset_dir)
    alerts = read_jsonl(dataset_dir / "alerts.jsonl")
    ground_truth_rows = read_jsonl(dataset_dir / "ground_truth.jsonl")
    ground_truth = {
        row["scenario_id"]: row for row in ground_truth_rows if row.get("scenario_id")
    }
    manifest_path = dataset_dir / "manifest.json"
    manifest = read_json(manifest_path) if manifest_path.is_file() else {}
    return alerts, ground_truth, manifest


def load_archived_hybrid(path: Path) -> dict[str, dict[str, Any]]:
    path = Path(path)
    if not path.is_file():
        return {}
    return {
        row["scenario_id"]: row
        for row in read_jsonl(path)
        if row.get("scenario_id")
    }


def latest_rows(path: Path) -> dict[str, dict[str, Any]]:
    """Load a result file keeping the last row per scenario id."""

    path = Path(path)
    if not path.is_file():
        return {}
    latest: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(path):
        scenario_id = row.get("scenario_id")
        if scenario_id:
            latest[scenario_id] = row
    return latest


def build_strategies(
    project_root: Path,
    names: list[str],
    config: dict[str, Any],
    *,
    dry_run: bool = False,
    repeats_override: int | None = None,
    gemini_model_override: str | None = None,
    gemini_arm_name: str = "gemini_only",
    gemini_api_key_env: str | None = None,
    gemini_thinking_budget: int | None = None,
) -> dict[str, Any]:
    strategies: dict[str, Any] = {}
    if "bm25_only" in names:
        bm25_config = dict(config.get("bm25_only", {}))
        extra_variants = bm25_config.pop("extra_variants", [])
        strategies["bm25_only"] = BM25OnlyStrategy(project_root, **bm25_config)
        for variant in extra_variants:
            variant_config = dict(bm25_config)
            variant_config["variant"] = variant
            strategies[f"bm25_only_{variant}"] = BM25OnlyStrategy(project_root, **variant_config)
    if "gemini_only" in names:
        gemini_config = dict(config.get("gemini_only", {}))
        if gemini_model_override:
            gemini_config["model"] = gemini_model_override
        if gemini_api_key_env:
            gemini_config["api_key_env"] = gemini_api_key_env
        if gemini_thinking_budget is not None:
            gemini_config["thinking_budget"] = gemini_thinking_budget
        if repeats_override is not None:
            gemini_config["repeats"] = int(repeats_override)
        strategy = GeminiOnlyStrategy(
            project_root, dry_run=dry_run, **gemini_config,
        )
        if gemini_arm_name and gemini_arm_name != "gemini_only":
            strategy.name = gemini_arm_name
        strategies[strategy.name] = strategy
    return strategies


def run_strategy(
    strategy: Any,
    alerts: list[dict[str, Any]],
    *,
    limit: int | None = None,
    checkpoint_path: Path | None = None,
    resume: bool = True,
) -> dict[str, dict[str, Any]]:
    success_statuses = {"mapped", "uncertain", "insufficient_evidence"}
    results: dict[str, dict[str, Any]] = {}
    signature = _strategy_signature(strategy)
    if checkpoint_path is not None and resume:
        meta_path = checkpoint_path.with_suffix(checkpoint_path.suffix + ".meta.json")
        existing_signature = None
        if meta_path.is_file():
            try:
                existing_signature = read_json(meta_path).get("signature")
            except (ValueError, OSError):
                existing_signature = None
        if existing_signature == signature and checkpoint_path.is_file():
            for row in read_jsonl(checkpoint_path):
                scenario_id = row.get("scenario_id")
                if scenario_id and row.get("mapping_status") in success_statuses:
                    results[scenario_id] = row
        elif checkpoint_path.is_file():
            # Configuration changed: drop stale rows instead of mixing runs.
            checkpoint_path.write_text("", encoding="utf-8")
    if checkpoint_path is not None:
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        checkpoint_path.with_suffix(checkpoint_path.suffix + ".meta.json").write_text(
            json.dumps({"signature": signature, "strategy": getattr(strategy, "name", "unknown")},
                       ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    for index, alert_row in enumerate(alerts):
        if limit is not None and index >= limit:
            break
        scenario_id = alert_row.get("scenario_id")
        if not scenario_id:
            continue
        if scenario_id in results:
            continue
        started = time.perf_counter()
        try:
            result = strategy.map_alert(alert_row["input"], scenario_id=scenario_id).to_dict()
        except QuotaExhausted as exc:
            result = {
                "schema_version": "1.0.0",
                "strategy": getattr(strategy, "name", "unknown"),
                "scenario_id": scenario_id,
                "mapping_status": "error",
                "primary_mapping": None,
                "alternative_candidates": [],
                "candidate_trace": [],
                "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                "details": {"errors": [f"QuotaExhausted: {exc}"]},
            }
            results[scenario_id] = result
            if checkpoint_path is not None:
                with checkpoint_path.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
                    stream.flush()
            break
        except Exception as exc:  # noqa: BLE001 - keep one bad alert from aborting the run
            result = {
                "schema_version": "1.0.0",
                "strategy": getattr(strategy, "name", "unknown"),
                "scenario_id": scenario_id,
                "mapping_status": "error",
                "primary_mapping": None,
                "alternative_candidates": [],
                "candidate_trace": [],
                "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                "details": {"errors": [f"{type(exc).__name__}: {exc}"]},
            }
        results[scenario_id] = result
        if checkpoint_path is not None:
            with checkpoint_path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
                stream.flush()
    return results


def _strategy_signature(strategy: Any) -> str:
    """Fingerprint the settings that affect a strategy's output."""

    keys = (
        "name", "version", "model", "mode", "temperature", "repeats",
        "prompt_version", "max_output_tokens", "thinking_budget",
        "variant", "min_score", "margin_ratio",
    )
    payload = {key: getattr(strategy, key, None) for key in keys}
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def consensus_results(
    results: dict[str, dict[str, Any]],
    name_by_id: dict[str, str],
    arm_name: str = "gemini_only",
) -> dict[str, dict[str, Any]]:
    consensus: dict[str, dict[str, Any]] = {}
    for scenario_id, result in results.items():
        details = result.get("details") if isinstance(result.get("details"), dict) else {}
        votes = details.get("consensus")
        if not isinstance(votes, dict):
            continue
        technique_id = votes.get("primary_technique_id")
        primary = None
        if technique_id:
            primary = {
                "technique_id": technique_id,
                "name": name_by_id.get(technique_id, technique_id),
                "confidence": votes.get("agreement", 0.0),
            }
        consensus[scenario_id] = {
            "schema_version": "1.0.0",
            "strategy": f"{arm_name}_consensus",
            "scenario_id": scenario_id,
            "mapping_status": votes.get("mapping_status", "insufficient_evidence"),
            "primary_mapping": primary,
            "alternative_candidates": [],
            "candidate_trace": [],
            "latency_ms": result.get("latency_ms"),
            "details": {
                "source": "majority_vote_across_repeats",
                "votes": votes.get("votes"),
                "agreement": votes.get("agreement"),
            },
        }
    return consensus


def run_comparison(
    project_root: Path,
    dataset_dir: Path,
    output_dir: Path,
    *,
    strategy_names: list[str] | None = None,
    config_path: Path | None = None,
    dry_run: bool = False,
    limit: int | None = None,
    repeats_override: int | None = None,
    include_archived_hybrid: bool = True,
    resume: bool = True,
    gemini_model_override: str | None = None,
    gemini_arm_name: str = "gemini_only",
    gemini_api_key_env: str | None = None,
    gemini_thinking_budget: int | None = None,
    load_only_arms: list[str] | None = None,
) -> dict[str, Any]:
    project_root = Path(project_root)
    dataset_dir = Path(dataset_dir)
    output_dir = Path(output_dir)
    config_path = Path(config_path) if config_path else project_root / "configs" / "baselines.json"
    config = read_json(config_path) if config_path.is_file() else {}
    strategy_names = strategy_names or ["bm25_only", "gemini_only"]

    alerts, ground_truth, dataset_manifest = load_dataset(dataset_dir)
    parent_map = load_parent_map(project_root / "artifacts" / "attack" / "attack_final.mapping.json")
    strategies = build_strategies(
        project_root, strategy_names, config,
        dry_run=dry_run, repeats_override=repeats_override,
        gemini_model_override=gemini_model_override,
        gemini_arm_name=gemini_arm_name,
        gemini_api_key_env=gemini_api_key_env,
        gemini_thinking_budget=gemini_thinking_budget,
    )

    raw_results: dict[str, dict[str, dict[str, Any]]] = {}
    checkpoint_dir = output_dir / "checkpoints"
    for name, strategy in strategies.items():
        result_map = run_strategy(
            strategy, alerts,
            limit=limit,
            checkpoint_path=checkpoint_dir / f"{name}.jsonl",
            resume=resume,
        )
        raw_results[name] = result_map
        if isinstance(strategy, GeminiOnlyStrategy) and getattr(strategy, "repeats", 1) > 1:
            extra = consensus_results(result_map, strategy.name_by_id, arm_name=name)
            if extra:
                raw_results["gemini_only_consensus"] = extra

    if include_archived_hybrid:
        hybrid = load_archived_hybrid(dataset_dir / "archived_hybrid_results.jsonl")
        if hybrid:
            raw_results["hybrid_current"] = hybrid

    for arm in load_only_arms or []:
        if arm in raw_results:
            continue
        loaded = latest_rows(checkpoint_dir / f"{arm}.jsonl")
        if not loaded:
            loaded = latest_rows(output_dir / "raw_results" / f"{arm}.jsonl")
        if loaded:
            raw_results[arm] = loaded

    top_n = int((config.get("evaluation") or {}).get("top_n", 3))
    partial_credit = float((config.get("evaluation") or {}).get("partial_credit_parent", 0.5))
    metrics_by_strategy: dict[str, dict[str, Any]] = {}
    for name, result_map in raw_results.items():
        metrics_by_strategy[name] = evaluate_strategy(
            name, result_map, ground_truth, parent_map,
            partial_credit_parent=partial_credit, top_n=top_n,
        )

    raw_dir = output_dir / "raw_results"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_paths: dict[str, str] = {}
    for name, result_map in raw_results.items():
        path = raw_dir / f"{name}.jsonl"
        write_jsonl(path, [result_map[key] for key in sorted(result_map)])
        raw_paths[name] = str(path)

    comparison = build_comparison(
        metrics_by_strategy,
        dataset_manifest=dataset_manifest,
        config=config,
    )
    comparison["run"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": bool(dry_run),
        "limit": limit,
        "repeats_override": repeats_override,
        "strategies": sorted(raw_results),
        "raw_results": raw_paths,
        "config_path": str(config_path),
        "loaded_arms": list(load_only_arms or []),
    }
    report_paths = write_reports(output_dir, comparison, metrics_by_strategy)
    comparison["run"]["report_paths"] = report_paths
    write_json(output_dir / "comparison.json", comparison)
    write_json(output_dir / "run_metadata.json", {
        "generated_at": comparison["run"]["generated_at"],
        "dry_run": bool(dry_run),
        "limit": limit,
        "repeats_override": repeats_override,
        "strategies": sorted(raw_results),
        "dataset_manifest": dataset_manifest,
        "config": config,
        "raw_results": raw_paths,
        "report_paths": report_paths,
    })
    return comparison
