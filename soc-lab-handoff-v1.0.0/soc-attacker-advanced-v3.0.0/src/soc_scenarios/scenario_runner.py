"""Run SID-oriented A1/A2 scenarios against the already-running local lab."""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import time
import uuid
import re
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .actions import ACTIONS
from .a2_actions import run_a2_action
from .client import LabClient
from .evaluation import EvaluationResult, evaluate
from .eve import (
    AlertObservation, collect_alerts, file_offset, marker_segment, parse_time, read_jsonl,
)
from .rule_catalog import RuleCatalog
from .mapper import map_alert, mapped_techniques
from .scenario_model import Scenario, validate_scenario
from .siem import SIEMAlert, WazuhAlertFileClient, select_nearest_alert


LOG = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_time(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def monotonic_duration(started: float, finished: float) -> float:
    """Return non-negative elapsed time, independent of wall-clock corrections."""
    return round(max(0.0, finished - started), 3)


def _source_ip(target_host: str) -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((target_host, 80))
            return str(probe.getsockname()[0])
    except OSError:
        return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def _active_rule_text(sid: int) -> str | None:
    candidates = (
        Path("/opt/soc/rule-state/rules/soc-combined.rules"),
        Path("/opt/soc/rule-state/rules/suricata.rules"),
    )
    marker = re.compile(rf"(?:^|;)\s*sid\s*:\s*{sid}\s*;")
    for path in candidates:
        try:
            with path.open(encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if marker.search(line):
                        return line.rstrip("\r\n")
        except OSError:
            continue
    return None


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")


def _run_action(scenario: Scenario, client: LabClient) -> None:
    if scenario.execution.action_id:
        if scenario.execution.action_id.startswith("A2-"):
            run_a2_action(scenario.execution.action_id, client)
            return
        action = ACTIONS.get(scenario.execution.action_id)
        if action is None:
            raise ValueError(f"unknown registered action: {scenario.execution.action_id}")
        action(client)
        return
    command = scenario.execution.command
    if command not in {"./run.sh", "run.sh"} or scenario.path is None:
        raise ValueError("execution.command is restricted to run.sh in the scenario directory")
    script = (scenario.path.parent / "run.sh").resolve()
    if script.parent != scenario.path.parent.resolve() or not script.is_file():
        raise ValueError("scenario run.sh does not exist")
    completed = subprocess.run(
        ["/bin/sh", str(script)], cwd=str(script.parent), check=False,
        capture_output=True, text=True, timeout=scenario.timeout,
        env={**os.environ, "SCENARIO_ID": scenario.id, "SOC_TARGET": client.target},
    )
    client.results.append({
        "type": "command", "argv": ["/bin/sh", str(script)], "sent": True,
        "returncode": completed.returncode, "stdout": completed.stdout[-2000:],
        "stderr": completed.stderr[-2000:],
    })
    if completed.returncode != 0:
        raise RuntimeError(f"run.sh exited with {completed.returncode}")


def _healthcheck() -> bool:
    client = LabClient(scenario_id="SCENARIO-PREFLIGHT", run_id=str(uuid.uuid4()))
    result = client.request("GET", "/__gateway_health__", timeout=3)
    return bool(result.get("sent") and result.get("status") == 200)


def _wait_for_eve_marker(path: Path, offset: int, run_id: str, timeout: int) -> bool:
    """Prove sensor visibility instead of assuming container readiness."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events, _ = read_jsonl(path, offset=offset)
        for event in events:
            url = str((event.get("http") or {}).get("url") or "")
            if run_id in url and "/__soc_attack_marker__" in url:
                return True
        time.sleep(0.5)
    return False


def _traffic_generated(results: list[dict[str, Any]]) -> bool:
    return any(
        item.get("sent")
        for item in results
        if str(item.get("path", "")).split("?", 1)[0] != "/__soc_attack_marker__"
    )


def run_scenario(
    scenario: Scenario, catalog: RuleCatalog, *, eve_path: Path, wazuh_path: Path,
    report_dir: Path, ground_truth_path: Path, mapper_url: str | None = None,
    alert_quiet_seconds: float = 2.0,
) -> dict[str, Any]:
    """Execute one validated scenario and produce independent phase results."""
    errors = validate_scenario(scenario, catalog)
    if errors:
        raise ValueError("scenario configuration error: " + "; ".join(errors))

    gateway_ok = _healthcheck()
    if not gateway_ok:
        raise RuntimeError("gateway health check failed; start the existing lab stack first")

    probe_offset = file_offset(eve_path)
    probe_id = str(uuid.uuid4())
    probe = LabClient(scenario_id="SCENARIO-PREFLIGHT", run_id=probe_id)
    probe.request("GET", f"/__soc_attack_marker__?phase=probe&run_id={probe_id}")
    environment_ok = _wait_for_eve_marker(
        eve_path, probe_offset, probe_id, min(30, scenario.timeout),
    )
    if not environment_ok:
        raise RuntimeError("Suricata did not emit EVE telemetry for the preflight marker")

    eve_start = file_offset(eve_path)
    wazuh_start = file_offset(wazuh_path)
    run_id = str(uuid.uuid4())
    client = LabClient(scenario_id=scenario.id, run_id=run_id)
    started = utc_now()
    started_monotonic = time.monotonic()
    execution_error: str | None = None
    client.request("GET", f"/__soc_attack_marker__?phase=start&run_id={run_id}")
    try:
        _run_action(scenario, client)
    except Exception as error:
        execution_error = f"{type(error).__name__}: {error}"
        LOG.exception("Scenario %s execution failed", scenario.id)
    finally:
        client.request("GET", f"/__soc_attack_marker__?phase=end&run_id={run_id}")
    traffic_ok = _traffic_generated(client.results)
    execution_finished = started + timedelta(
        seconds=monotonic_duration(started_monotonic, time.monotonic()),
    )

    eve_alerts: list[AlertObservation] = []
    raw_eve_alerts: list[dict[str, Any]] = []
    siem_alerts: list[SIEMAlert] = []
    mapper_results: list[dict[str, Any]] = []
    mapper_errors: list[str] = []
    siem = WazuhAlertFileClient(wazuh_path)
    deadline = time.monotonic() + scenario.timeout
    candidate_fingerprint: tuple[tuple[str, ...], ...] = ()
    candidate_changed_at = time.monotonic()
    result: EvaluationResult
    while True:
        events, _ = read_jsonl(eve_path, offset=eve_start)
        segment = marker_segment(events, run_id)
        eve_alerts = collect_alerts(segment)
        raw_eve_alerts = [
            event for event in segment
            if event.get("event_type") == "alert"
            and int((event.get("alert") or {}).get("signature_id", -1)) in scenario.expected_sids
        ]
        flow_ids = {item.flow_id for item in eve_alerts if item.flow_id}
        siem_alerts = siem.query_alerts(
            started,
            started + timedelta(
                seconds=monotonic_duration(started_monotonic, time.monotonic()),
            ),
            scenario, flow_ids=flow_ids, offset=wazuh_start,
        )
        expected_siem_now = [
            item for item in siem_alerts if item.signature_id in scenario.expected_sids
        ]
        fingerprint = tuple(sorted(
            (
                item.event_id or "", item.sensor_timestamp or "", item.flow_id or "",
                str(item.signature_id or ""), item.transaction_id or "",
            )
            for item in expected_siem_now
        ))
        now = time.monotonic()
        if fingerprint != candidate_fingerprint:
            candidate_fingerprint = fingerprint
            candidate_changed_at = now
        result = evaluate(
            scenario, environment_ok=environment_ok,
            traffic_ok=traffic_ok and execution_error is None,
            eve_alerts=eve_alerts, siem_alerts=siem_alerts,
        )
        collection_ready = (
            result.detection_status == "PASS"
            and (not scenario.expected.ingestion_required or result.ingestion_status == "PASS")
            and bool(expected_siem_now)
            and now - candidate_changed_at >= max(0.0, alert_quiet_seconds)
        )
        if collection_ready or now >= deadline:
            break
        time.sleep(0.5)

    expected_siem = [
        item for item in siem_alerts if item.signature_id in scenario.expected_sids
    ]
    flow_ids = {item.flow_id for item in eve_alerts if item.flow_id}
    selected_siem = select_nearest_alert(
        expected_siem, expected_sids=set(scenario.expected_sids),
        flow_ids=flow_ids, reference_time=execution_finished,
    )
    mapper_results = []
    mapper_errors = []
    if mapper_url and selected_siem is not None:
        try:
            mapper_results.append(map_alert(
                selected_siem.raw, mapper_url,
                timeout=min(60, max(5, scenario.timeout)),
                scenario_id=scenario.id, run_id=run_id,
            ))
        except Exception as error:
            mapper_errors.append(f"{type(error).__name__}: {error}")
    result = evaluate(
        scenario, environment_ok=environment_ok,
        traffic_ok=traffic_ok and execution_error is None,
        eve_alerts=eve_alerts, siem_alerts=siem_alerts,
        mapper_techniques=mapped_techniques(mapper_results) if mapper_url else None,
        mapper_statuses={
            str(item.get("mapping_status")) for item in mapper_results
            if item.get("mapping_status")
        } if mapper_url else None,
        mapper_source="N8N_MAPPING_WEBHOOK",
    )
    duration_seconds = monotonic_duration(started_monotonic, time.monotonic())
    finished = started + timedelta(seconds=duration_seconds)
    expected_rules = []
    for sid in scenario.expected_sids:
        rule = catalog.rules[sid]
        expected_rules.append({
            **rule.to_dict(),
            "raw_rule": _active_rule_text(sid),
        })
    expected_alerts = [
        item for item in eve_alerts if item.signature_id in scenario.expected_sids
    ]
    selected_timestamp = (
        selected_siem.sensor_timestamp or selected_siem.timestamp
        if selected_siem is not None else None
    )
    selected_time = parse_time(selected_timestamp)
    selection_delta_ms = (
        round(abs((selected_time - execution_finished).total_seconds()) * 1000, 3)
        if selected_time is not None else None
    )

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "started_at": iso_time(started),
        "traffic_finished_at": iso_time(execution_finished),
        "finished_at": iso_time(finished),
        "duration_seconds": duration_seconds,
        "run_id": run_id,
        "environment": {"status": result.environment_status},
        "traffic": {
            "status": result.traffic_status,
            "generated": traffic_ok,
            "actions": client.results,
        },
        "attack_commands": [
            item["attack_command"] for item in client.results if item.get("attack_command")
        ],
        "ground_truth": {
            "tactic_ids": list(scenario.mitre.tactic_ids),
            "technique_ids": list(scenario.mitre.technique_ids),
            "expected_mapping_status": scenario.expected.mapping_status,
        },
        "detection": {
            "status": result.detection_status,
            "expected_sids": list(result.expected_sids),
            "observed_sids": list(result.observed_sids),
            "minimum_alerts": scenario.expected.minimum_alerts,
        },
        "siem": {
            "status": result.ingestion_status,
            "adapter": "wazuh_alerts_json",
        },
        "suricata_rules_triggered": expected_rules,
        "raw_suricata_alerts": raw_eve_alerts,
        "normalized_alerts": [
            result["normalized_alert"] for result in mapper_results
            if isinstance(result.get("normalized_alert"), dict)
        ],
        "raw_wazuh_alerts": [item.raw for item in expected_siem],
        "selected_wazuh_alert": selected_siem.raw if selected_siem is not None else None,
        "alert_correlation": {
            "suricata_candidate_count": len(expected_alerts),
            "wazuh_candidate_count": len(expected_siem),
            "flow_matched_candidate_count": sum(
                item.flow_id in flow_ids for item in expected_siem
            ) if flow_ids else 0,
            "selected_alert_id": selected_siem.event_id if selected_siem else None,
            "selected_flow_id": selected_siem.flow_id if selected_siem else None,
            "selected_transaction_id": (
                selected_siem.transaction_id if selected_siem else None
            ),
            "selected_sensor_timestamp": selected_timestamp,
            "selection_method": "nearest_to_traffic_finished_at",
            "selection_reference": iso_time(execution_finished),
            "selection_delta_ms": selection_delta_ms,
            "quiet_window_seconds": alert_quiet_seconds,
        },
        "mapper_output": mapper_results,
        "mapper_errors": mapper_errors,
        "mitre": {
            "status": result.mapping_status,
            "expected_tactics": list(scenario.mitre.tactic_ids),
            "expected_techniques": list(scenario.mitre.technique_ids),
            "observed_tactics": list(result.observed_tactics),
            "observed_techniques": list(result.observed_techniques),
            "mapping_sources": list(result.mapping_sources),
        },
        "expected_alerts": list(scenario.expected_sids),
        "observed_alerts": [item.to_dict() for item in expected_alerts],
        "siem_alerts": [
            {key: value for key, value in asdict(item).items() if key != "raw"}
            for item in expected_siem
        ],
        "unexpected_alerts": list(result.unexpected_sids),
        "result": result.result,
        "errors": ([execution_error] if execution_error else []) + mapper_errors,
    }
    _write_json(report_dir / f"{scenario.id}.json", payload)
    ground_truth = {
        "record_type": "scenario_run",
        "schema_version": "1.0",
        "run_id": run_id,
        "scenario_id": scenario.id,
        "name": scenario.name,
        "start_time": iso_time(started),
        "end_time": iso_time(execution_finished),
        "source": _source_ip(client.target_host),
        "target": client.target,
        "expected_mitre": list(scenario.mitre.technique_ids),
        "expected_sids": list(scenario.expected_sids),
        "expected_detection": True,
        "scenario_executed": execution_error is None,
        "traffic_generated": traffic_ok,
    }
    _append_jsonl(ground_truth_path, ground_truth)
    return payload


def print_result(report: dict[str, Any]) -> None:
    print("=" * 50)
    print("Scenario:", report["scenario_id"], "-", report["scenario_name"])
    print("Environment:", report["environment"]["status"])
    print("Traffic:", report["traffic"]["status"])
    print("Detection:", report["detection"]["status"])
    print("  Expected SID:", ", ".join(map(str, report["detection"]["expected_sids"])))
    print("  Observed SID:", ", ".join(map(str, report["detection"]["observed_sids"])) or "-")
    print("SIEM ingestion:", report["siem"]["status"])
    print("MITRE mapping:", report["mitre"]["status"])
    print("Additional alerts:", ", ".join(map(str, report["unexpected_alerts"])) or "-")
    print("Final:", report["result"])
    print("=" * 50)
