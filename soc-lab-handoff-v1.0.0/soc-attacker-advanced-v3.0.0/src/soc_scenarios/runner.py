from __future__ import annotations

import json
import os
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .actions import ACTIONS
from .client import LabClient


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _source_ip(target_host: str) -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((target_host, 80))
            return probe.getsockname()[0]
    except OSError:
        return None


def _write_record(record: dict[str, Any]) -> None:
    output = Path(os.environ.get(
        "GROUND_TRUTH_PATH", "/opt/soc/runtime/ground-truth/scenario-runs.jsonl",
    ))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def run_scenario(metadata: dict[str, Any], *, dry_run: bool = False,
                 chain_id: str | None = None) -> dict[str, Any]:
    scenario_id = metadata["id"]
    run_id = str(uuid.uuid4())
    client = LabClient(scenario_id=scenario_id, run_id=run_id, dry_run=dry_run)
    started = utc_now()
    print("\n===", scenario_id, metadata["name"], "===")
    client.request("GET", "/__soc_attack_marker__?phase=start&run_id=" + run_id)
    execution_error = None
    try:
        ACTIONS[scenario_id](client)
    except Exception as error:
        execution_error = type(error).__name__ + ": " + str(error)
        print("SCENARIO ERROR:", execution_error)
    client.request("GET", "/__soc_attack_marker__?phase=end&run_id=" + run_id)
    ended = utc_now()
    action_results = [
        result for result in client.results
        if result.get("path", "").split("?", 1)[0] != "/__soc_attack_marker__"
    ]
    record = {
        "record_type": "scenario",
        "schema_version": "2.0",
        "run_id": run_id,
        "chain_id": chain_id,
        "scenario_id": scenario_id,
        "name": metadata["name"],
        "category": metadata["category"],
        "start_time": started,
        "end_time": ended,
        "source": _source_ip(client.target_host),
        "target": client.target,
        "expected_mitre": metadata["mitre"]["expected_techniques"],
        "expected_detection": metadata["expected_detection"],
        "expected_suricata": metadata["expected_suricata"],
        "expected_wazuh": metadata["expected_wazuh"],
        "minimum_alert_count": metadata["minimum_alert_count"],
        "scenario_executed": execution_error is None and not dry_run,
        "traffic_generated": any(result.get("sent") for result in action_results),
        "execution_error": execution_error,
        "actions": action_results,
    }
    if not dry_run:
        _write_record(record)
    print("GROUND TRUTH", json.dumps({
        "run_id": run_id,
        "scenario_id": scenario_id,
        "scenario_executed": record["scenario_executed"],
        "traffic_generated": record["traffic_generated"],
    }))
    return record


def write_chain_record(chain_id: str, chain: dict[str, Any],
                       records: list[dict[str, Any]]) -> dict[str, Any]:
    record = {
        "record_type": "chain",
        "schema_version": "2.0",
        "run_id": str(uuid.uuid4()),
        "chain_id": chain_id,
        "name": chain["name"],
        "purpose": chain["purpose"],
        "scenario_ids": chain["scenarios"],
        "scenario_run_ids": [item["run_id"] for item in records],
        "start_time": records[0]["start_time"],
        "end_time": records[-1]["end_time"],
        "scenario_executed": all(item["scenario_executed"] for item in records),
        "traffic_generated": all(item["traffic_generated"] for item in records),
    }
    _write_record(record)
    return record
