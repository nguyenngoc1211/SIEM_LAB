from __future__ import annotations

import csv
import json
import os
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


CSV_FIELDS = [
    "Scenario ID", "Category", "Scenario Name", "Expected MITRE",
    "Expected Detection", "Execution Status", "Traffic Generated",
    "Suricata Telemetry", "Suricata Alert", "Suricata SID",
    "Suricata Signature", "Wazuh Alert", "Wazuh Rule ID", "Wazuh Level",
    "Mapped MITRE", "Mapping Correct", "Latency", "False Positive",
    "False Negative", "Notes", "Run ID",
]


def _runtime_dir() -> Path:
    configured = os.environ.get("SOC_RUNTIME")
    if configured:
        return Path(configured)
    here = Path(__file__).resolve()
    candidates = [here.parents[1] / "runtime", here.parents[3] / "runtime"]
    return next((path for path in candidates if path.exists()), candidates[-1])


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    cleaned = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                rows.append(value)
    return rows


def _read_wazuh(path: Path | None, container: str) -> tuple[list[dict[str, Any]], str | None]:
    if path:
        return _read_jsonl(path), None
    try:
        completed = subprocess.run(
            ["docker", "exec", container, "sh", "-c",
             "tail -n 50000 /var/ossec/logs/alerts/alerts.json 2>/dev/null || true"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except Exception as error:
        return [], type(error).__name__ + ": " + str(error)
    rows = []
    for line in completed.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    note = None if completed.returncode == 0 else completed.stderr.strip()[:300]
    return rows, note


def _sid_from_eve(event: dict[str, Any]) -> int | None:
    value = (event.get("alert") or {}).get("signature_id")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sid_from_wazuh(event: dict[str, Any]) -> int | None:
    value = (((event.get("data") or {}).get("alert") or {}).get("signature_id"))
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _event_time(event: dict[str, Any]) -> datetime | None:
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    return _parse_time(data.get("timestamp") or event.get("timestamp") or event.get("@timestamp"))


def _in_window(event: dict[str, Any], start: datetime, end: datetime) -> bool:
    timestamp = _event_time(event)
    return timestamp is not None and start <= timestamp <= end


def _eve_segment(events: list[dict[str, Any]], record: dict[str, Any]) -> list[dict[str, Any]]:
    """Use marker order as ground-truth boundaries, not as a detection signal.

    Docker Desktop can resynchronise a VM clock while a short scenario is running.
    File order remains stable even when wall-clock timestamps move backwards.
    """
    run_id = str(record.get("run_id") or "")
    start_index = None
    end_index = None
    for index, event in enumerate(events):
        url = str((event.get("http") or {}).get("url") or "")
        if run_id not in url or "/__soc_attack_marker__" not in url:
            continue
        if "phase=start" in url:
            start_index = index
        elif "phase=end" in url and start_index is not None and index >= start_index:
            end_index = index
            break
    if start_index is not None and end_index is not None:
        return events[start_index:end_index + 1]
    start = _parse_time(record.get("start_time"))
    end = _parse_time(record.get("end_time"))
    if not start or not end:
        return []
    if end < start:
        start, end = end, start
    return [event for event in events if _in_window(event, start, end)]


def _flow_ids(events: Iterable[dict[str, Any]]) -> set[str]:
    return {str(event["flow_id"]) for event in events if event.get("flow_id") is not None}


def _wazuh_flow_id(event: dict[str, Any]) -> str | None:
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    value = data.get("flow_id")
    if value is None:
        return None
    # Wazuh's JSON decoder renders Suricata's integer flow_id as "N.000000".
    return str(value).split(".", 1)[0]


def _as_strings(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, list):
        return {str(item) for item in value}
    return {str(value)}


def _suricata_mitre(events: Iterable[dict[str, Any]]) -> set[str]:
    techniques: set[str] = set()
    for event in events:
        metadata = (event.get("alert") or {}).get("metadata") or {}
        techniques |= _as_strings(metadata.get("mitre_technique_id"))
    return techniques


def _wazuh_mitre(events: Iterable[dict[str, Any]]) -> set[str]:
    techniques: set[str] = set()
    for event in events:
        techniques |= _as_strings((((event.get("rule") or {}).get("mitre") or {}).get("id")))
    return techniques


def _map_alert(event: dict[str, Any], mapper_url: str | None) -> tuple[set[str], str | None]:
    if not mapper_url:
        return set(), None
    try:
        request = urllib.request.Request(
            mapper_url.rstrip("/") + "/map",
            data=json.dumps(event).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.load(response)
    except Exception as error:
        return set(), "mapper unavailable: " + type(error).__name__ + ": " + str(error)
    primary = result.get("primary_mapping") or {}
    technique = primary.get("technique_id")
    return ({str(technique)} if technique else set()), "mapper_status=" + str(result.get("mapping_status"))


def _status(record: dict[str, Any], telemetry: bool, suricata_alert: bool,
            wazuh_alert: bool, mapping_correct: bool, false_positive: bool) -> str:
    if record.get("execution_error") or not record.get("scenario_executed"):
        return "INFRA_ERROR"
    if not record.get("traffic_generated") or not telemetry:
        return "NO_TELEMETRY"
    if false_positive:
        return "FALSE_POSITIVE"
    if record.get("expected_detection") and not suricata_alert:
        return "FAIL"
    if record.get("expected_detection") and (not wazuh_alert or not mapping_correct):
        return "PARTIAL"
    return "PASS"


def generate_report(
    *,
    ground_truth: Path | None = None,
    eve: Path | None = None,
    wazuh: Path | None = None,
    output_dir: Path | None = None,
    mapper_url: str | None = None,
    wazuh_container: str = "single-node-wazuh.manager-1",
) -> tuple[Path, Path]:
    runtime = _runtime_dir()
    ground_truth = ground_truth or runtime / "ground-truth" / "scenario-runs.jsonl"
    eve = eve or runtime / "suricata-logs" / "eve.json"
    output_dir = output_dir or runtime / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    records = [row for row in _read_jsonl(ground_truth) if row.get("record_type") == "scenario"]
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        latest[record["scenario_id"]] = record
    records = sorted(latest.values(), key=lambda value: value["start_time"])
    eve_events = _read_jsonl(eve)
    if wazuh is None:
        configured_wazuh = os.environ.get("WAZUH_ALERTS_PATH")
        if configured_wazuh and Path(configured_wazuh).exists():
            wazuh = Path(configured_wazuh)
    wazuh_events, wazuh_note = _read_wazuh(wazuh, wazuh_container)
    results: list[dict[str, Any]] = []
    for record in records:
        start = _parse_time(record.get("start_time"))
        end = _parse_time(record.get("end_time"))
        if not start or not end:
            continue
        expected_sids = {
            int(item["sid"]) for item in record.get("expected_suricata", [])
            if item.get("sid") is not None
        }
        window_eve = _eve_segment(eve_events, record)
        matching_eve = [
            event for event in window_eve
            if event.get("event_type") == "alert" and _sid_from_eve(event) in expected_sids
        ]
        baseline_custom = [
            event for event in window_eve
            if event.get("event_type") == "alert"
            and (_sid_from_eve(event) or 0) in range(1001001, 1001100)
        ]
        matching_flow_ids = _flow_ids(matching_eve)
        if matching_flow_ids:
            window_wazuh = [event for event in wazuh_events if _wazuh_flow_id(event) in matching_flow_ids]
        else:
            window_wazuh = [event for event in wazuh_events if _in_window(event, start, end)]
        matching_wazuh = [event for event in window_wazuh if _sid_from_wazuh(event) in expected_sids]
        telemetry = any(event.get("event_type") in {"http", "flow", "alert", "anomaly"} for event in window_eve)
        expected_detection = bool(record.get("expected_detection"))
        suricata_alert = bool(matching_eve)
        wazuh_alert = bool(matching_wazuh)
        false_positive = not expected_detection and bool(baseline_custom)
        false_negative = expected_detection and not suricata_alert
        mapped = _suricata_mitre(matching_eve) | _wazuh_mitre(matching_wazuh)
        mapper_note = None
        if matching_wazuh and mapper_url:
            api_mapped, mapper_note = _map_alert(matching_wazuh[0], mapper_url)
            mapped |= api_mapped
        expected_mitre = set(record.get("expected_mitre") or [])
        mapping_correct = not expected_mitre or expected_mitre.issubset(mapped)
        signatures = sorted({
            str((event.get("alert") or {}).get("signature"))
            for event in matching_eve if (event.get("alert") or {}).get("signature")
        })
        sids = sorted({_sid_from_eve(event) for event in matching_eve if _sid_from_eve(event)})
        wazuh_rule_ids = sorted({
            str((event.get("rule") or {}).get("id"))
            for event in matching_wazuh if (event.get("rule") or {}).get("id")
        })
        wazuh_levels = sorted({
            str((event.get("rule") or {}).get("level"))
            for event in matching_wazuh if (event.get("rule") or {}).get("level") is not None
        })
        alert_times = [_parse_time(event.get("timestamp")) for event in matching_eve]
        alert_times = [value for value in alert_times if value]
        latency = round(abs((alert_times[0] - start).total_seconds()) * 1000, 3) if alert_times else ""
        notes = []
        if record.get("execution_error"):
            notes.append("attack generator problem: " + str(record["execution_error"]))
        if record.get("traffic_generated") and not telemetry:
            notes.append("Suricata visibility problem")
        if expected_detection and telemetry and not suricata_alert:
            notes.append("missing Suricata rule or rule did not match")
        if suricata_alert and not wazuh_alert:
            notes.append("Wazuh ingestion problem")
        if wazuh_alert and expected_mitre and not mapping_correct:
            notes.append("MITRE mapper problem: expected mapping absent")
        if wazuh_note:
            notes.append("Wazuh collector: " + wazuh_note)
        if mapper_note:
            notes.append(mapper_note)
        result = {
            "Scenario ID": record["scenario_id"],
            "Category": record["category"],
            "Scenario Name": record["name"],
            "Expected MITRE": ";".join(record.get("expected_mitre") or []),
            "Expected Detection": expected_detection,
            "Execution Status": _status(
                record, telemetry, suricata_alert, wazuh_alert, mapping_correct, false_positive,
            ),
            "Traffic Generated": bool(record.get("traffic_generated")),
            "Suricata Telemetry": telemetry,
            "Suricata Alert": suricata_alert,
            "Suricata SID": ";".join(str(value) for value in sids),
            "Suricata Signature": ";".join(signatures),
            "Wazuh Alert": wazuh_alert,
            "Wazuh Rule ID": ";".join(wazuh_rule_ids),
            "Wazuh Level": ";".join(wazuh_levels),
            "Mapped MITRE": ";".join(sorted(mapped)),
            "Mapping Correct": mapping_correct,
            "Latency": latency,
            "False Positive": false_positive,
            "False Negative": false_negative,
            "Notes": "; ".join(notes),
            "Run ID": record["run_id"],
        }
        results.append(result)

    csv_path = output_dir / "scenario-results.csv"
    json_path = output_dir / "scenario-results.json"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(results)
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump({"schema_version": "2.0", "results": results}, handle, ensure_ascii=False, indent=2)
    return csv_path, json_path
