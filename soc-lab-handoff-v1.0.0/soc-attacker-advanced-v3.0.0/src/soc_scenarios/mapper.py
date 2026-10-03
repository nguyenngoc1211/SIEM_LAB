"""HTTP boundary for the n8n normalization and ATT&CK mapping workflow."""

from __future__ import annotations

import json
import urllib.request
from typing import Any


def _mapping_payload(value: Any) -> dict[str, Any]:
    """Extract a mapping object from common n8n response envelopes."""
    if isinstance(value, list):
        if len(value) != 1:
            raise ValueError("n8n response must contain exactly one mapping item")
        return _mapping_payload(value[0])
    if not isinstance(value, dict):
        raise ValueError("n8n response must be a JSON object")
    if value.get("mapping_status"):
        return value
    if value.get("status") and "primary_mapping" in value:
        return {**value, "mapping_status": value["status"]}
    for key in (
        "mapping", "mapping_snapshot", "mapper_output", "attack_mapping", "body", "json",
    ):
        nested = value.get(key)
        if isinstance(nested, (dict, list)):
            try:
                return _mapping_payload(nested)
            except ValueError:
                continue
        if isinstance(nested, str):
            try:
                return _mapping_payload(json.loads(nested))
            except (json.JSONDecodeError, ValueError):
                continue
    raise ValueError("n8n response does not contain mapping_status")


def map_alert(
    event: dict[str, Any], webhook_url: str, timeout: int = 30, *,
    scenario_id: str | None = None, run_id: str | None = None,
) -> dict[str, Any]:
    """Send one raw Wazuh alert through the active n8n workflow."""
    headers = {"Content-Type": "application/json"}
    if scenario_id:
        headers["X-SOC-Scenario"] = scenario_id
    if run_id:
        headers["X-SOC-Run-Id"] = run_id
    request = urllib.request.Request(
        webhook_url,
        data=json.dumps(event, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    return _mapping_payload(payload)


def mapped_techniques(results: list[dict[str, Any]]) -> set[str]:
    values: set[str] = set()
    for result in results:
        mappings = result.get("mappings")
        if isinstance(mappings, list):
            for mapping in mappings:
                if isinstance(mapping, dict) and mapping.get("technique_id"):
                    values.add(str(mapping["technique_id"]))
        primary = result.get("primary_mapping")
        if isinstance(primary, dict) and primary.get("technique_id"):
            values.add(str(primary["technique_id"]))
    return values
