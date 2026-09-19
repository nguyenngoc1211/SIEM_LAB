from __future__ import annotations

import json
from copy import deepcopy
from typing import Any


def _get(value: Any, path: str, default: Any = None) -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _first(source: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _get(source, path)
        if value is not None:
            return value
    return None


def unwrap_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError("Alert payload must be a JSON object")
    if isinstance(value.get("body"), dict):
        value = value["body"]
    elif isinstance(value.get("body"), str):
        value = json.loads(value["body"])
    if isinstance(value.get("alert"), dict) and not value.get("producer"):
        value = value["alert"]
    return value


def build_retrieval_text(alert: dict[str, Any]) -> str:
    fields = [
        ("IDS rule", _get(alert, "producer.rule_name")),
        ("Event type", _get(alert, "event.type")),
        ("Action", _get(alert, "event.action")),
        ("Outcome", _get(alert, "event.outcome")),
        ("Disposition", _get(alert, "event.disposition")),
        ("Data source", _get(alert, "data_source.category")),
        ("Target type", _get(alert, "target.type")),
        ("Protocol", _get(alert, "network.application_protocol") or _get(alert, "network.transport")),
        ("Source port", _get(alert, "source.port")),
        ("Destination port", _get(alert, "target.port")),
        ("HTTP method", _get(alert, "http.method")),
        ("HTTP path", _get(alert, "http.path")),
        ("HTTP query", _get(alert, "http.query")),
        ("HTTP status", _get(alert, "http.status_code")),
        ("DNS query", _get(alert, "dns.question.name")),
        ("Network direction", _get(alert, "network.direction")),
        ("Attack pattern", _get(alert, "derived.attack_pattern")),
    ]
    parts = []
    for label, value in fields:
        if value is None or value == "":
            continue
        display = str(value).replace("_", " ")
        parts.append(f"{label}: {display}.")
    return "\n".join(parts)


def normalize_alert(payload: Any) -> dict[str, Any]:
    source = unwrap_payload(payload)
    if source.get("producer") and source.get("event"):
        alert = deepcopy(source)
        alert.setdefault("schema_version", "1.0")
        alert.setdefault("derived", {})
        if not alert["derived"].get("retrieval_text"):
            alert["derived"]["retrieval_text"] = build_retrieval_text(alert)
        alert["derived"].setdefault("renderer_version", "retrieval-text-renderer-1.0")
        return alert

    wazuh = source.get("_source") if isinstance(source.get("_source"), dict) else source
    data = wazuh.get("data") if isinstance(wazuh.get("data"), dict) else {}
    rule_name = _first(
        wazuh,
        "rule.description",
        "data.alert.signature",
        "data.signature",
        "alert.signature",
        "message",
    )
    event_type = _first(wazuh, "event.type", "data.event_type", "data.event.type") or "network_event"
    action = _first(wazuh, "event.action", "data.event.action", "data.action") or "unknown"
    alert: dict[str, Any] = {
        "schema_version": "1.0",
        "producer": {
            "type": "nids",
            "name": _first(wazuh, "data.app_proto", "decoder.name") or "Suricata/Wazuh",
            "rule_id": _first(wazuh, "rule.id", "data.alert.signature_id"),
            "rule_name": rule_name or "Unknown IDS alert",
        },
        "data_source": {"category": "network_traffic", "subcategory": _first(wazuh, "rule.groups.0")},
        "event": {
            "type": event_type,
            "action": action,
            "outcome": _first(wazuh, "event.outcome", "data.event.outcome") or "unknown",
            "disposition": _first(wazuh, "data.alert.action", "event.disposition") or "unknown",
        },
        "source": {
            "type": "host",
            "ip": _first(wazuh, "data.src_ip", "data.srcip", "source.ip"),
            "port": _first(wazuh, "data.src_port", "data.srcport", "source.port"),
        },
        "target": {
            "type": "service",
            "ip": _first(wazuh, "data.dest_ip", "data.dst_ip", "data.destip", "destination.ip"),
            "port": _first(wazuh, "data.dest_port", "data.dst_port", "data.destport", "destination.port"),
        },
        "network": {
            "transport": _first(wazuh, "data.proto", "network.transport"),
            "application_protocol": _first(wazuh, "data.app_proto", "network.protocol"),
            "direction": _first(wazuh, "network.direction", "data.flow.direction"),
        },
    }
    http = {
        "method": _first(wazuh, "data.http.http_method", "http.request.method"),
        "path": _first(wazuh, "data.http.url", "url.path"),
        "status_code": _first(wazuh, "data.http.status", "http.response.status_code"),
    }
    if any(value is not None for value in http.values()):
        alert["http"] = http
    alert["derived"] = {
        "retrieval_text": build_retrieval_text(alert),
        "renderer_version": "retrieval-text-renderer-1.0",
    }
    return alert
