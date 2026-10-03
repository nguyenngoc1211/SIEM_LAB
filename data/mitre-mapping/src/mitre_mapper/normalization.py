from __future__ import annotations

import json
import re
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


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple, set)) else [value]
    result: list[str] = []
    for item in values:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _infer_event_semantics(rule_name: Any, http_status: Any) -> tuple[str, str, str]:
    """Infer controlled behavior fields from sensor language, never test markers."""
    text = str(rule_name or "").lower()
    if re.search(r"\b(brute[ -]?force|password (?:spray|guess)|credential attack)\b", text):
        return "authentication", "login", "failure"
    if re.search(r"\b(scan|scanner|enumerat|fingerprint|service discovery|reconnaissance)\w*\b", text):
        action = "discover" if "discovery" in text or "enumerat" in text else "probe"
        return "network_scan", action, "unknown"
    if re.search(r"\b(c2|command and control|beacon)\b", text):
        return "network_communication", "connect", "unknown"
    if re.search(r"\b(exfiltrat|data transfer|encoded payload)\w*\b", text):
        return "data_transfer", "transfer", "unknown"
    if re.search(
        r"\b(sql injection|xss|cross-site scripting|path traversal|lfi|file inclusion|"
        r"command injection|prototype pollution|jwt tamper|ssrf|file upload|framing conflict)\b",
        text,
    ):
        return "web_request", "exploit", "unknown"
    try:
        status = int(http_status)
    except (TypeError, ValueError):
        status = None
    if status in {401, 403}:
        return "authentication", "login", "failure"
    return "network_event", "unknown", "unknown"


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
        ("Declared MITRE tactics", _get(alert, "mitre.tactic_ids")),
        ("Declared MITRE techniques", _get(alert, "mitre.technique_ids")),
    ]
    parts = []
    for label, value in fields:
        if value is None or value == "":
            continue
        if isinstance(value, (list, tuple, set)):
            display = ", ".join(str(item) for item in value)
        else:
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
    sensor_rule_name = _first(
        wazuh,
        "data.alert.signature",
        "data.signature",
        "alert.signature",
        "message",
    )
    sensor_rule_id = _first(
        wazuh, "data.alert.signature_id", "data.signature_id", "alert.signature_id",
    )
    collector_rule_id = _first(wazuh, "rule.id")
    tactic_ids = _string_list(_first(
        wazuh, "data.alert.metadata.mitre_tactic_id",
        "alert.metadata.mitre_tactic_id", "rule.mitre.tactic",
    ))
    technique_ids = _string_list(_first(
        wazuh, "data.alert.metadata.mitre_technique_id",
        "alert.metadata.mitre_technique_id", "rule.mitre.id",
    ))
    wazuh_description = _first(wazuh, "rule.description")
    rule_name_parts = []
    for value in (sensor_rule_name, wazuh_description):
        if value and value not in rule_name_parts:
            rule_name_parts.append(str(value))
    rule_name = " | ".join(rule_name_parts) or "Unknown IDS alert"
    http_status = _first(wazuh, "data.http.status", "http.response.status_code")
    inferred_type, inferred_action, inferred_outcome = _infer_event_semantics(rule_name, http_status)
    raw_event_type = _first(wazuh, "event.type", "data.event_type", "data.event.type")
    event_type = inferred_type if raw_event_type in {None, "", "alert"} else raw_event_type
    action = _first(wazuh, "event.action", "data.event.action", "data.action") or inferred_action
    application_protocol = _first(wazuh, "data.app_proto", "network.protocol")
    target_type = "application" if application_protocol in {"http", "tls"} or event_type == "web_request" else "service"
    alert: dict[str, Any] = {
        "schema_version": "1.0",
        "producer": {
            "type": "nids",
            "name": _first(wazuh, "data.app_proto", "decoder.name") or "Suricata/Wazuh",
            "rule_id": sensor_rule_id or collector_rule_id,
            "rule_name": rule_name or "Unknown IDS alert",
        },
        "data_source": {"category": "network_traffic", "subcategory": _first(wazuh, "rule.groups.0")},
        "event": {
            "type": event_type,
            "action": action,
            "outcome": _first(wazuh, "event.outcome", "data.event.outcome") or inferred_outcome,
            "disposition": _first(wazuh, "data.alert.action", "event.disposition") or "unknown",
        },
        "source": {
            "type": "host",
            "ip": _first(wazuh, "data.src_ip", "data.srcip", "source.ip"),
            "port": _first(wazuh, "data.src_port", "data.srcport", "source.port"),
        },
        "target": {
            "type": target_type,
            "ip": _first(wazuh, "data.dest_ip", "data.dst_ip", "data.destip", "destination.ip"),
            "port": _first(wazuh, "data.dest_port", "data.dst_port", "data.destport", "destination.port"),
        },
        "network": {
            "transport": _first(wazuh, "data.proto", "network.transport"),
            "application_protocol": application_protocol,
            "direction": _first(wazuh, "data.direction", "network.direction", "data.flow.direction"),
        },
    }
    if collector_rule_id is not None and str(collector_rule_id) != str(sensor_rule_id):
        alert["producer"]["collector_rule_id"] = collector_rule_id
    if tactic_ids or technique_ids:
        alert["mitre"] = {
            "tactic_ids": tactic_ids,
            "technique_ids": technique_ids,
            "source": "sensor_rule_metadata",
        }
    http = {
        "method": _first(wazuh, "data.http.http_method", "http.request.method"),
        "path": _first(wazuh, "data.http.url", "url.path"),
        "status_code": http_status,
    }
    if any(value is not None for value in http.values()):
        alert["http"] = http
    alert["derived"] = {
        "retrieval_text": build_retrieval_text(alert),
        "renderer_version": "retrieval-text-renderer-1.0",
    }
    return alert
