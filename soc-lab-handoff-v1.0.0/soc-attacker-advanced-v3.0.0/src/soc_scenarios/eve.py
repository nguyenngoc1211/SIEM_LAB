"""Streaming Suricata EVE reader and SID-based alert extraction."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, list):
        return {str(item) for item in value}
    return {str(value)}


@dataclass(frozen=True)
class AlertObservation:
    signature_id: int
    signature: str
    timestamp: str | None
    src_ip: str | None
    src_port: int | None
    dest_ip: str | None
    dest_port: int | None
    proto: str | None
    app_proto: str | None
    category: str | None
    severity: int | None
    flow_id: str | None
    tactics: tuple[str, ...] = field(default_factory=tuple)
    techniques: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def file_offset(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def read_jsonl(path: Path, *, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    events: list[dict[str, Any]] = []
    try:
        size = path.stat().st_size
    except OSError:
        return events, offset
    if size < offset:
        offset = 0
    with path.open("rb") as handle:
        handle.seek(offset)
        for raw in handle:
            try:
                value = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                events.append(value)
        return events, handle.tell()


def marker_segment(events: list[dict[str, Any]], run_id: str) -> list[dict[str, Any]]:
    start: int | None = None
    end: int | None = None
    for index, event in enumerate(events):
        url = str((event.get("http") or {}).get("url") or "")
        if run_id not in url or "/__soc_attack_marker__" not in url:
            continue
        if "phase=start" in url:
            start = index
        elif start is not None and "phase=end" in url:
            end = index
            break
    if start is None:
        return events
    return events[start:(end + 1 if end is not None else len(events))]


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def alert_observation(event: dict[str, Any]) -> AlertObservation | None:
    if event.get("event_type") != "alert" or not isinstance(event.get("alert"), dict):
        return None
    alert = event["alert"]
    sid = _integer(alert.get("signature_id"))
    if sid is None:
        return None
    metadata = alert.get("metadata") if isinstance(alert.get("metadata"), dict) else {}
    return AlertObservation(
        signature_id=sid, signature=str(alert.get("signature") or ""),
        timestamp=str(event.get("timestamp")) if event.get("timestamp") else None,
        src_ip=str(event.get("src_ip")) if event.get("src_ip") else None,
        src_port=_integer(event.get("src_port")),
        dest_ip=str(event.get("dest_ip")) if event.get("dest_ip") else None,
        dest_port=_integer(event.get("dest_port")),
        proto=str(event.get("proto")) if event.get("proto") else None,
        app_proto=str(event.get("app_proto")) if event.get("app_proto") else None,
        category=str(alert.get("category")) if alert.get("category") else None,
        severity=_integer(alert.get("severity")),
        flow_id=str(event.get("flow_id")) if event.get("flow_id") is not None else None,
        tactics=tuple(sorted(string_set(metadata.get("mitre_tactic_id")))),
        techniques=tuple(sorted(string_set(metadata.get("mitre_technique_id")))),
    )


def collect_alerts(events: Iterable[dict[str, Any]]) -> list[AlertObservation]:
    return [value for event in events if (value := alert_observation(event)) is not None]
