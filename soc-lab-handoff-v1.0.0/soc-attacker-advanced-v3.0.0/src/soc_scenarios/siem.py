"""Minimal SIEM boundary backed by the Wazuh alerts.json already in use."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .eve import parse_time, read_jsonl, string_set
from .scenario_model import Scenario


@dataclass(frozen=True)
class SIEMAlert:
    signature_id: int | None
    timestamp: str | None
    src_ip: str | None
    dest_ip: str | None
    flow_id: str | None
    rule_id: str | None
    rule_level: int | None
    sensor_timestamp: str | None = None
    transaction_id: str | None = None
    event_id: str | None = None
    tactics: tuple[str, ...] = field(default_factory=tuple)
    techniques: tuple[str, ...] = field(default_factory=tuple)
    mapping_source: str = "MISSING"
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


class SIEMClient(ABC):
    @abstractmethod
    def query_alerts(
        self, start_time: datetime, end_time: datetime, scenario: Scenario, *,
        flow_ids: set[str] | None = None, offset: int = 0,
    ) -> list[SIEMAlert]:
        """Return alerts associated with the scenario execution window."""


def _integer(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _data(event: dict[str, Any]) -> dict[str, Any]:
    return event.get("data") if isinstance(event.get("data"), dict) else {}


def _flow_id(event: dict[str, Any]) -> str | None:
    value = _data(event).get("flow_id")
    return str(value).split(".", 1)[0] if value is not None else None


def _sid(event: dict[str, Any]) -> int | None:
    alert = _data(event).get("alert")
    return _integer(alert.get("signature_id")) if isinstance(alert, dict) else None


def select_nearest_alert(
    alerts: list[SIEMAlert], *, expected_sids: set[int],
    flow_ids: set[str] | None, reference_time: datetime,
) -> SIEMAlert | None:
    """Choose one scenario alert nearest to traffic completion.

    SID is mandatory. When at least one expected-SID alert also matches a
    scenario flow, non-matching flows are discarded. Sensor event time is used
    instead of Wazuh ingestion time so ingestion latency cannot change the
    selection.
    """
    candidates = [item for item in alerts if item.signature_id in expected_sids]
    if flow_ids:
        flow_matches = [item for item in candidates if item.flow_id in flow_ids]
        if flow_matches:
            candidates = flow_matches
    if not candidates:
        return None

    def selection_key(item: SIEMAlert) -> tuple[float, float, str]:
        timestamp = parse_time(item.sensor_timestamp or item.timestamp)
        if timestamp is None:
            return (float("inf"), 0.0, item.event_id or "")
        return (
            abs((timestamp - reference_time).total_seconds()),
            -timestamp.timestamp(),
            item.event_id or "",
        )

    return min(candidates, key=selection_key)


def _mitre(event: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    rule_mitre = ((event.get("rule") or {}).get("mitre") or {})
    rule_techniques = string_set(rule_mitre.get("id"))
    data_alert = _data(event).get("alert")
    metadata = data_alert.get("metadata") if isinstance(data_alert, dict) else {}
    if not isinstance(metadata, dict):
        metadata = {}
    tactics = string_set(metadata.get("mitre_tactic_id"))
    raw_techniques = string_set(metadata.get("mitre_technique_id"))
    if rule_techniques:
        return tuple(sorted(tactics)), tuple(sorted(rule_techniques)), "WAZUH_RULE"
    if raw_techniques or tactics:
        return tuple(sorted(tactics)), tuple(sorted(raw_techniques)), "INGESTED_SENSOR_METADATA"
    return (), (), "MISSING"


class WazuhAlertFileClient(SIEMClient):
    """Query Wazuh's existing JSON alert file; no new API or service is added."""

    def __init__(self, path: Path):
        self.path = path

    def query_alerts(
        self, start_time: datetime, end_time: datetime, scenario: Scenario, *,
        flow_ids: set[str] | None = None, offset: int = 0,
    ) -> list[SIEMAlert]:
        events, _ = read_jsonl(self.path, offset=offset)
        expected_sids = set(scenario.expected_sids)
        tolerance_end = end_time + timedelta(seconds=scenario.timeout)
        results: list[SIEMAlert] = []
        for event in events:
            sid = _sid(event)
            flow_id = _flow_id(event)
            timestamp_text = str(event.get("timestamp") or _data(event).get("timestamp") or "")
            timestamp = parse_time(timestamp_text)
            flow_match = bool(flow_ids and flow_id in flow_ids)
            sid_match = sid in expected_sids
            time_match = timestamp is not None and start_time <= timestamp <= tolerance_end
            if not flow_match and not (sid_match and time_match):
                continue
            tactics, techniques, source = _mitre(event)
            rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
            results.append(SIEMAlert(
                signature_id=sid, timestamp=timestamp_text or None,
                src_ip=str(_data(event).get("src_ip")) if _data(event).get("src_ip") else None,
                dest_ip=str(_data(event).get("dest_ip")) if _data(event).get("dest_ip") else None,
                flow_id=flow_id, rule_id=str(rule.get("id")) if rule.get("id") else None,
                rule_level=_integer(rule.get("level")),
                sensor_timestamp=(
                    str(_data(event).get("timestamp"))
                    if _data(event).get("timestamp") else None
                ),
                transaction_id=(
                    str(_data(event).get("tx_id"))
                    if _data(event).get("tx_id") is not None else None
                ),
                event_id=str(event.get("id")) if event.get("id") else None,
                tactics=tactics,
                techniques=techniques, mapping_source=source, raw=event,
            ))
        return results
