"""Typed scenario model, YAML loader, validation, and legacy adapter."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .rule_catalog import RuleCatalog
from .simple_yaml import load as load_yaml


SCENARIO_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,79}$")
TACTIC_RE = re.compile(r"^TA\d{4}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SAFE_CONTAINERS = {
    "attacker", "soc_attacker_v2", "gateway", "soc_gateway",
    "victim", "soc_juice_shop", "soc_lab_backend",
}


@dataclass(frozen=True)
class MitreExpectation:
    tactic_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]


@dataclass(frozen=True)
class Endpoint:
    container: str
    port: int | None = None
    type: str | None = None
    reference: str | None = None


@dataclass(frozen=True)
class Execution:
    action_id: str | None = None
    command: str | None = None


@dataclass(frozen=True)
class Expected:
    minimum_alerts: int = 1
    ingestion_required: bool = True
    mapping_required: bool = True
    mapping_status: str = "mapped"


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    description: str
    mitre: MitreExpectation
    expected_sids: tuple[int, ...]
    expected_rule_names: tuple[str, ...]
    rule_source: str | None
    source: Endpoint
    target: Endpoint
    execution: Execution
    expected: Expected = field(default_factory=Expected)
    timeout: int = 30
    path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, path: Path | None = None) -> "Scenario":
        def mapping(name: str) -> dict[str, Any]:
            value = data.get(name, {})
            if not isinstance(value, dict):
                raise ValueError(f"{name} must be a mapping")
            return value

        mitre = mapping("mitre")
        suricata = mapping("suricata")
        source = mapping("source")
        target = mapping("target")
        execution = mapping("execution")
        expected = mapping("expected")
        return cls(
            id=str(data.get("id", "")), name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            mitre=MitreExpectation(
                tactic_ids=tuple(str(value) for value in mitre.get("tactic_id", []) or []),
                technique_ids=tuple(str(value) for value in mitre.get("technique_id", []) or []),
            ),
            expected_sids=tuple(int(value) for value in suricata.get("expected_sid", []) or []),
            expected_rule_names=tuple(
                str(value) for value in suricata.get("rule_name", []) or []
            ) if isinstance(suricata.get("rule_name", []), list) else (
                (str(suricata["rule_name"]),) if suricata.get("rule_name") else ()
            ),
            rule_source=str(suricata["rule_source"]) if suricata.get("rule_source") else None,
            source=Endpoint(
                container=str(source.get("container", "")),
                type=str(source["type"]) if source.get("type") else None,
                reference=str(source["reference"]) if source.get("reference") else None,
            ),
            target=Endpoint(
                container=str(target.get("container", "")),
                port=int(target["port"]) if target.get("port") is not None else None,
            ),
            execution=Execution(
                action_id=str(execution["action_id"]) if execution.get("action_id") else None,
                command=str(execution["command"]) if execution.get("command") else None,
            ),
            expected=Expected(
                minimum_alerts=int(expected.get("minimum_alerts", 1)),
                ingestion_required=bool(expected.get("ingestion_required", True)),
                mapping_required=bool(expected.get("mapping_required", True)),
                mapping_status=str(expected.get("mapping_status", "mapped")),
            ),
            timeout=int(data.get("timeout", 30)), path=path,
        )


def load_scenario(path: Path) -> Scenario:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        data = load_yaml(path)
    if not isinstance(data, dict):
        raise ValueError("scenario document must be a mapping")
    return Scenario.from_dict(data, path=path)


def validate_scenario(scenario: Scenario, catalog: RuleCatalog | None = None) -> list[str]:
    errors: list[str] = []
    if not SCENARIO_ID_RE.fullmatch(scenario.id):
        errors.append("id must contain only uppercase letters, digits, '.', '_' or '-'")
    if not scenario.name:
        errors.append("name is required")
    if not scenario.description:
        errors.append("description is required")
    if not scenario.expected_sids:
        errors.append("suricata.expected_sid must contain at least one SID")
    if len(set(scenario.expected_sids)) != len(scenario.expected_sids):
        errors.append("suricata.expected_sid contains duplicate SID values")
    if len(scenario.expected_sids) != 1:
        errors.append("each scenario must define exactly one Suricata SID")
    if scenario.expected_rule_names and len(scenario.expected_rule_names) != len(scenario.expected_sids):
        errors.append("suricata.rule_name must contain one name per expected SID")
    for tactic in scenario.mitre.tactic_ids:
        if not TACTIC_RE.fullmatch(tactic):
            errors.append(f"invalid tactic ID: {tactic}")
    for technique in scenario.mitre.technique_ids:
        if not TECHNIQUE_RE.fullmatch(technique):
            errors.append(f"invalid technique ID: {technique}")
    if scenario.source.container not in SAFE_CONTAINERS:
        errors.append(f"source container is outside the lab allowlist: {scenario.source.container}")
    if scenario.target.container not in SAFE_CONTAINERS:
        errors.append(f"target container is outside the lab allowlist: {scenario.target.container}")
    if scenario.target.port is not None and not 1 <= scenario.target.port <= 65535:
        errors.append("target port must be between 1 and 65535")
    if bool(scenario.execution.action_id) == bool(scenario.execution.command):
        errors.append("execution must define exactly one of action_id or command")
    if scenario.expected.minimum_alerts < 1:
        errors.append("expected.minimum_alerts must be at least 1")
    if scenario.expected.mapping_status not in {"mapped", "uncertain", "insufficient_evidence"}:
        errors.append("expected.mapping_status must be mapped, uncertain, or insufficient_evidence")
    if scenario.timeout < 1 or scenario.timeout > 600:
        errors.append("timeout must be between 1 and 600 seconds")

    if catalog is not None and scenario.expected_sids:
        catalog_tactics: set[str] = set()
        catalog_techniques: set[str] = set()
        for index, sid in enumerate(scenario.expected_sids):
            rule = catalog.rules.get(sid)
            if rule is None or not rule.enabled:
                errors.append(f"expected SID {sid} does not exist in the active Rule Catalog")
                continue
            if scenario.expected_rule_names and scenario.expected_rule_names[index] != rule.signature:
                errors.append(
                    f"expected rule name for SID {sid} does not match active catalog: "
                    f"scenario={scenario.expected_rule_names[index]!r} catalog={rule.signature!r}"
                )
            if scenario.rule_source and scenario.rule_source not in {rule.source, "et_open"}:
                errors.append(
                    f"rule source for SID {sid} does not match active catalog: "
                    f"scenario={scenario.rule_source!r} catalog={rule.source!r}"
                )
            catalog_tactics.update(item.id for item in rule.mitre.get("tactics", []))
            catalog_techniques.update(item.id for item in rule.mitre.get("techniques", []))
        if catalog_tactics and set(scenario.mitre.tactic_ids) != catalog_tactics:
            errors.append(
                "expected tactic IDs must match active rule metadata: "
                f"scenario={sorted(scenario.mitre.tactic_ids)} catalog={sorted(catalog_tactics)}"
            )
        if catalog_techniques and set(scenario.mitre.technique_ids) != catalog_techniques:
            errors.append(
                "expected technique IDs must match active rule metadata: "
                f"scenario={sorted(scenario.mitre.technique_ids)} catalog={sorted(catalog_techniques)}"
            )
    return errors


def legacy_scenario(metadata: dict[str, Any]) -> Scenario:
    """Adapt one v2 JSON catalog entry without changing the existing format."""
    techniques = metadata.get("mitre", {}).get("expected_techniques", [])
    return Scenario(
        id=str(metadata["id"]), name=str(metadata["name"]),
        description=str(metadata.get("description", metadata["name"])),
        mitre=MitreExpectation(tactic_ids=(), technique_ids=tuple(techniques)),
        expected_sids=tuple(
            int(item["sid"]) for item in metadata.get("expected_suricata", [])
            if item.get("sid") is not None
        ),
        expected_rule_names=tuple(
            str(item.get("signature", "")) for item in metadata.get("expected_suricata", [])
        ),
        rule_source="custom",
        source=Endpoint("soc_attacker_v2"), target=Endpoint("soc_gateway", 80),
        execution=Execution(action_id=str(metadata["id"])),
        expected=Expected(
            minimum_alerts=max(1, int(metadata.get("minimum_alert_count", 1))),
            ingestion_required=bool(metadata.get("expected_detection", True)),
            mapping_required=bool(techniques),
            mapping_status="mapped",
        ),
        timeout=int(metadata.get("timeout", 30)),
    )
