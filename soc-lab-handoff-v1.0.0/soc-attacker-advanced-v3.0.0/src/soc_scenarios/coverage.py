"""Compute technique, scenario, and rule coverage from catalog and YAML scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .rule_catalog import RuleCatalog
from .scenario_model import load_scenario


def build_coverage(catalog: RuleCatalog, scenario_paths: Iterable[Path]) -> dict[str, Any]:
    scenarios = [load_scenario(path) for path in scenario_paths]
    available: dict[str, set[int]] = {}
    for rule in catalog.rules.values():
        if not rule.enabled:
            continue
        for technique in rule.mitre.get("techniques", []):
            available.setdefault(technique.id, set()).add(rule.sid)
    tested: dict[str, set[int]] = {}
    scenario_count: dict[str, int] = {}
    for scenario in scenarios:
        for technique in scenario.mitre.technique_ids:
            tested.setdefault(technique, set()).update(scenario.expected_sids)
            scenario_count[technique] = scenario_count.get(technique, 0) + 1
    techniques: dict[str, Any] = {}
    for technique in sorted(set(available) | set(tested)):
        rules_available = available.get(technique, set())
        rules_tested = tested.get(technique, set()) & rules_available
        status = (
            "NOT_TESTED" if not rules_tested
            else "FULL" if rules_available and rules_tested == rules_available
            else "PARTIAL"
        )
        techniques[technique] = {
            "rules_available": len(rules_available),
            "rules_tested": len(rules_tested),
            "scenarios": scenario_count.get(technique, 0),
            "status": status,
        }
    tested_techniques = sum(item["status"] != "NOT_TESTED" for item in techniques.values())
    mapped_rules = {sid for values in available.values() for sid in values}
    tested_rules = {sid for values in tested.values() for sid in values} & mapped_rules
    return {
        "summary": {
            "technique_coverage": f"{tested_techniques}/{len(techniques)}",
            "scenario_count": len(scenarios),
            "rule_coverage": f"{len(tested_rules)}/{len(mapped_rules)}",
        },
        "techniques": techniques,
    }


def write_coverage(payload: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
