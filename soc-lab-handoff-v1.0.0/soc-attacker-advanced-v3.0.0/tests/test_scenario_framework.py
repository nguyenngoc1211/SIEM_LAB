"""Unit tests use tiny fixtures and never depend on or execute the ET ruleset."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_scenarios.evaluation import evaluate
from soc_scenarios.eve import alert_observation, collect_alerts, read_jsonl
from soc_scenarios.scenario_runner import monotonic_duration
from soc_scenarios.mapper import _mapping_payload, mapped_techniques
from soc_scenarios.rule_catalog import MitreItem, RuleCatalog, RuleRecord, build_catalog, parse_rule
from soc_scenarios.scenario_model import load_scenario, validate_scenario
from soc_scenarios.siem import SIEMAlert, select_nearest_alert


RULE = (
    'alert http any any -> any any (msg:"Fixture"; '
    'metadata:mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, '
    'mitre_technique_id T1190, mitre_technique_name Exploit_Public-Facing_Application; '
    'sid:2008538; rev:2;)'
)
MULTI_RULE = (
    'alert http any any -> any any (msg:"Multi"; '
    'metadata:mitre_tactic_id TA0001, mitre_tactic_id TA0011, '
    'mitre_tactic_name Initial_Access, mitre_tactic_name Command_And_Control, '
    'mitre_technique_id T1190, mitre_technique_id T1071.001, '
    'mitre_technique_name Exploit, mitre_technique_name Web_Protocols; '
    'sid:9000001; rev:1;)'
)
SCENARIO = """\
id: SCN-T1190-TEST
name: Fixture scenario
description: Unit test fixture.
mitre:
  tactic_id:
    - TA0001
  technique_id:
    - T1190
suricata:
  expected_sid:
    - 2008538
source:
  container: soc_attacker_v2
target:
  container: soc_gateway
  port: 80
execution:
  action_id: RECON-03
expected:
  minimum_alerts: 1
  ingestion_required: true
  mapping_required: true
timeout: 10
"""


def fixture_catalog() -> RuleCatalog:
    record = parse_rule(RULE, default_file="fixture.rules")
    assert record is not None
    return RuleCatalog({record.sid: record})


class RuleCatalogTests(unittest.TestCase):
    def test_rule_parser(self) -> None:
        rule = parse_rule(RULE, default_file="fixture.rules")
        self.assertIsNotNone(rule)
        assert rule is not None
        self.assertEqual(rule.action, "alert")
        self.assertTrue(rule.enabled)

    def test_commented_rules_are_disabled(self) -> None:
        self.assertIsNone(parse_rule("#" + RULE, default_file="fixture.rules"))
        self.assertIsNone(parse_rule("#drop http any any -> any any (sid:9;)", default_file="x.rules"))

    def test_sid_and_revision(self) -> None:
        rule = parse_rule(RULE, default_file="fixture.rules")
        assert rule is not None
        self.assertEqual((rule.sid, rule.rev), (2008538, 2))

    def test_multiple_mitre_values(self) -> None:
        rule = parse_rule(MULTI_RULE, default_file="fixture.rules")
        assert rule is not None
        self.assertEqual(
            [item.id for item in rule.mitre["tactics"]], ["TA0001", "TA0011"],
        )
        self.assertEqual(
            [item.id for item in rule.mitre["techniques"]], ["T1190", "T1071.001"],
        )

    def test_duplicate_sid_warns_and_highest_revision_wins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.rules"
            path.write_text(
                RULE + "\n" + RULE.replace("rev:2", "rev:1").replace("Fixture", "Older"),
                encoding="utf-8",
            )
            catalog = build_catalog([path])
        self.assertEqual(catalog.rules[2008538].rev, 2)
        self.assertTrue(any("Duplicate active SID" in item for item in catalog.warnings))


class ScenarioTests(unittest.TestCase):
    def load_fixture(self):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "scenario.yaml"
        path.write_text(SCENARIO, encoding="utf-8")
        return directory, load_scenario(path)

    def test_yaml_validation(self) -> None:
        directory, scenario = self.load_fixture()
        try:
            self.assertEqual(scenario.id, "SCN-T1190-TEST")
            self.assertEqual(validate_scenario(scenario, fixture_catalog()), [])
        finally:
            directory.cleanup()

    def test_expected_sid_missing(self) -> None:
        directory, scenario = self.load_fixture()
        try:
            errors = validate_scenario(scenario, RuleCatalog({}))
            self.assertTrue(any("does not exist" in item for item in errors))
        finally:
            directory.cleanup()

    def test_expected_technique_must_match_active_rule_metadata(self) -> None:
        directory, scenario = self.load_fixture()
        try:
            wrong = RuleRecord(
                sid=2008538, rev=1, action="alert", protocol="http",
                signature="Wrong map", rule_file="fixture.rules", enabled=True, source="et",
                mitre={
                    "tactics": [MitreItem("TA0011", "Command_And_Control")],
                    "techniques": [MitreItem("T1071.001", "Web_Protocols")],
                },
            )
            errors = validate_scenario(scenario, RuleCatalog({2008538: wrong}))
            self.assertTrue(any("expected technique IDs must match" in item for item in errors))
        finally:
            directory.cleanup()


class EventAndEvaluationTests(unittest.TestCase):
    def test_n8n_mapping_response_envelopes(self) -> None:
        direct = {"mapping_status": "mapped", "primary_mapping": {"technique_id": "T1078"}}
        self.assertEqual(_mapping_payload(direct), direct)
        self.assertEqual(_mapping_payload({"mapping": direct}), direct)
        self.assertEqual(_mapping_payload({"mapping_snapshot": direct}), direct)
        wrapped = _mapping_payload({
            "attack_mapping": {
                "status": "mapped", "primary_mapping": {"technique_id": "T1078"},
            },
        })
        self.assertEqual(wrapped["mapping_status"], "mapped")

    def test_selects_expected_alert_nearest_to_traffic_completion(self) -> None:
        reference = datetime(2026, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        alerts = [
            SIEMAlert(
                signature_id=1002060, timestamp=None, src_ip=None, dest_ip=None,
                flow_id="123", rule_id="86601", rule_level=3,
                sensor_timestamp=(reference - timedelta(seconds=3)).isoformat(),
                transaction_id="27", event_id="old",
            ),
            SIEMAlert(
                signature_id=1002060, timestamp=None, src_ip=None, dest_ip=None,
                flow_id="123", rule_id="86601", rule_level=3,
                sensor_timestamp=(reference - timedelta(milliseconds=100)).isoformat(),
                transaction_id="29", event_id="nearest",
            ),
            SIEMAlert(
                signature_id=9999999, timestamp=None, src_ip=None, dest_ip=None,
                flow_id="123", rule_id="86601", rule_level=3,
                sensor_timestamp=reference.isoformat(), event_id="wrong-sid",
            ),
        ]
        selected = select_nearest_alert(
            alerts, expected_sids={1002060}, flow_ids={"123"}, reference_time=reference,
        )
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.event_id, "nearest")

    def test_mapper_collects_all_declared_mappings(self) -> None:
        results = [{
            "primary_mapping": {"technique_id": "T1110"},
            "mappings": [
                {"technique_id": "T1110"},
                {"technique_id": "T1110.001"},
            ],
        }]
        self.assertEqual({"T1110", "T1110.001"}, mapped_techniques(results))

    def test_monotonic_duration_never_becomes_negative(self) -> None:
        self.assertEqual(2.25, monotonic_duration(10.0, 12.25))
        self.assertEqual(0.0, monotonic_duration(12.25, 10.0))

    def test_eve_alert_parser(self) -> None:
        event = {
            "timestamp": "2026-01-01T00:00:00Z", "event_type": "alert",
            "src_ip": "172.20.0.2", "dest_ip": "172.20.0.3", "flow_id": 123,
            "alert": {
                "signature_id": 2008538, "signature": "Fixture",
                "category": "Attempted Information Leak", "severity": 2,
                "metadata": {"mitre_tactic_id": ["TA0001"], "mitre_technique_id": ["T1190"]},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eve.json"
            path.write_text(json.dumps(event) + "\nnot-json\n", encoding="utf-8")
            values, _ = read_jsonl(path)
        alerts = collect_alerts(values)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].signature_id, 2008538)
        self.assertEqual(alerts[0].techniques, ("T1190",))

    def test_pass_fail_evaluator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scenario.yaml"
            path.write_text(SCENARIO, encoding="utf-8")
            scenario = load_scenario(path)
        event = {
            "event_type": "alert", "alert": {"signature_id": 2008538, "signature": "Fixture"},
        }
        eve_alert = alert_observation(event)
        assert eve_alert is not None
        siem_alert = SIEMAlert(
            signature_id=2008538, timestamp="2026-01-01T00:00:00Z",
            src_ip=None, dest_ip=None, flow_id=None, rule_id="86601", rule_level=5,
            tactics=("TA0001",), techniques=("T1190",), mapping_source="WAZUH_RULE",
        )
        additional_alert = SIEMAlert(
            signature_id=1001003, timestamp="2026-01-01T00:00:00Z",
            src_ip=None, dest_ip=None, flow_id=None, rule_id="110103", rule_level=6,
            tactics=("TA0043",), techniques=("T1595.002",), mapping_source="WAZUH_RULE",
        )
        passed = evaluate(
            scenario, environment_ok=True, traffic_ok=True,
            eve_alerts=[eve_alert], siem_alerts=[siem_alert, additional_alert],
        )
        failed = evaluate(
            scenario, environment_ok=True, traffic_ok=True,
            eve_alerts=[], siem_alerts=[],
        )
        self.assertEqual(passed.result, "PASS")
        self.assertEqual(failed.detection_status, "FAIL")
        self.assertEqual(failed.mapping_status, "MISSING")


if __name__ == "__main__":
    unittest.main()
