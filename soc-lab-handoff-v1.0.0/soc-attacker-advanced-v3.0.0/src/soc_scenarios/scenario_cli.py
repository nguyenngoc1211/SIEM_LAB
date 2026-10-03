"""Command line interface shared by the A1 and A2 scenario groups."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from .scenario_runner import print_result, run_scenario
from .rule_catalog import RuleCatalog
from .scenario_model import Scenario, load_scenario


DEFAULT_SCENARIOS = Path("/opt/soc/scenarios/a1")
DEFAULT_CATALOG = Path("/opt/soc/data/rule_catalog.json")
DEFAULT_EVE = Path("/opt/soc/telemetry/suricata/eve.json")
DEFAULT_WAZUH = Path("/var/ossec-logs/alerts/alerts.json")
DEFAULT_REPORTS = Path("/opt/soc/runtime/reports/a1")
DEFAULT_GROUND_TRUTH = Path("/opt/soc/runtime/ground-truth/a1-scenario-runs.jsonl")
DEFAULT_MAPPING_WEBHOOK_URL = os.environ.get(
    "N8N_MAPPING_WEBHOOK_URL",
    "http://host.docker.internal:5678/webhook/soc-alert-analysis",
)
DEFAULT_ALERT_QUIET_SECONDS = float(os.environ.get("ALERT_QUIET_SECONDS", "2.0"))


def discover(root: Path) -> list[Path]:
    return sorted(root.glob("**/scenario.yaml"))


def select(paths: list[Path], *, technique: str | None, scenario_id: str | None) -> list[Path]:
    scenarios: list[tuple[Path, Scenario]] = [(path, load_scenario(path)) for path in paths]
    if technique:
        scenarios = [
            item for item in scenarios if technique.upper() in item[1].mitre.technique_ids
        ]
    if scenario_id:
        scenarios = [item for item in scenarios if item[1].id == scenario_id.upper()]
    return [item[0] for item in scenarios]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, help="path to one scenario.yaml")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--all", action="store_true", help="run all discovered scenarios")
    group.add_argument("--technique", help="run scenarios for one MITRE technique")
    group.add_argument("--scenario", help="run one scenario by ID")
    parser.add_argument("--scenario-root", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--eve", type=Path, default=DEFAULT_EVE)
    parser.add_argument("--wazuh", type=Path, default=DEFAULT_WAZUH)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORTS)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH)
    parser.add_argument(
        "--mapping-webhook-url", "--mapper-url", dest="mapping_webhook_url",
        default=DEFAULT_MAPPING_WEBHOOK_URL,
        help="n8n webhook that normalizes one raw Wazuh alert and returns mapping JSON",
    )
    parser.add_argument(
        "--alert-quiet-seconds", type=float, default=DEFAULT_ALERT_QUIET_SECONDS,
        help="wait for matching Wazuh alerts to stop arriving before selecting one",
    )
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if args.path and (args.all or args.technique or args.scenario):
        parser.error("path cannot be combined with a batch selector")
    if args.path:
        paths = [args.path]
    else:
        paths = select(
            discover(args.scenario_root),
            technique=args.technique,
            scenario_id=args.scenario,
        )
        if not (args.all or args.technique or args.scenario):
            parser.error("provide a scenario path, --all, --technique, or --scenario")
    if not paths:
        parser.error("no matching scenarios")

    catalog = RuleCatalog.load(args.catalog)
    reports: list[dict] = []
    for path in paths:
        try:
            report = run_scenario(
                load_scenario(path), catalog, eve_path=args.eve, wazuh_path=args.wazuh,
                report_dir=args.report_dir, ground_truth_path=args.ground_truth,
                mapper_url=args.mapping_webhook_url,
                alert_quiet_seconds=max(0.0, args.alert_quiet_seconds),
            )
        except Exception as error:
            logging.error("%s: %s", path, error)
            report = {
                "scenario_id": path.parent.name, "result": "FAIL",
                "environment": {"status": "FAIL"}, "traffic": {"status": "NOT_TESTED"},
                "detection": {"status": "NOT_TESTED"}, "siem": {"status": "NOT_TESTED"},
                "mitre": {"status": "NOT_TESTED"},
            }
        else:
            print_result(report)
        reports.append(report)

    def count(section: str) -> int:
        return sum(item.get(section, {}).get("status") == "PASS" for item in reports)

    print("Total scenarios:", len(reports))
    print("PASS:", sum(item.get("result") == "PASS" for item in reports))
    print("FAIL:", sum(item.get("result") != "PASS" for item in reports))
    print(f"Detection: {count('detection')}/{len(reports)}")
    print(f"Ingestion: {count('siem')}/{len(reports)}")
    print(f"Mapping: {count('mitre')}/{len(reports)}")
    techniques = {
        technique
        for report in reports
        for technique in report.get("mitre", {}).get("expected_techniques", [])
    }
    print("Techniques validated:", len(techniques))
    raise SystemExit(0 if all(item.get("result") == "PASS" for item in reports) else 1)
