#!/usr/bin/env python3
"""Report MITRE technique/scenario/rule coverage for active rules."""

from __future__ import annotations

import argparse
from pathlib import Path

from soc_scenarios.coverage import build_coverage, write_coverage
from soc_scenarios.rule_catalog import RuleCatalog


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=Path("/opt/soc/data/rule_catalog.json"))
    parser.add_argument("--scenarios", type=Path, default=Path("/opt/soc/scenarios"))
    parser.add_argument(
        "--output", type=Path,
        default=Path("/opt/soc/runtime/reports/mitre_coverage.json"),
    )
    args = parser.parse_args()
    payload = build_coverage(
        RuleCatalog.load(args.catalog), sorted(args.scenarios.glob("**/scenario.yaml")),
    )
    write_coverage(payload, args.output)
    for technique, value in payload["techniques"].items():
        print(technique)
        print("Rules available:", value["rules_available"])
        print("Rules tested:", value["rules_tested"])
        print("Scenarios:", value["scenarios"])
        print("Status:", value["status"])
        print()
    print("Output:", args.output)


if __name__ == "__main__":
    main()
