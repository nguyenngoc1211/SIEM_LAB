#!/usr/bin/env python3
"""Run custom-rule A2 scenarios from their isolated scenario tree."""

from __future__ import annotations

import sys

from soc_scenarios.scenario_cli import main


if __name__ == "__main__":
    sys.argv[1:1] = [
        "--scenario-root", "/opt/soc/scenarios/a2",
        "--report-dir", "/opt/soc/runtime/reports/a2",
        "--ground-truth", "/opt/soc/runtime/ground-truth/a2-scenario-runs.jsonl",
    ]
    main()
