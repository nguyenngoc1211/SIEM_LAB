#!/usr/bin/env python3
"""Build data/rule_catalog.json from the active Suricata ruleset."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from soc_scenarios.rule_catalog import build_catalog


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rules", type=Path, nargs="+",
        default=[Path("/opt/soc/rule-state/rules/soc-combined.rules")],
        help="Active .rules file(s); defaults to the read-only Suricata state mount.",
    )
    parser.add_argument(
        "--et-archive", type=Path, action="append", default=[],
        help="Optional ET tar archive used to recover category filenames.",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("/opt/soc/data/rule_catalog.json"),
    )
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    archives = args.et_archive
    if not archives:
        cache = Path("/opt/soc/rule-state/update/cache")
        archives = sorted(cache.glob("*emerging.rules.tar.gz")) if cache.exists() else []
    catalog = build_catalog(args.rules, archives=archives)
    catalog.write(args.output)
    summary = catalog.to_dict()["summary"]
    print(f"Active rules: {summary['active_rules']}")
    print(f"MITRE mapped rules: {summary['mitre_mapped_rules']}")
    print(f"Unique SIDs: {summary['unique_sids']}")
    print(f"Techniques: {summary['techniques']}")
    print(f"Warnings: {len(catalog.warnings)}")
    print(f"Catalog: {args.output}")


if __name__ == "__main__":
    main()
