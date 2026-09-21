from __future__ import annotations

import argparse
import time
from pathlib import Path

from .catalog import CHAINS, load_catalog
from .runner import run_scenario, write_chain_record
from .reporting import generate_report


def _print_scenarios(category: str | None = None) -> None:
    for scenario in load_catalog():
        if category and scenario["category"] != category:
            continue
        mitre = ",".join(scenario["mitre"]["expected_techniques"]) or "-"
        print(scenario["id"] + "\t" + scenario["category"] + "\t" + mitre + "\t" + scenario["name"])


def _run_many(scenarios: list[dict], *, dry_run: bool, pause: float) -> None:
    for index, scenario in enumerate(scenarios):
        run_scenario(scenario, dry_run=dry_run)
        if index + 1 < len(scenarios) and pause > 0:
            time.sleep(pause)


def _run_chain(chain_id: str, dry_run: bool) -> None:
    chain_id = chain_id.upper()
    if chain_id not in CHAINS:
        raise SystemExit("unknown chain: " + chain_id)
    catalog = {scenario["id"]: scenario for scenario in load_catalog()}
    chain = CHAINS[chain_id]
    records = [
        run_scenario(catalog[scenario_id], dry_run=dry_run, chain_id=chain_id)
        for scenario_id in chain["scenarios"]
    ]
    if not dry_run:
        write_chain_record(chain_id, chain, records)


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC Attack Scenarios v2 - safe local/Docker lab evaluator")
    sub = parser.add_subparsers(dest="command", required=True)
    list_parser = sub.add_parser("list")
    list_parser.add_argument("--category")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("id")
    run_parser.add_argument("--dry-run", action="store_true")
    all_parser = sub.add_parser("run-all")
    all_parser.add_argument("--dry-run", action="store_true")
    all_parser.add_argument("--pause", type=float, default=1.0)
    batch_parser = sub.add_parser("run-batch")
    batch_parser.add_argument("ids", nargs="+")
    batch_parser.add_argument("--dry-run", action="store_true")
    batch_parser.add_argument("--pause", type=float, default=1.0)
    category_parser = sub.add_parser("run-category")
    category_parser.add_argument("category")
    category_parser.add_argument("--dry-run", action="store_true")
    category_parser.add_argument("--pause", type=float, default=1.0)
    sub.add_parser("chains")
    chain_parser = sub.add_parser("run-chain")
    chain_parser.add_argument("id")
    chain_parser.add_argument("--dry-run", action="store_true")
    report_parser = sub.add_parser("report")
    report_parser.add_argument("--ground-truth", type=Path)
    report_parser.add_argument("--eve", type=Path)
    report_parser.add_argument("--wazuh", type=Path)
    report_parser.add_argument("--output-dir", type=Path)
    report_parser.add_argument("--mapper-url")
    report_parser.add_argument("--wazuh-container", default="single-node-wazuh.manager-1")

    args = parser.parse_args()
    catalog = load_catalog()
    catalog_by_id = {scenario["id"].upper(): scenario for scenario in catalog}
    if args.command == "list":
        _print_scenarios(args.category)
    elif args.command == "run":
        scenario_id = args.id.upper()
        if scenario_id not in catalog_by_id:
            raise SystemExit("unknown scenario: " + scenario_id)
        run_scenario(catalog_by_id[scenario_id], dry_run=args.dry_run)
    elif args.command == "run-all":
        _run_many(catalog, dry_run=args.dry_run, pause=max(0.0, args.pause))
    elif args.command == "run-batch":
        requested = [value.upper() for value in args.ids]
        unknown = [value for value in requested if value not in catalog_by_id]
        if unknown:
            raise SystemExit("unknown scenario(s): " + ", ".join(unknown))
        _run_many(
            [catalog_by_id[value] for value in requested],
            dry_run=args.dry_run,
            pause=max(0.0, args.pause),
        )
    elif args.command == "run-category":
        matched = [scenario for scenario in catalog if scenario["category"] == args.category]
        if not matched:
            raise SystemExit("unknown/empty category: " + args.category)
        _run_many(matched, dry_run=args.dry_run, pause=max(0.0, args.pause))
    elif args.command == "chains":
        for chain_id, chain in CHAINS.items():
            print(chain_id + "\t" + ",".join(chain["scenarios"]) + "\t" + chain["name"])
    elif args.command == "run-chain":
        _run_chain(args.id, args.dry_run)
    elif args.command == "report":
        csv_path, json_path = generate_report(
            ground_truth=args.ground_truth,
            eve=args.eve,
            wazuh=args.wazuh,
            output_dir=args.output_dir,
            mapper_url=args.mapper_url,
            wazuh_container=args.wazuh_container,
        )
        print("CSV:", csv_path)
        print("JSON:", json_path)
