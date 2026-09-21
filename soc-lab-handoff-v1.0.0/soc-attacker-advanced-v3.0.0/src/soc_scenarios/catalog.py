from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_HERE = Path(__file__).resolve()
CATALOG_PATH = next(
    candidate
    for candidate in [
        _HERE.parents[1] / "scenarios" / "catalog.json",
        _HERE.parents[2] / "scenarios" / "catalog.json",
    ]
    if candidate.exists()
)


def load_catalog() -> list[dict[str, Any]]:
    with CATALOG_PATH.open(encoding="utf-8") as handle:
        scenarios = json.load(handle)
    ids = [scenario["id"] for scenario in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("Scenario IDs must be unique")
    return scenarios


def by_id() -> dict[str, dict[str, Any]]:
    return {scenario["id"].upper(): scenario for scenario in load_catalog()}


CHAINS = {
    "CHAIN-A": {
        "name": "Recon to SQL Injection",
        "scenarios": ["RECON-01", "RECON-02", "WEB-06"],
        "purpose": "Correlate service discovery, web enumeration, and exploitation attempts.",
    },
    "CHAIN-B": {
        "name": "Enumeration to Authentication Attacks",
        "scenarios": ["RECON-02", "AUTH-11", "AUTH-12"],
        "purpose": "Correlate content discovery, token manipulation, and focused brute force.",
    },
    "CHAIN-C": {
        "name": "Recon to SSRF Internal Access",
        "scenarios": ["RECON-01", "RECON-02", "SERVER-14"],
        "purpose": "Correlate reconnaissance with real server-side internal service access.",
    },
    "CHAIN-D": {
        "name": "Web Attack to Exfiltration and Beaconing",
        "scenarios": ["WEB-09", "EXFIL-16", "C2-17"],
        "purpose": "Correlate initial web exploitation indicators, fake-data exfiltration, and C2.",
    },
}
