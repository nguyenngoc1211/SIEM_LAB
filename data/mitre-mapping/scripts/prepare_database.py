from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.database import prepare_database  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and build the mapping-ready ATT&CK database")
    parser.add_argument(
        "--source",
        type=Path,
        default=ROOT / "artifacts" / "attack" / "attack_final.mapping.json",
        help=(
            "Source ATT&CK mapping JSON. Defaults to the canonical enriched "
            "snapshot in artifacts/attack."
        ),
    )
    args = parser.parse_args()
    manifest = prepare_database(ROOT, args.source.resolve())
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
