from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.database import read_json, validate_database  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a mapping-ready ATT&CK JSON database")
    parser.add_argument("path", nargs="?", type=Path, default=ROOT / "artifacts" / "attack" / "attack_final.mapping.json")
    args = parser.parse_args()
    result = validate_database(read_json(args.path))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
