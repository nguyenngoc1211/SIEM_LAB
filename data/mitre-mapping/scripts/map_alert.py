from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.pipeline import MappingPipeline  # noqa: E402
from mitre_mapper.settings import Settings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Map one normalized alert to MITRE ATT&CK")
    parser.add_argument("alert", type=Path)
    parser.add_argument("--expect", help="Fail unless this technique is mapped")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.loads(args.alert.read_text(encoding="utf-8-sig"))
    result = MappingPipeline(Settings.load(ROOT)).map_alert(payload)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    actual = (result.get("primary_mapping") or {}).get("technique_id")
    return 0 if not args.expect or actual == args.expect else 2


if __name__ == "__main__":
    raise SystemExit(main())
