from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.clients import build_qdrant_index  # noqa: E402
from mitre_mapper.settings import Settings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Embed retrieval documents and index them in Qdrant")
    parser.add_argument("--recreate", action="store_true", help="Delete and recreate only the configured mapping collection")
    parser.add_argument("--wait", type=int, default=0, help="Retry service startup for this many seconds")
    args = parser.parse_args()
    deadline = time.monotonic() + args.wait
    while True:
        try:
            result = build_qdrant_index(Settings.load(ROOT), recreate=args.recreate)
            break
        except Exception as exc:
            if time.monotonic() >= deadline:
                raise
            print(f"Services not ready ({exc}); retrying in 5 seconds...", file=sys.stderr, flush=True)
            time.sleep(5)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
