from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.baselines.dataset import build_dataset  # noqa: E402


DEFAULT_REPORTS = ROOT.parent.parent / "soc-lab-handoff-v1.0.0" / "runtime" / "reports"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Freeze A1/A2 normalized alerts and ground truth for baseline comparison",
    )
    parser.add_argument("--reports-root", type=Path, default=DEFAULT_REPORTS)
    parser.add_argument("--output", type=Path, default=ROOT / "benchmark")
    parser.add_argument("--groups", nargs="+", default=["a1", "a2"])
    parser.add_argument(
        "--keep-inline-ids",
        action="store_true",
        help="Do not scrub inline Txxxx/TAxxxx tokens inside free text.",
    )
    args = parser.parse_args()
    manifest = build_dataset(
        args.reports_root.resolve(),
        args.output.resolve(),
        project_root=ROOT,
        groups=args.groups,
        scrub_inline_ids=not args.keep_inline_ids,
    )
    print(json.dumps(manifest["counts"], ensure_ascii=False, indent=2))
    print(f"Wrote {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
