from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitre_mapper.baselines.runner import run_comparison  # noqa: E402


def _load_dotenv(path: Path) -> None:
    """Load GEMINI_API_KEY from mitre-mapping/.env without printing secrets."""
    import os

    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run BM25-only and Gemini-only baselines over the frozen dataset",
    )
    parser.add_argument("--dataset-dir", type=Path, default=ROOT / "benchmark")
    parser.add_argument("--config", type=Path, default=ROOT / "configs" / "baselines.json")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "reports" / "baselines")
    parser.add_argument(
        "--strategies",
        default="bm25_only,gemini_only",
        help="Comma-separated strategy names. Supported: bm25_only, gemini_only.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Only run the first N alerts.")
    parser.add_argument("--repeats", type=int, default=None, help="Override Gemini repeat count.")
    parser.add_argument("--model", default=None, help="Override the Gemini model id.")
    parser.add_argument(
        "--api-key-env",
        default=None,
        help="Environment variable holding the Gemini API key, e.g. GEMINI_API_KEY_NGOC.",
    )
    parser.add_argument(
        "--arm-name",
        default="gemini_only",
        help="Strategy name for this Gemini arm, e.g. gemini_only_pro.",
    )
    parser.add_argument(
        "--thinking-budget",
        type=int,
        default=None,
        help="Override Gemini thinking budget. Use 0 to disable thinking on supported models.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Skip Gemini API calls.")
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Ignore existing per-strategy checkpoints and start over.",
    )
    parser.add_argument(
        "--load-arms",
        default=None,
        help="Comma-separated existing arms to include without re-running, e.g. gemini_only.",
    )
    parser.add_argument(
        "--no-archived-hybrid",
        action="store_true",
        help="Exclude the archived hybrid reference results.",
    )
    args = parser.parse_args()
    _load_dotenv(ROOT / ".env")
    names = [name.strip() for name in args.strategies.split(",") if name.strip()]
    load_arms = [
        name.strip() for name in (args.load_arms or "").split(",") if name.strip()
    ]
    comparison = run_comparison(
        ROOT,
        args.dataset_dir.resolve(),
        args.output_dir.resolve(),
        strategy_names=names,
        config_path=args.config.resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
        repeats_override=args.repeats,
        include_archived_hybrid=not args.no_archived_hybrid,
        resume=not args.no_resume,
        gemini_model_override=args.model,
        gemini_arm_name=args.arm_name,
        gemini_api_key_env=args.api_key_env,
        gemini_thinking_budget=args.thinking_budget,
        load_only_arms=load_arms,
    )
    print(json.dumps(comparison["summaries"], ensure_ascii=False, indent=2))
    print(f"Reports: {comparison['run']['report_paths']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
