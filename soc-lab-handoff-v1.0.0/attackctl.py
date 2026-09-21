#!/usr/bin/env python3
import sys
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent / "soc-attacker-advanced-v3.0.0"
sys.path.insert(0, str(PACKAGE_ROOT / "src"))

from soc_scenarios.cli import main  # noqa: E402


if __name__ == "__main__":
    main()
