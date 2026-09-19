#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
find . -type f \
  ! -path './runtime/*' \
  ! -path './.git/*' \
  ! -name 'MANIFEST.sha256' \
  -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256
echo "Generated $ROOT_DIR/MANIFEST.sha256"
