#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

command -v docker >/dev/null 2>&1 || {
    echo "docker is required" >&2
    exit 1
}

docker compose config >/dev/null
bash -n scripts/*.sh wazuh/*.sh sensor/entrypoint.sh

echo "Compose and shell syntax validation passed."
