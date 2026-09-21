#!/usr/bin/env bash
set -euo pipefail

SOC_LAB_DIR="${1:-}"
RESTART="${2:-}"
if [ -z "$SOC_LAB_DIR" ]; then
  echo "Usage: $0 /path/to/soc-lab-handoff-v1.0.0 [--restart-suricata]" >&2
  exit 1
fi
SOC_LAB_DIR="$(cd "$SOC_LAB_DIR" && pwd)"
LOCAL_RULES="$SOC_LAB_DIR/sensor/local.rules"
[ -f "$LOCAL_RULES" ] || { echo "SOC lab local.rules not found: $LOCAL_RULES" >&2; exit 1; }

echo "Compatibility wrapper: v2 custom rules are already managed by $LOCAL_RULES."
echo "No ET rule is copied, replaced, or modified."

if [ "$RESTART" = "--restart-suricata" ]; then
  (cd "$SOC_LAB_DIR" && docker compose up -d --build --force-recreate suricata)
fi
(cd "$SOC_LAB_DIR" && docker compose exec -T suricata suricata -T -c /etc/suricata/suricata.yaml)
