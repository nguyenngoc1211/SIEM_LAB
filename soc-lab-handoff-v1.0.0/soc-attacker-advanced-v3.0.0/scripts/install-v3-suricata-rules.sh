#!/usr/bin/env bash
set -euo pipefail
SOC_LAB_DIR="${1:-}"
RESTART="${2:-}"
if [ -z "$SOC_LAB_DIR" ]; then
  echo "Usage: $0 /path/to/soc-lab-handoff-v1.2.0 [--restart-suricata]" >&2
  exit 1
fi
SOC_LAB_DIR="$(cd "$SOC_LAB_DIR" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RULES_SOURCE="$SCRIPT_DIR/../rules/soc-attacker-v3.rules"
LOCAL_RULES="$SOC_LAB_DIR/sensor/local.rules"
[ -f "$RULES_SOURCE" ] || { echo "Rules file not found: $RULES_SOURCE" >&2; exit 1; }
[ -f "$LOCAL_RULES" ] || { echo "SOC lab local.rules not found: $LOCAL_RULES" >&2; exit 1; }
BACKUP="$LOCAL_RULES.bak.$(date +%Y%m%d%H%M%S)"
cp "$LOCAL_RULES" "$BACKUP"
python3 - "$LOCAL_RULES" "$RULES_SOURCE" <<'PYSOCV3'
import re, sys
local, src = sys.argv[1:3]
start = '# --- SOC attacker advanced v3 rules BEGIN ---'
end = '# --- SOC attacker advanced v3 rules END ---'
text = open(local, encoding='utf-8', errors='ignore').read()
block = open(src, encoding='utf-8').read()
text = re.sub(r'\n?# --- SOC attacker advanced v3 rules BEGIN ---.*?# --- SOC attacker advanced v3 rules END ---\n?', '\n', text, flags=re.S)
open(local, 'w', encoding='ascii').write(text.rstrip() + '\n\n' + start + '\n' + block + '\n' + end + '\n')
PYSOCV3
echo "Installed v3 Suricata rules into: $LOCAL_RULES"
echo "Backup created: $BACKUP"
if [ "$RESTART" = "--restart-suricata" ]; then
  (cd "$SOC_LAB_DIR" && docker compose up -d --build --force-recreate suricata)
fi
