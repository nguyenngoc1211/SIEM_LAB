#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' '=== Containers ==='
docker compose ps

printf '\n%s\n' '=== Suricata version ==='
docker compose exec -T suricata suricata -V || true

printf '\n%s\n' '=== Recent Suricata alerts ==='
if [[ -s runtime/suricata-logs/eve.json ]]; then
    python3 - <<'PY'
import json
from collections import deque
from pathlib import Path

path = Path("runtime/suricata-logs/eve.json")
rows = deque(maxlen=10)
with path.open("r", encoding="utf-8", errors="replace") as f:
    for line in f:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "alert":
            rows.append(event)

if not rows:
    print("No alert events yet.")
else:
    for event in rows:
        alert = event.get("alert", {})
        print(f"{event.get('timestamp', '-')} sid={alert.get('signature_id', '-')} {alert.get('signature', '-')}")
PY
else
    printf '%s\n' 'eve.json does not exist yet.'
fi
