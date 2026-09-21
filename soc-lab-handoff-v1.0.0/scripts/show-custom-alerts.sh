#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
python3 - <<'PY'
import json
from collections import deque
from pathlib import Path

path = Path("runtime/suricata-logs/eve.json")
rows = deque(maxlen=50)
if not path.exists():
    raise SystemExit("eve.json chưa tồn tại")
for line in path.open(errors="replace"):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    alert = event.get("alert", {})
    sid = alert.get("signature_id")
    if isinstance(sid, int) and 1001001 <= sid <= 1001099:
        rows.append(event)
for event in rows:
    alert = event["alert"]
    print(f"{event.get('timestamp')} SID={alert.get('signature_id')} {alert.get('signature')}")
print(f"Displayed {len(rows)} recent custom alerts")
PY
