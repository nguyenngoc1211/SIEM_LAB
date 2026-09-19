#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
pass(){ printf '\033[32m[PASS]\033[0m %s\n' "$1"; PASS_COUNT=$((PASS_COUNT+1)); }
warn(){ printf '\033[33m[WARN]\033[0m %s\n' "$1"; WARN_COUNT=$((WARN_COUNT+1)); }
fail(){ printf '\033[31m[FAIL]\033[0m %s\n' "$1"; FAIL_COUNT=$((FAIL_COUNT+1)); }
info(){ printf '\033[36m[INFO]\033[0m %s\n' "$1"; }

find_wazuh_container() {
  local component="$1"
  docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null \
    | awk -v component="$component" '$2 ~ ("^wazuh/wazuh-" component ":") {print $1; exit}'
}

MANAGER="${WAZUH_MANAGER_CONTAINER:-$(find_wazuh_container manager)}"
INDEXER="$(find_wazuh_container indexer)"
DASHBOARD="$(find_wazuh_container dashboard)"

set -a
# shellcheck disable=SC1091
[[ -f .env ]] && source .env
set +a
BASE_URL="http://${CHECK_HOST:-127.0.0.1}:${LAB_PORT:-8081}"
EVE="runtime/suricata-logs/eve.json"

echo "========== SOC LAB SYSTEM CHECK =========="

echo
info "1. Containers"
for container in soc_gateway soc_juice_shop soc_suricata "$MANAGER" "$INDEXER" "$DASHBOARD"; do
  if [[ -n "$container" ]] && [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" == "true" ]]; then
    pass "$container đang chạy"
  else
    fail "${container:-Wazuh container} không chạy hoặc không tìm thấy"
  fi
done

echo
info "2. Gateway / Juice Shop"
HTTP="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$BASE_URL" 2>/dev/null || true)"
[[ "$HTTP" == "200" ]] && pass "$BASE_URL trả về HTTP 200" || fail "$BASE_URL trả về HTTP ${HTTP:-N/A}"

echo
info "3. Suricata engine"
if docker top soc_suricata -eo pid,comm,args 2>/dev/null | grep -Eq '[S]uricata-Main|[[:space:]]suricata[[:space:]].*-i[[:space:]]'; then
  pass "Suricata đang xử lý traffic"
  docker top soc_suricata -eo pid,comm,args 2>/dev/null | grep -i suricata || true
else
  fail "Không tìm thấy tiến trình Suricata capture"
fi
RESTARTS="$(docker inspect soc_suricata --format '{{.RestartCount}}' 2>/dev/null || echo '?')"
[[ "$RESTARTS" == "0" ]] && pass "Suricata RestartCount=0" || warn "Suricata RestartCount=${RESTARTS}"

echo
info "4. EVE JSON và Suricata alerts"
if [[ -s "$EVE" ]]; then
  pass "eve.json tồn tại: $(du -h "$EVE" | awk '{print $1}')"
else
  fail "eve.json không tồn tại hoặc rỗng"
fi
TOTAL_ALERTS="$(grep -c '"event_type":"alert"' "$EVE" 2>/dev/null || true)"; TOTAL_ALERTS="${TOTAL_ALERTS:-0}"
CUSTOM_ALERTS="$(grep -Ec '"signature_id":100000[1-7]' "$EVE" 2>/dev/null || true)"; CUSTOM_ALERTS="${CUSTOM_ALERTS:-0}"
NOISE_ALERTS="$(grep -Ec '"signature_id":2200122|"signature_id":2200003' "$EVE" 2>/dev/null || true)"; NOISE_ALERTS="${NOISE_ALERTS:-0}"
[[ "$TOTAL_ALERTS" -gt 0 ]] 2>/dev/null && pass "Suricata alerts tổng: $TOTAL_ALERTS" || fail "Suricata alerts tổng: 0"
[[ "$CUSTOM_ALERTS" -gt 0 ]] 2>/dev/null && pass "Custom SOC LAB alerts: $CUSTOM_ALERTS" || warn "Chưa có custom SID 1000001-1000007; chạy make test"
[[ "$NOISE_ALERTS" -gt 0 ]] 2>/dev/null && warn "Truncated-packet alerts: $NOISE_ALERTS (SID 2200122/2200003)" || pass "Không thấy truncated-packet alert"

echo
info "5. Wazuh mount và cấu hình"
if [[ -n "$MANAGER" ]] && docker exec "$MANAGER" test -s /var/log/suricata/eve.json 2>/dev/null; then
  pass "Wazuh Manager nhìn thấy eve.json"
else
  fail "Wazuh Manager chưa nhìn thấy /var/log/suricata/eve.json"
fi
if [[ -n "$MANAGER" ]] && docker exec "$MANAGER" grep -q '/var/log/suricata/eve.json' /var/ossec/etc/ossec.conf 2>/dev/null; then
  pass "Wazuh localfile đã cấu hình"
else
  fail "Wazuh localfile chưa cấu hình"
fi
TMP_LOG="/tmp/wazuh-analysisd-test.$$"
if [[ -n "$MANAGER" ]] && docker exec "$MANAGER" /var/ossec/bin/wazuh-analysisd -t >"$TMP_LOG" 2>&1; then
  pass "Cấu hình Wazuh hợp lệ"
else
  fail "Cấu hình Wazuh không hợp lệ hoặc Manager không khả dụng"
  cat "$TMP_LOG" 2>/dev/null || true
fi
rm -f "$TMP_LOG"

echo
info "6. Wazuh alerts"
if [[ -n "$MANAGER" ]]; then
  WAZUH_SURICATA="$(docker exec "$MANAGER" sh -c "grep -ic 'suricata' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true" 2>/dev/null)"; WAZUH_SURICATA="${WAZUH_SURICATA:-0}"
  WAZUH_CUSTOM="$(docker exec "$MANAGER" sh -c "grep -Ec '100000[1-7]|SOC LAB' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true" 2>/dev/null)"; WAZUH_CUSTOM="${WAZUH_CUSTOM:-0}"
  [[ "$WAZUH_SURICATA" -gt 0 ]] 2>/dev/null && pass "Wazuh Suricata alerts: $WAZUH_SURICATA" || fail "Wazuh Suricata alerts: 0"
  [[ "$WAZUH_CUSTOM" -gt 0 ]] 2>/dev/null && pass "Wazuh custom SOC LAB alerts: $WAZUH_CUSTOM" || warn "Wazuh chưa có custom SOC LAB alert"
else
  fail "Không tìm thấy Wazuh Manager"
fi

echo
info "7. Năm alert Suricata gần nhất"
python3 - "$EVE" <<'PY'
import json
import sys
from collections import deque
from pathlib import Path

path = Path(sys.argv[1])
rows = deque(maxlen=5)
if path.exists():
    for line in path.open(errors="replace"):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "alert":
            rows.append(event)
for event in rows:
    alert = event.get("alert", {})
    print(
        f"SID={alert.get('signature_id')} | {alert.get('signature')} | "
        f"{event.get('src_ip')} -> {event.get('dest_ip')}"
    )
PY

echo
printf 'SUMMARY: PASS=%d WARN=%d FAIL=%d\n' "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT"
echo "========== CHECK COMPLETE =========="
(( FAIL_COUNT == 0 ))
