#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:${LAB_PORT:-8081}}"
CURL=(curl --silent --show-error --output /dev/null --max-time 10)

request() {
    local name="$1"
    shift
    printf '[test] %-30s' "$name"
    if "${CURL[@]}" "$@"; then
        printf 'sent\n'
    else
        # Một số payload nhận 4xx/5xx nhưng vẫn đã đi qua Suricata.
        printf 'sent (HTTP endpoint may reject it)\n'
    fi
}

printf 'Target: %s\n\n' "$BASE_URL"

request "Lab probe" "$BASE_URL/__soc_probe__"
request "SQL injection pattern" --path-as-is "$BASE_URL/rest/products/search?q=1%20UNION%20SELECT%20password%20FROM%20Users"
request "XSS pattern" --path-as-is "$BASE_URL/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
request "Path traversal pattern" --path-as-is "$BASE_URL/../../../../etc/passwd"
request "sqlmap user-agent" -A "sqlmap/1.8-lab" "$BASE_URL/rest/products/search?q=test"
request "Command injection pattern" --path-as-is "$BASE_URL/api/test?cmd=%3Bid%20"

for attempt in {1..6}; do
    request "Login attempt ${attempt}/6" \
        -H 'Content-Type: application/json' \
        -X POST \
        --data '{"email":"lab@example.invalid","password":"wrong-password"}' \
        "$BASE_URL/rest/user/login"
done

cat <<'MSG'

Requests were sent. Check:
  tail -f runtime/suricata-logs/eve.json

Then search Wazuh for:
  rule.groups: suricata
  data.alert.signature_id: 1000001 to 1000007
MSG
