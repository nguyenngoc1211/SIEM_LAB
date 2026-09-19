#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

failures=0
pass() { printf '\033[32m[PASS]\033[0m %s\n' "$1"; }
fail() { printf '\033[31m[FAIL]\033[0m %s\n' "$1"; failures=$((failures + 1)); }
warn() { printf '\033[33m[WARN]\033[0m %s\n' "$1"; }

command -v docker >/dev/null 2>&1 && pass "Docker CLI tồn tại" || fail "Thiếu Docker CLI"
if docker compose version >/dev/null 2>&1; then
  pass "Docker Compose plugin hoạt động"
else
  fail "Docker Compose plugin không hoạt động"
fi

if docker info >/dev/null 2>&1; then
  pass "Docker daemon truy cập được"
else
  fail "Không truy cập được Docker daemon"
fi

if docker compose config >/dev/null 2>&1; then
  pass "docker-compose.yml hợp lệ"
else
  fail "docker-compose.yml không hợp lệ"
fi

bash -n scripts/*.sh wazuh/install-wazuh-4.8.sh \
  && pass "Shell scripts hợp lệ" \
  || fail "Có shell script sai cú pháp"

mkdir -p runtime/suricata-logs
if [[ -w runtime/suricata-logs ]]; then
  pass "Thư mục log ghi được"
else
  fail "runtime/suricata-logs không ghi được"
fi

set -a
# shellcheck disable=SC1091
[[ -f .env ]] && source .env
set +a
BIND_IP="${LAB_BIND_IP:-127.0.0.1}"
PORT="${LAB_PORT:-8081}"

if command -v ss >/dev/null 2>&1; then
  if ss -ltnH | awk '{print $4}' | grep -Eq "(^|:)${PORT}$"; then
    if docker ps --format '{{.Names}} {{.Ports}}' | grep -qE "^soc_gateway .*:${PORT}->"; then
      warn "Port ${PORT} đang do soc_gateway hiện tại sử dụng"
    else
      fail "Port ${PORT} đã bị tiến trình/container khác chiếm"
    fi
  else
    pass "Port ${PORT} đang trống"
  fi
else
  warn "Không có lệnh ss; bỏ qua kiểm tra port"
fi

if [[ "$BIND_IP" == "0.0.0.0" ]]; then
  warn "LAB_BIND_IP=0.0.0.0: Juice Shop sẽ lắng nghe trên mọi interface"
else
  pass "Bind address: ${BIND_IP}:${PORT}"
fi

if (( failures > 0 )); then
  printf '\nPreflight thất bại: %d lỗi.\n' "$failures" >&2
  exit 1
fi

printf '\nPreflight hoàn tất.\n'
