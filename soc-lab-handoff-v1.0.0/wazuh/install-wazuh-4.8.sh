#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  sudo ./wazuh/install-wazuh-4.8.sh /absolute/path/to/wazuh-docker/single-node

The script:
  1. Backs up config/wazuh_cluster/wazuh_manager.conf.
  2. Adds a JSON localfile reader for /var/log/suricata/eve.json.
  3. Creates docker-compose.suricata.yml to mount the lab log directory.
  4. Creates wazuh-suricata-up.sh for starting the stack with the override.
USAGE
}

if [[ $# -ne 1 ]]; then
    usage
    exit 1
fi

WAZUH_DIR="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$LAB_DIR/runtime/suricata-logs"
MANAGER_CONF="$WAZUH_DIR/config/wazuh_cluster/wazuh_manager.conf"
OVERRIDE_FILE="$WAZUH_DIR/docker-compose.suricata.yml"
UP_SCRIPT="$WAZUH_DIR/wazuh-suricata-up.sh"
DOWN_SCRIPT="$WAZUH_DIR/wazuh-suricata-down.sh"

if [[ ! -f "$WAZUH_DIR/docker-compose.yml" ]]; then
    echo "Not a Wazuh single-node directory: missing docker-compose.yml" >&2
    exit 1
fi

if [[ ! -f "$MANAGER_CONF" ]]; then
    echo "Missing Wazuh manager configuration: $MANAGER_CONF" >&2
    exit 1
fi

mkdir -p "$LOG_DIR"
chmod 0755 "$LOG_DIR"

BACKUP="${MANAGER_CONF}.backup.$(date +%Y%m%d%H%M%S)"
cp -a "$MANAGER_CONF" "$BACKUP"
echo "Backup created: $BACKUP"

python3 - "$MANAGER_CONF" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
location = "/var/log/suricata/eve.json"

if location in text:
    print("Wazuh localfile entry already exists; no XML change needed.")
    raise SystemExit(0)

block = """
  <!-- SOC lab: read Suricata EVE JSON directly from the shared host directory. -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
    <label key="integration">suricata-soc-lab</label>
  </localfile>
"""

closing = "</ossec_config>"
if closing not in text:
    raise SystemExit("Invalid Wazuh config: </ossec_config> was not found")

path.write_text(text.replace(closing, block + "\n" + closing, 1), encoding="utf-8")
print("Added Suricata localfile entry to Wazuh manager configuration.")
PY

cat > "$OVERRIDE_FILE" <<EOF_OVERRIDE
services:
  wazuh.manager:
    volumes:
      - "${LOG_DIR}:/var/log/suricata:ro"
EOF_OVERRIDE

cat > "$UP_SCRIPT" <<'EOF_UP'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker compose -f docker-compose.yml -f docker-compose.suricata.yml up -d
EOF_UP

cat > "$DOWN_SCRIPT" <<'EOF_DOWN'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker compose -f docker-compose.yml -f docker-compose.suricata.yml down
EOF_DOWN

chmod 0755 "$UP_SCRIPT" "$DOWN_SCRIPT"

cat <<EOF_DONE

Wazuh integration installed.

Start/recreate Wazuh with:
  cd "$WAZUH_DIR"
  sudo ./wazuh-suricata-up.sh

Verify the mounted file:
  docker compose -f docker-compose.yml -f docker-compose.suricata.yml \
    exec -T wazuh.manager ls -l /var/log/suricata/eve.json

The original manager configuration backup is:
  $BACKUP
EOF_DONE
