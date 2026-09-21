#!/bin/sh
set -eu

INTERFACE="${SURICATA_INTERFACE:-eth0}"
UPDATE_INTERVAL="${RULE_UPDATE_INTERVAL:-86400}"
UPDATE_ENABLED="${RULE_UPDATE_ENABLED:-false}"
RULE_DIR="/var/lib/suricata/rules"
ET_RULES="${RULE_DIR}/suricata.rules"
COMBINED_RULES="${RULE_DIR}/soc-combined.rules"
CANDIDATE_RULES="${RULE_DIR}/soc-combined.rules.candidate"
ET_BACKUP="${RULE_DIR}/suricata.rules.before-update"
LOCAL_RULES="/opt/soc/local.rules"
CONFIG_FILE="/etc/suricata/suricata.yaml"
LOG_DIR="/var/log/suricata"
PID_FILE="/run/suricata.pid"
LOCAL_MARKER="# --- SOC lab local rules ---"

case "$UPDATE_INTERVAL" in
    ''|*[!0-9]*)
        echo "RULE_UPDATE_INTERVAL must be an integer number of seconds." >&2
        exit 1
        ;;
esac

case "$UPDATE_ENABLED" in
    true|false) ;;
    *)
        echo "RULE_UPDATE_ENABLED must be true or false." >&2
        exit 1
        ;;
esac

umask 022
mkdir -p "$RULE_DIR" "$LOG_DIR" /run
touch "$ET_RULES"
chmod 0644 "$ET_RULES"

# Bản cũ từng nối local rules trực tiếp vào file cache ET. Khi tạo ruleset
# runtime, lọc phần legacy khỏi bản sao combined để file ET nguồn bất biến.
build_combined_rules() {
    output="$1"
    tmp="${output}.tmp"

    : > "$tmp"

    if [ -s "$ET_RULES" ]; then
        # Old lab versions appended custom SIDs to this cache. Filter those only
        # while creating the runtime ruleset; never rewrite or patch ET_RULES.
        awk -v marker="$LOCAL_MARKER" '
            $0 == marker { exit }
            /sid:10000[0-9][0-9];/ { next }
            { print }
        ' "$ET_RULES" >> "$tmp"
    fi

    printf '\n%s\n' "$LOCAL_MARKER" >> "$tmp"
    cat "$LOCAL_RULES" >> "$tmp"

    mv "$tmp" "$output"
    chmod 0644 "$output"
}

validate_rules_file() {
    rules_file="$1"
    echo "[suricata] Validating ruleset: ${rules_file}"

    suricata -T \
        -c "$CONFIG_FILE" \
        -S "$rules_file" \
        -l "$LOG_DIR"
}

prepare_initial_rules() {
    build_combined_rules "$CANDIDATE_RULES"

    if validate_rules_file "$CANDIDATE_RULES"; then
        mv "$CANDIDATE_RULES" "$COMBINED_RULES"
        return 0
    fi

    echo "[suricata] Cached ET rules are invalid; starting with local lab rules only." >&2
    cp "$ET_RULES" "${ET_RULES}.invalid" 2>/dev/null || true
    cp "$LOCAL_RULES" "$CANDIDATE_RULES"
    validate_rules_file "$CANDIDATE_RULES"
    mv "$CANDIDATE_RULES" "$COMBINED_RULES"
}

restore_et_backup() {
    if [ -f "$ET_BACKUP" ]; then
        cp "$ET_BACKUP" "$ET_RULES"
        chmod 0644 "$ET_RULES"
    fi
}

update_rules_once() {
    echo "[suricata] Updating Emerging Threats Open rules in background..."
    cp "$ET_RULES" "$ET_BACKUP"

    if ! suricata-update; then
        echo "[suricata] Rule update failed; keeping the active ruleset." >&2
        restore_et_backup
        return 1
    fi

    build_combined_rules "$CANDIDATE_RULES"

    if ! validate_rules_file "$CANDIDATE_RULES"; then
        echo "[suricata] Updated rules failed validation; keeping the active ruleset." >&2
        rm -f "$CANDIDATE_RULES"
        restore_et_backup
        return 1
    fi

    mv "$CANDIDATE_RULES" "$COMBINED_RULES"

    if [ -s "$PID_FILE" ]; then
        echo "[suricata] Reloading validated rules..."
        kill -USR2 "$(cat "$PID_FILE")" 2>/dev/null || true
    fi
}

reload_loop() {
    while ! suricatasc -c uptime >/dev/null 2>&1; do
        if ! kill -0 "$SURICATA_PID" 2>/dev/null; then
            return 0
        fi
        sleep 5
    done

    if [ "$UPDATE_ENABLED" != "true" ]; then
        echo "[suricata] Automatic rule updates disabled for isolated lab mode."
        return 0
    fi

    sleep 15

    while :; do
        update_rules_once || true
        sleep "$UPDATE_INTERVAL"
    done
}

shutdown() {
    if [ -n "${UPDATER_PID:-}" ]; then
        kill "$UPDATER_PID" 2>/dev/null || true
    fi

    if [ -n "${SURICATA_PID:-}" ]; then
        kill -TERM "$SURICATA_PID" 2>/dev/null || true
        wait "$SURICATA_PID" 2>/dev/null || true
    fi

    exit 0
}

trap shutdown INT TERM

# Wazuh's JSON decoder rejects Suricata's very large EVE stats objects.
# Keep the dedicated stats.log output, but omit only stats events from EVE.
sed -i '/^        - stats:$/,/^            deltas: no/d' "$CONFIG_FILE"

# /run is backed by a container volume and can retain a stale PID across
# Docker Desktop restarts. No Suricata child exists yet at this point.
rm -f "$PID_FILE"

prepare_initial_rules

echo "[suricata] Starting packet capture on interface ${INTERFACE}..."
suricata \
    -c "$CONFIG_FILE" \
    -i "$INTERFACE" \
    -k none \
    -S "$COMBINED_RULES" \
    -l "$LOG_DIR" \
    --pidfile "$PID_FILE" \
    --init-errors-fatal &
SURICATA_PID=$!

reload_loop &
UPDATER_PID=$!

if wait "$SURICATA_PID"; then
    STATUS=0
else
    STATUS=$?
fi

kill "$UPDATER_PID" 2>/dev/null || true
wait "$UPDATER_PID" 2>/dev/null || true
exit "$STATUS"
