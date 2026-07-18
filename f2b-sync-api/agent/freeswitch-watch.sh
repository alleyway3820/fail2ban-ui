#!/usr/bin/env bash
# freeswitch-watch.sh — Watches FreeSWITCH log for successful SIP REGISTERs
# and auto-whitelists the phone's IP via f2b-sync-api.
#
# Phones with dynamic IPs (residential ISPs) change addresses every 24-48h.
# This script ensures newly assigned IPs are whitelisted and any existing
# bans are cleared immediately.
#
# Install as a systemd service:
#   [Unit]
#   Description=FreeSWITCH SIP Register Whitelist Watcher
#   After=freeswitch.service
#   [Service]
#   ExecStart=/usr/local/bin/freeswitch-watch.sh
#   Restart=always
#   RestartSec=5
#   [Install]
#   WantedBy=multi-user.target

set -euo pipefail

CONF_FILE="${F2B_CENTRAL_CONF:-/etc/f2b-central.conf}"
LOG_FILE="/var/log/f2b-central.log"
FS_LOG="${FS_LOG:-/var/log/freeswitch/freeswitch.log}"
API_ENDPOINT="whitelist/register"

# ── Source config for COLLECTOR_URL and API_KEY ────────────────────────
if [[ ! -f "$CONF_FILE" ]]; then
    echo "$(date -Iseconds) [fswatch] ERROR: config file $CONF_FILE not found" >> "$LOG_FILE"
    exit 1
fi
# shellcheck source=/dev/null
source "$CONF_FILE"

if [[ -z "${COLLECTOR_URL:-}" ]] || [[ -z "${API_KEY:-}" ]]; then
    echo "$(date -Iseconds) [fswatch] ERROR: COLLECTOR_URL or API_KEY not set" >> "$LOG_FILE"
    exit 1
fi

# Strip trailing slash
COLLECTOR_URL="${COLLECTOR_URL%/}"

# ── Ensure log file exists ─────────────────────────────────────────────
if [[ ! -f "$FS_LOG" ]]; then
    echo "$(date -Iseconds) [fswatch] ERROR: FreeSWITCH log $FS_LOG not found" >> "$LOG_FILE"
    exit 1
fi

SERVER_ID="${SERVER_ID:-$(hostname -f)}"

log() {
    echo "$(date -Iseconds) [fswatch] $*" >> "$LOG_FILE"
}

log "Starting watcher on $FS_LOG..."

# ── Watch log for successful SIP REGISTERs ─────────────────────────────
# Log format:
#   2024-01-15 10:23:45.123456 [NOTICE] sofia_reg.c:xxxx SIP auth OK (REGISTER) on
#   sofia profile[internal] for [1000@domain.com] from ip [1.2.3.4]
#
# Uses tail -F (follow, retry on rotation) + grep with unbuffered output.

tail -F -n0 "$FS_LOG" 2>>"$LOG_FILE" | grep --line-buffered -E \
    "\[NOTICE\] .*SIP auth OK \(REGISTER\) .*from ip \[" \
    2>>"$LOG_FILE" | while IFS= read -r line; do

    # Extract IP address - matches pattern 'from ip [X.X.X.X]'
    IP=$(echo "$line" | sed -n 's/.*from ip \[\([0-9.]*\)\].*/\1/p')
    # Extract extension - matches pattern 'for [XXXX@domain]'
    EXT=$(echo "$line" | sed -n 's/.*for \[\([^@]*\).*\].*from ip.*/\1/p')

    [[ -z "$IP" ]] && continue

    # Build JSON payload
    PAYLOAD=$(python3 -c "
import json, sys
data = {
    'ip': '$IP',
    'extension': '${EXT:-unknown}',
    'server_id': '$SERVER_ID',
    'ttl_hours': 48
}
print(json.dumps(data))
" 2>/dev/null) || continue

    # Call the f2b-sync-api
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${COLLECTOR_URL}/api/v1/${API_ENDPOINT}" \
        -H "X-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        --connect-timeout 5 --max-time 10 2>>"$LOG_FILE") || HTTP_CODE="000"

    if [[ "$HTTP_CODE" =~ ^[23] ]]; then
        log "OK registered ip=$IP ext=${EXT:-unknown}"
    else
        log "WARN register ip=$IP http=$HTTP_CODE"
    fi

    # Also unban from local fail2ban if running
    if command -v fail2ban-client &>/dev/null; then
        BANNED_JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list:\s*//' | tr ',' ' ')
        for jail in $BANNED_JAILS; do
            fail2ban-client set "$jail" unbanip "$IP" 2>/dev/null || true
        done
    fi
done
