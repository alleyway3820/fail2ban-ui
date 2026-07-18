#!/usr/bin/env bash
# f2b-sync.sh — Incremental sync of global blocklist from central collector.
# Run via cron every 5 minutes:
#   */5 * * * * /usr/local/bin/f2b-sync.sh >> /var/log/f2b-central.log 2>&1

set -euo pipefail

CONF_FILE="${F2B_CENTRAL_CONF:-/etc/f2b-central.conf}"
LOG_FILE="/var/log/f2b-central.log"
STATE_FILE="/var/lib/f2b-central/last_sync"
IPSET_NAME="f2b-global"

log() {
    echo "$(date -Iseconds) [sync] $*" >> "$LOG_FILE"
}

for _cmd in ipset python3 iptables; do
    if ! command -v "$_cmd" &>/dev/null; then
        log "ERROR: required command not found: $_cmd"
        exit 1
    fi
done

if [[ ! -f "$CONF_FILE" ]]; then
    log "ERROR: config file $CONF_FILE not found"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONF_FILE"

if [[ -z "${COLLECTOR_URL:-}" ]] || [[ -z "${API_KEY:-}" ]]; then
    log "ERROR: COLLECTOR_URL or API_KEY not set in $CONF_FILE"
    exit 1
fi

mkdir -p "$(dirname "$STATE_FILE")"

# ── Ensure ipset exists ────────────────────────────────────────────────────────
if ! ipset list "$IPSET_NAME" &>/dev/null; then
    ipset create "$IPSET_NAME" hash:ip hashsize 4096 maxelem 1000000
    if ! iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
        iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
    fi
    log "Created ipset $IPSET_NAME and iptables rule"
fi

# ── Build query ────────────────────────────────────────────────────────────────
SINCE_PARAM=""
if [[ -f "$STATE_FILE" ]]; then
    LAST_SYNC="$(cat "$STATE_FILE")"
    SINCE_PARAM="?since=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${LAST_SYNC}'))" 2>/dev/null || echo "")"
fi

ENDPOINT="${COLLECTOR_URL%/}/api/v1/blocklist${SINCE_PARAM}"

# ── Pull blocklist ─────────────────────────────────────────────────────────────
RESPONSE=$(curl -s -f \
    -H "X-API-Key: ${API_KEY}" \
    --max-time 30 \
    "$ENDPOINT" 2>>"$LOG_FILE") || {
    log "ERROR: failed to fetch blocklist from $ENDPOINT"
    exit 1
}

# ── Add IPs to ipset ──────────────────────────────────────────────────────────
ADDED=0
while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    if ! ipset test "$IPSET_NAME" "$ip" &>/dev/null; then
        ipset add "$IPSET_NAME" "$ip" 2>/dev/null && ADDED=$((ADDED + 1)) || true
    fi
done < <(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for entry in data.get('ips', []):
    print(entry['ip'])
" 2>/dev/null)

log "Sync complete: added=$ADDED IPs to ipset $IPSET_NAME"

# ── Check whitelist — remove any whitelisted IPs from the blocklist ─────
# This prevents authenticated SIP phones from being blocked after their
# IP was added to the blocklist for a different reason.
COLLECTOR_BASE="${COLLECTOR_URL%/}"
WHITELIST_RESPONSE=$(curl -s \
    -H "X-API-Key: ${API_KEY}" \
    --max-time 15 \
    "${COLLECTOR_BASE}/api/v1/whitelist" 2>>"$LOG_FILE") || WHITELIST_RESPONSE=""

if [[ -n "$WHITELIST_RESPONSE" ]]; then
    UNBANNED=0
    while IFS= read -r wl_ip; do
        [[ -z "$wl_ip" ]] && continue
        # Remove from ipset if present
        if ipset test "$IPSET_NAME" "$wl_ip" &>/dev/null; then
            ipset del "$IPSET_NAME" "$wl_ip" 2>/dev/null && UNBANNED=$((UNBANNED + 1)) || true
            log "Whitelisted IP $wl_ip removed from blocklist"
        fi
        # Also unban from local fail2ban
        if command -v fail2ban-client &>/dev/null; then
            JAIL_LIST=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list:\s*//' | tr ',' ' ' | tr -d ' ')
            for jail_name in $JAIL_LIST; do
                fail2ban-client set "$jail_name" unbanip "$wl_ip" 2>/dev/null || true
            done
        fi
    done < <(echo "$WHITELIST_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for entry in data.get('whitelist', []):
    print(entry['ip'])
" 2>/dev/null)
    if [[ "$UNBANNED" -gt 0 ]]; then
        log "Whitelist check: unblocked $UNBANNED whitelisted IPs from $IPSET_NAME"
    fi
fi

# ── Save timestamp ─────────────────────────────────────────────────────────────
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$STATE_FILE"

# ── Report local fail2ban status ───────────────────────────────────────────────
if command -v fail2ban-client &>/dev/null; then
    JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list:\s*//' | tr ',' '\n' | tr -d ' ')
    TOTAL_BANNED=0
    while IFS= read -r jail; do
        [[ -z "$jail" ]] && continue
        COUNT=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned:" | awk '{print $NF}' || echo 0)
        TOTAL_BANNED=$((TOTAL_BANNED + COUNT))
    done <<< "$JAILS"
    log "Local fail2ban: total_banned=$TOTAL_BANNED"
fi
