#!/usr/bin/env bash
# Report a ban or unban event to the central f2b-sync-api collector.
# Called by fail2ban via central-api.conf action.
#
# Usage: f2b-central-report.sh <ban|unban> <ip> <jail> <server_id>

set -euo pipefail

CONF_FILE="${F2B_CENTRAL_CONF:-/etc/f2b-central.conf}"
LOG_FILE="/var/log/f2b-central.log"

log() {
    echo "$(date -Iseconds) [report] $*" >> "$LOG_FILE"
}

if [[ ! -f "$CONF_FILE" ]]; then
    log "ERROR: config file $CONF_FILE not found"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONF_FILE"

ACTION="${1:-}"
IP="${2:-}"
JAIL="${3:-unknown}"
SERVER_ID="${4:-$(hostname)}"

case "$ACTION" in
    ban|unban) ;;
    *)
        log "ERROR: invalid ACTION '${ACTION}'; must be 'ban' or 'unban'"
        exit 1
        ;;
esac

if [[ -z "$IP" ]]; then
    log "ERROR: no IP provided"
    exit 1
fi

if [[ -z "${COLLECTOR_URL:-}" ]] || [[ -z "${API_KEY:-}" ]]; then
    log "ERROR: COLLECTOR_URL or API_KEY not set in $CONF_FILE"
    exit 1
fi

HOSTNAME_VAL="$(hostname -f 2>/dev/null || hostname)"

if [[ "$ACTION" == "ban" ]]; then
    PAYLOAD=$(python3 -c "import json,sys; print(json.dumps({'ip':sys.argv[1],'jail':sys.argv[2],'server_id':sys.argv[3],'hostname':sys.argv[4],'failures':0}))" \
        "$IP" "$JAIL" "$SERVER_ID" "$HOSTNAME_VAL")
    ENDPOINT="${COLLECTOR_URL%/}/api/v1/report-ban"
else
    PAYLOAD=$(python3 -c "import json,sys; print(json.dumps({'ip':sys.argv[1],'jail':sys.argv[2],'server_id':sys.argv[3]}))" \
        "$IP" "$JAIL" "$SERVER_ID")
    ENDPOINT="${COLLECTOR_URL%/}/api/v1/report-unban"
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-API-Key: ${API_KEY}" \
    --max-time 10 \
    -d "$PAYLOAD" \
    "$ENDPOINT" 2>>"$LOG_FILE")

case "$HTTP_CODE" in
    2*)
        log "OK $ACTION ip=$IP jail=$JAIL server=$SERVER_ID http=$HTTP_CODE"
        ;;
    4*)
        log "WARN $ACTION ip=$IP jail=$JAIL server=$SERVER_ID http=$HTTP_CODE"
        ;;
    *)
        log "ERROR $ACTION ip=$IP jail=$JAIL server=$SERVER_ID http=$HTTP_CODE"
        ;;
esac
