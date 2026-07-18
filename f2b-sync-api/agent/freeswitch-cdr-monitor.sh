#!/usr/bin/env bash
# freeswitch-cdr-monitor.sh — FreeSWITCH CDR toll fraud detection
# 
# Scans FreeSWITCH CDR database for suspicious call patterns and emails alerts.
# Run via cron every 15 minutes:
#   */15 * * * * /usr/local/bin/freeswitch-cdr-monitor.sh
#
# CDR Database Locations (FusionPBX):
#   SQLite: /var/lib/freeswitch/db/cdr.db
#   MySQL:  Configured in FusionPBX Advanced → CDR → CDR DB

set -euo pipefail

LOG_FILE="/var/log/f2b-cdr-monitor.log"
ALERT_EMAIL="${ALERT_EMAIL:-admin@yourdomain.com}"

# ── Configurable thresholds ─────────────────────────────────────────────
# Max calls per extension in the lookback window
MAX_CALLS_PER_EXT="${MAX_CALLS_PER_EXT:-20}"
# Max total call duration in minutes per extension
MAX_DURATION_MINUTES="${MAX_DURATION_MINUTES:-60}"
# Lookback window in minutes
LOOKBACK_MINUTES="${LOOKBACK_MINUTES:-60}"
# Alert on calls to these country codes (international premium)
HIGH_RISK_COUNTRIES="${HIGH_RISK_COUNTRIES:-"238 242 246 247 248 249 250 252 254 255 256 257 258 260 261 262 263 264 265 266 267 268 269 284 338 339 368 369 370 371 372 373 374 375 376 377 378 379 380 381 382 383 384 385 386 387 389 390 391 392 393 394 395 396 397 398 399 500 501 502 503 504 505 506 507 508 509 664 683 684 685 686 687 688 689 690 691 692 693 694 695 696 697 698 699 758 767 784 787 800 808 809 811 829 849 850 856 858 859 860 861 862 863 864 865 866 867 868 869 870 871 872 873 874 875 876 877 878 879 880 881 882 883 884 885 886 887 888 889 900 901 902 903 904 905 906 907 908 909 910 911 912 913 914 915 916 917 918 919 920 921 922 923 924 925 926 927 928 929 930 931 932 933 934 935 936 937 938 939 940 941 942 943 944 945 946 947 948 949 950 951 952 953 954 955 956 957 958 959 960 961 962 963 964 965 966 967 968 969 970 971 972 973 974 975 976 977 978 979 980 981 982 983 984 985 986 987 988 989 990 991 992 993 994 995 996 997 998 999"}"
# ALWAYS trigger if a call goes to these country codes (Cuba, Somalia, etc.)
EXTREME_RISK_COUNTRIES="${EXTREME_RISK_COUNTRIES:-"53 252 211 881 882 883"}"

log() {
    echo "$(date -Iseconds) [cdr] $*" >> "$LOG_FILE"
}

alert() {
    local subject="$1"
    local body="$2"
    echo "$body" | mail -s "[TOLL-ALERT] $subject" "$ALERT_EMAIL" 2>>"$LOG_FILE" || true
    log "ALERT sent: $subject"
}

# ── Determine CDR source ───────────────────────────────────────────────
# FusionPBX typically uses SQLite by default. MySQL is optional.
CDR_DB="/var/lib/freeswitch/db/cdr.db"
USE_SQLITE=false
USE_MYSQL=false

if [[ -f "$CDR_DB" ]]; then
    USE_SQLITE=true
    log "Using SQLite CDR: $CDR_DB"
elif command -v mysql &>/dev/null; then
    # Check if MySQL has the cdr table
    if mysql -e "SELECT 1 FROM fusionpbx.v_xml_cdr LIMIT 1" 2>/dev/null; then
        USE_MYSQL=true
        log "Using MySQL CDR"
    fi
fi

if ! $USE_SQLITE && ! $USE_MYSQL; then
    log "No CDR source found. Skipping check."
    exit 0
fi

# ── Build query ─────────────────────────────────────────────────────────
SINCE=$(date -d "$LOOKBACK_MINUTES minutes ago" "+%Y-%m-%d %H:%M:%S")

# SQLite query
SQLITE_QUERY="
SELECT
    caller_id_number,
    destination_number,
    duration,
    billsec,
    hangup_cause,
    answer_stamp
FROM calls
WHERE start_stamp >= '$SINCE'
    AND duration > 0
ORDER BY start_stamp DESC;"

# ── Analyze CDR ────────────────────────────────────────────────────────
ALERTS=""
CALL_COUNT=0

if $USE_SQLITE; then
    RESULTS=$(sqlite3 "$CDR_DB" "$SQLITE_QUERY" 2>/dev/null) || {
        log "SQLite query failed"
        exit 0
    }
elif $USE_MYSQL; then
    RESULTS=$(mysql -N -B -e "USE fusionpbx; $SQLITE_QUERY" 2>/dev/null) || {
        log "MySQL query failed"
        exit 0
    }
fi

[[ -z "$RESULTS" ]] && { log "No calls in window. Clean."; exit 0; }

# ── Parse and analyze ──────────────────────────────────────────────────
declare -A EXT_CALL_COUNT
declare -A EXT_TOTAL_DURATION
declare -A EXT_HIGH_RISK_CALLS
declare -A EXT_EXTREME_RISK_CALLS
EXTREME_RISK_FOUND=false

while IFS='|' read -r caller dest duration billsec hangup answer; do
    [[ -z "$caller" ]] && continue
    CALL_COUNT=$((CALL_COUNT + 1))

    # Extract country code from destination (first digits after any prefix)
    DEST_CLEAN=$(echo "$dest" | sed 's/^+//')
    CC="${DEST_CLEAN:0:3}"  # first 3 chars
    # Check if first 2 chars match a country code
    CC2="${DEST_CLEAN:0:2}"

    # Count per extension
    EXT_CALL_COUNT["$caller"]=$((EXT_CALL_COUNT["$caller"] + 1))
    EXT_TOTAL_DURATION["$caller"]=$((EXT_TOTAL_DURATION["$caller"] + billsec))

    # Check extreme risk countries
    if echo "$EXTREME_RISK_COUNTRIES" | grep -qw "$CC" || echo "$EXTREME_RISK_COUNTRIES" | grep -qw "$CC2"; then
        EXT_EXTREME_RISK_CALLS["$caller"]+="  $dest (${billsec}s)"
        EXTREME_RISK_FOUND=true
    fi

    # Check high risk countries
    if echo "$HIGH_RISK_COUNTRIES" | grep -qw "$CC" || echo "$HIGH_RISK_COUNTRIES" | grep -qw "$CC2"; then
        EXT_HIGH_RISK_CALLS["$caller"]+="  $dest (${billsec}s)"
    fi

done <<< "$RESULTS"

# ── Generate alerts ────────────────────────────────────────────────────
BODY=""
for ext in "${!EXT_CALL_COUNT[@]}"; do
    COUNT=${EXT_CALL_COUNT[$ext]}
    DURATION=$((EXT_TOTAL_DURATION[$ext] / 60))
    HR=${EXT_HIGH_RISK_CALLS[$ext]:-}
    ER=${EXT_EXTREME_RISK_CALLS[$ext]:-}

    if [[ -n "$ER" ]]; then
        BODY+="⚠️  EXTREME RISK: Extension $ext called extreme-risk destinations:\n$ER\n\n"
    fi

    if [[ -n "$HR" ]]; then
        BODY+="⚠️  HIGH RISK: Extension $ext called high-risk destinations:\n$HR\n\n"
    fi

    if [[ "$COUNT" -gt "$MAX_CALLS_PER_EXT" ]]; then
        BODY+="⚠️  VOLUME: Extension $ext made $COUNT calls in $LOOKBACK_MINUTES min (threshold: $MAX_CALLS_PER_EXT)\n\n"
    fi

    if [[ "$DURATION" -gt "$MAX_DURATION_MINUTES" ]]; then
        BODY+="⚠️  DURATION: Extension $ext accumulated ${DURATION}m in $LOOKBACK_MINUTES min (threshold: ${MAX_DURATION_MINUTES}m)\n\n"
    fi
done

if [[ -n "$BODY" ]]; then
    SUMMARY="Suspicious call activity detected in the last $LOOKBACK_MINUTES minutes"
    alert "$SUMMARY" "Host: $(hostname -f)
Period: $SINCE to now
Total calls checked: $CALL_COUNT

$BODY
--
f2b-cdr-monitor.sh automated check"
    log "Alert sent: suspicious patterns found"
else
    log "No suspicious patterns. Checked $CALL_COUNT calls."
fi
