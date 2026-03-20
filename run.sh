#!/bin/bash
# =============================================================================
# KNX Failover Proxy — Main Orchestration Script  v2.1.0
# =============================================================================
# State machine:  PRIMARY → BACKUP → USB → DEGRADED
# Supports:       TCP/IP, UDP/IP (auto-bridged), USB/serial (TPUART/FT1.2)
# Recovery:       Automatic, with configurable rise/fall thresholds
# =============================================================================
#
# NOTE: intentionally NOT using "set -e".
#   The monitor loop must survive probe failures without terminating.
#   All error handling is explicit.
#
set -uo pipefail

readonly OPTIONS_FILE="/data/options.json"
readonly STATE_FILE="/run/knx-haproxy.state"
readonly HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
readonly HAPROXY_PID_FILE="/run/haproxy.pid"
readonly SOCAT_PID_FILE="/run/knx-bridge.pid"
readonly HA_NOTIFY_URL="http://supervisor/core/api/services/persistent_notification/create"
readonly SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN:-}"
readonly VERSION="2.1.0"

readonly STATE_PRIMARY="PRIMARY"
readonly STATE_BACKUP="BACKUP"
readonly STATE_USB="USB"
readonly STATE_DEGRADED="DEGRADED"

PRIMARY_HOST=""
PRIMARY_PORT=""
BACKUP_HOST=""
BACKUP_PORT=""
LISTEN_PORT=""
USB_DEVICE=""
USB_BAUD=""
CONN_TIMEOUT=""
CLIENT_TIMEOUT=""
SERVER_TIMEOUT=""
CHECK_INTERVAL=""
CHECK_FALL=""
CHECK_RISE=""
UDP_BRIDGE_PORT=""
LOG_LEVEL=""
USB_PRIORITY=""
NOTIFY_ON_FAILOVER=""

CURRENT_STATE=""
SOCAT_PID=""
HAPROXY_PID=""
BRIDGE_MODE=""
BACKUP_TARGET_HOST=""
BACKUP_TARGET_PORT=""

PRIMARY_FAIL_COUNT=0
PRIMARY_RISE_COUNT=0
BACKUP_FAIL_COUNT=0

# ---------------------------------------------------------------------------
# Logging — all functions explicitly return 0 so they never propagate failure
# ---------------------------------------------------------------------------
_log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    case "$level" in
        DEBUG)
            if [[ "${LOG_LEVEL:-info}" == "debug" ]]; then
                echo "[DEBUG] ${ts} $msg"
            fi
            ;;
        INFO)   echo "[INFO]  ${ts} $msg" ;;
        WARN)   echo "[WARN]  ${ts} $msg" ;;
        ERROR)  echo "[ERROR] ${ts} $msg" >&2 ;;
        NOTICE) echo "[NOTE]  ${ts} $msg" ;;
    esac
    return 0
}

log_debug()  { _log DEBUG  "$@"; return 0; }
log_info()   { _log INFO   "$@"; return 0; }
log_warn()   { _log WARN   "$@"; return 0; }
log_error()  { _log ERROR  "$@"; return 0; }
log_notice() { _log NOTICE "$@"; return 0; }

die() { log_error "$*"; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
read_option() {
    local key="$1" fallback="$2"
    jq -r --arg k "$key" --arg f "$fallback" '.[$k] // $f' "$OPTIONS_FILE"
}

is_int() { [[ "$1" =~ ^[0-9]+$ ]]; return $?; }

is_valid_host() { [[ -n "$1" ]] && [[ "$1" =~ ^[A-Za-z0-9._:-]+$ ]]; return $?; }

validate_port() {
    local v="$1" label="$2"
    if ! is_int "$v"; then die "$label must be a number, got: '$v'"; fi
    if [[ "$v" -lt 1 ]] || [[ "$v" -gt 65535 ]]; then die "$label out of range: $v"; fi
}

validate_positive_int() {
    local v="$1" label="$2"
    if ! is_int "$v" || [[ "$v" -lt 1 ]]; then die "$label must be a positive integer, got: '$v'"; fi
}

load_config() {
    [[ -f "$OPTIONS_FILE" ]] || die "Missing $OPTIONS_FILE"

    PRIMARY_HOST="$(read_option 'primary_host' '')"
    PRIMARY_PORT="$(read_option 'primary_port' '3671')"
    BACKUP_HOST="$(read_option 'backup_host' '')"
    BACKUP_PORT="$(read_option 'backup_port' '3671')"
    LISTEN_PORT="$(read_option 'listen_port' '3672')"
    UDP_BRIDGE_PORT="$(read_option 'udp_bridge_port' '13671')"
    CONN_TIMEOUT="$(read_option 'connection_timeout' '5')"
    CLIENT_TIMEOUT="$(read_option 'client_timeout' '300')"
    SERVER_TIMEOUT="$(read_option 'server_timeout' '300')"
    CHECK_INTERVAL="$(read_option 'health_check_interval' '5')"
    CHECK_FALL="$(read_option 'health_check_fall' '3')"
    CHECK_RISE="$(read_option 'health_check_rise' '2')"
    LOG_LEVEL="$(read_option 'log_level' 'info')"
    USB_DEVICE="$(read_option 'usb_device' '')"
    USB_BAUD="$(read_option 'usb_baud' '19200')"
    USB_PRIORITY="$(read_option 'usb_priority' 'last_resort')"
    NOTIFY_ON_FAILOVER="$(read_option 'notify_on_failover' 'false')"

    [[ -n "$PRIMARY_HOST" ]] || die "primary_host is required"
    [[ -n "$BACKUP_HOST"  ]] || die "backup_host is required"
    is_valid_host "$PRIMARY_HOST" || die "primary_host invalid: $PRIMARY_HOST"
    is_valid_host "$BACKUP_HOST"  || die "backup_host invalid: $BACKUP_HOST"

    validate_port         "$PRIMARY_PORT"    "primary_port"
    validate_port         "$BACKUP_PORT"     "backup_port"
    validate_port         "$LISTEN_PORT"     "listen_port"
    validate_port         "$UDP_BRIDGE_PORT" "udp_bridge_port"
    validate_positive_int "$CONN_TIMEOUT"    "connection_timeout"
    validate_positive_int "$CLIENT_TIMEOUT"  "client_timeout"
    validate_positive_int "$SERVER_TIMEOUT"  "server_timeout"
    validate_positive_int "$CHECK_INTERVAL"  "health_check_interval"
    validate_positive_int "$CHECK_FALL"      "health_check_fall"
    validate_positive_int "$CHECK_RISE"      "health_check_rise"
    validate_positive_int "$USB_BAUD"        "usb_baud"

    if [[ "$LISTEN_PORT" == "$UDP_BRIDGE_PORT" ]]; then
        die "listen_port and udp_bridge_port must differ"
    fi
    if [[ "$PRIMARY_HOST:$PRIMARY_PORT" == "$BACKUP_HOST:$BACKUP_PORT" ]]; then
        log_warn "Primary and backup targets are identical; failover provides no redundancy"
    fi
}

# ---------------------------------------------------------------------------
# HA notification (best-effort, never fatal)
# ---------------------------------------------------------------------------
ha_notify() {
    local title="$1" message="$2"
    [[ "$NOTIFY_ON_FAILOVER" == "true" ]] || return 0
    [[ -n "$SUPERVISOR_TOKEN" ]]           || return 0
    command -v curl >/dev/null 2>&1        || return 0
    local payload
    payload="$(jq -n --arg t "KNX Failover: $title" --arg m "$message" --arg n "knx_failover" \
        '{title:$t,message:$m,notification_id:$n}')" || return 0
    curl -sf --max-time 5 -X POST \
        -H "Authorization: Bearer ${SUPERVISOR_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$payload" "$HA_NOTIFY_URL" >/dev/null 2>&1 || true
    return 0
}

# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------
tcp_probe() {
    local host="$1" port="$2"
    timeout 2 socat -T1 - "TCP:${host}:${port},connect-timeout=1" \
        </dev/null >/dev/null 2>&1
    return $?
}

knx_udp_probe() {
    local host="$1" port="$2"
    printf '\x06\x10\x02\x01\x00\x0e\x08\x01\x00\x00\x00\x00\x0e\x57' | \
        timeout 3 socat -T2 STDIO "UDP:${host}:${port}" >/dev/null 2>&1
    return $?
}

detect_backup_protocol() {
    local host="$1" port="$2"
    if tcp_probe "$host" "$port"; then
        echo "tcp"
    elif knx_udp_probe "$host" "$port"; then
        echo "udp"
    else
        echo "none"
    fi
}

usb_probe() {
    local device="$1"
    [[ -n "$device" ]] && [[ -e "$device" ]] && [[ -r "$device" ]] && [[ -w "$device" ]]
    return $?
}

# ---------------------------------------------------------------------------
# socat bridges
# ---------------------------------------------------------------------------
start_bridge() {
    stop_bridge
    local local_port="$1" target_host="$2" target_port="$3"
    log_info "Starting TCP→UDP bridge: 127.0.0.1:${local_port} → ${target_host}:${target_port}"
    socat "TCP-LISTEN:${local_port},fork,reuseaddr,keepalive,nodelay,backlog=8" \
          "UDP:${target_host}:${target_port}" &
    SOCAT_PID="$!"
    echo "$SOCAT_PID" > "$SOCAT_PID_FILE"
    sleep 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_error "Bridge process died immediately"
        SOCAT_PID=""; rm -f "$SOCAT_PID_FILE"; return 1
    fi
    if ! tcp_probe "127.0.0.1" "$local_port"; then
        log_error "Bridge started but local probe failed"
        stop_bridge; return 1
    fi
    log_info "Bridge is up (pid=${SOCAT_PID})"
    return 0
}

start_usb_bridge() {
    local device="$1" baud="$2" local_port="$3"
    stop_bridge
    log_info "Starting USB serial bridge: ${device} (${baud} baud) → 127.0.0.1:${local_port}"
    socat "TCP-LISTEN:${local_port},fork,reuseaddr,keepalive,nodelay,backlog=4" \
          "OPEN:${device},raw,echo=0,b${baud},crtscts=0" &
    SOCAT_PID="$!"
    echo "$SOCAT_PID" > "$SOCAT_PID_FILE"
    sleep 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_error "USB bridge process died immediately"
        SOCAT_PID=""; rm -f "$SOCAT_PID_FILE"; return 1
    fi
    if ! tcp_probe "127.0.0.1" "$local_port"; then
        log_error "USB bridge started but local probe failed"
        stop_bridge; return 1
    fi
    log_info "USB bridge is up (pid=${SOCAT_PID})"
    return 0
}

stop_bridge() {
    local pid=""
    if [[ -f "$SOCAT_PID_FILE" ]]; then
        pid="$(cat "$SOCAT_PID_FILE" 2>/dev/null || true)"
        rm -f "$SOCAT_PID_FILE"
    fi
    [[ -z "$pid" ]] && pid="$SOCAT_PID"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    SOCAT_PID=""
    return 0
}

ensure_bridge_alive() {
    [[ -n "$SOCAT_PID" ]] || return 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_warn "Bridge died (pid=${SOCAT_PID}); restarting..."
        start_bridge "$UDP_BRIDGE_PORT" "$BACKUP_HOST" "$BACKUP_PORT"
        return $?
    fi
    return 0
}

# ---------------------------------------------------------------------------
# HAProxy  — run foreground (-W master-worker), backgrounded by bash
# -D (daemon) is intentionally NOT used; s6 supervises the process tree
# ---------------------------------------------------------------------------
generate_haproxy_cfg() {
    local backend_host="$1" backend_port="$2" mode="$3"
    log_debug "Generating HAProxy config: mode=${mode}"
    local server_line=""
    case "$mode" in
        primary-only)  server_line="    server primary ${PRIMARY_HOST}:${PRIMARY_PORT} check" ;;
        backup-only)   server_line="    server active  ${backend_host}:${backend_port} check" ;;
        *)             log_error "Unknown config mode: $mode"; return 1 ;;
    esac
    mkdir -p "$(dirname "$HAPROXY_CFG")"
    cat > "$HAPROXY_CFG" <<EOF
# KNX Failover Proxy v${VERSION} — $(date) — mode: ${mode}
global
    log stdout format raw local0
    maxconn 512
    hard-stop-after 3s

defaults
    log global
    mode tcp
    option tcplog
    option log-health-checks
    option clitcpka
    option srvtcpka
    option redispatch
    retries 2
    timeout connect  ${CONN_TIMEOUT}s
    timeout check    ${CONN_TIMEOUT}s
    timeout client   ${CLIENT_TIMEOUT}s
    timeout server   ${SERVER_TIMEOUT}s
    timeout tunnel   ${SERVER_TIMEOUT}s
    default-server inter ${CHECK_INTERVAL}s fall ${CHECK_FALL} rise ${CHECK_RISE} on-marked-down shutdown-sessions

frontend knx_frontend
    bind *:${LISTEN_PORT}
    default_backend knx_backend

backend knx_backend
    mode tcp
    option tcp-check
${server_line}
EOF
    if haproxy -c -f "$HAPROXY_CFG" >/dev/null 2>&1; then
        log_debug "HAProxy config validated OK"
        return 0
    fi
    log_error "HAProxy config validation failed — dumping:"
    cat "$HAPROXY_CFG" >&2
    return 1
}

start_haproxy() {
    stop_haproxy
    log_info "Starting HAProxy..."
    # -W = master-worker foreground mode; bash & gives us the master PID
    haproxy -W -f "$HAPROXY_CFG" &
    HAPROXY_PID="$!"
    # Wait up to 3s for the process to stay alive
    local i=0
    while [[ $i -lt 3 ]]; do
        sleep 1
        i=$((i + 1))
        if ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
            log_error "HAProxy exited during startup"
            HAPROXY_PID=""
            return 1
        fi
    done
    echo "$HAPROXY_PID" > "$HAPROXY_PID_FILE"
    log_info "HAProxy started (pid=${HAPROXY_PID})"
    return 0
}

reload_haproxy() {
    if [[ -n "$HAPROXY_PID" ]] && kill -0 "$HAPROXY_PID" 2>/dev/null; then
        log_info "Reloading HAProxy (USR2 → pid=${HAPROXY_PID})..."
        kill -USR2 "$HAPROXY_PID" 2>/dev/null || true
        sleep 1
        if kill -0 "$HAPROXY_PID" 2>/dev/null; then
            log_info "HAProxy reloaded"
            return 0
        fi
        log_warn "HAProxy didn't survive reload; restarting"
    fi
    start_haproxy
    return $?
}

stop_haproxy() {
    local pid="$HAPROXY_PID"
    if [[ -z "$pid" ]] && [[ -f "$HAPROXY_PID_FILE" ]]; then
        pid="$(cat "$HAPROXY_PID_FILE" 2>/dev/null || true)"
    fi
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -USR1 "$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
    fi
    rm -f "$HAPROXY_PID_FILE"
    HAPROXY_PID=""
    return 0
}

ensure_haproxy_alive() {
    if [[ -n "$HAPROXY_PID" ]] && kill -0 "$HAPROXY_PID" 2>/dev/null; then
        return 0
    fi
    log_warn "HAProxy not running; restarting..."
    start_haproxy
    return $?
}

# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------
write_state() {
    {
        echo "state=${CURRENT_STATE}"
        echo "bridge_mode=${BRIDGE_MODE}"
        echo "backup_target_host=${BACKUP_TARGET_HOST}"
        echo "backup_target_port=${BACKUP_TARGET_PORT}"
        echo "timestamp=$(date -Iseconds 2>/dev/null || date)"
        echo "version=${VERSION}"
    } > "$STATE_FILE" 2>/dev/null || true
    return 0
}

# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------
enter_primary() {
    log_notice "→ Entering state: PRIMARY (${PRIMARY_HOST}:${PRIMARY_PORT})"
    CURRENT_STATE="$STATE_PRIMARY"
    BRIDGE_MODE="tcp-direct"
    BACKUP_TARGET_HOST=""
    BACKUP_TARGET_PORT=""
    PRIMARY_FAIL_COUNT=0
    PRIMARY_RISE_COUNT=0
    BACKUP_FAIL_COUNT=0
    stop_bridge
    if ! generate_haproxy_cfg "" "" "primary-only"; then
        log_error "Cannot generate HAProxy config for PRIMARY"
        return 1
    fi
    reload_haproxy
    write_state
    ha_notify "Primary restored" "Routing through primary ${PRIMARY_HOST}:${PRIMARY_PORT}"
    return 0
}

enter_backup() {
    local proto="$1"
    log_notice "→ Entering state: BACKUP (${BACKUP_HOST}:${BACKUP_PORT}, proto=${proto})"
    CURRENT_STATE="$STATE_BACKUP"
    if [[ "$proto" == "udp" ]]; then
        BRIDGE_MODE="udp-bridge"
        BACKUP_TARGET_HOST="127.0.0.1"
        BACKUP_TARGET_PORT="$UDP_BRIDGE_PORT"
        if ! start_bridge "$UDP_BRIDGE_PORT" "$BACKUP_HOST" "$BACKUP_PORT"; then
            log_error "Cannot start UDP bridge; entering DEGRADED"
            enter_degraded "udp-bridge-start-failed"
            return 0
        fi
    else
        BRIDGE_MODE="tcp-direct"
        BACKUP_TARGET_HOST="$BACKUP_HOST"
        BACKUP_TARGET_PORT="$BACKUP_PORT"
        stop_bridge
    fi
    BACKUP_FAIL_COUNT=0
    if ! generate_haproxy_cfg "$BACKUP_TARGET_HOST" "$BACKUP_TARGET_PORT" "backup-only"; then
        log_error "Cannot generate HAProxy config for BACKUP"
        enter_degraded "haproxy-config-failed"
        return 0
    fi
    reload_haproxy
    write_state
    ha_notify "Failover to backup" \
        "Primary ${PRIMARY_HOST}:${PRIMARY_PORT} unreachable. Using backup ${BACKUP_HOST}:${BACKUP_PORT} [${proto}]."
    return 0
}

enter_usb() {
    log_notice "→ Entering state: USB (${USB_DEVICE}, ${USB_BAUD} baud)"
    CURRENT_STATE="$STATE_USB"
    BRIDGE_MODE="usb-tty"
    BACKUP_TARGET_HOST="127.0.0.1"
    BACKUP_TARGET_PORT="$UDP_BRIDGE_PORT"
    stop_bridge
    if ! start_usb_bridge "$USB_DEVICE" "$USB_BAUD" "$UDP_BRIDGE_PORT"; then
        log_error "Cannot start USB bridge; entering DEGRADED"
        enter_degraded "usb-bridge-start-failed"
        return 0
    fi
    if ! generate_haproxy_cfg "127.0.0.1" "$UDP_BRIDGE_PORT" "backup-only"; then
        log_error "Cannot generate HAProxy config for USB"
        enter_degraded "haproxy-config-failed"
        return 0
    fi
    reload_haproxy
    write_state
    ha_notify "Failover to USB" "Both IP interfaces unreachable. Using USB ${USB_DEVICE}."
    return 0
}

enter_degraded() {
    local reason="${1:-unknown}"
    log_warn "→ Entering state: DEGRADED (reason=${reason})"
    CURRENT_STATE="$STATE_DEGRADED"
    write_state
    ha_notify "KNX degraded" "No KNX interface available (${reason}). Retrying every ${CHECK_INTERVAL}s."
    return 0
}

# ---------------------------------------------------------------------------
# Startup probe
# ---------------------------------------------------------------------------
initial_probe() {
    log_info "Running startup probes..."

    if [[ "$USB_PRIORITY" == "prefer" ]] && [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_info "USB preferred and present: $USB_DEVICE"
        enter_usb; return
    fi

    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_info "Primary startup probe: OK"
        enter_primary; return
    fi
    log_warn "Primary startup probe failed (${PRIMARY_HOST}:${PRIMARY_PORT})"

    local proto
    proto="$(detect_backup_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_info "Backup startup probe: OK (proto=${proto})"
        enter_backup "$proto"; return
    fi
    log_warn "Backup startup probe failed (${BACKUP_HOST}:${BACKUP_PORT})"

    if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_info "USB available as last resort: $USB_DEVICE"
        enter_usb; return
    fi

    log_error "No KNX interface reachable at startup — entering DEGRADED retry loop"
    generate_haproxy_cfg "$PRIMARY_HOST" "$PRIMARY_PORT" "primary-only" || true
    start_haproxy || true
    enter_degraded "startup-all-probes-failed"
}

# ---------------------------------------------------------------------------
# Monitor tick  — must never exit non-zero
# ---------------------------------------------------------------------------
monitor_tick() {
    case "$CURRENT_STATE" in
        "$STATE_PRIMARY")   tick_primary  ;;
        "$STATE_BACKUP")    tick_backup   ;;
        "$STATE_USB")       tick_usb      ;;
        "$STATE_DEGRADED")  tick_degraded ;;
        *)
            log_warn "Unknown state '${CURRENT_STATE}'; resetting to DEGRADED"
            enter_degraded "unknown-state"
            ;;
    esac
    ensure_haproxy_alive || log_error "HAProxy watchdog: restart failed"
    return 0
}

tick_primary() {
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_debug "Primary probe: OK"
        PRIMARY_FAIL_COUNT=0
        return 0
    fi
    PRIMARY_FAIL_COUNT=$((PRIMARY_FAIL_COUNT + 1))
    log_warn "Primary probe failed (${PRIMARY_FAIL_COUNT}/${CHECK_FALL})"
    if [[ "$PRIMARY_FAIL_COUNT" -ge "$CHECK_FALL" ]]; then
        log_warn "Primary failed ${CHECK_FALL}x — initiating failover"
        local proto
        proto="$(detect_backup_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
        if [[ "$proto" != "none" ]]; then
            enter_backup "$proto"
        elif [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
            enter_usb
        else
            enter_degraded "primary-failed-no-backup"
        fi
    fi
    return 0
}

tick_backup() {
    # Check primary recovery
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        PRIMARY_RISE_COUNT=$((PRIMARY_RISE_COUNT + 1))
        log_info "Primary recovery probe OK (${PRIMARY_RISE_COUNT}/${CHECK_RISE})"
        if [[ "$PRIMARY_RISE_COUNT" -ge "$CHECK_RISE" ]]; then
            log_notice "Primary recovered — switching back"
            enter_primary
            return 0
        fi
    else
        if [[ "$PRIMARY_RISE_COUNT" -gt 0 ]]; then
            log_debug "Primary recovery counter reset"
        fi
        PRIMARY_RISE_COUNT=0
    fi

    # Check backup health
    local backup_ok=0
    if [[ "$BRIDGE_MODE" == "udp-bridge" ]]; then
        if ensure_bridge_alive && tcp_probe "127.0.0.1" "$UDP_BRIDGE_PORT"; then
            backup_ok=1
        fi
    else
        if tcp_probe "$BACKUP_HOST" "$BACKUP_PORT"; then
            backup_ok=1
        fi
    fi

    if [[ "$backup_ok" -eq 1 ]]; then
        log_debug "Backup probe: OK"
        BACKUP_FAIL_COUNT=0
    else
        BACKUP_FAIL_COUNT=$((BACKUP_FAIL_COUNT + 1))
        log_warn "Backup probe failed (${BACKUP_FAIL_COUNT}/${CHECK_FALL})"
        if [[ "$BACKUP_FAIL_COUNT" -ge "$CHECK_FALL" ]]; then
            log_warn "Backup also down"
            if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
                enter_usb
            else
                enter_degraded "backup-failed-no-usb"
            fi
        fi
    fi
    return 0
}

tick_usb() {
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_notice "Primary recovered (was in USB mode) — switching back"
        enter_primary; return 0
    fi
    local proto
    proto="$(detect_backup_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_notice "Backup recovered (was in USB mode) — switching to BACKUP"
        enter_backup "$proto"; return 0
    fi

    if ! ensure_bridge_alive || ! tcp_probe "127.0.0.1" "$UDP_BRIDGE_PORT"; then
        if ! usb_probe "$USB_DEVICE"; then
            log_error "USB device disappeared: $USB_DEVICE"
            enter_degraded "usb-device-gone"
        else
            log_warn "USB bridge died; restarting"
            start_usb_bridge "$USB_DEVICE" "$USB_BAUD" "$UDP_BRIDGE_PORT" || \
                enter_degraded "usb-bridge-restart-failed"
        fi
        return 0
    fi
    log_debug "USB probe: OK"
    return 0
}

tick_degraded() {
    log_debug "Retrying all interfaces (DEGRADED)..."
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_notice "Primary came back — leaving DEGRADED"
        enter_primary; return 0
    fi
    local proto
    proto="$(detect_backup_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_notice "Backup came back (proto=${proto}) — leaving DEGRADED"
        enter_backup "$proto"; return 0
    fi
    if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_notice "USB available — leaving DEGRADED"
        enter_usb; return 0
    fi
    log_debug "All interfaces still down — retrying in ${CHECK_INTERVAL}s"
    return 0
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    log_info "Shutting down KNX Failover Proxy..."
    stop_bridge  || true
    stop_haproxy || true
    rm -f "$STATE_FILE" 2>/dev/null || true
    log_info "Shutdown complete"
}
trap cleanup INT TERM EXIT

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log_info "===== KNX Failover Proxy v${VERSION} ====="

    require_cmd jq
    require_cmd haproxy
    require_cmd socat
    require_cmd timeout

    load_config

    log_info "Primary:  ${PRIMARY_HOST}:${PRIMARY_PORT}"
    log_info "Backup:   ${BACKUP_HOST}:${BACKUP_PORT}"
    log_info "Listen:   0.0.0.0:${LISTEN_PORT}"
    if [[ -n "$USB_DEVICE" ]]; then
        log_info "USB:      ${USB_DEVICE} @ ${USB_BAUD} baud (priority=${USB_PRIORITY})"
    fi
    log_info "Health:   interval=${CHECK_INTERVAL}s fall=${CHECK_FALL} rise=${CHECK_RISE}"

    initial_probe

    log_info "Entering monitor loop (interval=${CHECK_INTERVAL}s)..."
    while true; do
        sleep "$CHECK_INTERVAL" || true
        monitor_tick
    done
}

main "$@"