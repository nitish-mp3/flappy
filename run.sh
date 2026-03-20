#!/bin/bash
# =============================================================================
# KNX Failover Proxy v2.2.0
# =============================================================================
# Two processes managed by this script:
#   1. python3 /knx_udp_responder.py  — answers xknx's UDP DESCRIPTION_REQUEST
#   2. haproxy -W                      — proxies the actual TCP KNX tunnel
#
# State machine: PRIMARY → BACKUP → USB → DEGRADED (retries forever)
# =============================================================================
set -uo pipefail

readonly OPTIONS_FILE="/data/options.json"
readonly STATE_FILE="/run/knx-haproxy.state"
readonly HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
readonly HAPROXY_PID_FILE="/run/haproxy.pid"
readonly SOCAT_PID_FILE="/run/knx-bridge.pid"
readonly UDP_PID_FILE="/run/knx-udp.pid"
readonly HA_NOTIFY_URL="http://supervisor/core/api/services/persistent_notification/create"
readonly SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN:-}"
readonly VERSION="2.2.0"

readonly STATE_PRIMARY="PRIMARY"
readonly STATE_BACKUP="BACKUP"
readonly STATE_USB="USB"
readonly STATE_DEGRADED="DEGRADED"

PRIMARY_HOST=""
PRIMARY_PORT=""
BACKUP_HOST=""
BACKUP_PORT=""
LISTEN_PORT=""
UDP_BRIDGE_PORT=""
USB_DEVICE=""
USB_BAUD=""
CONN_TIMEOUT=""
CLIENT_TIMEOUT=""
SERVER_TIMEOUT=""
CHECK_INTERVAL=""
CHECK_FALL=""
CHECK_RISE=""
LOG_LEVEL=""
USB_PRIORITY=""
NOTIFY_ON_FAILOVER=""

CURRENT_STATE=""
HAPROXY_PID=""
SOCAT_PID=""
UDP_PID=""
BRIDGE_MODE=""
BACKUP_TARGET_HOST=""
BACKUP_TARGET_PORT=""

PRIMARY_FAIL_COUNT=0
PRIMARY_RISE_COUNT=0
BACKUP_FAIL_COUNT=0

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_log() {
    local level="$1"; shift
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    case "$level" in
        DEBUG)  [[ "${LOG_LEVEL:-info}" == "debug" ]] && echo "[DEBUG] ${ts} $*" || true ;;
        INFO)   echo "[INFO]  ${ts} $*" ;;
        WARN)   echo "[WARN]  ${ts} $*" ;;
        ERROR)  echo "[ERROR] ${ts} $*" >&2 ;;
        NOTICE) echo "[NOTE]  ${ts} $*" ;;
    esac
    return 0
}
log_debug()  { _log DEBUG  "$@"; return 0; }
log_info()   { _log INFO   "$@"; return 0; }
log_warn()   { _log WARN   "$@"; return 0; }
log_error()  { _log ERROR  "$@"; return 0; }
log_notice() { _log NOTICE "$@"; return 0; }
die() { log_error "$*"; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
read_option() { jq -r --arg k "$1" --arg f "$2" '.[$k] // $f' "$OPTIONS_FILE"; }
is_int()       { [[ "$1" =~ ^[0-9]+$ ]]; }
is_valid_host(){ [[ -n "$1" ]] && [[ "$1" =~ ^[A-Za-z0-9._:-]+$ ]]; }

validate_port() {
    local v="$1" l="$2"
    is_int "$v"                          || die "$l must be a number, got: '$v'"
    [[ "$v" -ge 1 && "$v" -le 65535 ]]  || die "$l out of range: $v"
}
validate_pos_int() {
    local v="$1" l="$2"
    is_int "$v" && [[ "$v" -ge 1 ]] || die "$l must be positive integer, got: '$v'"
}

load_config() {
    [[ -f "$OPTIONS_FILE" ]] || die "Missing $OPTIONS_FILE"

    PRIMARY_HOST="$(read_option primary_host '')"
    PRIMARY_PORT="$(read_option primary_port 3671)"
    BACKUP_HOST="$(read_option backup_host '')"
    BACKUP_PORT="$(read_option backup_port 3671)"
    LISTEN_PORT="$(read_option listen_port 3672)"
    UDP_BRIDGE_PORT="$(read_option udp_bridge_port 13671)"
    CONN_TIMEOUT="$(read_option connection_timeout 5)"
    CLIENT_TIMEOUT="$(read_option client_timeout 300)"
    SERVER_TIMEOUT="$(read_option server_timeout 300)"
    CHECK_INTERVAL="$(read_option health_check_interval 5)"
    CHECK_FALL="$(read_option health_check_fall 3)"
    CHECK_RISE="$(read_option health_check_rise 2)"
    LOG_LEVEL="$(read_option log_level info)"
    USB_DEVICE="$(read_option usb_device '')"
    USB_BAUD="$(read_option usb_baud 19200)"
    USB_PRIORITY="$(read_option usb_priority last_resort)"
    NOTIFY_ON_FAILOVER="$(read_option notify_on_failover false)"

    [[ -n "$PRIMARY_HOST" ]] || die "primary_host is required"
    [[ -n "$BACKUP_HOST"  ]] || die "backup_host is required"
    is_valid_host "$PRIMARY_HOST" || die "primary_host invalid: $PRIMARY_HOST"
    is_valid_host "$BACKUP_HOST"  || die "backup_host invalid: $BACKUP_HOST"
    validate_port    "$PRIMARY_PORT"    primary_port
    validate_port    "$BACKUP_PORT"     backup_port
    validate_port    "$LISTEN_PORT"     listen_port
    validate_port    "$UDP_BRIDGE_PORT" udp_bridge_port
    validate_pos_int "$CONN_TIMEOUT"    connection_timeout
    validate_pos_int "$CLIENT_TIMEOUT"  client_timeout
    validate_pos_int "$SERVER_TIMEOUT"  server_timeout
    validate_pos_int "$CHECK_INTERVAL"  health_check_interval
    validate_pos_int "$CHECK_FALL"      health_check_fall
    validate_pos_int "$CHECK_RISE"      health_check_rise
    validate_pos_int "$USB_BAUD"        usb_baud
    [[ "$LISTEN_PORT" != "$UDP_BRIDGE_PORT" ]] || die "listen_port and udp_bridge_port must differ"
}

# ---------------------------------------------------------------------------
# HA notification (best-effort)
# ---------------------------------------------------------------------------
ha_notify() {
    [[ "$NOTIFY_ON_FAILOVER" == "true" ]] || return 0
    [[ -n "$SUPERVISOR_TOKEN" ]]           || return 0
    command -v curl >/dev/null 2>&1        || return 0
    local payload
    payload="$(jq -n --arg t "KNX Failover: $1" --arg m "$2" --arg n "knx_failover" \
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
    timeout 2 socat -T1 - "TCP:${1}:${2},connect-timeout=1" </dev/null >/dev/null 2>&1
    return $?
}

knx_udp_probe() {
    printf '\x06\x10\x02\x01\x00\x0e\x08\x01\x00\x00\x00\x00\x0e\x57' | \
        timeout 3 socat -T2 STDIO "UDP:${1}:${2}" >/dev/null 2>&1
    return $?
}

detect_protocol() {
    if tcp_probe "$1" "$2"; then echo "tcp"
    elif knx_udp_probe "$1" "$2"; then echo "udp"
    else echo "none"; fi
}

usb_probe() {
    [[ -n "$1" ]] && [[ -e "$1" ]] && [[ -r "$1" ]] && [[ -w "$1" ]]
    return $?
}

# ---------------------------------------------------------------------------
# UDP responder (python3 /knx_udp_responder.py)
# Handles xknx's DESCRIPTION_REQUEST so the TCP proxy can be used
# ---------------------------------------------------------------------------
start_udp_responder() {
    stop_udp_responder
    log_info "Starting KNX/IP UDP responder on port ${LISTEN_PORT}/udp"
    LOG_LEVEL="$LOG_LEVEL" python3 /knx_udp_responder.py "$LISTEN_PORT" &
    UDP_PID="$!"
    echo "$UDP_PID" > "$UDP_PID_FILE"
    sleep 1
    if ! kill -0 "$UDP_PID" 2>/dev/null; then
        log_error "UDP responder died immediately"
        UDP_PID=""; rm -f "$UDP_PID_FILE"; return 1
    fi
    log_info "UDP responder started (pid=${UDP_PID})"
    return 0
}

stop_udp_responder() {
    local pid="${UDP_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$UDP_PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    rm -f "$UDP_PID_FILE"; UDP_PID=""; return 0
}

ensure_udp_responder_alive() {
    if [[ -n "$UDP_PID" ]] && kill -0 "$UDP_PID" 2>/dev/null; then return 0; fi
    log_warn "UDP responder not running — restarting"
    start_udp_responder; return $?
}

# ---------------------------------------------------------------------------
# socat bridges (TCP→UDP for IP backup, TCP→serial for USB)
# ---------------------------------------------------------------------------
start_ip_bridge() {
    stop_bridge
    local lport="$1" thost="$2" tport="$3"
    log_info "Starting TCP→UDP bridge: 127.0.0.1:${lport} → ${thost}:${tport}"
    socat "TCP-LISTEN:${lport},fork,reuseaddr,keepalive,nodelay,backlog=8" \
          "UDP:${thost}:${tport}" &
    SOCAT_PID="$!"; echo "$SOCAT_PID" > "$SOCAT_PID_FILE"
    sleep 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_error "IP bridge died immediately"; SOCAT_PID=""; rm -f "$SOCAT_PID_FILE"; return 1; fi
    if ! tcp_probe "127.0.0.1" "$lport"; then
        log_error "IP bridge probe failed"; stop_bridge; return 1; fi
    log_info "IP bridge up (pid=${SOCAT_PID})"; return 0
}

start_usb_bridge() {
    stop_bridge
    local dev="$1" baud="$2" lport="$3"
    log_info "Starting USB bridge: ${dev} @ ${baud} baud → 127.0.0.1:${lport}"
    socat "TCP-LISTEN:${lport},fork,reuseaddr,keepalive,nodelay,backlog=4" \
          "OPEN:${dev},raw,echo=0,b${baud},crtscts=0" &
    SOCAT_PID="$!"; echo "$SOCAT_PID" > "$SOCAT_PID_FILE"
    sleep 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_error "USB bridge died immediately"; SOCAT_PID=""; rm -f "$SOCAT_PID_FILE"; return 1; fi
    if ! tcp_probe "127.0.0.1" "$lport"; then
        log_error "USB bridge probe failed"; stop_bridge; return 1; fi
    log_info "USB bridge up (pid=${SOCAT_PID})"; return 0
}

stop_bridge() {
    local pid="${SOCAT_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$SOCAT_PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    rm -f "$SOCAT_PID_FILE"; SOCAT_PID=""; return 0
}

ensure_bridge_alive() {
    [[ -n "$SOCAT_PID" ]] || return 1
    kill -0 "$SOCAT_PID" 2>/dev/null && return 0
    log_warn "Bridge died; restarting"
    start_ip_bridge "$UDP_BRIDGE_PORT" "$BACKUP_HOST" "$BACKUP_PORT"; return $?
}

# ---------------------------------------------------------------------------
# HAProxy
# ---------------------------------------------------------------------------
generate_haproxy_cfg() {
    local host="$1" port="$2" mode="$3"
    local server_line=""
    case "$mode" in
        primary-only) server_line="    server primary ${PRIMARY_HOST}:${PRIMARY_PORT} check" ;;
        backup-only)  server_line="    server active  ${host}:${port} check" ;;
        *) log_error "Unknown haproxy mode: $mode"; return 1 ;;
    esac
    mkdir -p "$(dirname "$HAPROXY_CFG")"
    cat > "$HAPROXY_CFG" <<EOF
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
        log_debug "HAProxy config OK"; return 0
    fi
    log_error "HAProxy config validation failed:"; cat "$HAPROXY_CFG" >&2; return 1
}

start_haproxy() {
    stop_haproxy
    log_info "Starting HAProxy..."
    haproxy -W -f "$HAPROXY_CFG" &
    HAPROXY_PID="$!"
    local i=0
    while [[ $i -lt 3 ]]; do sleep 1; i=$((i+1))
        kill -0 "$HAPROXY_PID" 2>/dev/null && break
    done
    if ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
        log_error "HAProxy exited during startup"; HAPROXY_PID=""; return 1; fi
    echo "$HAPROXY_PID" > "$HAPROXY_PID_FILE"
    log_info "HAProxy started (pid=${HAPROXY_PID})"; return 0
}

reload_haproxy() {
    if [[ -n "$HAPROXY_PID" ]] && kill -0 "$HAPROXY_PID" 2>/dev/null; then
        log_info "Reloading HAProxy (USR2 → ${HAPROXY_PID})"
        kill -USR2 "$HAPROXY_PID" 2>/dev/null || true
        sleep 1
        kill -0 "$HAPROXY_PID" 2>/dev/null && { log_info "HAProxy reloaded"; return 0; }
        log_warn "HAProxy didn't survive reload; restarting"
    fi
    start_haproxy; return $?
}

stop_haproxy() {
    local pid="${HAPROXY_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$HAPROXY_PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && { kill -USR1 "$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true; }
    rm -f "$HAPROXY_PID_FILE"; HAPROXY_PID=""; return 0
}

ensure_haproxy_alive() {
    [[ -n "$HAPROXY_PID" ]] && kill -0 "$HAPROXY_PID" 2>/dev/null && return 0
    log_warn "HAProxy not running; restarting"
    start_haproxy; return $?
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
write_state() {
    { echo "state=${CURRENT_STATE}"
      echo "bridge_mode=${BRIDGE_MODE}"
      echo "timestamp=$(date -Iseconds 2>/dev/null || date)"
      echo "version=${VERSION}"
    } > "$STATE_FILE" 2>/dev/null || true; return 0
}

enter_primary() {
    log_notice "→ PRIMARY (${PRIMARY_HOST}:${PRIMARY_PORT})"
    CURRENT_STATE="$STATE_PRIMARY"; BRIDGE_MODE="tcp-direct"
    BACKUP_TARGET_HOST=""; BACKUP_TARGET_PORT=""
    PRIMARY_FAIL_COUNT=0; PRIMARY_RISE_COUNT=0; BACKUP_FAIL_COUNT=0
    stop_bridge
    generate_haproxy_cfg "" "" "primary-only" || { log_error "Cannot build HAProxy config"; return 1; }
    reload_haproxy; write_state
    ha_notify "Primary restored" "Routing through primary ${PRIMARY_HOST}:${PRIMARY_PORT}"; return 0
}

enter_backup() {
    local proto="$1"
    log_notice "→ BACKUP (${BACKUP_HOST}:${BACKUP_PORT}, proto=${proto})"
    CURRENT_STATE="$STATE_BACKUP"; BACKUP_FAIL_COUNT=0
    if [[ "$proto" == "udp" ]]; then
        BRIDGE_MODE="udp-bridge"
        BACKUP_TARGET_HOST="127.0.0.1"; BACKUP_TARGET_PORT="$UDP_BRIDGE_PORT"
        start_ip_bridge "$UDP_BRIDGE_PORT" "$BACKUP_HOST" "$BACKUP_PORT" || {
            enter_degraded "udp-bridge-start-failed"; return 0; }
    else
        BRIDGE_MODE="tcp-direct"
        BACKUP_TARGET_HOST="$BACKUP_HOST"; BACKUP_TARGET_PORT="$BACKUP_PORT"
        stop_bridge
    fi
    generate_haproxy_cfg "$BACKUP_TARGET_HOST" "$BACKUP_TARGET_PORT" "backup-only" || {
        enter_degraded "haproxy-config-failed"; return 0; }
    reload_haproxy; write_state
    ha_notify "Failover to backup" "Primary down. Using backup ${BACKUP_HOST}:${BACKUP_PORT} [${proto}]."; return 0
}

enter_usb() {
    log_notice "→ USB (${USB_DEVICE}, ${USB_BAUD} baud)"
    CURRENT_STATE="$STATE_USB"; BRIDGE_MODE="usb-tty"
    BACKUP_TARGET_HOST="127.0.0.1"; BACKUP_TARGET_PORT="$UDP_BRIDGE_PORT"
    stop_bridge
    start_usb_bridge "$USB_DEVICE" "$USB_BAUD" "$UDP_BRIDGE_PORT" || {
        enter_degraded "usb-bridge-start-failed"; return 0; }
    generate_haproxy_cfg "127.0.0.1" "$UDP_BRIDGE_PORT" "backup-only" || {
        enter_degraded "haproxy-config-failed"; return 0; }
    reload_haproxy; write_state
    ha_notify "Failover to USB" "Both IP interfaces down. Using USB ${USB_DEVICE}."; return 0
}

enter_degraded() {
    local reason="${1:-unknown}"
    log_warn "→ DEGRADED (${reason})"
    CURRENT_STATE="$STATE_DEGRADED"; write_state
    ha_notify "KNX degraded" "No interface available (${reason}). Retrying every ${CHECK_INTERVAL}s."; return 0
}

# ---------------------------------------------------------------------------
# Startup probe
# ---------------------------------------------------------------------------
initial_probe() {
    log_info "Running startup probes..."
    if [[ "$USB_PRIORITY" == "prefer" ]] && [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_info "USB preferred and present"; enter_usb; return; fi
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_info "Primary: OK"; enter_primary; return; fi
    log_warn "Primary probe failed (${PRIMARY_HOST}:${PRIMARY_PORT})"
    local proto; proto="$(detect_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_info "Backup: OK (${proto})"; enter_backup "$proto"; return; fi
    log_warn "Backup probe failed (${BACKUP_HOST}:${BACKUP_PORT})"
    if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_info "USB available"; enter_usb; return; fi
    log_error "No interface reachable — entering DEGRADED retry loop"
    generate_haproxy_cfg "$PRIMARY_HOST" "$PRIMARY_PORT" "primary-only" || true
    start_haproxy || true
    enter_degraded "startup-all-probes-failed"
}

# ---------------------------------------------------------------------------
# Monitor loop
# ---------------------------------------------------------------------------
monitor_tick() {
    case "$CURRENT_STATE" in
        "$STATE_PRIMARY")  tick_primary  ;;
        "$STATE_BACKUP")   tick_backup   ;;
        "$STATE_USB")      tick_usb      ;;
        "$STATE_DEGRADED") tick_degraded ;;
        *) log_warn "Unknown state '${CURRENT_STATE}'"; enter_degraded "unknown-state" ;;
    esac
    ensure_haproxy_alive    || log_error "HAProxy watchdog: restart failed"
    ensure_udp_responder_alive || log_error "UDP responder watchdog: restart failed"
    return 0
}

tick_primary() {
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_debug "Primary: OK"; PRIMARY_FAIL_COUNT=0; return 0; fi
    PRIMARY_FAIL_COUNT=$((PRIMARY_FAIL_COUNT + 1))
    log_warn "Primary probe failed (${PRIMARY_FAIL_COUNT}/${CHECK_FALL})"
    if [[ "$PRIMARY_FAIL_COUNT" -ge "$CHECK_FALL" ]]; then
        log_warn "Failing over from primary"
        local proto; proto="$(detect_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
        if [[ "$proto" != "none" ]]; then enter_backup "$proto"
        elif [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then enter_usb
        else enter_degraded "primary-failed-no-backup"; fi
    fi; return 0
}

tick_backup() {
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        PRIMARY_RISE_COUNT=$((PRIMARY_RISE_COUNT + 1))
        log_info "Primary recovery (${PRIMARY_RISE_COUNT}/${CHECK_RISE})"
        if [[ "$PRIMARY_RISE_COUNT" -ge "$CHECK_RISE" ]]; then
            log_notice "Primary recovered — switching back"; enter_primary; return 0; fi
    else
        [[ "$PRIMARY_RISE_COUNT" -gt 0 ]] && log_debug "Primary recovery reset"
        PRIMARY_RISE_COUNT=0
    fi
    local ok=0
    if [[ "$BRIDGE_MODE" == "udp-bridge" ]]; then
        ensure_bridge_alive && tcp_probe "127.0.0.1" "$UDP_BRIDGE_PORT" && ok=1
    else
        tcp_probe "$BACKUP_HOST" "$BACKUP_PORT" && ok=1
    fi
    if [[ "$ok" -eq 1 ]]; then
        log_debug "Backup: OK"; BACKUP_FAIL_COUNT=0
    else
        BACKUP_FAIL_COUNT=$((BACKUP_FAIL_COUNT + 1))
        log_warn "Backup probe failed (${BACKUP_FAIL_COUNT}/${CHECK_FALL})"
        if [[ "$BACKUP_FAIL_COUNT" -ge "$CHECK_FALL" ]]; then
            if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then enter_usb
            else enter_degraded "backup-failed-no-usb"; fi
        fi
    fi; return 0
}

tick_usb() {
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_notice "Primary recovered (from USB)"; enter_primary; return 0; fi
    local proto; proto="$(detect_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_notice "Backup recovered (from USB, proto=${proto})"; enter_backup "$proto"; return 0; fi
    if ! ensure_bridge_alive || ! tcp_probe "127.0.0.1" "$UDP_BRIDGE_PORT"; then
        if ! usb_probe "$USB_DEVICE"; then
            log_error "USB device gone: $USB_DEVICE"; enter_degraded "usb-device-gone"
        else
            log_warn "USB bridge died; restarting"
            start_usb_bridge "$USB_DEVICE" "$USB_BAUD" "$UDP_BRIDGE_PORT" || \
                enter_degraded "usb-bridge-restart-failed"
        fi; return 0
    fi
    log_debug "USB: OK"; return 0
}

tick_degraded() {
    log_debug "DEGRADED: retrying all interfaces..."
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_notice "Primary back"; enter_primary; return 0; fi
    local proto; proto="$(detect_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_notice "Backup back (${proto})"; enter_backup "$proto"; return 0; fi
    if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_notice "USB available"; enter_usb; return 0; fi
    log_debug "All interfaces still down — retrying in ${CHECK_INTERVAL}s"; return 0
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    log_info "Shutting down..."
    stop_udp_responder || true
    stop_bridge        || true
    stop_haproxy       || true
    rm -f "$STATE_FILE" 2>/dev/null || true
    log_info "Done"
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
    require_cmd python3
    require_cmd timeout

    load_config

    log_info "Primary:  ${PRIMARY_HOST}:${PRIMARY_PORT}"
    log_info "Backup:   ${BACKUP_HOST}:${BACKUP_PORT}"
    log_info "Listen:   0.0.0.0:${LISTEN_PORT} (TCP + UDP)"
    [[ -n "$USB_DEVICE" ]] && log_info "USB:      ${USB_DEVICE} @ ${USB_BAUD} baud (priority=${USB_PRIORITY})"
    log_info "Health:   interval=${CHECK_INTERVAL}s fall=${CHECK_FALL} rise=${CHECK_RISE}"

    # Start UDP responder first — must be up before HA tries to connect
    start_udp_responder || die "Cannot start UDP responder"

    initial_probe

    log_info "Entering monitor loop (interval=${CHECK_INTERVAL}s)..."
    while true; do
        sleep "$CHECK_INTERVAL" || true
        monitor_tick
    done
}

main "$@"