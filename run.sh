#!/bin/bash
# =============================================================================
# KNX Failover Proxy v2.3.0
# =============================================================================
# Manages backend selection (PRIMARY / BACKUP / USB / DEGRADED) and writes
# the active backend address to /run/knx-active-backend so the Python
# KNX/IP proxy can read it.  On every state change, SIGHUP is sent to the
# proxy so existing sessions are dropped and HA reconnects to the new backend.
#
# The Python proxy (knx_proxy.py) handles the full KNXnet/IP v1 UDP tunnel
# protocol. No HAProxy is used.
# =============================================================================
set -uo pipefail

readonly OPTIONS_FILE="/data/options.json"
readonly STATE_FILE="/run/knx-haproxy.state"
readonly BACKEND_FILE="/run/knx-active-backend"
readonly SOCAT_PID_FILE="/run/knx-bridge.pid"
readonly PROXY_PID_FILE="/run/knx-proxy.pid"
readonly HA_NOTIFY_URL="http://supervisor/core/api/services/persistent_notification/create"
readonly SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN:-}"
readonly VERSION="2.3.0"

readonly STATE_PRIMARY="PRIMARY"
readonly STATE_BACKUP="BACKUP"
readonly STATE_USB="USB"
readonly STATE_DEGRADED="DEGRADED"

PRIMARY_HOST="" PRIMARY_PORT=""
BACKUP_HOST=""  BACKUP_PORT=""
LISTEN_PORT=""  UDP_BRIDGE_PORT=""
USB_DEVICE=""   USB_BAUD=""
CONN_TIMEOUT="" CHECK_INTERVAL="" CHECK_FALL="" CHECK_RISE=""
LOG_LEVEL=""    USB_PRIORITY=""   NOTIFY_ON_FAILOVER=""

CURRENT_STATE=""
SOCAT_PID=""
PROXY_PID=""
BRIDGE_MODE=""

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
    esac; return 0
}
log_debug()  { _log DEBUG  "$@"; return 0; }
log_info()   { _log INFO   "$@"; return 0; }
log_warn()   { _log WARN   "$@"; return 0; }
log_error()  { _log ERROR  "$@"; return 0; }
log_notice() { _log NOTICE "$@"; return 0; }
die() { log_error "$*"; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required: $1"; }

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
read_option() { jq -r --arg k "$1" --arg f "$2" '.[$k] // $f' "$OPTIONS_FILE"; }
is_int()       { [[ "$1" =~ ^[0-9]+$ ]]; }
is_valid_host(){ [[ -n "$1" ]] && [[ "$1" =~ ^[A-Za-z0-9._:-]+$ ]]; }
validate_port() {
    is_int "$1" && [[ "$1" -ge 1 && "$1" -le 65535 ]] || die "$2 invalid: $1"
}
validate_pos_int() {
    is_int "$1" && [[ "$1" -ge 1 ]] || die "$2 must be positive int, got: $1"
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
    validate_pos_int "$CHECK_INTERVAL"  health_check_interval
    validate_pos_int "$CHECK_FALL"      health_check_fall
    validate_pos_int "$CHECK_RISE"      health_check_rise
    validate_pos_int "$USB_BAUD"        usb_baud
    [[ "$LISTEN_PORT" != "$UDP_BRIDGE_PORT" ]] || die "listen_port and udp_bridge_port must differ"
}

# ---------------------------------------------------------------------------
# HA notification
# ---------------------------------------------------------------------------
ha_notify() {
    [[ "$NOTIFY_ON_FAILOVER" == "true" ]] || return 0
    [[ -n "$SUPERVISOR_TOKEN" ]]           || return 0
    command -v curl >/dev/null 2>&1        || return 0
    local p
    p="$(jq -n --arg t "KNX Failover: $1" --arg m "$2" --arg n "knx_failover" \
        '{title:$t,message:$m,notification_id:$n}')" || return 0
    curl -sf --max-time 5 -X POST \
        -H "Authorization: Bearer ${SUPERVISOR_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$p" "$HA_NOTIFY_URL" >/dev/null 2>&1 || true
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
    [[ -n "$1" ]] && [[ -e "$1" ]] && [[ -r "$1" ]] && [[ -w "$1" ]]; return $?
}

# ---------------------------------------------------------------------------
# KNX proxy (knx_proxy.py) management
# ---------------------------------------------------------------------------
start_proxy() {
    stop_proxy
    log_info "Starting KNX/IP proxy on port ${LISTEN_PORT}/udp"
    LOG_LEVEL="$LOG_LEVEL" python3 /knx_proxy.py "$LISTEN_PORT" &
    PROXY_PID="$!"
    echo "$PROXY_PID" > "$PROXY_PID_FILE"
    sleep 1
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        log_error "KNX proxy died immediately"
        PROXY_PID=""; rm -f "$PROXY_PID_FILE"; return 1
    fi
    log_info "KNX proxy started (pid=${PROXY_PID})"
    return 0
}

stop_proxy() {
    local pid="${PROXY_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$PROXY_PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && {
        kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    rm -f "$PROXY_PID_FILE"; PROXY_PID=""; return 0
}

ensure_proxy_alive() {
    [[ -n "$PROXY_PID" ]] && kill -0 "$PROXY_PID" 2>/dev/null && return 0
    log_warn "KNX proxy not running — restarting"
    start_proxy; return $?
}

signal_proxy_reload() {
    # SIGHUP tells the proxy to drop all sessions so HA reconnects to new backend
    local pid="${PROXY_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$PROXY_PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && kill -HUP "$pid" 2>/dev/null || true
    return 0
}

# ---------------------------------------------------------------------------
# Backend file — read by knx_proxy.py
# ---------------------------------------------------------------------------
write_backend() {
    local host="$1" port="$2"
    echo "${host}:${port}" > "$BACKEND_FILE"
    log_debug "Backend set to ${host}:${port}"
}

write_backend_none() {
    echo "none" > "$BACKEND_FILE"
}

# ---------------------------------------------------------------------------
# socat bridge (UDP→serial for USB)
# ---------------------------------------------------------------------------
start_usb_bridge() {
    stop_bridge
    local dev="$1" baud="$2" lport="$3"
    log_info "Starting USB bridge: ${dev} @ ${baud} baud → UDP localhost:${lport}"
    # socat: UDP listen → serial
    socat "UDP-LISTEN:${lport},fork,reuseaddr" \
          "OPEN:${dev},raw,echo=0,b${baud},crtscts=0" &
    SOCAT_PID="$!"; echo "$SOCAT_PID" > "$SOCAT_PID_FILE"
    sleep 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_error "USB bridge died immediately"; SOCAT_PID=""; rm -f "$SOCAT_PID_FILE"; return 1
    fi
    log_info "USB bridge up (pid=${SOCAT_PID})"; return 0
}

stop_bridge() {
    local pid="${SOCAT_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$SOCAT_PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && {
        kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    rm -f "$SOCAT_PID_FILE"; SOCAT_PID=""; return 0
}

# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------
write_state() {
    { echo "state=${CURRENT_STATE}"
      echo "bridge_mode=${BRIDGE_MODE:-none}"
      echo "timestamp=$(date -Iseconds 2>/dev/null || date)"
      echo "version=${VERSION}"
    } > "$STATE_FILE" 2>/dev/null || true; return 0
}

# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------
enter_primary() {
    log_notice "→ PRIMARY (${PRIMARY_HOST}:${PRIMARY_PORT})"
    CURRENT_STATE="$STATE_PRIMARY"; BRIDGE_MODE="tcp-direct"
    PRIMARY_FAIL_COUNT=0; PRIMARY_RISE_COUNT=0; BACKUP_FAIL_COUNT=0
    stop_bridge
    write_backend "$PRIMARY_HOST" "$PRIMARY_PORT"
    signal_proxy_reload
    write_state
    ha_notify "Primary restored" "Routing through ${PRIMARY_HOST}:${PRIMARY_PORT}"; return 0
}

enter_backup() {
    local proto="$1"
    log_notice "→ BACKUP (${BACKUP_HOST}:${BACKUP_PORT}, proto=${proto})"
    CURRENT_STATE="$STATE_BACKUP"; BACKUP_FAIL_COUNT=0
    stop_bridge
    if [[ "$proto" == "udp" ]]; then
        BRIDGE_MODE="udp-direct"
    else
        BRIDGE_MODE="tcp-direct"
    fi
    write_backend "$BACKUP_HOST" "$BACKUP_PORT"
    signal_proxy_reload
    write_state
    ha_notify "Failover to backup" "Primary down. Using ${BACKUP_HOST}:${BACKUP_PORT} [${proto}]."; return 0
}

enter_usb() {
    log_notice "→ USB (${USB_DEVICE}, ${USB_BAUD} baud)"
    CURRENT_STATE="$STATE_USB"; BRIDGE_MODE="usb-tty"
    stop_bridge
    if start_usb_bridge "$USB_DEVICE" "$USB_BAUD" "$UDP_BRIDGE_PORT"; then
        write_backend "127.0.0.1" "$UDP_BRIDGE_PORT"
        signal_proxy_reload
        write_state
        ha_notify "Failover to USB" "Both IP interfaces down. Using USB ${USB_DEVICE}."
    else
        enter_degraded "usb-bridge-start-failed"
    fi; return 0
}

enter_degraded() {
    local reason="${1:-unknown}"
    log_warn "→ DEGRADED (${reason})"
    CURRENT_STATE="$STATE_DEGRADED"
    write_backend_none
    signal_proxy_reload
    write_state
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
    ensure_proxy_alive || log_error "KNX proxy watchdog: restart failed"
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
            log_notice "Primary recovered"; enter_primary; return 0; fi
    else
        [[ "$PRIMARY_RISE_COUNT" -gt 0 ]] && log_debug "Primary recovery reset"
        PRIMARY_RISE_COUNT=0
    fi
    if tcp_probe "$BACKUP_HOST" "$BACKUP_PORT" || knx_udp_probe "$BACKUP_HOST" "$BACKUP_PORT"; then
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
        log_notice "Backup recovered (from USB)"; enter_backup "$proto"; return 0; fi
    if [[ -n "$SOCAT_PID" ]] && ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        if ! usb_probe "$USB_DEVICE"; then
            log_error "USB device gone"; enter_degraded "usb-device-gone"
        else
            log_warn "USB bridge died; restarting"
            start_usb_bridge "$USB_DEVICE" "$USB_BAUD" "$UDP_BRIDGE_PORT" || \
                enter_degraded "usb-bridge-restart-failed"
        fi
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
    stop_proxy  || true
    stop_bridge || true
    rm -f "$STATE_FILE" "$BACKEND_FILE" 2>/dev/null || true
    log_info "Done"
}
trap cleanup INT TERM EXIT

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log_info "===== KNX Failover Proxy v${VERSION} ====="
    require_cmd jq
    require_cmd python3
    require_cmd socat
    require_cmd timeout

    load_config

    log_info "Primary:  ${PRIMARY_HOST}:${PRIMARY_PORT}"
    log_info "Backup:   ${BACKUP_HOST}:${BACKUP_PORT}"
    log_info "Listen:   0.0.0.0:${LISTEN_PORT}/udp"
    [[ -n "$USB_DEVICE" ]] && \
        log_info "USB:      ${USB_DEVICE} @ ${USB_BAUD} baud (priority=${USB_PRIORITY})"
    log_info "Health:   interval=${CHECK_INTERVAL}s fall=${CHECK_FALL} rise=${CHECK_RISE}"

    # Start proxy first — it will wait until backend file is written
    write_backend_none
    start_proxy || die "Cannot start KNX proxy"

    initial_probe

    log_info "Entering monitor loop (interval=${CHECK_INTERVAL}s)..."
    while true; do
        sleep "$CHECK_INTERVAL" || true
        monitor_tick
    done
}

main "$@"