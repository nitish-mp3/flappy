#!/bin/bash
# =============================================================================
# KNX Failover Proxy — Main Orchestration Script  v3.0.0
# =============================================================================
# Architecture:
#   knxd acts as the KNX/IP server (speaks UDP+TCP, handles DESCRIPTION etc.)
#   This script manages which backend knxd connects to and restarts it on
#   failover. HA always talks to knxd on listen_port — never changes.
#
# State machine:  PRIMARY → BACKUP → USB → DEGRADED (retry forever)
# Protocols:      TCP/IP, UDP/IP (auto-detected), USB TPUART/FT1.2
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly OPTIONS_FILE="/data/options.json"
readonly STATE_FILE="/run/knx-proxy.state"
readonly KNXD_PID_FILE="/run/knxd.pid"
readonly SOCAT_PID_FILE="/run/knx-bridge.pid"
readonly HA_NOTIFY_URL="http://supervisor/core/api/services/persistent_notification/create"
readonly SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN:-}"
readonly VERSION="2.2.0"

readonly STATE_PRIMARY="PRIMARY"
readonly STATE_BACKUP="BACKUP"
readonly STATE_USB="USB"
readonly STATE_DEGRADED="DEGRADED"

# ---------------------------------------------------------------------------
# Runtime globals (populated by load_config)
# ---------------------------------------------------------------------------
PRIMARY_HOST=""
PRIMARY_PORT=""
BACKUP_HOST=""
BACKUP_PORT=""
LISTEN_PORT=""
USB_DEVICE=""
USB_BAUD=""
CONN_TIMEOUT=""
CHECK_INTERVAL=""
CHECK_FALL=""
CHECK_RISE=""
LOG_LEVEL=""
USB_PRIORITY=""
NOTIFY_ON_FAILOVER=""
CLIENT_TUNNELS=""

CURRENT_STATE=""
KNXD_PID=""
SOCAT_PID=""
BRIDGE_PORT=13671          # internal UDP bridge port (not user-visible)

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
read_option() {
    jq -r --arg k "$1" --arg f "$2" '.[$k] // $f' "$OPTIONS_FILE"
}

is_int()        { [[ "$1" =~ ^[0-9]+$ ]]; }
is_valid_host() { [[ -n "$1" ]] && [[ "$1" =~ ^[A-Za-z0-9._:-]+$ ]]; }

validate_port() {
    local v="$1" label="$2"
    is_int "$v" || die "$label must be a number"
    [[ "$v" -ge 1 && "$v" -le 65535 ]] || die "$label out of range: $v"
}
validate_pos_int() {
    local v="$1" label="$2"
    { is_int "$v" && [[ "$v" -ge 1 ]]; } || die "$label must be positive integer"
}

load_config() {
    [[ -f "$OPTIONS_FILE" ]] || die "Missing $OPTIONS_FILE"

    PRIMARY_HOST="$(read_option 'primary_host'          '')"
    PRIMARY_PORT="$(read_option 'primary_port'          '3671')"
    BACKUP_HOST="$(read_option  'backup_host'           '')"
    BACKUP_PORT="$(read_option  'backup_port'           '3671')"
    LISTEN_PORT="$(read_option  'listen_port'           '3671')"
    CONN_TIMEOUT="$(read_option 'connection_timeout'    '5')"
    CHECK_INTERVAL="$(read_option 'health_check_interval' '5')"
    CHECK_FALL="$(read_option   'health_check_fall'     '3')"
    CHECK_RISE="$(read_option   'health_check_rise'     '2')"
    LOG_LEVEL="$(read_option    'log_level'             'info')"
    USB_DEVICE="$(read_option   'usb_device'            '')"
    USB_BAUD="$(read_option     'usb_baud'              '19200')"
    USB_PRIORITY="$(read_option 'usb_priority'          'last_resort')"
    NOTIFY_ON_FAILOVER="$(read_option 'notify_on_failover' 'false')"
    CLIENT_TUNNELS="$(read_option 'client_tunnels'      '4')"

    [[ -n "$PRIMARY_HOST" ]] || die "primary_host is required"
    [[ -n "$BACKUP_HOST"  ]] || die "backup_host is required"
    is_valid_host "$PRIMARY_HOST" || die "primary_host invalid: $PRIMARY_HOST"
    is_valid_host "$BACKUP_HOST"  || die "backup_host invalid: $BACKUP_HOST"

    validate_port    "$PRIMARY_PORT"   "primary_port"
    validate_port    "$BACKUP_PORT"    "backup_port"
    validate_port    "$LISTEN_PORT"    "listen_port"
    validate_pos_int "$CONN_TIMEOUT"   "connection_timeout"
    validate_pos_int "$CHECK_INTERVAL" "health_check_interval"
    validate_pos_int "$CHECK_FALL"     "health_check_fall"
    validate_pos_int "$CHECK_RISE"     "health_check_rise"
    validate_pos_int "$USB_BAUD"       "usb_baud"
    validate_pos_int "$CLIENT_TUNNELS" "client_tunnels"

    # Reserve BRIDGE_PORT — pick one that doesn't clash with listen_port
    if [[ "$LISTEN_PORT" == "13671" ]]; then
        BRIDGE_PORT=13672
    else
        BRIDGE_PORT=13671
    fi

    if [[ "$PRIMARY_HOST:$PRIMARY_PORT" == "$BACKUP_HOST:$BACKUP_PORT" ]]; then
        log_warn "Primary and backup targets are identical — failover provides no redundancy"
    fi
}

# ---------------------------------------------------------------------------
# HA notification (best-effort)
# ---------------------------------------------------------------------------
ha_notify() {
    local title="$1" message="$2"
    [[ "$NOTIFY_ON_FAILOVER" == "true" ]] || return 0
    [[ -n "$SUPERVISOR_TOKEN" ]]           || return 0
    command -v curl >/dev/null 2>&1        || return 0
    local payload
    payload="$(jq -n --arg t "KNX: $title" --arg m "$message" --arg n "knx_proxy" \
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

# TCP connect probe — fast, cheap
tcp_probe() {
    local host="$1" port="$2"
    timeout "${CONN_TIMEOUT}" bash -c \
        ">/dev/tcp/${host}/${port}" 2>/dev/null
    return $?
}

# KNX/IP UDP DESCRIPTION_REQUEST probe
# Every KNX/IP interface MUST respond to this — it's how we know it's truly a KNX device
knx_udp_probe() {
    local host="$1" port="$2"
    # Header: 06 10 02 03 00 0e  (KNXIPv1, DESCRIPTION_REQUEST, length 14)
    # HPAI:   08 01 00 00 00 00 0e 57  (UDP, 0.0.0.0:3671 — "use source address")
    local response
    response=$(printf '\x06\x10\x02\x03\x00\x0e\x08\x01\x00\x00\x00\x00\x0e\x57' | \
        timeout 3 socat -T2 STDIO "UDP:${host}:${port}" 2>/dev/null | head -c 2 | od -A n -t x1 2>/dev/null || true)
    # Valid KNX/IP response starts with 06 10
    if [[ "$response" == *"06"*"10"* ]]; then
        return 0
    fi
    return 1
}

# Combined probe: try TCP first (fast), then UDP KNX description (deep verify)
# Returns: "tcp" | "udp" | "none"
probe_interface() {
    local host="$1" port="$2"
    if tcp_probe "$host" "$port"; then
        echo "tcp"
        return 0
    fi
    if knx_udp_probe "$host" "$port"; then
        echo "udp"
        return 0
    fi
    echo "none"
}

# USB device check
usb_probe() {
    local dev="$1"
    [[ -n "$dev" ]] && [[ -e "$dev" ]] && [[ -r "$dev" ]] && [[ -w "$dev" ]]
    return $?
}

# ---------------------------------------------------------------------------
# socat TCP→UDP bridge (used when backup speaks only UDP)
# knxd will connect to 127.0.0.1:BRIDGE_PORT over TCP;
# socat forwards that to UDP at the real backup host
# ---------------------------------------------------------------------------
start_udp_bridge() {
    stop_bridge
    log_info "Starting TCP→UDP bridge: 127.0.0.1:${BRIDGE_PORT} → ${BACKUP_HOST}:${BACKUP_PORT}"
    socat "TCP-LISTEN:${BRIDGE_PORT},fork,reuseaddr,keepalive,nodelay,backlog=8" \
          "UDP:${BACKUP_HOST}:${BACKUP_PORT}" &
    SOCAT_PID="$!"
    echo "$SOCAT_PID" > "$SOCAT_PID_FILE"
    sleep 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_error "UDP bridge died immediately"
        SOCAT_PID=""; rm -f "$SOCAT_PID_FILE"; return 1
    fi
    log_info "UDP bridge up (pid=${SOCAT_PID})"
    return 0
}

stop_bridge() {
    local pid=""
    [[ -f "$SOCAT_PID_FILE" ]] && pid="$(cat "$SOCAT_PID_FILE" 2>/dev/null || true)" && rm -f "$SOCAT_PID_FILE"
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
        log_warn "UDP bridge died; restarting..."
        start_udp_bridge; return $?
    fi
    return 0
}

# ---------------------------------------------------------------------------
# knxd process management
#
# knxd backend driver strings:
#   ipt:HOST:PORT          KNX/IP over TCP (Tunneling v2)
#   ip:HOST:PORT           KNX/IP over UDP (Tunneling v1)
#   tpuart:/dev/ttyUSBx    USB TPUART serial
#   ft12:/dev/ttyUSBx      FT1.2 serial
#
# knxd server flags:
#   -u /run/knxd.sock      Unix socket for local clients
#   -i                     KNX/IP tunneling server on all interfaces
#   --listen-tcp=PORT      TCP listen port  (Tunneling v2)
#   --listen-udp=PORT      UDP listen port  (responses to DESCRIPTION_REQUEST etc)
#   -n NAME                server name shown in SEARCH_RESPONSE
#   -c CLIENTS             max tunneling clients
# ---------------------------------------------------------------------------

knxd_args_for_backend() {
    local proto="$1"   # tcp | udp | usb-tpuart | usb-ft12
    local host="$2"    # ip or device path
    local port="$3"    # port or baud

    local backend_arg=""
    case "$proto" in
        tcp)       backend_arg="ipt:${host}:${port}" ;;
        udp)       backend_arg="ip:${host}:${port}" ;;
        usb-tpuart) backend_arg="tpuart:${host}" ;;
        usb-ft12)   backend_arg="ft12:${host}" ;;
        *)
            log_error "Unknown backend proto: $proto"
            return 1
            ;;
    esac

    local knxd_log_level=""
    case "$LOG_LEVEL" in
        debug)   knxd_log_level="--trace" ;;
        info)    knxd_log_level="" ;;
        warning|error) knxd_log_level="--error-log" ;;
    esac

    # Build args array
    KNXD_ARGS=(
        --listen-tcp="$LISTEN_PORT"
        --listen-udp="$LISTEN_PORT"
        --client-tunnels="$CLIENT_TUNNELS"
        --server-name="KNX-Failover-Proxy"
        --pid-file="$KNXD_PID_FILE"
        ${knxd_log_level}
        "$backend_arg"
    )
}

start_knxd() {
    local proto="$1" host="$2" port_or_baud="$3"
    stop_knxd

    knxd_args_for_backend "$proto" "$host" "$port_or_baud" || return 1

    log_info "Starting knxd: proto=${proto} backend=${host}:${port_or_baud} listen=${LISTEN_PORT}"
    log_debug "knxd args: ${KNXD_ARGS[*]}"

    knxd "${KNXD_ARGS[@]}" &
    KNXD_PID="$!"

    # Wait up to 5s for knxd to start listening
    local i=0
    while [[ $i -lt 5 ]]; do
        sleep 1
        i=$((i+1))
        if ! kill -0 "$KNXD_PID" 2>/dev/null; then
            log_error "knxd exited during startup"
            KNXD_PID=""; return 1
        fi
        # Check that it's actually listening on our port
        if tcp_probe "127.0.0.1" "$LISTEN_PORT"; then
            log_info "knxd started and listening (pid=${KNXD_PID})"
            echo "$KNXD_PID" > "$KNXD_PID_FILE"
            return 0
        fi
    done

    log_error "knxd started but not listening on port ${LISTEN_PORT} after 5s"
    stop_knxd
    return 1
}

stop_knxd() {
    local pid="$KNXD_PID"
    [[ -z "$pid" ]] && [[ -f "$KNXD_PID_FILE" ]] && \
        pid="$(cat "$KNXD_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -f "$KNXD_PID_FILE"
    KNXD_PID=""
    return 0
}

ensure_knxd_alive() {
    if [[ -n "$KNXD_PID" ]] && kill -0 "$KNXD_PID" 2>/dev/null; then
        return 0
    fi
    log_warn "knxd not running; restarting for current state..."
    case "$CURRENT_STATE" in
        "$STATE_PRIMARY")  start_knxd "tcp" "$PRIMARY_HOST" "$PRIMARY_PORT" ;;
        "$STATE_BACKUP")
            if [[ -n "$SOCAT_PID" ]]; then
                start_knxd "tcp" "127.0.0.1" "$BRIDGE_PORT"
            else
                start_knxd "tcp" "$BACKUP_HOST" "$BACKUP_PORT"
            fi
            ;;
        "$STATE_USB")      start_knxd "$_USB_PROTO" "$USB_DEVICE" "$USB_BAUD" ;;
        *)                 return 1 ;;
    esac
    return $?
}

# Store USB protocol for watchdog restarts
_USB_PROTO="usb-tpuart"

# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------
write_state() {
    {
        echo "state=${CURRENT_STATE}"
        echo "timestamp=$(date -Iseconds 2>/dev/null || date)"
        echo "version=${VERSION}"
    } > "$STATE_FILE" 2>/dev/null || true
    return 0
}

# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------
enter_primary() {
    log_notice "→ PRIMARY: ${PRIMARY_HOST}:${PRIMARY_PORT}"
    CURRENT_STATE="$STATE_PRIMARY"
    PRIMARY_FAIL_COUNT=0; PRIMARY_RISE_COUNT=0; BACKUP_FAIL_COUNT=0
    stop_bridge
    if ! start_knxd "tcp" "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_error "Cannot start knxd for PRIMARY"
        enter_degraded "knxd-start-failed-primary"
        return 0
    fi
    write_state
    ha_notify "Primary active" "Routing through primary ${PRIMARY_HOST}:${PRIMARY_PORT}"
    return 0
}

enter_backup() {
    local proto="$1"
    log_notice "→ BACKUP: ${BACKUP_HOST}:${BACKUP_PORT} [proto=${proto}]"
    CURRENT_STATE="$STATE_BACKUP"
    BACKUP_FAIL_COUNT=0

    if [[ "$proto" == "udp" ]]; then
        # knxd connects upstream via TCP; bridge converts TCP→UDP
        if ! start_udp_bridge; then
            log_error "Cannot start UDP bridge for backup"
            enter_degraded "udp-bridge-failed"
            return 0
        fi
        if ! start_knxd "tcp" "127.0.0.1" "$BRIDGE_PORT"; then
            log_error "Cannot start knxd for BACKUP (via bridge)"
            enter_degraded "knxd-start-failed-backup"
            return 0
        fi
    else
        stop_bridge
        if ! start_knxd "tcp" "$BACKUP_HOST" "$BACKUP_PORT"; then
            log_error "Cannot start knxd for BACKUP"
            enter_degraded "knxd-start-failed-backup"
            return 0
        fi
    fi

    write_state
    ha_notify "Failover to backup" \
        "Primary ${PRIMARY_HOST}:${PRIMARY_PORT} down. Using backup ${BACKUP_HOST}:${BACKUP_PORT} [${proto}]."
    return 0
}

enter_usb() {
    # Detect TPUART vs FT1.2 by checking for 'tpuart' in device name, else try tpuart first
    _USB_PROTO="usb-tpuart"

    log_notice "→ USB: ${USB_DEVICE} [${_USB_PROTO}]"
    CURRENT_STATE="$STATE_USB"
    stop_bridge

    if ! start_knxd "$_USB_PROTO" "$USB_DEVICE" "$USB_BAUD"; then
        log_warn "TPUART failed; trying FT1.2..."
        _USB_PROTO="usb-ft12"
        if ! start_knxd "$_USB_PROTO" "$USB_DEVICE" "$USB_BAUD"; then
            log_error "Cannot start knxd for USB"
            enter_degraded "knxd-start-failed-usb"
            return 0
        fi
    fi

    write_state
    ha_notify "Failover to USB" "Both IP interfaces down. Using USB ${USB_DEVICE}."
    return 0
}

enter_degraded() {
    local reason="${1:-unknown}"
    log_warn "→ DEGRADED (${reason}) — retrying every ${CHECK_INTERVAL}s"
    CURRENT_STATE="$STATE_DEGRADED"
    # Keep knxd running if it is — HA stays connected even if backend is dead
    write_state
    ha_notify "KNX degraded" "No interface available (${reason}). Retrying."
    return 0
}

# ---------------------------------------------------------------------------
# Startup probe
# ---------------------------------------------------------------------------
initial_probe() {
    log_info "Running startup probes..."

    # USB preferred
    if [[ "$USB_PRIORITY" == "prefer" ]] && [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_info "USB preferred and present: $USB_DEVICE"
        enter_usb; return
    fi

    # Primary
    local proto
    proto="$(probe_interface "$PRIMARY_HOST" "$PRIMARY_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_info "Primary reachable (proto=${proto})"
        # Always use TCP to upstream if possible; knxd handles the KNX/IP layer
        if [[ "$proto" == "udp" ]]; then
            # primary speaks only UDP — start via bridge
            if start_udp_bridge_for_primary; then
                enter_primary_via_bridge
            else
                log_warn "Primary UDP bridge failed; trying backup"
            fi
        else
            enter_primary
        fi
        return
    fi
    log_warn "Primary not reachable (${PRIMARY_HOST}:${PRIMARY_PORT})"

    # Backup
    proto="$(probe_interface "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_info "Backup reachable (proto=${proto})"
        enter_backup "$proto"
        return
    fi
    log_warn "Backup not reachable (${BACKUP_HOST}:${BACKUP_PORT})"

    # USB last resort
    if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_info "USB available: $USB_DEVICE"
        enter_usb; return
    fi

    log_error "No KNX interface reachable at startup"
    enter_degraded "startup-all-probes-failed"
}

# Handle case where primary speaks UDP only
start_udp_bridge_for_primary() {
    stop_bridge
    log_info "Starting TCP→UDP bridge for primary: 127.0.0.1:${BRIDGE_PORT} → ${PRIMARY_HOST}:${PRIMARY_PORT}"
    socat "TCP-LISTEN:${BRIDGE_PORT},fork,reuseaddr,keepalive,nodelay,backlog=8" \
          "UDP:${PRIMARY_HOST}:${PRIMARY_PORT}" &
    SOCAT_PID="$!"
    echo "$SOCAT_PID" > "$SOCAT_PID_FILE"
    sleep 1
    kill -0 "$SOCAT_PID" 2>/dev/null || { SOCAT_PID=""; rm -f "$SOCAT_PID_FILE"; return 1; }
    return 0
}

enter_primary_via_bridge() {
    log_notice "→ PRIMARY (via UDP bridge): ${PRIMARY_HOST}:${PRIMARY_PORT}"
    CURRENT_STATE="$STATE_PRIMARY"
    PRIMARY_FAIL_COUNT=0; PRIMARY_RISE_COUNT=0; BACKUP_FAIL_COUNT=0
    if ! start_knxd "tcp" "127.0.0.1" "$BRIDGE_PORT"; then
        enter_degraded "knxd-start-failed-primary-bridge"
        return 0
    fi
    write_state
    return 0
}

# ---------------------------------------------------------------------------
# Monitor tick
# ---------------------------------------------------------------------------
monitor_tick() {
    case "$CURRENT_STATE" in
        "$STATE_PRIMARY")   tick_primary  ;;
        "$STATE_BACKUP")    tick_backup   ;;
        "$STATE_USB")       tick_usb      ;;
        "$STATE_DEGRADED")  tick_degraded ;;
        *) log_warn "Unknown state ${CURRENT_STATE}"; enter_degraded "unknown-state" ;;
    esac
    ensure_knxd_alive || log_error "knxd watchdog: restart failed"
    return 0
}

tick_primary() {
    local proto
    proto="$(probe_interface "$PRIMARY_HOST" "$PRIMARY_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_debug "Primary probe: OK"
        PRIMARY_FAIL_COUNT=0
        return 0
    fi
    PRIMARY_FAIL_COUNT=$((PRIMARY_FAIL_COUNT + 1))
    log_warn "Primary probe failed (${PRIMARY_FAIL_COUNT}/${CHECK_FALL})"
    if [[ "$PRIMARY_FAIL_COUNT" -ge "$CHECK_FALL" ]]; then
        log_warn "Primary failed ${CHECK_FALL}x — failing over"
        local bproto
        bproto="$(probe_interface "$BACKUP_HOST" "$BACKUP_PORT")"
        if [[ "$bproto" != "none" ]]; then
            enter_backup "$bproto"
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
    local pproto
    pproto="$(probe_interface "$PRIMARY_HOST" "$PRIMARY_PORT")"
    if [[ "$pproto" != "none" ]]; then
        PRIMARY_RISE_COUNT=$((PRIMARY_RISE_COUNT + 1))
        log_info "Primary recovery probe OK (${PRIMARY_RISE_COUNT}/${CHECK_RISE})"
        if [[ "$PRIMARY_RISE_COUNT" -ge "$CHECK_RISE" ]]; then
            log_notice "Primary recovered — switching back"
            if [[ "$pproto" == "udp" ]]; then
                start_udp_bridge_for_primary && enter_primary_via_bridge || enter_primary
            else
                enter_primary
            fi
            return 0
        fi
    else
        [[ "$PRIMARY_RISE_COUNT" -gt 0 ]] && log_debug "Primary recovery counter reset"
        PRIMARY_RISE_COUNT=0
    fi

    # Check backup health
    local backup_ok=0
    if [[ -n "$SOCAT_PID" ]]; then
        ensure_bridge_alive && tcp_probe "127.0.0.1" "$BRIDGE_PORT" && backup_ok=1
    else
        probe_interface "$BACKUP_HOST" "$BACKUP_PORT" | grep -qv none && backup_ok=1
    fi

    if [[ "$backup_ok" -eq 1 ]]; then
        log_debug "Backup probe: OK"
        BACKUP_FAIL_COUNT=0
    else
        BACKUP_FAIL_COUNT=$((BACKUP_FAIL_COUNT + 1))
        log_warn "Backup probe failed (${BACKUP_FAIL_COUNT}/${CHECK_FALL})"
        if [[ "$BACKUP_FAIL_COUNT" -ge "$CHECK_FALL" ]]; then
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
    # Check if any IP interface recovered
    local pproto
    pproto="$(probe_interface "$PRIMARY_HOST" "$PRIMARY_PORT")"
    if [[ "$pproto" != "none" ]]; then
        log_notice "Primary recovered (from USB) — switching back"
        if [[ "$pproto" == "udp" ]]; then
            start_udp_bridge_for_primary && enter_primary_via_bridge || enter_primary
        else
            enter_primary
        fi
        return 0
    fi
    local bproto
    bproto="$(probe_interface "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$bproto" != "none" ]]; then
        log_notice "Backup recovered (from USB) — switching"
        enter_backup "$bproto"; return 0
    fi
    # Check USB device still present
    if ! usb_probe "$USB_DEVICE"; then
        log_error "USB device disappeared: $USB_DEVICE"
        enter_degraded "usb-device-gone"
    fi
    log_debug "USB probe: OK"
    return 0
}

tick_degraded() {
    log_debug "Retrying all interfaces (DEGRADED)..."
    local proto
    proto="$(probe_interface "$PRIMARY_HOST" "$PRIMARY_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_notice "Primary recovered — leaving DEGRADED"
        if [[ "$proto" == "udp" ]]; then
            start_udp_bridge_for_primary && enter_primary_via_bridge || enter_primary
        else
            enter_primary
        fi
        return 0
    fi
    proto="$(probe_interface "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_notice "Backup recovered (proto=${proto}) — leaving DEGRADED"
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
    stop_knxd  || true
    stop_bridge || true
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
    require_cmd knxd
    require_cmd socat
    require_cmd timeout

    load_config

    log_info "Primary:  ${PRIMARY_HOST}:${PRIMARY_PORT}"
    log_info "Backup:   ${BACKUP_HOST}:${BACKUP_PORT}"
    log_info "Listen:   0.0.0.0:${LISTEN_PORT} (TCP + UDP)"
    [[ -n "$USB_DEVICE" ]] && log_info "USB:      ${USB_DEVICE} @ ${USB_BAUD} baud (priority=${USB_PRIORITY})"
    log_info "Health:   interval=${CHECK_INTERVAL}s fall=${CHECK_FALL} rise=${CHECK_RISE}"

    initial_probe

    log_info "Entering monitor loop (interval=${CHECK_INTERVAL}s)..."
    while true; do
        sleep "$CHECK_INTERVAL" || true
        monitor_tick
    done
}

main "$@"