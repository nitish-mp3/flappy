#!/bin/bash
# =============================================================================
# KNX Failover Proxy — Main Orchestration Script
# =============================================================================
# State machine:  PRIMARY → BACKUP → USB → DEGRADED → FAILED
# Supports:       TCP/IP, UDP/IP (auto-bridged), USB/serial (TPUART/FT1.2)
# Recovery:       Automatic, with configurable rise/fall thresholds
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly OPTIONS_FILE="/data/options.json"
readonly STATE_FILE="/run/knx-haproxy.state"
readonly HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
readonly HAPROXY_PID_FILE="/run/haproxy.pid"
readonly SOCAT_PID_FILE="/run/knx-bridge.pid"
readonly HA_NOTIFY_URL="http://supervisor/core/api/services/persistent_notification/create"
readonly SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN:-}"
readonly VERSION="2.0.0"

# ---------------------------------------------------------------------------
# State constants
# ---------------------------------------------------------------------------
readonly STATE_PRIMARY="PRIMARY"
readonly STATE_BACKUP="BACKUP"
readonly STATE_USB="USB"
readonly STATE_DEGRADED="DEGRADED"

# ---------------------------------------------------------------------------
# Global runtime vars (set after config is loaded)
# ---------------------------------------------------------------------------
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
BRIDGE_MODE=""            # tcp-direct | udp-bridge | usb-tty
BACKUP_TARGET_HOST=""
BACKUP_TARGET_PORT=""

# Consecutive fail/rise counters for hysteresis
PRIMARY_FAIL_COUNT=0
PRIMARY_RISE_COUNT=0
BACKUP_FAIL_COUNT=0

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    case "$level" in
        DEBUG)   [[ "$LOG_LEVEL" == "debug" ]] && echo "[DEBUG] ${ts} $msg" ;;
        INFO)    echo "[INFO]  ${ts} $msg" ;;
        WARN)    echo "[WARN]  ${ts} $msg" ;;
        ERROR)   echo "[ERROR] ${ts} $msg" >&2 ;;
        NOTICE)  echo "[NOTE]  ${ts} $msg" ;;
    esac
}

log_debug()  { _log DEBUG  "$@"; }
log_info()   { _log INFO   "$@"; }
log_warn()   { _log WARN   "$@"; }
log_error()  { _log ERROR  "$@"; }
log_notice() { _log NOTICE "$@"; }

die() {
    log_error "$*"
    exit 1
}

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1 — check Dockerfile"
}

# ---------------------------------------------------------------------------
# Option reading and validation
# ---------------------------------------------------------------------------
read_option() {
    local key="$1" fallback="$2"
    jq -r --arg k "$key" --arg f "$fallback" '.[$k] // $f' "$OPTIONS_FILE"
}

is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

is_valid_host() { [[ -n "$1" ]] && [[ "$1" =~ ^[A-Za-z0-9._:-]+$ ]]; }

validate_port() {
    local v="$1" label="$2"
    is_int "$v"           || die "$label must be a number, got: '$v'"
    (( v >= 1 && v <= 65535 )) || die "$label must be 1-65535, got: $v"
}

validate_positive_int() {
    local v="$1" label="$2"
    { is_int "$v" && (( v >= 1 )); } || die "$label must be a positive integer, got: '$v'"
}

load_config() {
    [[ -f "$OPTIONS_FILE" ]] || die "Missing $OPTIONS_FILE; HA addon options unavailable"

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

    # Validate required fields
    [[ -n "$PRIMARY_HOST" ]]  || die "primary_host is required"
    [[ -n "$BACKUP_HOST" ]]   || die "backup_host is required"
    is_valid_host "$PRIMARY_HOST" || die "primary_host has invalid characters: $PRIMARY_HOST"
    is_valid_host "$BACKUP_HOST"  || die "backup_host has invalid characters: $BACKUP_HOST"

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
        die "listen_port and udp_bridge_port cannot be the same ($LISTEN_PORT)"
    fi

    # Warn on identical primary/backup
    if [[ "$PRIMARY_HOST:$PRIMARY_PORT" == "$BACKUP_HOST:$BACKUP_PORT" ]]; then
        log_warn "Primary and backup targets are identical; failover provides no redundancy"
    fi
}

# ---------------------------------------------------------------------------
# HA Persistent notification
# ---------------------------------------------------------------------------
ha_notify() {
    local title="$1" message="$2"
    [[ "$NOTIFY_ON_FAILOVER" == "true" ]] || return 0
    [[ -n "$SUPERVISOR_TOKEN" ]]           || return 0
    command -v curl >/dev/null 2>&1        || return 0

    local payload
    payload="$(jq -n \
        --arg t "KNX Failover: $title" \
        --arg m "$message" \
        --arg n "knx_failover" \
        '{title:$t, message:$m, notification_id:$n}')"

    curl -sf -X POST \
        -H "Authorization: Bearer ${SUPERVISOR_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$HA_NOTIFY_URL" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# TCP probe  — returns 0 if port accepts connection within timeout
# ---------------------------------------------------------------------------
tcp_probe() {
    local host="$1" port="$2"
    timeout 2 socat -T1 - "TCP:${host}:${port},connect-timeout=1" </dev/null >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# KNX-aware UDP probe — sends KNX/IP Search Request, expects any UDP reply
# Useful for confirming a UDP KNX/IP interface is alive at the KNX layer
# ---------------------------------------------------------------------------
knx_udp_probe() {
    local host="$1" port="$2"
    # KNX/IP Search Request (minimal: header only, no DIBs)
    # Header: 06 10 02 01 00 0E + HPAI with 0.0.0.0:3671
    local knx_search='\x06\x10\x02\x01\x00\x0e\x08\x01\x00\x00\x00\x00\x0e\x57'
    timeout 3 bash -c \
        "printf '${knx_search}' | socat -T2 - UDP:${host}:${port}" \
        >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Detect whether a backup endpoint speaks TCP or UDP
# Returns: "tcp" | "udp" | "none"
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# USB device probe — checks device node exists and is accessible
# ---------------------------------------------------------------------------
usb_probe() {
    local device="$1"
    [[ -n "$device" ]] && [[ -e "$device" ]] && [[ -r "$device" ]] && [[ -w "$device" ]]
}

# ---------------------------------------------------------------------------
# socat TCP→UDP bridge (supervised, with restart on exit)
# ---------------------------------------------------------------------------
start_bridge() {
    stop_bridge
    local local_port="$1" target_host="$2" target_port="$3"
    log_info "Starting TCP→UDP bridge on 127.0.0.1:${local_port} → ${target_host}:${target_port}"

    socat \
        "TCP-LISTEN:${local_port},fork,reuseaddr,keepalive,nodelay,backlog=8" \
        "UDP:${target_host}:${target_port}" \
        &
    SOCAT_PID="$!"
    echo "$SOCAT_PID" > "$SOCAT_PID_FILE"

    # Give it a moment then verify it's alive
    sleep 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_error "Bridge process died immediately after start"
        SOCAT_PID=""
        return 1
    fi

    if ! tcp_probe "127.0.0.1" "$local_port"; then
        log_error "Bridge started but local probe on 127.0.0.1:${local_port} failed"
        stop_bridge
        return 1
    fi

    log_info "Bridge is up (pid=${SOCAT_PID})"
    return 0
}

stop_bridge() {
    if [[ -f "$SOCAT_PID_FILE" ]]; then
        local pid
        pid="$(cat "$SOCAT_PID_FILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$SOCAT_PID_FILE"
    fi
    SOCAT_PID=""
}

ensure_bridge_alive() {
    [[ -n "$SOCAT_PID" ]] || return 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_warn "TCP→UDP bridge died (pid=${SOCAT_PID}); restarting..."
        start_bridge "$UDP_BRIDGE_PORT" "$BACKUP_HOST" "$BACKUP_PORT" || return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# HAProxy config generator
# ---------------------------------------------------------------------------
generate_haproxy_cfg() {
    local primary_server backup_server
    local backend_host="$1"
    local backend_port="$2"
    local mode="$3"   # primary-only | primary-backup | backup-only | usb-stub

    log_debug "Generating HAProxy config: mode=${mode} backend=${backend_host}:${backend_port}"

    case "$mode" in
        primary-only)
            primary_server="server primary ${PRIMARY_HOST}:${PRIMARY_PORT} check"
            backup_server=""
            ;;
        primary-backup)
            primary_server="server primary ${PRIMARY_HOST}:${PRIMARY_PORT} check"
            backup_server="    server backup  ${backend_host}:${backend_port} check backup"
            ;;
        backup-only)
            primary_server="server backup  ${backend_host}:${backend_port} check"
            backup_server=""
            ;;
        usb-stub)
            # HAProxy cannot route serial; we use socat directly in USB mode.
            # Generate a minimal haproxy that just binds the port and rejects
            # so we can gracefully hand off. Actual traffic goes via socat below.
            primary_server="server backup  127.0.0.1:${UDP_BRIDGE_PORT} check"
            backup_server=""
            ;;
    esac

    mkdir -p "$(dirname "$HAPROXY_CFG")"
    cat > "$HAPROXY_CFG" <<EOF
# Generated by KNX Failover Proxy v${VERSION} — $(date)
# Mode: ${mode}
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
    default-server inter ${CHECK_INTERVAL}s fall ${CHECK_FALL} rise ${CHECK_RISE} \
        on-marked-down shutdown-sessions on-marked-up shutdown-backup-sessions

frontend knx_frontend
    bind *:${LISTEN_PORT}
    default_backend knx_backend

backend knx_backend
    mode tcp
    option tcp-check
    ${primary_server}
$([ -n "$backup_server" ] && echo "$backup_server" || true)
EOF

    haproxy -c -f "$HAPROXY_CFG" >/dev/null 2>&1 || {
        log_error "HAProxy config validation failed — dumping config:"
        cat "$HAPROXY_CFG" >&2
        return 1
    }
    log_debug "HAProxy config validated OK"
    return 0
}

# ---------------------------------------------------------------------------
# HAProxy lifecycle
# ---------------------------------------------------------------------------
start_haproxy() {
    stop_haproxy
    log_info "Starting HAProxy..."
    haproxy -f "$HAPROXY_CFG" -D -p "$HAPROXY_PID_FILE" || {
        log_error "HAProxy failed to start"
        return 1
    }
    sleep 1
    local pid
    pid="$(cat "$HAPROXY_PID_FILE" 2>/dev/null || true)"
    if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
        log_error "HAProxy died immediately after start"
        return 1
    fi
    HAPROXY_PID="$pid"
    log_info "HAProxy started (pid=${HAPROXY_PID})"
    return 0
}

reload_haproxy() {
    local pid
    pid="$(cat "$HAPROXY_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        log_info "Hot-reloading HAProxy config..."
        haproxy -f "$HAPROXY_CFG" -D -p "$HAPROXY_PID_FILE" -sf "$pid" || {
            log_warn "Hot-reload failed, doing full restart"
            start_haproxy
            return
        }
        sleep 1
        HAPROXY_PID="$(cat "$HAPROXY_PID_FILE" 2>/dev/null || echo '')"
        log_info "HAProxy reloaded (pid=${HAPROXY_PID})"
    else
        start_haproxy
    fi
}

stop_haproxy() {
    if [[ -f "$HAPROXY_PID_FILE" ]]; then
        local pid
        pid="$(cat "$HAPROXY_PID_FILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -USR1 "$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$HAPROXY_PID_FILE"
    fi
    HAPROXY_PID=""
}

ensure_haproxy_alive() {
    local pid
    pid="$(cat "$HAPROXY_PID_FILE" 2>/dev/null || true)"
    if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
        log_warn "HAProxy is not running; restarting..."
        start_haproxy || return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# USB serial routing via socat (replaces HAProxy for USB mode)
# Uses a local TCP listener → serial bridge so HAProxy can still front it
# ---------------------------------------------------------------------------
start_usb_bridge() {
    local device="$1" baud="$2" local_port="$3"
    stop_bridge

    log_info "Starting USB serial bridge: ${device} (${baud} baud) → 127.0.0.1:${local_port}"

    socat \
        "TCP-LISTEN:${local_port},fork,reuseaddr,keepalive,nodelay,backlog=4" \
        "OPEN:${device},raw,echo=0,b${baud},crtscts=0" \
        &
    SOCAT_PID="$!"
    echo "$SOCAT_PID" > "$SOCAT_PID_FILE"

    sleep 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_error "USB bridge process died immediately"
        SOCAT_PID=""
        return 1
    fi

    if ! tcp_probe "127.0.0.1" "$local_port"; then
        log_error "USB bridge started but local probe failed"
        stop_bridge
        return 1
    fi

    log_info "USB bridge is up (pid=${SOCAT_PID}, device=${device})"
    return 0
}

# ---------------------------------------------------------------------------
# State machine transitions
# ---------------------------------------------------------------------------
write_state() {
    {
        echo "state=${CURRENT_STATE}"
        echo "bridge_mode=${BRIDGE_MODE}"
        echo "backup_target_host=${BACKUP_TARGET_HOST}"
        echo "backup_target_port=${BACKUP_TARGET_PORT}"
        echo "timestamp=$(date -Iseconds)"
        echo "version=${VERSION}"
    } > "$STATE_FILE"
}

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
    generate_haproxy_cfg "" "" "primary-only" || die "Cannot generate HAProxy config for PRIMARY"
    reload_haproxy
    write_state
    ha_notify "Primary restored" "KNX is routing through primary interface ${PRIMARY_HOST}:${PRIMARY_PORT}"
}

enter_backup() {
    local proto="$1"   # tcp | udp
    log_notice "→ Entering state: BACKUP (${BACKUP_HOST}:${BACKUP_PORT}, proto=${proto})"
    CURRENT_STATE="$STATE_BACKUP"

    if [[ "$proto" == "udp" ]]; then
        BRIDGE_MODE="udp-bridge"
        BACKUP_TARGET_HOST="127.0.0.1"
        BACKUP_TARGET_PORT="$UDP_BRIDGE_PORT"
        start_bridge "$UDP_BRIDGE_PORT" "$BACKUP_HOST" "$BACKUP_PORT" || {
            log_error "Cannot start UDP bridge for backup; entering DEGRADED"
            enter_degraded "udp-bridge-start-failed"
            return
        }
    else
        BRIDGE_MODE="tcp-direct"
        BACKUP_TARGET_HOST="$BACKUP_HOST"
        BACKUP_TARGET_PORT="$BACKUP_PORT"
        stop_bridge
    fi

    BACKUP_FAIL_COUNT=0
    generate_haproxy_cfg "$BACKUP_TARGET_HOST" "$BACKUP_TARGET_PORT" "backup-only" || {
        log_error "Cannot generate HAProxy config for BACKUP"
        enter_degraded "haproxy-config-failed"
        return
    }
    reload_haproxy
    write_state
    ha_notify "Failover to backup" \
        "Primary (${PRIMARY_HOST}:${PRIMARY_PORT}) is unreachable. Now using backup ${BACKUP_HOST}:${BACKUP_PORT} [${proto}]."
}

enter_usb() {
    log_notice "→ Entering state: USB (${USB_DEVICE}, ${USB_BAUD} baud)"
    CURRENT_STATE="$STATE_USB"
    BRIDGE_MODE="usb-tty"
    BACKUP_TARGET_HOST="127.0.0.1"
    BACKUP_TARGET_PORT="$UDP_BRIDGE_PORT"

    # Stop any existing IP bridge first
    stop_bridge

    start_usb_bridge "$USB_DEVICE" "$USB_BAUD" "$UDP_BRIDGE_PORT" || {
        log_error "Cannot start USB bridge; entering DEGRADED"
        enter_degraded "usb-bridge-start-failed"
        return
    }

    generate_haproxy_cfg "127.0.0.1" "$UDP_BRIDGE_PORT" "backup-only" || {
        log_error "Cannot generate HAProxy config for USB"
        enter_degraded "haproxy-config-failed"
        return
    }
    reload_haproxy
    write_state
    ha_notify "Failover to USB" \
        "Both IP interfaces unreachable. Now using USB interface ${USB_DEVICE}."
}

enter_degraded() {
    local reason="${1:-unknown}"
    log_warn "→ Entering state: DEGRADED (reason=${reason})"
    CURRENT_STATE="$STATE_DEGRADED"
    write_state
    ha_notify "KNX degraded" \
        "No working KNX interface found. Reason: ${reason}. Will keep retrying every ${CHECK_INTERVAL}s."
}

# ---------------------------------------------------------------------------
# Startup: pick initial state
# ---------------------------------------------------------------------------
initial_probe() {
    log_info "Running startup probes..."

    # If USB is preferred and present, start there
    if [[ "$USB_PRIORITY" == "prefer" ]] && usb_probe "$USB_DEVICE"; then
        log_info "USB device found and preferred: $USB_DEVICE"
        enter_usb
        return
    fi

    # Try primary
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_info "Primary startup probe: OK"
        enter_primary
        return
    fi
    log_warn "Primary startup probe failed (${PRIMARY_HOST}:${PRIMARY_PORT})"

    # Try backup
    local proto
    proto="$(detect_backup_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_info "Backup startup probe: OK (proto=${proto})"
        enter_backup "$proto"
        return
    fi
    log_warn "Backup startup probe failed (${BACKUP_HOST}:${BACKUP_PORT})"

    # Try USB (last resort)
    if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_info "USB device available as last resort: $USB_DEVICE"
        enter_usb
        return
    fi

    # Nothing works
    log_error "No KNX interface reachable at startup"
    # Start HAProxy in a degraded state so at least the listener is up
    generate_haproxy_cfg "$PRIMARY_HOST" "$PRIMARY_PORT" "primary-only" || true
    start_haproxy || true
    enter_degraded "startup-all-probes-failed"
}

# ---------------------------------------------------------------------------
# Monitor loop tick — called on every CHECK_INTERVAL
# ---------------------------------------------------------------------------
monitor_tick() {
    case "$CURRENT_STATE" in
        "$STATE_PRIMARY")    tick_primary    ;;
        "$STATE_BACKUP")     tick_backup     ;;
        "$STATE_USB")        tick_usb        ;;
        "$STATE_DEGRADED")   tick_degraded   ;;
    esac
    ensure_haproxy_alive || log_error "HAProxy watchdog: restart failed"
}

tick_primary() {
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_debug "Primary probe: OK (state=PRIMARY)"
        PRIMARY_FAIL_COUNT=0
    else
        (( PRIMARY_FAIL_COUNT++ )) || true
        log_warn "Primary probe failed (${PRIMARY_FAIL_COUNT}/${CHECK_FALL})"
        if (( PRIMARY_FAIL_COUNT >= CHECK_FALL )); then
            log_warn "Primary has failed ${CHECK_FALL} consecutive checks; initiating failover"
            # Determine backup protocol fresh
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
    fi
}

tick_backup() {
    # Check if primary has recovered (with hysteresis)
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        (( PRIMARY_RISE_COUNT++ )) || true
        log_info "Primary recovery probe: OK (${PRIMARY_RISE_COUNT}/${CHECK_RISE})"
        if (( PRIMARY_RISE_COUNT >= CHECK_RISE )); then
            log_notice "Primary has recovered; switching back"
            enter_primary
            return
        fi
    else
        PRIMARY_RISE_COUNT=0
    fi

    # Check backup health (bridge supervision included)
    local backup_ok=false
    if [[ "$BRIDGE_MODE" == "udp-bridge" ]]; then
        if ensure_bridge_alive && tcp_probe "127.0.0.1" "$UDP_BRIDGE_PORT"; then
            backup_ok=true
        fi
    else
        tcp_probe "$BACKUP_HOST" "$BACKUP_PORT" && backup_ok=true
    fi

    if $backup_ok; then
        log_debug "Backup probe: OK (state=BACKUP)"
        BACKUP_FAIL_COUNT=0
    else
        (( BACKUP_FAIL_COUNT++ )) || true
        log_warn "Backup probe failed (${BACKUP_FAIL_COUNT}/${CHECK_FALL})"
        if (( BACKUP_FAIL_COUNT >= CHECK_FALL )); then
            log_warn "Backup also down; trying USB or DEGRADED"
            if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
                enter_usb
            else
                enter_degraded "backup-failed-no-usb"
            fi
        fi
    fi
}

tick_usb() {
    # Check if any IP interface has recovered
    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_notice "Primary recovered while in USB mode; switching back"
        enter_primary
        return
    fi
    local proto
    proto="$(detect_backup_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_notice "Backup recovered while in USB mode; switching to BACKUP"
        enter_backup "$proto"
        return
    fi

    # Check USB bridge is still alive
    if ! ensure_bridge_alive || ! tcp_probe "127.0.0.1" "$UDP_BRIDGE_PORT"; then
        log_error "USB bridge died and could not be restarted"
        if ! usb_probe "$USB_DEVICE"; then
            log_error "USB device disappeared: $USB_DEVICE"
            enter_degraded "usb-device-gone"
        else
            # Device still there, try to restart bridge
            start_usb_bridge "$USB_DEVICE" "$USB_BAUD" "$UDP_BRIDGE_PORT" || \
                enter_degraded "usb-bridge-restart-failed"
        fi
    fi
    log_debug "USB probe: OK (state=USB)"
}

tick_degraded() {
    log_debug "Retrying all interfaces from DEGRADED..."

    if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
        log_notice "Primary came back from DEGRADED"
        enter_primary
        return
    fi

    local proto
    proto="$(detect_backup_protocol "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$proto" != "none" ]]; then
        log_notice "Backup came back from DEGRADED (proto=${proto})"
        enter_backup "$proto"
        return
    fi

    if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_notice "USB device available from DEGRADED"
        enter_usb
        return
    fi

    log_debug "All interfaces still down (DEGRADED); will retry in ${CHECK_INTERVAL}s..."
}

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------
cleanup() {
    log_info "Shutting down KNX Failover Proxy..."
    stop_bridge
    stop_haproxy
    rm -f "$STATE_FILE"
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
        sleep "$CHECK_INTERVAL"
        monitor_tick
    done
}

main "$@"