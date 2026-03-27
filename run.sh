#!/bin/bash
# =============================================================================
# KNX Failover Proxy v4.1.3  — Backend Manager
# =============================================================================
# This script:
#   1. Loads config from /data/options.json
#   2. Detects interface protocols and selects best available backend
#   3. Manages knxd for USB interfaces (or falls back to socat)
#   4. Monitors health and triggers failover/failback
#   5. Manages the KNX proxy process lifecycle
# =============================================================================
set -euo pipefail

readonly OPTIONS_FILE="/data/options.json"
readonly STATE_FILE="/run/knx-failover.state"
readonly BACKEND_FILE="/run/knx-active-backend"
readonly BACKEND_REJECT_FILE="/run/knx-backend-reject"
readonly METRICS_FILE="/run/knx-metrics.json"
readonly KNXD_PID_FILE="/run/knxd.pid"
readonly SOCAT_PID_FILE="/run/knx-bridge.pid"
readonly PROXY_PID_FILE="/run/knx-proxy.pid"
readonly WEBUI_PID_FILE="/run/knx-webui.pid"
readonly HA_NOTIFY_URL="http://supervisor/core/api/services/persistent_notification/create"
readonly SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN:-}"
readonly VERSION="4.2.9"

readonly STATE_PRIMARY="PRIMARY"
readonly STATE_BACKUP="BACKUP"
readonly STATE_USB="USB"
readonly STATE_DEGRADED="DEGRADED"
readonly STATE_FAILBACK_PENDING="FAILBACK_PENDING"
readonly STATE_KNXD="KNXD"

# -- Config vars ---
PRIMARY_HOST="" PRIMARY_PORT="" PRIMARY_PROTOCOL="" PRIMARY_SECURE=""
BACKUP_HOST="" BACKUP_PORT="" BACKUP_PROTOCOL="" BACKUP_SECURE=""
PRIMARY_DEVICE_PW="" PRIMARY_USER_PW=""
BACKUP_DEVICE_PW="" BACKUP_USER_PW=""
FRONTEND_PROTOCOL="" LISTEN_PORT=""
USB_DEVICE="" USB_BAUD="" USB_PRIORITY="" USB_MODE="" USB_KNXD_EXTRA=""
KNXD_HOST="" KNXD_PORT="" KNXD_PROTOCOL=""
CHECK_INTERVAL="" CHECK_FALL="" CHECK_RISE="" CHECK_METHOD=""
CONNECTION_TIMEOUT=""
FAILBACK_MODE="" FAILBACK_DELAY=""
MAX_SESSIONS="" SESSION_TIMEOUT="" DRAIN_TIMEOUT=""
LOG_LEVEL="" NOTIFY_ON_FAILOVER=""

# -- Runtime state ---
CURRENT_STATE=""
KNXD_PID=""
SOCAT_PID=""
PROXY_PID=""
PRIMARY_FAIL_COUNT=0
PRIMARY_RISE_COUNT=0
BACKUP_FAIL_COUNT=0
PRIMARY_HOLD_UNTIL=0
HAS_KNXD=false
HAS_PYUSB=false
USB_LOCAL_PORT=13671
NATIVE_USB_PID=""
WEBUI_PID=""
readonly NATIVE_USB_PID_FILE="/run/knx-usb-bridge.pid"
USB_BRIDGE_FAIL_COUNT=0
USB_BRIDGE_FAIL_TS=0

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
    is_int "$1" && [[ "$1" -ge 1 ]] || die "$2 must be positive int: $1"
}

load_config() {
    [[ -f "$OPTIONS_FILE" ]] || die "Missing $OPTIONS_FILE"

    # Primary
    PRIMARY_HOST="$(read_option primary_host '')"
    PRIMARY_PORT="$(read_option primary_port 3671)"
    PRIMARY_PROTOCOL="$(read_option primary_protocol tcp)"
    PRIMARY_SECURE="$(read_option primary_secure false)"
    PRIMARY_DEVICE_PW="$(read_option primary_device_password '')"
    PRIMARY_USER_PW="$(read_option primary_user_password '')"

    # Backup
    BACKUP_HOST="$(read_option backup_host '')"
    BACKUP_PORT="$(read_option backup_port 3671)"
    BACKUP_PROTOCOL="$(read_option backup_protocol udp)"
    BACKUP_SECURE="$(read_option backup_secure false)"
    BACKUP_DEVICE_PW="$(read_option backup_device_password '')"
    BACKUP_USER_PW="$(read_option backup_user_password '')"

    # Frontend
    FRONTEND_PROTOCOL="$(read_option frontend_protocol udp)"
    LISTEN_PORT="$(read_option listen_port 3671)"

    # USB
    USB_DEVICE="$(read_option usb_device '')"
    USB_BAUD="$(read_option usb_baud 19200)"
    USB_PRIORITY="$(read_option usb_priority last_resort)"
    USB_KNXD_EXTRA="$(read_option usb_knxd_extra_args '')"
    USB_MODE="$(read_option usb_mode auto)"

    # External knxd addon (third failover tier)
    KNXD_HOST="$(read_option knxd_host '')"
    KNXD_PORT="$(read_option knxd_port 3671)"
    KNXD_PROTOCOL="$(read_option knxd_protocol udp)"

    # Health
    CHECK_INTERVAL="$(read_option health_check_interval 5)"
    CHECK_FALL="$(read_option health_check_fall 3)"
    CHECK_RISE="$(read_option health_check_rise 2)"
    CHECK_METHOD="$(read_option health_check_method probe)"
    CONNECTION_TIMEOUT="$(read_option connection_timeout 5)"

    # Failover/Failback
    FAILBACK_MODE="$(read_option failback_mode auto)"
    FAILBACK_DELAY="$(read_option failback_delay_seconds 30)"

    # Sessions
    MAX_SESSIONS="$(read_option max_sessions 8)"
    SESSION_TIMEOUT="$(read_option session_timeout 120)"
    DRAIN_TIMEOUT="$(read_option drain_timeout_seconds 5)"

    # Logging
    LOG_LEVEL="$(read_option log_level info)"
    NOTIFY_ON_FAILOVER="$(read_option notify_on_failover false)"

    # Validation
    [[ -n "$PRIMARY_HOST" || -n "$BACKUP_HOST" || -n "$KNXD_HOST" || -n "$USB_DEVICE" ]] || die "At least one backend must be configured"
    
    if [[ -n "$PRIMARY_HOST" ]]; then
        is_valid_host "$PRIMARY_HOST" || die "primary_host invalid: $PRIMARY_HOST"
        validate_port    "$PRIMARY_PORT"    primary_port
    fi
    if [[ -n "$BACKUP_HOST" ]]; then
        is_valid_host "$BACKUP_HOST"  || die "backup_host invalid: $BACKUP_HOST"
        validate_port    "$BACKUP_PORT"     backup_port
    fi
    validate_port    "$LISTEN_PORT"     listen_port
    validate_pos_int "$CHECK_INTERVAL"  health_check_interval
    validate_pos_int "$CHECK_FALL"      health_check_fall
    validate_pos_int "$CHECK_RISE"      health_check_rise
    validate_pos_int "$CONNECTION_TIMEOUT" connection_timeout
    validate_pos_int "$FAILBACK_DELAY" failback_delay_seconds
    validate_pos_int "$USB_BAUD"       usb_baud
    validate_pos_int "$MAX_SESSIONS"   max_sessions
    validate_pos_int "$SESSION_TIMEOUT" session_timeout
    validate_pos_int "$DRAIN_TIMEOUT"  drain_timeout_seconds

    [[ "$PRIMARY_PROTOCOL" =~ ^(tcp|udp|auto)$ ]] || die "primary_protocol invalid"
    [[ "$BACKUP_PROTOCOL" =~ ^(tcp|udp|auto)$ ]]  || die "backup_protocol invalid"
    [[ "$FRONTEND_PROTOCOL" =~ ^(udp|tcp|both)$ ]] || die "frontend_protocol invalid"
    [[ "$FAILBACK_MODE" =~ ^(auto|manual|disabled)$ ]] || die "failback_mode invalid"
    [[ "$CHECK_METHOD" =~ ^(probe|heartbeat|both)$ ]] || die "health_check_method invalid"
    [[ "$USB_MODE" =~ ^(auto|knxd|native|socat)$ ]] || die "usb_mode invalid"
    if [[ -n "$KNXD_HOST" ]]; then
        is_valid_host "$KNXD_HOST" || die "knxd_host invalid: $KNXD_HOST"
        validate_port "$KNXD_PORT" knxd_port
        [[ "$KNXD_PROTOCOL" =~ ^(tcp|udp)$ ]] || die "knxd_protocol invalid"
    fi

    # Deterministic fallback when both are auto
    if [[ "$PRIMARY_PROTOCOL" == "auto" && "$BACKUP_PROTOCOL" == "auto" ]]; then
        PRIMARY_PROTOCOL="tcp"
        BACKUP_PROTOCOL="udp"
    fi

    # Check knxd availability
    if command -v knxd >/dev/null 2>&1; then
        HAS_KNXD=true
    fi

    # Check pyusb availability
    if python3 -c 'import usb.core' 2>/dev/null; then
        HAS_PYUSB=true
    fi

    # Auto-discover USB device if set to "auto" or empty
    if [[ -n "$USB_DEVICE" ]] && [[ "$USB_DEVICE" == "auto" ]]; then
        local discovered
        discovered="$(python3 /knx_usb.py --discover 2>/dev/null | jq -r '.devices[0].path // ""' 2>/dev/null || true)"
        if [[ -n "$discovered" ]]; then
            USB_DEVICE="$discovered"
            log_info "USB auto-discovered: ${USB_DEVICE}"
        else
            log_warn "USB auto-discovery found no KNX devices"
            USB_DEVICE=""
        fi
    fi
}

select_backend_proto() {
    local detected="$1" forced="$2"
    if [[ "$forced" == "tcp" || "$forced" == "udp" ]]; then
        echo "$forced"
    else
        echo "$detected"
    fi
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
# Protocol detection (delegates to Python health module)
# ---------------------------------------------------------------------------
detect_protocol() {
    local host="$1" port="$2" prefer="${3:-$PRIMARY_PROTOCOL}"
    [[ "$prefer" == "auto" ]] && prefer="tcp"
    python3 - "$host" "$port" "$prefer" "$CONNECTION_TIMEOUT" <<'PYEOF'
import sys
sys.path.insert(0, '/')
from knx_health import detect_protocol
host = sys.argv[1]
port = int(sys.argv[2])
prefer = sys.argv[3]
timeout = int(sys.argv[4])
result = detect_protocol(host, port, prefer, timeout)
print(result)
PYEOF
}

usb_probe() {
    [[ -n "$1" ]] && [[ -e "$1" ]] && [[ -r "$1" ]] && [[ -w "$1" ]]
}

# ---------------------------------------------------------------------------
# Backend file
# ---------------------------------------------------------------------------
set_backend() {
    local host="$1" port="$2" proto="$3"
    echo "${host}:${port}:${proto}" > "$BACKEND_FILE"
    rm -f "$BACKEND_REJECT_FILE" 2>/dev/null || true
    log_debug "Backend → ${host}:${port} [${proto}]"
}
clear_backend() {
    echo "none" > "$BACKEND_FILE"
    rm -f "$BACKEND_REJECT_FILE" 2>/dev/null || true
}

current_backend_proto() {
    [[ -f "$BACKEND_FILE" ]] || { echo ""; return 0; }
    local line proto
    line="$(cat "$BACKEND_FILE" 2>/dev/null || true)"
    [[ -n "$line" && "$line" != "none" ]] || { echo ""; return 0; }
    proto="${line##*:}"
    echo "$proto"
}

read_backend_reject_status() {
    local host="$1" port="$2"
    [[ -f "$BACKEND_REJECT_FILE" ]] || { echo ""; return 0; }
    local r_host r_port r_status r_ts now age
    r_host="$(awk -F= '$1=="host"{print $2; exit}' "$BACKEND_REJECT_FILE" 2>/dev/null || true)"
    r_port="$(awk -F= '$1=="port"{print $2; exit}' "$BACKEND_REJECT_FILE" 2>/dev/null || true)"
    r_status="$(awk -F= '$1=="status"{print $2; exit}' "$BACKEND_REJECT_FILE" 2>/dev/null || true)"
    r_ts="$(awk -F= '$1=="ts"{print $2; exit}' "$BACKEND_REJECT_FILE" 2>/dev/null || true)"
    [[ "$r_host" == "$host" ]] || { echo ""; return 0; }
    [[ "$r_port" == "$port" ]] || { echo ""; return 0; }
    [[ -n "$r_status" && -n "$r_ts" ]] || { echo ""; return 0; }
    is_int "$r_ts" || { echo ""; return 0; }
    now="$(date +%s)"
    age=$(( now - r_ts ))
    if [[ "$age" -gt 30 ]]; then
        echo ""; return 0
    fi
    echo "$r_status"
}

# ---------------------------------------------------------------------------
# Proxy management
# ---------------------------------------------------------------------------
start_proxy() {
    stop_proxy
    pkill -f "knx_proxy.py" 2>/dev/null || true
    sleep 1
    log_info "Starting KNX/IP proxy on port ${LISTEN_PORT} (frontend=${FRONTEND_PROTOCOL})"

    FRONTEND_PROTOCOL="$FRONTEND_PROTOCOL" \
    LOG_LEVEL="$LOG_LEVEL" \
    MAX_SESSIONS="$MAX_SESSIONS" \
    SESSION_TIMEOUT="$SESSION_TIMEOUT" \
    DRAIN_TIMEOUT="$DRAIN_TIMEOUT" \
    PRIMARY_SECURE="$PRIMARY_SECURE" \
    BACKUP_SECURE="$BACKUP_SECURE" \
    PRIMARY_DEVICE_PASSWORD="$PRIMARY_DEVICE_PW" \
    PRIMARY_USER_PASSWORD="$PRIMARY_USER_PW" \
    BACKUP_DEVICE_PASSWORD="$BACKUP_DEVICE_PW" \
    BACKUP_USER_PASSWORD="$BACKUP_USER_PW" \
    python3 /knx_proxy.py "$LISTEN_PORT" &

    PROXY_PID="$!"
    echo "$PROXY_PID" > "$PROXY_PID_FILE"
    sleep 2
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        log_error "KNX proxy died immediately"
        PROXY_PID=""; rm -f "$PROXY_PID_FILE"; return 1
    fi
    log_info "KNX proxy started (pid=${PROXY_PID})"; return 0
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

reload_proxy() {
    local pid="${PROXY_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$PROXY_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -HUP "$pid" 2>/dev/null || true
    else
        log_debug "reload_proxy: proxy not running — skipping SIGHUP"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# USB Bridge — knxd or socat
# ---------------------------------------------------------------------------
start_usb_knxd() {
    stop_usb_bridge
    local dev="$1" lport="$2"
    log_info "Starting knxd USB bridge: ${dev} → KNXnet/IP on port ${lport}"

    local knxd_args="-e 1.1.254 -E 1.1.255:8 -D -T -S"
    [[ -n "$USB_KNXD_EXTRA" ]] && knxd_args="$knxd_args $USB_KNXD_EXTRA"

    # knxd will expose the USB interface as a local KNXnet/IP tunnel
    knxd $knxd_args --listen-tcp="0.0.0.0:${lport}" "usb:${dev}" &
    KNXD_PID="$!"
    echo "$KNXD_PID" > "$KNXD_PID_FILE"
    sleep 2
    if ! kill -0 "$KNXD_PID" 2>/dev/null; then
        log_error "knxd died immediately"
        KNXD_PID=""; rm -f "$KNXD_PID_FILE"; return 1
    fi
    log_info "knxd USB bridge up (pid=${KNXD_PID})"; return 0
}

start_usb_socat() {
    stop_usb_bridge
    local dev="$1" baud="$2" lport="$3"

    # socat can only bridge serial/TTY devices, not raw USB HID
    if [[ "$dev" == /dev/bus/usb/* ]] || [[ "$dev" == /dev/hidraw* ]]; then
        log_error "socat cannot handle raw USB device ${dev}"
        log_error "KNX USB HID interfaces require knxd or pyusb (native mode)"
        log_error "Hint: Rebuild the add-on to install pyusb, or set usb_mode=native"
        return 1
    fi

    if ! [[ -c "$dev" ]] || ! stty -F "$dev" 2>/dev/null; then
        log_error "Device ${dev} is not a serial port — socat bridge cannot work"
        return 1
    fi

    log_info "Starting socat USB bridge: ${dev} @ ${baud} → UDP:${lport}"
    socat "UDP-LISTEN:${lport},fork,reuseaddr" \
          "OPEN:${dev},raw,echo=0,b${baud},crtscts=0" &
    SOCAT_PID="$!"
    echo "$SOCAT_PID" > "$SOCAT_PID_FILE"
    sleep 1
    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        log_error "socat USB bridge died immediately"
        SOCAT_PID=""; rm -f "$SOCAT_PID_FILE"; return 1
    fi
    log_info "socat USB bridge up (pid=${SOCAT_PID})"; return 0
}

start_usb_bridge() {
    local dev="$1"
    local is_raw_usb=false
    [[ "$dev" == /dev/bus/usb/* ]] || [[ "$dev" == /dev/hidraw* ]] && is_raw_usb=true

    # Select bridge mode based on usb_mode config
    case "$USB_MODE" in
        knxd)
            if [[ "$HAS_KNXD" == "true" ]]; then
                start_usb_knxd "$dev" "$USB_LOCAL_PORT"
            else
                log_warn "usb_mode=knxd but knxd not available — falling back to native"
                start_usb_native "$dev" "$USB_LOCAL_PORT"
            fi
            ;;
        native)
            start_usb_native "$dev" "$USB_LOCAL_PORT"
            ;;
        socat)
            start_usb_socat "$dev" "$USB_BAUD" "$USB_LOCAL_PORT"
            ;;
        auto|*)
            if [[ "$HAS_KNXD" == "true" ]]; then
                start_usb_knxd "$dev" "$USB_LOCAL_PORT"
            elif [[ "$HAS_PYUSB" == "true" ]]; then
                start_usb_native "$dev" "$USB_LOCAL_PORT"
            elif [[ "$is_raw_usb" == "true" ]]; then
                log_error "Cannot bridge raw USB device ${dev} — neither knxd nor pyusb available"
                log_error "Raw USB HID devices require knxd or pyusb for protocol translation"
                log_error "socat only works with serial ports (/dev/ttyUSB*, /dev/ttyACM*)"
                log_error "Hint: Rebuild the add-on image, or install a USB-serial KNX interface"
                return 1
            else
                start_usb_socat "$dev" "$USB_BAUD" "$USB_LOCAL_PORT"
            fi
            ;;
    esac
}

start_usb_native() {
    stop_usb_bridge
    local dev="$1" lport="$2"
    log_info "Starting native USB bridge: ${dev} → KNXnet/IP on port ${lport}"

    if [[ "$HAS_PYUSB" != "true" ]]; then
        log_error "pyusb not available — cannot start native USB bridge"
        return 1
    fi

    LOG_LEVEL="$LOG_LEVEL" python3 /knx_usb.py --bridge "$dev" --port "$lport" &
    NATIVE_USB_PID="$!"
    echo "$NATIVE_USB_PID" > "$NATIVE_USB_PID_FILE"
    sleep 3
    if ! kill -0 "$NATIVE_USB_PID" 2>/dev/null; then
        log_error "Native USB bridge died immediately"
        NATIVE_USB_PID=""; rm -f "$NATIVE_USB_PID_FILE"; return 1
    fi
    log_info "Native USB bridge up (pid=${NATIVE_USB_PID})"
    return 0
}

stop_usb_bridge() {
    # Stop knxd
    local pid="${KNXD_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$KNXD_PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && {
        kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    rm -f "$KNXD_PID_FILE"; KNXD_PID=""

    # Stop socat
    pid="${SOCAT_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$SOCAT_PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && {
        kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    rm -f "$SOCAT_PID_FILE"; SOCAT_PID=""

    # Stop native USB bridge
    pid="${NATIVE_USB_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$NATIVE_USB_PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && {
        kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    rm -f "$NATIVE_USB_PID_FILE"; NATIVE_USB_PID=""

    return 0
}

is_usb_bridge_alive() {
    # Check if knxd, socat, or native bridge is alive
    if [[ -n "$KNXD_PID" ]] && kill -0 "$KNXD_PID" 2>/dev/null; then return 0; fi
    if [[ -n "$SOCAT_PID" ]] && kill -0 "$SOCAT_PID" 2>/dev/null; then return 0; fi
    if [[ -n "$NATIVE_USB_PID" ]] && kill -0 "$NATIVE_USB_PID" 2>/dev/null; then return 0; fi
    return 1
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
write_state() {
    {
        echo "state=${CURRENT_STATE}"
        echo "primary_host=${PRIMARY_HOST}"
        echo "primary_port=${PRIMARY_PORT}"
        echo "backup_host=${BACKUP_HOST}"
        echo "backup_port=${BACKUP_PORT}"
        echo "failback_mode=${FAILBACK_MODE}"
        echo "timestamp=$(date -Iseconds 2>/dev/null || date)"
        echo "version=${VERSION}"
    } > "$STATE_FILE" 2>/dev/null || true; return 0
}

set_failback_holdoff() {
    local reason="${1:-failover}"
    local now
    now="$(date +%s)"
    PRIMARY_HOLD_UNTIL=$(( now + FAILBACK_DELAY ))
    log_info "Failback delayed for ${FAILBACK_DELAY}s (${reason})"
}

is_failback_holdoff_active() {
    local now; now="$(date +%s)"
    [[ "$now" -lt "$PRIMARY_HOLD_UNTIL" ]]
}

failback_remaining() {
    local now remain
    now="$(date +%s)"
    remain=$(( PRIMARY_HOLD_UNTIL - now ))
    [[ "$remain" -lt 0 ]] && remain=0
    echo "$remain"
}

# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------
enter_primary() {
    local proto="$1"
    log_notice "→ PRIMARY (${PRIMARY_HOST}:${PRIMARY_PORT} [${proto}])"
    CURRENT_STATE="$STATE_PRIMARY"
    PRIMARY_FAIL_COUNT=0; PRIMARY_RISE_COUNT=0; BACKUP_FAIL_COUNT=0
    PRIMARY_HOLD_UNTIL=0
    stop_usb_bridge
    set_backend "$PRIMARY_HOST" "$PRIMARY_PORT" "$proto"
    reload_proxy
    write_state
    ha_notify "Primary active" "Routing through ${PRIMARY_HOST}:${PRIMARY_PORT} [${proto}]"
    return 0
}

enter_backup() {
    local proto="$1"
    log_notice "→ BACKUP (${BACKUP_HOST}:${BACKUP_PORT} [${proto}])"
    CURRENT_STATE="$STATE_BACKUP"; BACKUP_FAIL_COUNT=0
    stop_usb_bridge
    set_backend "$BACKUP_HOST" "$BACKUP_PORT" "$proto"
    reload_proxy
    write_state
    ha_notify "Failover to backup" "Primary down. Using ${BACKUP_HOST}:${BACKUP_PORT} [${proto}]."

    # Set failback holdoff when entering backup
    if [[ "$FAILBACK_MODE" == "auto" ]]; then
        set_failback_holdoff "failover-to-backup"
    fi
    return 0
}

enter_backup_fast() {
    local proto
    proto="$(select_backend_proto udp "$BACKUP_PROTOCOL")"
    log_notice "→ BACKUP-FAST (${BACKUP_HOST}:${BACKUP_PORT} [${proto}])"
    CURRENT_STATE="$STATE_BACKUP"
    BACKUP_FAIL_COUNT=0; PRIMARY_RISE_COUNT=0
    stop_usb_bridge
    set_backend "$BACKUP_HOST" "$BACKUP_PORT" "$proto"
    reload_proxy
    write_state
    ha_notify "Fast failover" "Primary rejected. Using ${BACKUP_HOST}:${BACKUP_PORT} [${proto}]."

    if [[ "$FAILBACK_MODE" == "auto" ]]; then
        set_failback_holdoff "fast-failover"
    fi
    return 0
}

enter_usb() {
    log_notice "→ USB (${USB_DEVICE}) [mode=${USB_MODE}]"
    CURRENT_STATE="$STATE_USB"
    if start_usb_bridge "$USB_DEVICE"; then
        local usb_proto="tcp"
        [[ "$HAS_KNXD" != "true" ]] && [[ "$USB_MODE" != "native" ]] && [[ "$HAS_PYUSB" != "true" ]] && usb_proto="udp"
        set_backend "127.0.0.1" "$USB_LOCAL_PORT" "$usb_proto"
        reload_proxy
        write_state
        USB_BRIDGE_FAIL_COUNT=0
        USB_BRIDGE_FAIL_TS=0
        ha_notify "Failover to USB" "Both IP interfaces down. Using USB ${USB_DEVICE}."
    else
        USB_BRIDGE_FAIL_COUNT=$((USB_BRIDGE_FAIL_COUNT + 1))
        USB_BRIDGE_FAIL_TS="$(date +%s)"
        local cooldown=$(( USB_BRIDGE_FAIL_COUNT * 15 ))
        [[ $cooldown -gt 120 ]] && cooldown=120
        log_warn "USB bridge failed (attempt ${USB_BRIDGE_FAIL_COUNT}, retry in ${cooldown}s)"
        enter_degraded "usb-bridge-start-failed"
    fi; return 0
}

enter_degraded() {
    local reason="${1:-unknown}"
    log_warn "→ DEGRADED (${reason})"
    CURRENT_STATE="$STATE_DEGRADED"
    PRIMARY_HOLD_UNTIL=0
    clear_backend
    reload_proxy
    write_state
    ha_notify "KNX degraded" "No interface available (${reason}). Retrying every ${CHECK_INTERVAL}s."
    return 0
}

enter_knxd() {
    local proto="${1:-$KNXD_PROTOCOL}"
    log_notice "→ KNXD (${KNXD_HOST}:${KNXD_PORT} [${proto}])"
    CURRENT_STATE="$STATE_KNXD"
    BACKUP_FAIL_COUNT=0
    PRIMARY_RISE_COUNT=0
    stop_usb_bridge
    set_backend "$KNXD_HOST" "$KNXD_PORT" "$proto"
    reload_proxy
    write_state
    ha_notify "Failover to knxd" "IP interfaces down. Using knxd at ${KNXD_HOST}:${KNXD_PORT} [${proto}]."
    if [[ "$FAILBACK_MODE" == "auto" ]]; then
        set_failback_holdoff "failover-to-knxd"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Startup probe
# ---------------------------------------------------------------------------
initial_probe() {
    log_info "Running startup probes..."

    # USB preferred?
    if [[ "$USB_PRIORITY" == "prefer" ]] && [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_info "USB preferred and present"; enter_usb; return; fi

    # Try primary
    if [[ -n "$PRIMARY_HOST" ]]; then
        local proto
        proto="$(detect_protocol "$PRIMARY_HOST" "$PRIMARY_PORT" "$PRIMARY_PROTOCOL")"
        if [[ "$proto" != "none" ]]; then
            proto="$(select_backend_proto "$proto" "$PRIMARY_PROTOCOL")"
            log_info "Primary: OK [${proto}]"; enter_primary "$proto"; return; fi
        log_warn "Primary probe failed (${PRIMARY_HOST}:${PRIMARY_PORT})"
    fi

    # Try backup
    if [[ -n "$BACKUP_HOST" ]]; then
        proto="$(detect_protocol "$BACKUP_HOST" "$BACKUP_PORT" "$BACKUP_PROTOCOL")"
        if [[ "$proto" != "none" ]]; then
            proto="$(select_backend_proto "$proto" "$BACKUP_PROTOCOL")"
            log_info "Backup: OK [${proto}]"; enter_backup "$proto"; return; fi
        log_warn "Backup probe failed (${BACKUP_HOST}:${BACKUP_PORT})"
    fi

    # Try external knxd
    if [[ -n "$KNXD_HOST" ]]; then
        proto="$(detect_protocol "$KNXD_HOST" "$KNXD_PORT" "$KNXD_PROTOCOL")"
        if [[ "$proto" != "none" ]]; then
            proto="$(select_backend_proto "$proto" "$KNXD_PROTOCOL")"
            log_info "knxd: OK [${proto}]"; enter_knxd "$proto"; return; fi
        log_warn "knxd probe failed (${KNXD_HOST}:${KNXD_PORT})"
    fi

    # Try USB as last resort
    if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        log_info "USB available as last resort"; enter_usb; return; fi

    # Everything down
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
        "$STATE_KNXD")     tick_knxd     ;;
        "$STATE_DEGRADED") tick_degraded ;;
        *) log_warn "Unknown state '${CURRENT_STATE}'"; enter_degraded "unknown-state" ;;
    esac
    ensure_proxy_alive || log_error "Proxy watchdog: restart failed"
    return 0
}

tick_primary() {
    # Check for runtime tunnel rejection
    local rej_status
    rej_status="$(read_backend_reject_status "$PRIMARY_HOST" "$PRIMARY_PORT")"
    if [[ "$rej_status" == "0x29" ]]; then
        log_warn "Primary tunnel not supported (0x29) — failing over"
        if [[ -n "$BACKUP_HOST" ]]; then enter_backup_fast
        elif [[ -n "$KNXD_HOST" ]]; then enter_knxd
        elif [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then enter_usb
        else enter_degraded "primary-unsupported"
        fi
        return 0
    fi

    # Probe primary health
    local proto
    proto="$(detect_protocol "$PRIMARY_HOST" "$PRIMARY_PORT" "$PRIMARY_PROTOCOL")"
    if [[ "$proto" != "none" ]]; then
        # Check for soft rejects
        rej_status="$(read_backend_reject_status "$PRIMARY_HOST" "$PRIMARY_PORT")"
        if [[ -n "$rej_status" ]]; then
            PRIMARY_FAIL_COUNT=$((PRIMARY_FAIL_COUNT + 1))
            log_warn "Primary tunnel rejected (${rej_status}) (${PRIMARY_FAIL_COUNT}/${CHECK_FALL})"
            if [[ "$PRIMARY_FAIL_COUNT" -ge "$CHECK_FALL" ]]; then
                log_warn "Primary repeatedly rejected — failing over"
                if [[ -n "$BACKUP_HOST" ]]; then enter_backup_fast
                elif [[ -n "$KNXD_HOST" ]]; then enter_knxd
                elif [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then enter_usb
                else enter_degraded "primary-repeated-reject-no-backup"
                fi
            fi
            return 0
        fi
        log_debug "Primary: OK [${proto}]"; PRIMARY_FAIL_COUNT=0; return 0
    fi

    PRIMARY_FAIL_COUNT=$((PRIMARY_FAIL_COUNT + 1))
    log_warn "Primary probe failed (${PRIMARY_FAIL_COUNT}/${CHECK_FALL})"
    if [[ "$PRIMARY_FAIL_COUNT" -ge "$CHECK_FALL" ]]; then
        log_warn "Primary failed — initiating failover"
        if [[ -n "$BACKUP_HOST" ]]; then
            local bproto; bproto="$(detect_protocol "$BACKUP_HOST" "$BACKUP_PORT" "$BACKUP_PROTOCOL")"
            if [[ "$bproto" != "none" ]]; then
                bproto="$(select_backend_proto "$bproto" "$BACKUP_PROTOCOL")"
                enter_backup "$bproto"
                return 0
            fi
        fi
        if [[ -n "$KNXD_HOST" ]]; then
            local kproto; kproto="$(detect_protocol "$KNXD_HOST" "$KNXD_PORT" "$KNXD_PROTOCOL")"
            if [[ "$kproto" != "none" ]]; then
                kproto="$(select_backend_proto "$kproto" "$KNXD_PROTOCOL")"
                enter_knxd "$kproto"
                return 0
            fi
        fi
        if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
            enter_usb
        else
            enter_degraded "primary-failed-no-backup"
        fi
    fi; return 0
}

tick_backup() {
    # Check backup health (via reject file only — avoid probing active backend)
    local rej_status
    rej_status="$(read_backend_reject_status "$BACKUP_HOST" "$BACKUP_PORT")"
    if [[ "$rej_status" == "0x29" ]]; then
        log_warn "Backup tunnel not supported (0x29)"
        if [[ -n "$KNXD_HOST" ]]; then
            local kproto; kproto="$(detect_protocol "$KNXD_HOST" "$KNXD_PORT" "$KNXD_PROTOCOL")"
            if [[ "$kproto" != "none" ]]; then
                kproto="$(select_backend_proto "$kproto" "$KNXD_PROTOCOL")"
                enter_knxd "$kproto"
                return 0
            fi
        fi
        if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
            enter_usb
        else
            enter_degraded "backup-unsupported"
        fi
        return 0
    fi

    # Failback logic
    case "$FAILBACK_MODE" in
        disabled)
            log_debug "Failback disabled — staying on backup"
            return 0
            ;;
        manual)
            log_debug "Failback manual — staying on backup (restart to failback)"
            return 0
            ;;
        auto)
            if is_failback_holdoff_active; then
                local remain; remain="$(failback_remaining)"
                log_debug "Failback holdoff active (${remain}s remaining)"
                PRIMARY_RISE_COUNT=0
                return 0
            fi

            local proto
            proto="$(detect_protocol "$PRIMARY_HOST" "$PRIMARY_PORT" "$PRIMARY_PROTOCOL")"
            if [[ "$proto" != "none" ]]; then
                proto="$(select_backend_proto "$proto" "$PRIMARY_PROTOCOL")"
                PRIMARY_RISE_COUNT=$((PRIMARY_RISE_COUNT + 1))
                log_info "Primary recovery probe OK (${PRIMARY_RISE_COUNT}/${CHECK_RISE})"
                if [[ "$PRIMARY_RISE_COUNT" -ge "$CHECK_RISE" ]]; then
                    log_notice "Primary recovered — failing back"
                    enter_primary "$proto"
                fi
            else
                [[ "$PRIMARY_RISE_COUNT" -gt 0 ]] && log_debug "Primary recovery reset"
                PRIMARY_RISE_COUNT=0
            fi
            ;;
    esac
    return 0
}

tick_usb() {
    # Try to recover to IP interfaces
    if [[ "$USB_PRIORITY" != "prefer" ]]; then
        if [[ -n "$PRIMARY_HOST" ]]; then
            local proto
            proto="$(detect_protocol "$PRIMARY_HOST" "$PRIMARY_PORT" "$PRIMARY_PROTOCOL")"
            if [[ "$proto" != "none" ]]; then
                proto="$(select_backend_proto "$proto" "$PRIMARY_PROTOCOL")"
                log_notice "Primary recovered (from USB)"; enter_primary "$proto"; return 0; fi
        fi

        if [[ -n "$BACKUP_HOST" ]]; then
            local proto
            proto="$(detect_protocol "$BACKUP_HOST" "$BACKUP_PORT" "$BACKUP_PROTOCOL")"
            if [[ "$proto" != "none" ]]; then
                proto="$(select_backend_proto "$proto" "$BACKUP_PROTOCOL")"
                log_notice "Backup recovered (from USB)"; enter_backup "$proto"; return 0; fi
        fi
    fi

    # Check USB bridge is still alive
    if ! is_usb_bridge_alive; then
        if ! usb_probe "$USB_DEVICE"; then
            # Device path gone — try to rediscover at new path
            if [[ "$HAS_PYUSB" == "true" ]]; then
                local new_path
                new_path="$(python3 /knx_usb.py --discover 2>/dev/null | jq -r '.devices[0].path // ""' 2>/dev/null || true)"
                if [[ -n "$new_path" ]] && usb_probe "$new_path"; then
                    log_info "USB device re-discovered at ${new_path} (was ${USB_DEVICE})"
                    USB_DEVICE="$new_path"
                    log_warn "USB bridge died; restarting with new path"
                    start_usb_bridge "$USB_DEVICE" || enter_degraded "usb-bridge-restart-failed"
                    return 0
                fi
            fi
            log_error "USB device gone"; enter_degraded "usb-device-gone"
        else
            log_warn "USB bridge died; restarting"
            start_usb_bridge "$USB_DEVICE" || enter_degraded "usb-bridge-restart-failed"
        fi; return 0
    fi
    log_debug "USB: OK"; return 0
}

tick_degraded() {
    log_debug "DEGRADED: retrying all interfaces..."

    # Try primary (unless in holdoff)
    if ! is_failback_holdoff_active && [[ -n "$PRIMARY_HOST" ]]; then
        local proto; proto="$(detect_protocol "$PRIMARY_HOST" "$PRIMARY_PORT" "$PRIMARY_PROTOCOL")"
        if [[ "$proto" != "none" ]]; then
            proto="$(select_backend_proto "$proto" "$PRIMARY_PROTOCOL")"
            log_notice "Primary back [${proto}]"; enter_primary "$proto"; return 0; fi
    fi

    # Try backup
    if [[ -n "$BACKUP_HOST" ]]; then
        local proto; proto="$(detect_protocol "$BACKUP_HOST" "$BACKUP_PORT" "$BACKUP_PROTOCOL")"
        if [[ "$proto" != "none" ]]; then
            proto="$(select_backend_proto "$proto" "$BACKUP_PROTOCOL")"
            log_notice "Backup back [${proto}]"; enter_backup "$proto"; return 0; fi
    fi

    # Try external knxd
    if [[ -n "$KNXD_HOST" ]]; then
        local kproto; kproto="$(detect_protocol "$KNXD_HOST" "$KNXD_PORT" "$KNXD_PROTOCOL")"
        if [[ "$kproto" != "none" ]]; then
            kproto="$(select_backend_proto "$kproto" "$KNXD_PROTOCOL")"
            log_notice "knxd available"; enter_knxd "$kproto"; return 0; fi
    fi

    # Try USB — rediscover if stored path is gone
    if [[ -n "$USB_DEVICE" ]] && ! usb_probe "$USB_DEVICE"; then
        if [[ "$HAS_PYUSB" == "true" ]]; then
            local new_path
            new_path="$(python3 /knx_usb.py --discover 2>/dev/null | jq -r '.devices[0].path // ""' 2>/dev/null || true)"
            if [[ -n "$new_path" ]] && usb_probe "$new_path"; then
                log_info "USB device re-discovered at ${new_path} (was ${USB_DEVICE})"
                USB_DEVICE="$new_path"
            fi
        fi
    fi
    if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
        # Check USB bridge cooldown (exponential backoff after failures)
        if [[ "$USB_BRIDGE_FAIL_COUNT" -gt 0 ]] && [[ "$USB_BRIDGE_FAIL_TS" -gt 0 ]]; then
            local now cooldown elapsed
            now="$(date +%s)"
            cooldown=$(( USB_BRIDGE_FAIL_COUNT * 15 ))
            [[ $cooldown -gt 120 ]] && cooldown=120
            elapsed=$(( now - USB_BRIDGE_FAIL_TS ))
            if [[ "$elapsed" -lt "$cooldown" ]]; then
                local remain=$(( cooldown - elapsed ))
                log_debug "USB bridge in cooldown (${remain}s remaining after ${USB_BRIDGE_FAIL_COUNT} failures)"
            else
                log_notice "USB available (cooldown expired)"; enter_usb; return 0
            fi
        else
            log_notice "USB available"; enter_usb; return 0
        fi
    fi

    log_debug "All interfaces still down — retrying in ${CHECK_INTERVAL}s"; return 0
}

tick_knxd() {
    # Check knxd health via reject file
    # Check for runtime tunnel rejection
    local rej_status
    rej_status="$(read_backend_reject_status "$KNXD_HOST" "$KNXD_PORT")"
    if [[ "$rej_status" == "0x29" ]]; then
        log_warn "knxd tunnel not supported (0x29)"
        if [[ -n "$USB_DEVICE" ]] && usb_probe "$USB_DEVICE"; then
            enter_usb
        else
            enter_degraded "knxd-unsupported"
        fi
        return 0
    fi

    # Try to recover to primary or backup (failback)
    case "$FAILBACK_MODE" in
        disabled) return 0 ;;
        manual)   return 0 ;;
        auto)
            if is_failback_holdoff_active; then
                log_debug "Failback holdoff active from knxd state"
                return 0
            fi

            if [[ -n "$PRIMARY_HOST" ]]; then
                local proto
                proto="$(detect_protocol "$PRIMARY_HOST" "$PRIMARY_PORT" "$PRIMARY_PROTOCOL")"
                if [[ "$proto" != "none" ]]; then
                    proto="$(select_backend_proto "$proto" "$PRIMARY_PROTOCOL")"
                    PRIMARY_RISE_COUNT=$((PRIMARY_RISE_COUNT + 1))
                    log_info "Primary recovery probe OK (${PRIMARY_RISE_COUNT}/${CHECK_RISE})"
                    if [[ "$PRIMARY_RISE_COUNT" -ge "$CHECK_RISE" ]]; then
                        log_notice "Primary recovered — failing back from knxd"
                        enter_primary "$proto"
                    fi
                    return 0
                fi
                PRIMARY_RISE_COUNT=0
            fi

            if [[ -n "$BACKUP_HOST" ]]; then
                proto="$(detect_protocol "$BACKUP_HOST" "$BACKUP_PORT" "$BACKUP_PROTOCOL")"
                if [[ "$proto" != "none" ]]; then
                    proto="$(select_backend_proto "$proto" "$BACKUP_PROTOCOL")"
                    log_notice "Backup recovered — moving from knxd to backup"
                    enter_backup "$proto"
                    return 0
                fi
            fi
            ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------
start_webui() {
    stop_webui
    local port="${INGRESS_PORT:-8099}"
    log_info "Starting Web UI on port ${port}"
    python3 /knx_webui.py "$port" &
    WEBUI_PID="$!"
    echo "$WEBUI_PID" > "$WEBUI_PID_FILE"
    sleep 1
    if ! kill -0 "$WEBUI_PID" 2>/dev/null; then
        log_warn "Web UI failed to start (non-critical)"
        WEBUI_PID=""; rm -f "$WEBUI_PID_FILE"
    else
        log_info "Web UI started (pid=${WEBUI_PID})"
    fi
    return 0
}

stop_webui() {
    local pid="${WEBUI_PID}"
    [[ -z "$pid" ]] && pid="$(cat "$WEBUI_PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && {
        kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    rm -f "$WEBUI_PID_FILE"; WEBUI_PID=""; return 0
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    log_info "Shutting down..."
    stop_webui    || true
    stop_proxy    || true
    stop_usb_bridge || true
    rm -f "$STATE_FILE" "$BACKEND_FILE" "$BACKEND_REJECT_FILE" \
          "$METRICS_FILE" 2>/dev/null || true
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

    load_config

    if [[ -n "$PRIMARY_HOST" ]]; then
        log_info "Primary:   ${PRIMARY_HOST}:${PRIMARY_PORT} [${PRIMARY_PROTOCOL}]${PRIMARY_SECURE:+ (secure=${PRIMARY_SECURE})}"
    else
        log_info "Primary:   (not configured)"
    fi
    if [[ -n "$BACKUP_HOST" ]]; then
        log_info "Backup:    ${BACKUP_HOST}:${BACKUP_PORT} [${BACKUP_PROTOCOL}]${BACKUP_SECURE:+ (secure=${BACKUP_SECURE})}"
    else
        log_info "Backup:    (not configured)"
    fi
    [[ -n "$KNXD_HOST" ]] && \
        log_info "knxd Ext:  ${KNXD_HOST}:${KNXD_PORT} [${KNXD_PROTOCOL}]"
    log_info "Frontend:  ${FRONTEND_PROTOCOL} on port ${LISTEN_PORT}"
    [[ -n "$USB_DEVICE" ]] && \
        log_info "USB:       ${USB_DEVICE} @ ${USB_BAUD} baud (priority=${USB_PRIORITY}, mode=${USB_MODE}, knxd=${HAS_KNXD}, pyusb=${HAS_PYUSB})"
    log_info "Health:    interval=${CHECK_INTERVAL}s fall=${CHECK_FALL} rise=${CHECK_RISE} method=${CHECK_METHOD}"
    log_info "Failback:  mode=${FAILBACK_MODE} delay=${FAILBACK_DELAY}s"
    log_info "Sessions:  max=${MAX_SESSIONS} timeout=${SESSION_TIMEOUT}s drain=${DRAIN_TIMEOUT}s"
    log_info "Timeout:   ${CONNECTION_TIMEOUT}s"

    clear_backend

    # Clear ghost sessions from previous addon instances BEFORE probing.
    # When the addon restarts, old tunnel sessions are still held by the
    # gateway for 60-120s. This sends DISCONNECT for ch_id 1-8 to free them.
    if [[ -n "$PRIMARY_HOST" ]]; then
        log_info "Clearing ghost sessions on ${PRIMARY_HOST}:${PRIMARY_PORT} [${PRIMARY_PROTOCOL}]..."
        PYTHONPATH=/ python3 -c "
import logging, sys; logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
from knx_health import clear_ghost_sessions
n = clear_ghost_sessions('${PRIMARY_HOST}', ${PRIMARY_PORT}, '${PRIMARY_PROTOCOL}')
print(n)
" 2>/dev/null || true
        sleep 2  # Give gateway time to process
    fi
    if [[ -n "$BACKUP_HOST" ]] && [[ "$BACKUP_HOST" != "$PRIMARY_HOST" || "$BACKUP_PORT" != "$PRIMARY_PORT" ]]; then
        log_info "Clearing ghost sessions on ${BACKUP_HOST}:${BACKUP_PORT} [${BACKUP_PROTOCOL}]..."
        PYTHONPATH=/ python3 -c "
import logging, sys; logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
from knx_health import clear_ghost_sessions
n = clear_ghost_sessions('${BACKUP_HOST}', ${BACKUP_PORT}, '${BACKUP_PROTOCOL}')
print(n)
" 2>/dev/null || true
    fi

    # Probe all backends FIRST — find a working one before accepting clients.
    # Starting the proxy before a backend is ready causes a flood of
    # "CONNECT rejected — no backend configured" errors from HA.
    initial_probe

    # Start web UI (ingress) before proxy — non-blocking, non-critical
    start_webui

    # NOW start the proxy — clients will connect to an already-configured backend
    start_proxy || die "Cannot start KNX proxy"

    log_info "Entering monitor loop (interval=${CHECK_INTERVAL}s)..."
    while true; do
        sleep "$CHECK_INTERVAL" || true
        monitor_tick
    done
}

main "$@"