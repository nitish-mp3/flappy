#!/bin/bash
set -euo pipefail

OPTIONS_FILE="/data/options.json"
STATE_FILE="/run/knx-haproxy.state"
SOCAT_PID=""
HAPROXY_PID=""

log_info() {
    echo "[INFO] $*"
}

log_warn() {
    echo "[WARNING] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

die() {
    log_error "$*"
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

read_option() {
    local key="$1"
    local fallback="$2"
    jq -r --arg key "$key" --arg fallback "$fallback" '.[$key] // $fallback' "$OPTIONS_FILE"
}

is_int() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

is_valid_host() {
    [[ "$1" =~ ^[A-Za-z0-9._:-]+$ ]]
}

validate_port() {
    local value="$1"
    local label="$2"
    if ! is_int "$value"; then
        die "$label must be a number"
    fi
    if [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
        die "$label must be between 1 and 65535"
    fi
}

validate_positive_int() {
    local value="$1"
    local label="$2"
    if ! is_int "$value" || [ "$value" -lt 1 ]; then
        die "$label must be a positive integer"
    fi
}

tcp_probe() {
    local host="$1"
    local port="$2"
    timeout 2 socat -T1 - "TCP:${host}:${port},connect-timeout=1" </dev/null >/dev/null 2>&1
}

cleanup() {
    if [ -n "$HAPROXY_PID" ] && kill -0 "$HAPROXY_PID" 2>/dev/null; then
        kill "$HAPROXY_PID" 2>/dev/null || true
        wait "$HAPROXY_PID" 2>/dev/null || true
    fi

    if [ -n "$SOCAT_PID" ] && kill -0 "$SOCAT_PID" 2>/dev/null; then
        kill "$SOCAT_PID" 2>/dev/null || true
        wait "$SOCAT_PID" 2>/dev/null || true
    fi
}

trap cleanup INT TERM EXIT

require_cmd jq
require_cmd haproxy
require_cmd socat
require_cmd timeout

[ -f "$OPTIONS_FILE" ] || die "Missing $OPTIONS_FILE; Home Assistant addon options are unavailable"

PRIMARY_HOST="$(read_option 'primary_host' '')"
PRIMARY_PORT="$(read_option 'primary_port' '3671')"
BACKUP_HOST="$(read_option 'backup_host' '')"
BACKUP_PORT="$(read_option 'backup_port' '3671')"
LISTEN_PORT="$(read_option 'listen_port' '3672')"
CONN_TIMEOUT="$(read_option 'connection_timeout' '5')"
CLIENT_TIMEOUT="$(read_option 'client_timeout' '60')"
SERVER_TIMEOUT="$(read_option 'server_timeout' '60')"
CHECK_INTERVAL="$(read_option 'health_check_interval' '2')"
CHECK_FALL="$(read_option 'health_check_fall' '2')"
CHECK_RISE="$(read_option 'health_check_rise' '1')"
UDP_BRIDGE_PORT="$(read_option 'udp_bridge_port' '13671')"

[ -n "$PRIMARY_HOST" ] || die "primary_host is required and cannot be empty"
[ -n "$BACKUP_HOST" ] || die "backup_host is required and cannot be empty"

is_valid_host "$PRIMARY_HOST" || die "primary_host has invalid characters"
is_valid_host "$BACKUP_HOST" || die "backup_host has invalid characters"

validate_port "$PRIMARY_PORT" "primary_port"
validate_port "$BACKUP_PORT" "backup_port"
validate_port "$LISTEN_PORT" "listen_port"
validate_port "$UDP_BRIDGE_PORT" "udp_bridge_port"
validate_positive_int "$CONN_TIMEOUT" "connection_timeout"
validate_positive_int "$CLIENT_TIMEOUT" "client_timeout"
validate_positive_int "$SERVER_TIMEOUT" "server_timeout"
validate_positive_int "$CHECK_INTERVAL" "health_check_interval"
validate_positive_int "$CHECK_FALL" "health_check_fall"
validate_positive_int "$CHECK_RISE" "health_check_rise"

if [ "$LISTEN_PORT" = "$UDP_BRIDGE_PORT" ]; then
    die "listen_port and udp_bridge_port cannot be the same"
fi

log_info "Starting KNX HAProxy"
log_info "Primary target: ${PRIMARY_HOST}:${PRIMARY_PORT}"
log_info "Backup target:  ${BACKUP_HOST}:${BACKUP_PORT}"
log_info "Listen bind:    0.0.0.0:${LISTEN_PORT}"
log_info "Health check:   interval=${CHECK_INTERVAL}s fall=${CHECK_FALL} rise=${CHECK_RISE}"

if [ "$PRIMARY_HOST" = "$BACKUP_HOST" ] && [ "$PRIMARY_PORT" = "$BACKUP_PORT" ]; then
    log_warn "Primary and backup targets are identical; failover will provide no redundancy"
fi

if tcp_probe "$PRIMARY_HOST" "$PRIMARY_PORT"; then
    log_info "Primary startup probe succeeded"
else
    log_warn "Primary startup probe failed; backup may be used immediately"
fi

BACKUP_TARGET_HOST="$BACKUP_HOST"
BACKUP_TARGET_PORT="$BACKUP_PORT"
BACKUP_SERVER_PARAMS="check backup"
BACKUP_MODE="tcp"

if tcp_probe "$BACKUP_HOST" "$BACKUP_PORT"; then
    log_info "Backup endpoint accepts TCP; using direct TCP failover"
else
    BACKUP_MODE="udp-bridge"
    log_warn "Backup endpoint did not accept TCP probe; enabling local TCP->UDP bridge on 127.0.0.1:${UDP_BRIDGE_PORT}"

    socat "TCP-LISTEN:${UDP_BRIDGE_PORT},fork,reuseaddr,keepalive,nodelay" "UDP:${BACKUP_HOST}:${BACKUP_PORT}" &
    SOCAT_PID="$!"
    sleep 1

    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        die "Failed to start TCP->UDP bridge process"
    fi

    if ! tcp_probe "127.0.0.1" "$UDP_BRIDGE_PORT"; then
        die "TCP->UDP bridge started but local probe failed"
    fi

    BACKUP_TARGET_HOST="127.0.0.1"
    BACKUP_TARGET_PORT="$UDP_BRIDGE_PORT"
    BACKUP_SERVER_PARAMS="check backup"
fi

cat > /etc/haproxy.cfg <<EOF
global
    log stdout format raw local0
    maxconn 4096

defaults
    log global
    mode tcp
    option redispatch
    timeout connect ${CONN_TIMEOUT}s
    timeout check ${CONN_TIMEOUT}s
    timeout client ${CLIENT_TIMEOUT}s
    timeout server ${SERVER_TIMEOUT}s
    default-server inter ${CHECK_INTERVAL}s fall ${CHECK_FALL} rise ${CHECK_RISE} on-marked-down shutdown-sessions

frontend knx_frontend
    bind *:${LISTEN_PORT}
    default_backend knx_backend

backend knx_backend
    mode tcp
    option tcp-check
    server primary ${PRIMARY_HOST}:${PRIMARY_PORT} check
    server backup ${BACKUP_TARGET_HOST}:${BACKUP_TARGET_PORT} ${BACKUP_SERVER_PARAMS}
EOF

echo "backup_mode=${BACKUP_MODE}" > "$STATE_FILE"
echo "backup_target_host=${BACKUP_TARGET_HOST}" >> "$STATE_FILE"
echo "backup_target_port=${BACKUP_TARGET_PORT}" >> "$STATE_FILE"

haproxy -c -f /etc/haproxy.cfg >/dev/null || die "HAProxy configuration validation failed"

log_info "HAProxy config validated"
log_info "Backup mode: ${BACKUP_MODE}"
log_info "HAProxy ready"

haproxy -f /etc/haproxy.cfg -db &
HAPROXY_PID="$!"
wait "$HAPROXY_PID"