#!/bin/bash
set -eo pipefail

OPTIONS_FILE="/data/options.json"
UDP_BRIDGE_PORT="13671"
SOCAT_PID=""
HAPROXY_PID=""

if [ ! -f "$OPTIONS_FILE" ]; then
    echo "[ERROR] Missing $OPTIONS_FILE; Home Assistant addon options are unavailable" >&2
    exit 1
fi

read_option() {
    local key="$1"
    local fallback="$2"
    jq -r --arg key "$key" --arg fallback "$fallback" '.[$key] // $fallback' "$OPTIONS_FILE"
}

# Load configuration from Home Assistant addon options
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

# Validate required configuration
if [ -z "$PRIMARY_HOST" ] || [ -z "$BACKUP_HOST" ]; then
    echo "[ERROR] primary_host and backup_host are required and cannot be empty" >&2
    exit 1
fi

echo "[INFO] Starting KNX HAProxy"
echo "[INFO] Primary: ${PRIMARY_HOST}:${PRIMARY_PORT}"
echo "[INFO] Backup:  ${BACKUP_HOST}:${BACKUP_PORT}"
echo "[INFO] Listen:  0.0.0.0:${LISTEN_PORT}"
echo "[INFO] Health check: interval=${CHECK_INTERVAL}s fall=${CHECK_FALL} rise=${CHECK_RISE}"

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

BACKUP_TARGET_HOST="$BACKUP_HOST"
BACKUP_TARGET_PORT="$BACKUP_PORT"
BACKUP_SERVER_PARAMS="check backup"

# Mixed-protocol fallback behavior:
# - If backup exposes TCP, use it directly with health checks.
# - If backup TCP probe fails, spin up a local TCP->UDP bridge and target that bridge.
if timeout 2 bash -c "</dev/tcp/${BACKUP_HOST}/${BACKUP_PORT}" 2>/dev/null; then
    echo "[INFO] Backup endpoint accepts TCP, using direct TCP failover"
else
    echo "[WARNING] Backup endpoint did not accept TCP probe; enabling TCP->UDP bridge on 127.0.0.1:${UDP_BRIDGE_PORT}"

    socat "TCP-LISTEN:${UDP_BRIDGE_PORT},fork,reuseaddr,keepalive,nodelay" "UDP:${BACKUP_HOST}:${BACKUP_PORT}" &
    SOCAT_PID="$!"

    # Give bridge a moment to initialize.
    sleep 1

    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
        echo "[ERROR] Failed to start TCP->UDP bridge process"
        exit 1
    fi

    BACKUP_TARGET_HOST="127.0.0.1"
    BACKUP_TARGET_PORT="$UDP_BRIDGE_PORT"
    # TCP checks are meaningless on a UDP destination behind a stream bridge.
    BACKUP_SERVER_PARAMS="backup"
fi

# Generate config with variables substituted inline
cat > /etc/haproxy.cfg <<EOF
global
    log stdout format raw local0
    maxconn 4096

defaults
    log global
    mode tcp
    timeout connect ${CONN_TIMEOUT}s
    timeout check ${CONN_TIMEOUT}s
    timeout client ${CLIENT_TIMEOUT}s
    timeout server ${SERVER_TIMEOUT}s
    option redispatch
    default-server inter ${CHECK_INTERVAL}s fall ${CHECK_FALL} rise ${CHECK_RISE} on-marked-down shutdown-sessions

frontend knx_frontend
    bind *:${LISTEN_PORT}
    default_backend knx_backend

backend knx_backend
    mode tcp
    option tcp-check
    # Active-passive failover: primary is preferred, backup is only used when primary is down.
    server primary ${PRIMARY_HOST}:${PRIMARY_PORT} check
    server backup ${BACKUP_TARGET_HOST}:${BACKUP_TARGET_PORT} ${BACKUP_SERVER_PARAMS}
EOF

echo "[INFO] HAProxy ready"

# Run in foreground - s6 will manage the process
haproxy -f /etc/haproxy.cfg -db &
HAPROXY_PID="$!"
wait "$HAPROXY_PID"