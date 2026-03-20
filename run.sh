#!/bin/bash
set -eo pipefail

OPTIONS_FILE="/data/options.json"

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

# Validate required configuration
if [ -z "$PRIMARY_HOST" ] || [ -z "$BACKUP_HOST" ]; then
    echo "[ERROR] primary_host and backup_host are required and cannot be empty" >&2
    exit 1
fi

echo "[INFO] Starting KNX HAProxy"
echo "[INFO] Primary: ${PRIMARY_HOST}:${PRIMARY_PORT}"
echo "[INFO] Backup:  ${BACKUP_HOST}:${BACKUP_PORT}"
echo "[INFO] Listen:  0.0.0.0:${LISTEN_PORT}"

# Generate config with variables substituted inline
cat > /etc/haproxy.cfg <<EOF
global
    log stdout format raw local0
    maxconn 4096

defaults
    log global
    mode tcp
    timeout connect ${CONN_TIMEOUT}s
    timeout client ${CLIENT_TIMEOUT}s
    timeout server ${SERVER_TIMEOUT}s
    default-server inter 2s fall 3 rise 2

frontend knx_frontend
    bind *:${LISTEN_PORT}
    default_backend knx_backend

backend knx_backend
    mode tcp
    option tcp-check
    balance roundrobin
    server primary ${PRIMARY_HOST}:${PRIMARY_PORT} check
    server backup ${BACKUP_HOST}:${BACKUP_PORT} check backup
EOF

echo "[INFO] HAProxy ready"

# Run in foreground - s6 will manage the process
exec haproxy -f /etc/haproxy.cfg