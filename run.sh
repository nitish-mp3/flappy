#!/bin/bash
set -euo pipefail

# Source bashio if available, otherwise provide fallback
if [ -f /usr/lib/bashio.sh ]; then
    source /usr/lib/bashio.sh || true
fi

# Function to get config value with bashio or fallback
get_config() {
    local key=$1
    local default=$2
    
    if type bashio::config &>/dev/null; then
        bashio::config "$key // $default" 2>/dev/null || echo "$default"
    else
        echo "$default"
    fi
}

# Function to log
log_info() {
    if type bashio::log.info &>/dev/null; then
        bashio::log.info "$1"
    else
        echo "[INFO] $1"
    fi
}

log_error() {
    if type bashio::log.error &>/dev/null; then
        bashio::log.error "$1"
    else
        echo "[ERROR] $1" >&2
    fi
}

# Load configuration
PRIMARY_HOST="$(get_config 'primary_host' '192.168.1.212')"
PRIMARY_PORT="$(get_config 'primary_port' '3671')"
BACKUP_HOST="$(get_config 'backup_host' '192.168.1.104')"
BACKUP_PORT="$(get_config 'backup_port' '3671')"
LISTEN_PORT="$(get_config 'listen_port' '3672')"
LOG_LEVEL="$(get_config 'log_level' 'info')"
CONN_TIMEOUT="$(get_config 'connection_timeout' '5')"
CLIENT_TIMEOUT="$(get_config 'client_timeout' '60')"
SERVER_TIMEOUT="$(get_config 'server_timeout' '60')"

# Validate configuration
if [ -z "$PRIMARY_HOST" ] || [ -z "$BACKUP_HOST" ]; then
    log_error "Primary and backup hosts must be configured"
    exit 1
fi

log_info "Starting KNX HAProxy with:"
log_info "  Primary: ${PRIMARY_HOST}:${PRIMARY_PORT}"
log_info "  Backup:  ${BACKUP_HOST}:${BACKUP_PORT}"
log_info "  Listen:  0.0.0.0:${LISTEN_PORT}"

# Generate HAProxy configuration
cat >/etc/haproxy.cfg <<EOF
global
    log stdout format raw local0
    maxconn 4096
    daemon

defaults
    log global
    mode tcp
    timeout connect ${CONN_TIMEOUT}s
    timeout client ${CLIENT_TIMEOUT}s
    timeout server ${SERVER_TIMEOUT}s
    default-server inter 2s fall 3 rise 2

frontend knx_frontend
    bind *:${LISTEN_PORT}
    description KNX TCP Input
    default_backend knx_backend

backend knx_backend
    description KNX TCP Backend with Failover
    mode tcp
    option tcp-check
    balance roundrobin
    server primary ${PRIMARY_HOST}:${PRIMARY_PORT} check
    server backup ${BACKUP_HOST}:${BACKUP_PORT} check backup
EOF

log_info "HAProxy configuration generated successfully"

# Start HAProxy
exec haproxy -f /etc/haproxy.cfg -V