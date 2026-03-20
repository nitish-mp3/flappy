#!/bin/bash
set -e

# Source bashio if available
if [ -f /usr/lib/bashio.sh ]; then
    source /usr/lib/bashio.sh || true
fi

# Get config with bashio or fallback
get_config() {
    local key=$1
    local default=$2
    
    if type bashio::config &>/dev/null; then
        bashio::config "$key // $default" 2>/dev/null || echo "$default"
    else
        echo "$default"
    fi
}

# Logging functions
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
PRIMARY_HOST="$(get_config 'primary_host' '')"
PRIMARY_PORT="$(get_config 'primary_port' '3671')"
BACKUP_HOST="$(get_config 'backup_host' '')"
BACKUP_PORT="$(get_config 'backup_port' '3671')"
LISTEN_PORT="$(get_config 'listen_port' '3672')"
CONN_TIMEOUT="$(get_config 'connection_timeout' '5')"
CLIENT_TIMEOUT="$(get_config 'client_timeout' '60')"
SERVER_TIMEOUT="$(get_config 'server_timeout' '60')"

# Validate
if [ -z "$PRIMARY_HOST" ] || [ -z "$BACKUP_HOST" ]; then
    log_error "primary_host and backup_host are required and cannot be empty"
    exit 1
fi

log_info "Starting KNX HAProxy"
log_info "  Primary: ${PRIMARY_HOST}:${PRIMARY_PORT}"
log_info "  Backup:  ${BACKUP_HOST}:${BACKUP_PORT}"
log_info "  Listen:  0.0.0.0:${LISTEN_PORT}"

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

log_info "HAProxy ready"

# Run in foreground - s6 will manage the process
exec haproxy -f /etc/haproxy.cfg