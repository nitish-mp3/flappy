#!/usr/bin/with-contenv bashio
set -euo pipefail

# Load configuration from Home Assistant addon options
PRIMARY_HOST="$(bashio::config 'primary_host')"
PRIMARY_PORT="$(bashio::config 'primary_port')"
BACKUP_HOST="$(bashio::config 'backup_host')"
BACKUP_PORT="$(bashio::config 'backup_port')"
LISTEN_PORT="$(bashio::config 'listen_port')"
CONN_TIMEOUT="$(bashio::config 'connection_timeout')"
CLIENT_TIMEOUT="$(bashio::config 'client_timeout')"
SERVER_TIMEOUT="$(bashio::config 'server_timeout')"

# Validate required configuration
if ! bashio::config.has_value 'primary_host' || ! bashio::config.has_value 'backup_host'; then
    bashio::log.error "primary_host and backup_host are required and cannot be empty"
    exit 1
fi

bashio::log.info "Starting KNX HAProxy"
bashio::log.info "  Primary: ${PRIMARY_HOST}:${PRIMARY_PORT}"
bashio::log.info "  Backup:  ${BACKUP_HOST}:${BACKUP_PORT}"
bashio::log.info "  Listen:  0.0.0.0:${LISTEN_PORT}"

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

bashio::log.info "HAProxy ready"

# Run in foreground - s6 will manage the process
exec haproxy -f /etc/haproxy.cfg