#!/usr/bin/with-contenv bashio
set -euo pipefail

# Load configuration
PRIMARY_HOST="$(bashio::config 'primary_host')"
PRIMARY_PORT="$(bashio::config 'primary_port')"
BACKUP_HOST="$(bashio::config 'backup_host')"
BACKUP_PORT="$(bashio::config 'backup_port')"
LISTEN_PORT="$(bashio::config 'listen_port')"
LOG_LEVEL="$(bashio::config 'log_level // info')"
CONN_TIMEOUT="$(bashio::config 'connection_timeout // 5')"
CLIENT_TIMEOUT="$(bashio::config 'client_timeout // 60')"
SERVER_TIMEOUT="$(bashio::config 'server_timeout // 60')"

# Validate configuration
if [ -z "$PRIMARY_HOST" ] || [ -z "$BACKUP_HOST" ]; then
    bashio::log.error "Primary and backup hosts must be configured"
    exit 1
fi

bashio::log.info "Starting KNX HAProxy with:"
bashio::log.info "  Primary: ${PRIMARY_HOST}:${PRIMARY_PORT}"
bashio::log.info "  Backup:  ${BACKUP_HOST}:${BACKUP_PORT}"
bashio::log.info "  Listen:  0.0.0.0:${LISTEN_PORT}"

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

bashio::log.info "HAProxy configuration generated successfully"

# Start HAProxy
exec haproxy -f /etc/haproxy.cfg -V