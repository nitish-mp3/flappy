#!/bin/bash
# =============================================================================
# KNX Failover Proxy — cont-init.d pre-flight checks
# Runs once at container start, before the service is launched by s6.
# =============================================================================
set -euo pipefail

OPTIONS_FILE="/data/options.json"

log()  { echo "[cont-init] $*"; }
warn() { echo "[cont-init] WARN: $*"; }
fail() { echo "[cont-init] FATAL: $*" >&2; exit 1; }

log "KNX Failover Proxy — pre-flight checks"

# ---------------------------------------------------------------------------
# 1. Verify options file exists and is valid JSON
# ---------------------------------------------------------------------------
[[ -f "$OPTIONS_FILE" ]] || fail "Missing $OPTIONS_FILE"
jq empty "$OPTIONS_FILE" 2>/dev/null || fail "Options file is not valid JSON"

# ---------------------------------------------------------------------------
# 2. Validate required string fields are non-empty
# ---------------------------------------------------------------------------
read_opt() {
    jq -r --arg k "$1" '.[$k] // ""' "$OPTIONS_FILE"
}

PRIMARY_HOST="$(read_opt primary_host)"
BACKUP_HOST="$(read_opt backup_host)"
LISTEN_PORT="$(read_opt listen_port)"
UDP_BRIDGE_PORT="$(read_opt udp_bridge_port)"
USB_DEVICE="$(read_opt usb_device)"

[[ -n "$PRIMARY_HOST" ]] || fail "primary_host is required"
[[ -n "$BACKUP_HOST"  ]] || fail "backup_host is required"

if [[ -n "$LISTEN_PORT" && -n "$UDP_BRIDGE_PORT" ]]; then
    if [[ "$LISTEN_PORT" == "$UDP_BRIDGE_PORT" ]]; then
        fail "listen_port and udp_bridge_port must be different (both are ${LISTEN_PORT})"
    fi
fi

# ---------------------------------------------------------------------------
# 3. USB device presence check (advisory only — device may hotplug in later)
# ---------------------------------------------------------------------------
if [[ -n "$USB_DEVICE" ]]; then
    if [[ ! -e "$USB_DEVICE" ]]; then
        warn "USB device not present at startup: $USB_DEVICE (will retry at runtime)"
    elif [[ ! -r "$USB_DEVICE" ]] || [[ ! -w "$USB_DEVICE" ]]; then
        warn "USB device exists but is not readable/writable: $USB_DEVICE"
    else
        log "USB device found: $USB_DEVICE"
    fi
fi

# ---------------------------------------------------------------------------
# 4. Ensure HAProxy config directory exists
# ---------------------------------------------------------------------------
mkdir -p /etc/haproxy
mkdir -p /run
mkdir -p /data

log "Pre-flight checks passed"