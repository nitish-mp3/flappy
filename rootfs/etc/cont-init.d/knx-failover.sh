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

log "KNX Failover Proxy v3.0.0 — pre-flight checks"

# ---------------------------------------------------------------------------
# 1. Verify options file exists and is valid JSON
# ---------------------------------------------------------------------------
[[ -f "$OPTIONS_FILE" ]] || fail "Missing $OPTIONS_FILE"
jq empty "$OPTIONS_FILE" 2>/dev/null || fail "Options file is not valid JSON"

# ---------------------------------------------------------------------------
# 2. Helper
# ---------------------------------------------------------------------------
read_opt() {
    jq -r --arg k "$1" '.[$k] // ""' "$OPTIONS_FILE"
}

# ---------------------------------------------------------------------------
# 3. Validate required string fields
# ---------------------------------------------------------------------------
PRIMARY_HOST="$(read_opt primary_host)"
BACKUP_HOST="$(read_opt backup_host)"
USB_DEVICE="$(read_opt usb_device)"
PRIMARY_SECURE="$(read_opt primary_secure)"
BACKUP_SECURE="$(read_opt backup_secure)"

KNXD_HOST="$(read_opt knxd_host)"
[[ -n "$PRIMARY_HOST" || -n "$BACKUP_HOST" || -n "$KNXD_HOST" || -n "$USB_DEVICE" ]] || fail "At least one backend config (primary, backup, knxd, or usb) must be provided"

# ---------------------------------------------------------------------------
# 4. Validate secure config consistency
# ---------------------------------------------------------------------------
if [[ "$PRIMARY_SECURE" == "true" ]]; then
    P_DEV_PW="$(read_opt primary_device_password)"
    [[ -n "$P_DEV_PW" ]] || warn "primary_secure=true but primary_device_password is empty — connection may fail"
fi

if [[ "$BACKUP_SECURE" == "true" ]]; then
    B_DEV_PW="$(read_opt backup_device_password)"
    [[ -n "$B_DEV_PW" ]] || warn "backup_secure=true but backup_device_password is empty — connection may fail"
fi

# ---------------------------------------------------------------------------
# 5. USB device presence check (advisory — device may hotplug later)
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
# 6. Ensure runtime directories
# ---------------------------------------------------------------------------
mkdir -p /run
mkdir -p /data
mkdir -p /data/knx-secure

# ---------------------------------------------------------------------------
# 7. Check for knxd availability if USB is configured
# ---------------------------------------------------------------------------
if [[ -n "$USB_DEVICE" ]]; then
    if command -v knxd >/dev/null 2>&1; then
        log "knxd available — USB will use knxd daemon"
    else
        warn "knxd not installed — USB will use socat serial bridge fallback"
    fi
fi

log "Pre-flight checks passed"
