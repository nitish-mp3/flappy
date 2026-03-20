#!/bin/bash
# =============================================================================
# KNX Failover Proxy — Docker Health Check
# =============================================================================
# Checks:
#   1. knx_proxy.py process is running
#   2. Frontend port is actually listening (TCP or UDP)
#   3. KNX protocol responds to DESCRIPTION_REQUEST
#   4. Reports current state and session count
# =============================================================================
set -uo pipefail

OPTIONS_FILE="/data/options.json"
STATE_FILE="/run/knx-failover.state"
METRICS_FILE="/run/knx-metrics.json"
LISTEN_PORT="3671"

if [[ -f "$OPTIONS_FILE" ]] && command -v jq >/dev/null 2>&1; then
    LISTEN_PORT="$(jq -r '.listen_port // 3671' "$OPTIONS_FILE")"
fi

# ── 1. Process check ──────────────────────────────────────────────────
if ! pgrep -f "knx_proxy.py" >/dev/null 2>&1; then
    echo "FAIL: knx_proxy.py process not found" >&2
    exit 1
fi

# ── 2. Port check ─────────────────────────────────────────────────────
# Try UDP first (lightweight), then TCP
port_ok=false
if command -v python3 >/dev/null 2>&1; then
    if python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
try:
    # Send KNX DESCRIPTION_REQUEST
    req = b'\x06\x10\x02\x03\x00\x0e\x08\x01\x00\x00\x00\x00\x0e\x57'
    s.sendto(req, ('127.0.0.1', ${LISTEN_PORT}))
    data, _ = s.recvfrom(512)
    if len(data) >= 6 and data[:2] == b'\x06\x10':
        sys.exit(0)
except Exception:
    pass
finally:
    s.close()
sys.exit(1)
" 2>/dev/null; then
        port_ok=true
    fi
fi

if [[ "$port_ok" != "true" ]]; then
    # Fallback: just check if anything is listening on the port
    if ss -lntu 2>/dev/null | grep -q ":${LISTEN_PORT} " 2>/dev/null; then
        port_ok=true
    fi
fi

if [[ "$port_ok" != "true" ]]; then
    echo "FAIL: port ${LISTEN_PORT} not responding" >&2
    exit 1
fi

# ── 3. State report (advisory) ────────────────────────────────────────
if [[ -f "$STATE_FILE" ]]; then
    STATE="$(grep '^state=' "$STATE_FILE" | cut -d= -f2 || true)"
    if [[ "$STATE" == "DEGRADED" ]]; then
        echo "WARN: state=DEGRADED — all KNX interfaces down, retrying" >&2
    fi
fi

# ── 4. Metrics report (advisory) ──────────────────────────────────────
if [[ -f "$METRICS_FILE" ]] && command -v jq >/dev/null 2>&1; then
    SESSIONS="$(jq -r '.active_sessions // 0' "$METRICS_FILE" 2>/dev/null || echo 0)"
    FAILOVERS="$(jq -r '.total_failovers // 0' "$METRICS_FILE" 2>/dev/null || echo 0)"
    echo "OK: sessions=${SESSIONS} failovers=${FAILOVERS}"
fi

exit 0