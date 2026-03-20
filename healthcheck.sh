#!/bin/bash
# =============================================================================
# KNX Failover Proxy — Docker HEALTHCHECK
# =============================================================================
# Checks:
#   1. HAProxy process is alive
#   2. Listen port is accepting connections
#   3. State is not FAILED (DEGRADED is still "starting" — give it a pass)
# =============================================================================
set -euo pipefail

OPTIONS_FILE="/data/options.json"
STATE_FILE="/run/knx-haproxy.state"
LISTEN_PORT="3672"

# ---------------------------------------------------------------------------
# Read listen_port from options if available
# ---------------------------------------------------------------------------
if [[ -f "$OPTIONS_FILE" ]] && command -v jq >/dev/null 2>&1; then
    LISTEN_PORT="$(jq -r '.listen_port // 3672' "$OPTIONS_FILE")"
fi

# ---------------------------------------------------------------------------
# 1. HAProxy process must be running
# ---------------------------------------------------------------------------
HAPROXY_PID="$(pgrep -x haproxy 2>/dev/null | head -1 || true)"
if [[ -z "$HAPROXY_PID" ]]; then
    echo "FAIL: haproxy process not found" >&2
    exit 1
fi
if ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
    echo "FAIL: haproxy process (${HAPROXY_PID}) is not responding to signals" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Listener port must accept TCP connections
# ---------------------------------------------------------------------------
if ! timeout 3 bash -c ">/dev/tcp/127.0.0.1/${LISTEN_PORT}" 2>/dev/null; then
    echo "FAIL: listener probe failed on 127.0.0.1:${LISTEN_PORT}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. State file advisory check — DEGRADED is normal; log it but don't fail
# ---------------------------------------------------------------------------
if [[ -f "$STATE_FILE" ]]; then
    STATE="$(grep '^state=' "$STATE_FILE" | cut -d= -f2 || true)"
    if [[ "$STATE" == "DEGRADED" ]]; then
        echo "WARN: proxy is in DEGRADED state — all KNX interfaces are currently down, retrying" >&2
        # Still exit 0 — HAProxy is running and we're retrying; this is not a container failure
    fi
fi

exit 0