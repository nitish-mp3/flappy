#!/bin/bash
set -uo pipefail

OPTIONS_FILE="/data/options.json"
STATE_FILE="/run/knx-haproxy.state"
LISTEN_PORT="3671"

if [[ -f "$OPTIONS_FILE" ]] && command -v jq >/dev/null 2>&1; then
    LISTEN_PORT="$(jq -r '.listen_port // 3671' "$OPTIONS_FILE")"
fi

# 1. KNX proxy process must be running
if ! pgrep -f "knx_proxy.py" >/dev/null 2>&1; then
    echo "FAIL: knx_proxy.py process not found" >&2; exit 1
fi

# 2. State advisory
if [[ -f "$STATE_FILE" ]]; then
    STATE="$(grep '^state=' "$STATE_FILE" | cut -d= -f2 || true)"
    if [[ "$STATE" == "DEGRADED" ]]; then
        echo "WARN: state=DEGRADED — all KNX interfaces down, retrying" >&2
    fi
fi

exit 0