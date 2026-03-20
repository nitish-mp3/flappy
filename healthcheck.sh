#!/bin/bash
set -uo pipefail

OPTIONS_FILE="/data/options.json"
STATE_FILE="/run/knx-haproxy.state"
LISTEN_PORT="3672"

if [[ -f "$OPTIONS_FILE" ]] && command -v jq >/dev/null 2>&1; then
    LISTEN_PORT="$(jq -r '.listen_port // 3672' "$OPTIONS_FILE")"
fi

if ! pgrep -x haproxy >/dev/null 2>&1; then
    echo "FAIL: haproxy process not found" >&2; exit 1
fi

if ! timeout 3 bash -c ">/dev/tcp/127.0.0.1/${LISTEN_PORT}" 2>/dev/null; then
    echo "FAIL: TCP listener not responding on port ${LISTEN_PORT}" >&2; exit 1
fi

if ! pgrep -f "knx_udp_responder" >/dev/null 2>&1; then
    echo "FAIL: UDP responder process not found" >&2; exit 1
fi

if [[ -f "$STATE_FILE" ]]; then
    STATE="$(grep '^state=' "$STATE_FILE" | cut -d= -f2 || true)"
    if [[ "$STATE" == "DEGRADED" ]]; then
        echo "WARN: state=DEGRADED (all KNX interfaces down, retrying)" >&2
    fi
fi

exit 0