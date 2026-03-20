#!/bin/bash
set -euo pipefail

OPTIONS_FILE="/data/options.json"
LISTEN_PORT="3672"

if [ -f "$OPTIONS_FILE" ] && command -v jq >/dev/null 2>&1; then
    LISTEN_PORT="$(jq -r '.listen_port // 3672' "$OPTIONS_FILE")"
fi

HAPROXY_PID="$(pgrep -x haproxy || true)"

if [ -z "$HAPROXY_PID" ]; then
    echo "haproxy process not found" >&2
    exit 1
fi

if ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
    echo "haproxy process is not alive" >&2
    exit 1
fi

if ! timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/${LISTEN_PORT}" 2>/dev/null; then
    echo "listener probe failed on 127.0.0.1:${LISTEN_PORT}" >&2
    exit 1
fi

exit 0
