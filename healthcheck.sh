#!/bin/bash
set -euo pipefail

HAPROXY_PID=$(pgrep haproxy)

if [ -z "$HAPROXY_PID" ]; then
    exit 1
fi

if ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
    exit 1
fi

exit 0
