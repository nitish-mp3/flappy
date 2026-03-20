ARG BUILD_FROM
FROM $BUILD_FROM

# ---------------------------------------------------------------------------
# Runtime dependencies
#   haproxy   — TCP proxy and health-checking layer
#   socat     — TCP↔UDP bridge and USB/serial bridge
#   jq        — JSON option parsing
#   python3   — KNX/IP UDP responder (DESCRIPTION_REQUEST handler)
#   curl      — HA Supervisor API notifications (optional)
# ---------------------------------------------------------------------------
RUN apk add --no-cache \
    haproxy \
    socat \
    jq \
    python3 \
    curl \
    ca-certificates

# ---------------------------------------------------------------------------
# Copy rootfs (s6-overlay service structure)
# ---------------------------------------------------------------------------
COPY rootfs /

# ---------------------------------------------------------------------------
# Copy main scripts
# ---------------------------------------------------------------------------
COPY run.sh                  /run.sh
COPY healthcheck.sh          /healthcheck.sh
COPY knx_udp_responder.py    /knx_udp_responder.py

RUN chmod 0755 \
        /run.sh \
        /healthcheck.sh \
        /knx_udp_responder.py \
        /etc/cont-init.d/knx-haproxy.sh \
        /etc/services.d/knx-haproxy/run \
        /etc/services.d/knx-haproxy/finish \
        /etc/services.d/knx-udp-responder/run \
        /etc/services.d/knx-udp-responder/finish

# ---------------------------------------------------------------------------
# Docker health check
# ---------------------------------------------------------------------------
HEALTHCHECK \
    --interval=30s \
    --timeout=10s \
    --start-period=20s \
    --retries=3 \
    CMD /healthcheck.sh