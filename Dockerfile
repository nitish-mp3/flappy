ARG BUILD_FROM
FROM $BUILD_FROM

# ---------------------------------------------------------------------------
# Runtime dependencies
#   haproxy   — TCP proxy and health-checking layer
#   socat     — TCP↔UDP bridge and USB/serial bridge
#   jq        — JSON option parsing
#   curl      — HA Supervisor API notifications
#   iproute2  — optional: ss/ip for diagnostics
# ---------------------------------------------------------------------------
RUN apk add --no-cache \
    haproxy \
    socat \
    jq \
    curl \
    ca-certificates \
    iproute2

# ---------------------------------------------------------------------------
# Copy rootfs (s6-overlay service structure)
# ---------------------------------------------------------------------------
COPY rootfs /

# ---------------------------------------------------------------------------
# Copy main scripts and set permissions
# ---------------------------------------------------------------------------
COPY run.sh         /run.sh
COPY healthcheck.sh /healthcheck.sh

RUN chmod 0755 \
        /run.sh \
        /healthcheck.sh \
        /etc/cont-init.d/knx-haproxy.sh \
        /etc/services.d/knx-haproxy/run \
        /etc/services.d/knx-haproxy/finish

# ---------------------------------------------------------------------------
# Docker health check (used by HA to report addon status)
# ---------------------------------------------------------------------------
HEALTHCHECK \
    --interval=30s \
    --timeout=10s \
    --start-period=20s \
    --retries=3 \
    CMD /healthcheck.sh