ARG BUILD_FROM
FROM $BUILD_FROM

# ── Runtime dependencies ──────────────────────────────────────────────
# socat       – fallback USB serial bridge (if knxd unavailable)
# knxd        – proper KNX USB HID interface daemon
# jq          – JSON option parsing in bash
# python3     – KNX proxy engine
# py3-cryptography – ECDH / AES-128-CCM for KNX IP Secure
# curl        – HA Supervisor API notifications
# udev        – USB device auto-detection and permissions
RUN apk add --no-cache \
    socat \
    jq \
    python3 \
    py3-cryptography \
    curl \
    ca-certificates \
    udev \
    && (apk add --no-cache knxd 2>/dev/null || echo "WARN: knxd not in repo — USB will use socat fallback")

# ── Copy files ────────────────────────────────────────────────────────
COPY rootfs /

COPY run.sh           /run.sh
COPY healthcheck.sh   /healthcheck.sh
COPY knx_proxy.py     /knx_proxy.py
COPY knx_secure.py    /knx_secure.py
COPY knx_transport.py /knx_transport.py
COPY knx_session.py   /knx_session.py
COPY knx_health.py    /knx_health.py
COPY knx_const.py     /knx_const.py

RUN chmod 0755 \
        /run.sh \
        /healthcheck.sh \
        /knx_proxy.py \
        /knx_secure.py \
        /knx_transport.py \
        /knx_session.py \
        /knx_health.py \
        /knx_const.py \
        /etc/cont-init.d/knx-failover.sh \
        /etc/services.d/knx-failover/run \
        /etc/services.d/knx-failover/finish

# ── Health check ──────────────────────────────────────────────────────
HEALTHCHECK \
    --interval=30s \
    --timeout=10s \
    --start-period=20s \
    --retries=3 \
    CMD /healthcheck.sh