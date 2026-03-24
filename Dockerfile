ARG BUILD_FROM
FROM $BUILD_FROM

# ── Runtime dependencies ──────────────────────────────────────────────
# socat       – fallback USB serial bridge (serial-only, e.g. /dev/ttyUSB*)
# knxd        – proper KNX USB HID interface daemon
# jq          – JSON option parsing in bash
# python3     – KNX proxy engine
# py3-cryptography – ECDH / AES-128-CCM for KNX IP Secure
# py3-pyusb   – native USB HID access for KNX USB interfaces
# libusb      – USB library backend for pyusb
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
    libusb \
    libusb-dev \
    && (apk add --no-cache py3-pyusb 2>/dev/null \
        || (apk add --no-cache py3-pip 2>/dev/null && pip3 install --no-cache-dir --break-system-packages pyusb 2>/dev/null) \
        || (python3 -m ensurepip 2>/dev/null && python3 -m pip install --no-cache-dir --break-system-packages pyusb 2>/dev/null) \
        || echo "WARN: pyusb not available — native USB will be disabled") \
    && (apk add --no-cache knxd 2>/dev/null || echo "WARN: knxd not in repo — USB will use native or socat fallback")

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
COPY knx_usb.py       /knx_usb.py
COPY knx_webui.py     /knx_webui.py
COPY www/             /www/

RUN chmod 0755 \
        /run.sh \
        /healthcheck.sh \
        /knx_proxy.py \
        /knx_secure.py \
        /knx_transport.py \
        /knx_session.py \
        /knx_health.py \
        /knx_const.py \
        /knx_usb.py \
        /knx_webui.py \
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