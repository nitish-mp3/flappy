ARG BUILD_FROM
FROM $BUILD_FROM

# haproxy removed — Python proxy handles the full KNX/IP UDP tunnel protocol
RUN apk add --no-cache \
    socat \
    jq \
    python3 \
    curl \
    ca-certificates

COPY rootfs /

COPY run.sh        /run.sh
COPY healthcheck.sh /healthcheck.sh
COPY knx_proxy.py  /knx_proxy.py

RUN chmod 0755 \
        /run.sh \
        /healthcheck.sh \
        /knx_proxy.py \
        /etc/cont-init.d/knx-haproxy.sh \
        /etc/services.d/knx-haproxy/run \
        /etc/services.d/knx-haproxy/finish

HEALTHCHECK \
    --interval=30s \
    --timeout=10s \
    --start-period=20s \
    --retries=3 \
    CMD /healthcheck.sh