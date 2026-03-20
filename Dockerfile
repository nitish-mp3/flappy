ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache \
    haproxy \
    socat \
    jq \
    python3 \
    curl \
    ca-certificates

# rootfs contains only knx-haproxy service (run + finish)
# knx-udp-responder is launched from run.sh directly — no separate s6 service
COPY rootfs /

COPY run.sh               /run.sh
COPY healthcheck.sh       /healthcheck.sh
COPY knx_udp_responder.py /knx_udp_responder.py

RUN chmod 0755 \
        /run.sh \
        /healthcheck.sh \
        /knx_udp_responder.py \
        /etc/cont-init.d/knx-haproxy.sh \
        /etc/services.d/knx-haproxy/run \
        /etc/services.d/knx-haproxy/finish

HEALTHCHECK \
    --interval=30s \
    --timeout=10s \
    --start-period=20s \
    --retries=3 \
    CMD /healthcheck.sh