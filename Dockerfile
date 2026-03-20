ARG BUILD_FROM
FROM $BUILD_FROM

# Install dependencies
RUN apk add --no-cache \
    haproxy \
    curl \
    ca-certificates

# Copy rootfs (s6-overlay compatible service structure)
COPY rootfs /

# Copy main scripts and set permissions
COPY run.sh /
COPY healthcheck.sh /
RUN chmod a+x /run.sh /healthcheck.sh \
    && chmod a+x /etc/services.d/knx-haproxy/run

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD /healthcheck.sh