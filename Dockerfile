ARG BUILD_FROM
FROM $BUILD_FROM

# Install dependencies
RUN apk add --no-cache \
    haproxy \
    curl \
    ca-certificates

# Copy scripts and set permissions
COPY run.sh /
COPY healthcheck.sh /
RUN chmod a+x /run.sh /healthcheck.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD /healthcheck.sh

# Run the startup script
CMD ["/run.sh"]