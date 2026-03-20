ARG BUILD_FROM
FROM $BUILD_FROM

# Install dependencies
RUN apk add --no-cache \
    haproxy \
    curl \
    ca-certificates \
    tini

# Copy scripts and set permissions
COPY run.sh /
COPY healthcheck.sh /
RUN chmod a+x /run.sh /healthcheck.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD /healthcheck.sh

# Use tini for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/run.sh"]