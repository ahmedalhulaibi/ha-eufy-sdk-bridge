# Stable upstream runtime and SDK, pinned to an immutable multi-platform digest.
# Only the reviewed bridge/storage patch is overlaid; no beta dependencies.
FROM ghcr.io/mega-yfue/ha-eufy-sdk-bridge:0.7.2@sha256:b9bb59b2040960998873926a90763921167b13538eaa015b8ce2fb4fc226f29c
USER root
COPY server.mjs streams.mjs go2rtc-config.mjs package.json /app/
COPY src /app/src
COPY bin /app/bin
RUN chmod 0755 /app/bin/start.sh \
 && mkdir -p /data /run \
 && chown 10001:10001 /data \
 && chmod 0700 /data
ENV HOME=/tmp GO2RTC_CONFIG=/data/state/go2rtc.yaml EUFY_SESSION=/data/state/eufy-session.json
LABEL org.opencontainers.image.source="https://github.com/ahmedalhulaibi/ha-eufy-sdk-bridge"
USER 10001:10001
ENTRYPOINT []
CMD ["/app/bin/start.sh"]
