# valvur scanner image.
# Scanners are pinned to exact versions (F2.2). Non-root, read-only root filesystem,
# no capabilities (F10.2). The image never needs network for the quick profile.

FROM zricethezav/gitleaks:v8.30.1 AS gitleaks

FROM alpine:3.22
LABEL org.opencontainers.image.source="https://github.com/MaverickHQ/valvur"
LABEL org.opencontainers.image.description="Fully offline security scanner for AI-generated code"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks

RUN adduser -D -u 10001 valvur
USER 10001:10001

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/gitleaks"]
