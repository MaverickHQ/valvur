# valvur scanner image.
#
# Scanners are pinned to exact versions (F2.2). Non-root, read-only root filesystem,
# no capabilities (F10.2). No GPL/AGPL components (ADR-0005).
#
# The vulnerability DB is deliberately NOT baked in — it is 1.2GB and would tie
# advisory freshness to image release cadence (ADR-0012).

FROM zricethezav/gitleaks:v8.30.1        AS gitleaks
FROM aquasec/trivy:0.74.0                AS trivy
FROM ghcr.io/google/osv-scanner:v2.2.4   AS osv
FROM anchore/syft:v1.51.1                AS syft

FROM python:3.12-alpine3.22
ARG TARGETARCH
LABEL org.opencontainers.image.source="https://github.com/MaverickHQ/valvur"
LABEL org.opencontainers.image.description="Fully offline security scanner for AI-generated code"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=gitleaks /usr/bin/gitleaks        /usr/local/bin/gitleaks
COPY --from=trivy    /usr/local/bin/trivy     /usr/local/bin/trivy
COPY --from=osv      /osv-scanner             /usr/local/bin/osv-scanner
COPY --from=syft     /syft                    /usr/local/bin/syft

# Opengrep publishes signed static musllinux binaries but no image. LGPL-2.1, and
# the consortium fork of Semgrep - see ADR-0004 for why not Semgrep itself.
ADD --chmod=755 https://github.com/opengrep/opengrep/releases/download/v1.29.0/opengrep_musllinux_x86 /tmp/opengrep_amd64
ADD --chmod=755 https://github.com/opengrep/opengrep/releases/download/v1.29.0/opengrep_musllinux_aarch64 /tmp/opengrep_arm64
RUN mv /tmp/opengrep_${TARGETARCH} /usr/local/bin/opengrep && rm -f /tmp/opengrep_*

# Our own rules, licensed with the project. Bundling the community registry would
# reintroduce exactly the licensing problem ADR-0004 exists to avoid.
COPY rules /opt/valvur-rules

# Checkov is Python. Installed into the system environment; no compiler is kept.
RUN apk add --no-cache --virtual .build gcc musl-dev libffi-dev \
 && pip install --no-cache-dir checkov==3.2.517 \
 && apk del .build \
 && find /usr/local -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

# Checkov ships an update checker that calls out at startup and writes a cache.
# Both are disabled explicitly: a scanner that phones home would break the central
# claim in ADR-0010, and our read-only rootfs caught it only by accident.
ENV TRIVY_CACHE_DIR=/cache/trivy \
    PYTHONDONTWRITEBYTECODE=1 \
    CHECKOV_DISABLE_UPDATE_CHECK=true \
    HOME=/tmp

RUN adduser -D -u 10001 valvur
USER 10001:10001
WORKDIR /workspace
# No ENTRYPOINT: the shim names a specific scanner binary per adapter.
