# valvur scanner image.
# Scanners are pinned to exact versions (F2.2). Non-root, read-only root filesystem,
# no capabilities (F10.2). The image never needs network for the quick profile.

FROM zricethezav/gitleaks:v8.30.1 AS gitleaks
FROM aquasec/trivy:0.74.0 AS trivy

FROM alpine:3.22
LABEL org.opencontainers.image.source="https://github.com/MaverickHQ/valvur"
LABEL org.opencontainers.image.description="Fully offline security scanner for AI-generated code"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# Trivy needs a writable cache and DB location; both live outside the read-only
# root filesystem so the container can still run --read-only.
# The vulnerability DB is NOT baked into the image. It is 1.2GB, and baking it would
# tie advisory freshness to image release cadence - a six-month-old image would imply
# six-month-old vulnerability data. The DB lives in a host cache mounted at scan time
# (ADR-0012), so the image stays lean and the data stays current independently.
ENV TRIVY_CACHE_DIR=/cache/trivy

RUN adduser -D -u 10001 valvur
USER 10001:10001

WORKDIR /workspace
# No ENTRYPOINT: the shim invokes a specific scanner binary per adapter.
