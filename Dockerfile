# valvur scanner image.
#
# Scanners are pinned to exact versions (F2.2). Non-root, read-only root filesystem,
# no capabilities (F10.2). No GPL/AGPL components added by us (ADR-0005).
#
# The vulnerability DB is deliberately NOT baked in — 1.2GB unpacked, and baking it
# would tie advisory freshness to image release cadence (ADR-0012).
#
# Every base is pinned by DIGEST with its tag in the comment above, so Dependabot can
# still see what it tracks (task 15.1). We pin GitHub Actions to commit SHAs because
# a tag is a mutable pointer; every FROM here was pinned by tag, which is the same
# defect in the build that signs our releases. These are INDEX digests — pinning a
# child manifest would silently break the multi-arch build from Phase 13 by resolving
# to one architecture whatever --platform asked for.

# Declared before the first FROM so it can select the Opengrep stage below.
ARG TARGETARCH

# Opengrep publishes signed static musllinux binaries but no image. LGPL-2.1, and the
# consortium fork of Semgrep — see ADR-0004 for why not Semgrep itself.
#
# Fetched per architecture (task 15.4). Both binaries used to be ADDed and the unused
# one deleted, but layers are additive so `rm` reclaims nothing: measured at ~98MB of
# binaries plus a 50MB copy, carried by every image, for a 50MB tool. Selecting the
# stage by TARGETARCH means only the one needed is ever fetched.
#
# The digests are verified (task 15.2). These were previously fetched over HTTPS and
# trusted — in the build that signs our releases, where a compromised binary would
# not merely run but be signed with our identity and logged as authentic. Opengrep
# signs each release keylessly with sigstore, from its own workflow:
#   identity  https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/main
#   issuer    https://token.actions.githubusercontent.com
# Both signatures verified out of band 2026-09-05, and these are the digests of those
# verified artifacts. `scripts/verify-opengrep.sh` re-checks the signatures in CI;
# the check below is the deterministic half — no network, and it fails the build
# rather than baking in whatever was served.
ARG OPENGREP_SHA256_AMD64=1b474bf207905a3cffe4e915fe36895835bc89de2620cb2ffd88ca512d9ea31b
ARG OPENGREP_SHA256_ARM64=6cccb7466a98608e308204e17b259f4ca3a9028c6eb71e6b07ea21b89026c484
ARG OPENGREP_URL=https://github.com/opengrep/opengrep/releases/download/v1.29.0

# 3.12-alpine3.22
FROM python@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322 AS opengrep-amd64
ARG OPENGREP_SHA256_AMD64
ARG OPENGREP_URL
ADD --chmod=755 ${OPENGREP_URL}/opengrep_musllinux_x86 /opengrep
RUN echo "${OPENGREP_SHA256_AMD64}  /opengrep" | sha256sum -c -

# 3.12-alpine3.22
FROM python@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322 AS opengrep-arm64
ARG OPENGREP_SHA256_ARM64
ARG OPENGREP_URL
ADD --chmod=755 ${OPENGREP_URL}/opengrep_musllinux_aarch64 /opengrep
RUN echo "${OPENGREP_SHA256_ARM64}  /opengrep" | sha256sum -c -

# Resolved by the platform being built; only this stage's download ever runs.
FROM opengrep-${TARGETARCH} AS opengrep

# v8.30.1
FROM zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks
# 0.74.0
FROM aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 AS trivy
# v2.2.4
FROM ghcr.io/google/osv-scanner@sha256:f7ba4be68bac8086b1f88fd598fdca1ca67239c79ad2c2b5c78e03a82e5187c4 AS osv
# v1.51.1
FROM anchore/syft@sha256:95fe0835e5bebc6f8b1f8acef68d47d63d594ef4c0f25c097ff853b23cbac74c AS syft

# 3.12-alpine3.22
FROM python@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322
ARG VALVUR_VERSION=0.0.0-dev
LABEL org.opencontainers.image.source="https://github.com/MaverickHQ/valvur"
LABEL org.opencontainers.image.description="Fully offline security scanner for AI-generated code"
LABEL org.opencontainers.image.licenses="Apache-2.0"
# Read by the shim to refuse an incompatible pair (F1.9). ADR-0001 accepted two
# artifacts on condition this check existed.
LABEL org.opencontainers.image.version="${VALVUR_VERSION}"

COPY --from=gitleaks /usr/bin/gitleaks        /usr/local/bin/gitleaks
COPY --from=trivy    /usr/local/bin/trivy     /usr/local/bin/trivy
COPY --from=osv      /osv-scanner             /usr/local/bin/osv-scanner
COPY --from=syft     /syft                    /usr/local/bin/syft
COPY --from=opengrep /opengrep                /usr/local/bin/opengrep

# Our own rules, licensed with the project. Bundling the community registry would
# reintroduce exactly the licensing problem ADR-0004 exists to avoid.
COPY rules /opt/valvur-rules

# valvur's own Checks run in the container, like Scanners (ADR-0013), so the package
# ships in the image. Last layer: check code changes rebuild only this.
COPY src/valvur /usr/local/lib/python3.12/site-packages/valvur

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
