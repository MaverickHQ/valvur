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
# v2.6.0
FROM ghcr.io/google/osv-scanner@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa AS osv
# v1.51.1
FROM anchore/syft@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02 AS syft

# 3.12-alpine3.22
FROM python@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322
ARG VALVUR_VERSION=0.0.0-dev
LABEL org.opencontainers.image.source="https://github.com/MaverickHQ/valvur"
LABEL org.opencontainers.image.description="Fully offline security scanner for AI-generated code"
LABEL org.opencontainers.image.licenses="Apache-2.0"
# Read by the shim to refuse an incompatible pair (F1.9). ADR-0001 accepted two
# artifacts on condition this check existed.
LABEL org.opencontainers.image.version="${VALVUR_VERSION}"
# The shim/image protocol this image speaks (26.3.1): docs/PROTOCOL.md is the
# contract, `compat.PROTOCOL` the shim's side, and a test holds all three to the
# same number. A change that breaks anything on that page bumps it here and there.
LABEL org.valvur.protocol="1"

COPY --from=gitleaks /usr/bin/gitleaks        /usr/local/bin/gitleaks
COPY --from=trivy    /usr/local/bin/trivy     /usr/local/bin/trivy
COPY --from=osv      /osv-scanner             /usr/local/bin/osv-scanner
COPY --from=syft     /syft                    /usr/local/bin/syft
COPY --from=opengrep /opengrep                /usr/local/bin/opengrep

# Checkov is Python, and the only Scanner that is. It goes into its own virtual
# environment, hash-locked (task 23.4.1): `requirements-checkov.txt` pins every one
# of its ~96 transitive packages by version and sha256, generated from
# `requirements-checkov.in` by `scripts/lock-checkov.sh`, and `--require-hashes`
# refuses anything else. Until this, `pip install checkov==<version>` resolved those
# 96 packages afresh on every build — the one input of the image we sign with our
# identity that was not pinned by hash — and they shared valvur's interpreter.
# Dependabot watches the lock. `--no-deps` because the lock is complete — every
# package, every hash — and because it carries one deliberate override
# (`requirements-checkov.overrides`): Checkov pins an asteval with two sandbox-escape
# advisories, and the lock ships the fixed release instead; pip's resolver would
# refuse the pair, and the lock is the resolution. No compiler is kept. Before our
# own files, so that editing a Check or a rule rebuilds only the layers below and
# never this one.
#
# Bytecode is compiled here and kept (28.2.1). Until then the layer ended by
# deleting every `__pycache__` under `/opt/checkov` and `/usr/local` — and the
# container runs on a read-only root as a non-root user with
# `PYTHONDONTWRITEBYTECODE=1`, so every Checkov start compiled its 3,913 modules
# from source: profiled at 2.6 s of `compile` per run, `checkov --version` 5.9 s
# cold against 1.3 s with bytecode. The stdlib's bytecode, which the base image
# ships, is kept for the same reason (0.35 s against 0.06 s for the imports a Check
# makes). The size the bytecode costs is measured in 28.2.1's STATUS note.
# `--invalidation-mode unchecked-hash` and `PYTHONHASHSEED=0` (28.4.5): a `.pyc`
# otherwise records its source's mtime, which is the build's wall clock, and
# marshals its constants in an order the process's hash seed decides — measured:
# with the mtime fixed and the seed random, all 5,533 `.pyc` files still differed
# between two builds of one tree, and nothing else in the layer did. Serial, not
# `-j 0`: the workers' own seeds are as random as the parent's. `-f`, and pip's
# `--no-compile`: pip writes timestamp-mode `.pyc` as it installs, and compileall
# without `-f` reads their header, finds them "current" and leaves them — which is
# how the first two fixes changed nothing (measured: flags 0, mtime = wall clock).
COPY requirements-checkov.txt /opt/checkov-requirements.txt
RUN apk add --no-cache --virtual .build gcc musl-dev libffi-dev \
 && python3 -m venv --without-pip /opt/checkov \
 && pip --python /opt/checkov/bin/python install --no-cache-dir --no-deps --no-compile \
        --require-hashes -r /opt/checkov-requirements.txt \
 && test -x /opt/checkov/bin/checkov \
 && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
 && apk del .build \
 && PYTHONHASHSEED=0 /opt/checkov/bin/python -m compileall -q -f --invalidation-mode unchecked-hash /opt/checkov/lib

# Checkov ships an update checker that asks PyPI for the latest version at every
# start and caches the answer under `$HOME`. A scanner that phones home would break
# the central claim in ADR-0010, so it is switched off — by the variable this
# Checkov actually reads. From 23.4.1 to 28.2.1 the line here set
# `CHECKOV_DISABLE_UPDATE_CHECK`, which nothing in Checkov reads
# (`env_vars_config.py` reads `CKV_SKIP_PACKAGE_UPDATE_CHECK`), so the check ran
# at every start: under `--network=none` it waited 5.0 s for DNS to fail, profiled
# in 28.2.1, and on `full` it would have reached pypi.org. `HOME=/tmp` keeps its
# cache on the tmpfs, off the read-only root. `tests/test_checkov_startup.py` asks
# the installed Checkov's own configuration whether the skip is read.
ENV TRIVY_CACHE_DIR=/cache/trivy \
    PYTHONDONTWRITEBYTECODE=1 \
    CKV_SKIP_PACKAGE_UPDATE_CHECK=true \
    HOME=/tmp

# Our own rules, licensed with the project. Bundling the community registry would
# reintroduce exactly the licensing problem ADR-0004 exists to avoid.
COPY rules /opt/valvur-rules

# valvur's own Checks run in the container, like Scanners (ADR-0013), so the package
# ships in the image. Last content layer: check code changes rebuild only this.
COPY src/valvur /usr/local/lib/python3.12/site-packages/valvur

# The attribution the redistributed tools' licences ask for (28.3.5): the same
# file the repository carries at its root, at the path a reader of the image would
# look. A test holds it to every `FROM … AS` stage above, so a tool cannot arrive
# unattributed.
COPY NOTICE /usr/share/doc/valvur/NOTICE

# The image records what it was built from (22.C.1): a digest over exactly the
# files copied above and this Dockerfile, computed by the same module the host uses
# to check it. `scripts/check_image.py` and the e2e suite refuse a stale image with
# the rebuild command, instead of running yesterday's Checks against today's tests.
COPY Dockerfile /etc/valvur/Dockerfile
RUN python3 -m valvur.tree_hash --image > /etc/valvur/inputs.sha256 \
 && chmod 0444 /etc/valvur/inputs.sha256 \
 && PYTHONHASHSEED=0 python3 -m compileall -q -f --invalidation-mode unchecked-hash /usr/local/lib/python3.12/site-packages/valvur

RUN adduser -D -u 10001 valvur
USER 10001:10001
WORKDIR /workspace
# No ENTRYPOINT: the shim names a specific scanner binary per adapter.
