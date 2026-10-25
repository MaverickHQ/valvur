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

# Opengrep publishes signed static musllinux binaries but no image. LGPL-2.1, and the
# consortium fork of Semgrep — see ADR-0004 for why not Semgrep itself.
#
# Fetched per architecture (task 15.4). Both binaries used to be ADDed and the unused
# one deleted, but layers are additive so `rm` reclaims nothing: measured at ~98MB of
# binaries plus a 50MB copy, carried by every image, for a 50MB tool. The stage below
# downloads the one the platform being built needs, and nothing else.
#
# One stage, not one per architecture selected by `FROM opengrep-${TARGETARCH}` (R27.3,
# D63b): Scorecard reads a FROM that names a variable as an image not pinned by hash,
# and `COPY --from` cannot take the variable instead (BuildKit refuses the expansion,
# measured). So no FROM here names a variable.
#
# The digests are verified (task 15.2). These were previously fetched over HTTPS and
# trusted — in the build that signs our releases, where a compromised binary would
# not merely run but be signed with our identity and logged as authentic. Opengrep
# signs each release keylessly with sigstore, from its own workflow, on a branch named
# for the release since 1.30.2 (on `main` before):
#   identity  https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.31.0
#   issuer    https://token.actions.githubusercontent.com
# Both signatures checked against their Fulcio certificates 2026-10-25, and these are the
# digests of those artifacts. `scripts/verify-opengrep.sh` re-checks the signatures in CI;
# the check below is the deterministic half — no network, and it fails the build
# rather than baking in whatever was served.
ARG OPENGREP_SHA256_AMD64=02c9fba481611aa0664bc79ccf7ce59e9e334b76af8921c80b2f738d17fabf9b
ARG OPENGREP_SHA256_ARM64=b7cbedab0b6c9953ea27ce3baa006ad8b6fa1c50ee7433638b63f7fc731519d9
ARG OPENGREP_URL=https://github.com/opengrep/opengrep/releases/download/v1.31.0

FROM python:3.12-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d AS opengrep
ARG TARGETARCH
ARG OPENGREP_SHA256_AMD64
ARG OPENGREP_SHA256_ARM64
ARG OPENGREP_URL
# Python's urllib, not BusyBox's wget: it reads SSL_CERT_FILE, which a build behind a
# re-terminating proxy names (scripts/cloud_image.py). An unknown platform, or no
# TARGETARCH at all (a builder without BuildKit), fails here, by name.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) asset=opengrep_musllinux_x86; sha="$OPENGREP_SHA256_AMD64" ;; \
      arm64) asset=opengrep_musllinux_aarch64; sha="$OPENGREP_SHA256_ARM64" ;; \
      *) echo "no Opengrep binary for platform '${TARGETARCH}'" >&2; exit 1 ;; \
    esac; \
    python3 -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], "/opengrep")' \
      "$OPENGREP_URL/$asset"; \
    echo "$sha  /opengrep" | sha256sum -c -; \
    chmod 755 /opengrep

# Gitleaks, built from its source with a current Go (the owner, 2026-10-25). Its last
# release, 8.30.1 (2026-03-12), ships a binary built with go1.24.13, which Go stopped
# supporting when go1.26 was released: R43.4's image gate counted 69 findings in it. This
# builds the same release from its Go module, v8.30.1, as Go's checksum database records
# it (`GITLEAKS_SUM`); its dependencies are held by the module's own go.sum. The module is
# commit 8d1f98c. The tag has since moved to 83d9cd6, the commit the published binary's
# build information names, which changes `.goreleaser.yml` alone, so the Go source is the
# same. Static, path-free, with the version set as upstream sets it, so two builds of one
# tree are one binary. MIT. Dependabot's docker ecosystem moves the Go base; a Gitleaks
# release moves the two pins below together.
FROM golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS gitleaks
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SUM=h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w=
RUN set -eu; \
    module="github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION}"; \
    go mod download -json "$module" > /module.json; \
    grep -qF "\"Sum\": \"${GITLEAKS_SUM}\"" /module.json; \
    cd "$(go env GOMODCACHE)/${module}"; \
    CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go build -trimpath -buildvcs=false \
      -ldflags="-X=github.com/zricethezav/gitleaks/v8/version.Version=v${GITLEAKS_VERSION}" \
      -o /gitleaks .; \
    /gitleaks version
FROM aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222 AS trivy
FROM ghcr.io/google/osv-scanner:v2.7.0@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0 AS osv
FROM anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa AS syft

FROM python:3.12-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d
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
LABEL org.valvur.protocol="2"

COPY --from=gitleaks /gitleaks               /usr/local/bin/gitleaks
COPY --from=trivy    /usr/local/bin/trivy     /usr/local/bin/trivy
COPY --from=osv      /osv-scanner             /usr/local/bin/osv-scanner
COPY --from=syft     /syft                    /usr/local/bin/syft
COPY --from=opengrep /opengrep                /usr/local/bin/opengrep
# Opengrep is one file that unpacks its core under XDG_CACHE_HOME and runs it from
# there: 239 MB, on every scan, which needed an executable /tmp for every tool in
# the Scan Container. Unpacked once here instead, read-only at run time, and the
# adapter points XDG_CACHE_HOME at it, so /tmp is noexec for all (D54a).
RUN XDG_CACHE_HOME=/opt/opengrep /usr/local/bin/opengrep --version \
 && chmod -R a+rX /opt/opengrep

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
# `--no-logfile`: Alpine 3.24's apk-tools 3 appends each call, with the time it ran, to
# the base's `/var/log/apk.log`, the one file two builds of one tree then differed in.
COPY requirements-checkov.txt /opt/checkov-requirements.txt
RUN apk add --no-logfile --no-cache --virtual .build gcc musl-dev libffi-dev \
 && python3 -m venv --without-pip /opt/checkov \
 && pip --python /opt/checkov/bin/python install --no-cache-dir --no-deps --no-compile \
        --require-hashes -r /opt/checkov-requirements.txt \
 && test -x /opt/checkov/bin/checkov \
 && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
 && apk del --no-logfile .build \
 && PYTHONHASHSEED=0 /opt/checkov/bin/python -m compileall -q -f --invalidation-mode unchecked-hash /opt/checkov/lib

# zizmor (R4.2, ADR-0023) audits GitHub Actions workflows. One package, a static
# binary in a musl wheel per architecture, pinned by hash in `requirements-zizmor.txt`
# and installed into its own environment with `--require-hashes`, the Checkov way.
COPY requirements-zizmor.txt /opt/zizmor-requirements.txt
RUN python3 -m venv --without-pip /opt/zizmor \
 && pip --python /opt/zizmor/bin/python install --no-cache-dir --no-deps --no-compile \
        --only-binary=:all: --require-hashes -r /opt/zizmor-requirements.txt \
 && test -x /opt/zizmor/bin/zizmor \
 && ln -s /opt/zizmor/bin/zizmor /usr/local/bin/zizmor

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

# The image as a pipeline step (R8.1, D15): `valvur scan` run here has no runtime
# to start a Scan Container from, so it runs the same engine as a process in this
# container. `VALVUR_IN_IMAGE` tells it so; `valvur` is the CLI, as the wheel names it.
RUN printf '#!/bin/sh\nexec python3 -m valvur.cli "$@"\n' > /usr/local/bin/valvur \
 && chmod 0755 /usr/local/bin/valvur
ENV VALVUR_IN_IMAGE=1

# The Snapshot's landing (ADR-0022): a tmpfs made 1777 up to the shim's TMPFS_LIMIT,
# and past it a per-scan volume, which Docker's classic store initialises from this
# directory's owner and mode. The scan runs as the invoking user with every
# capability dropped, so it must be writable by anyone, sticky as /tmp is. Under
# WORKDIR alone it was 10001's and 755, and a large Snapshot could not be unpacked.
RUN mkdir -p /workspace && chmod 1777 /workspace
RUN adduser -D -u 10001 valvur
USER 10001:10001
WORKDIR /workspace
# No ENTRYPOINT: the shim names a specific scanner binary per adapter, and a
# pipeline step names `valvur scan`.
