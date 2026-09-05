#!/bin/sh
# Verify the Opengrep binaries the image installs, by signature (task 15.2).
#
# The Dockerfile pins their SHA256, which makes the build deterministic and
# tamper-evident. That is not the same as knowing where they came from: a pinned
# digest is only as trustworthy as the download that produced it. Opengrep signs
# each release binary with sigstore, keylessly, so provenance is checkable — and
# this script is where that check lives, because it needs cosign and the network
# and the build should need neither.
#
#   sh scripts/verify-opengrep.sh
set -eu

VERSION="${OPENGREP_VERSION:-v1.29.0}"
BASE="https://github.com/opengrep/opengrep/releases/download/${VERSION}"
IDENTITY="https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/main"
ISSUER="https://token.actions.githubusercontent.com"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
status=0

for asset in opengrep_musllinux_x86 opengrep_musllinux_aarch64; do
    echo "==> $asset"
    for suffix in "" ".cert" ".sig"; do
        curl -fsSL -o "$work/${asset}${suffix}" "${BASE}/${asset}${suffix}"
    done

    if cosign verify-blob \
        --certificate "$work/${asset}.cert" \
        --signature "$work/${asset}.sig" \
        --certificate-identity "$IDENTITY" \
        --certificate-oidc-issuer "$ISSUER" \
        "$work/$asset" >/dev/null 2>&1; then
        echo "    signature: OK"
    else
        echo "    signature: FAILED — do not ship this binary"
        status=1
    fi

    # And the digest the Dockerfile pins must be the digest of what was just
    # verified. Pinning one artifact while verifying another proves nothing.
    actual="$(sha256sum "$work/$asset" | cut -d' ' -f1)"
    case "$asset" in
        *_x86)     want_arg=OPENGREP_SHA256_AMD64 ;;
        *_aarch64) want_arg=OPENGREP_SHA256_ARM64 ;;
    esac
    pinned="$(grep "^ARG ${want_arg}=" Dockerfile | cut -d= -f2)"
    if [ "$actual" = "$pinned" ]; then
        echo "    digest matches the Dockerfile pin"
    else
        echo "    digest MISMATCH: pinned $pinned, signed artifact is $actual"
        status=1
    fi
done

[ "$status" -eq 0 ] && echo "Opengrep binaries are signed by Opengrep and match the pins."
exit "$status"
