#!/usr/bin/env sh
# Regenerate requirements-checkov.txt — Checkov and every transitive package,
# pinned by version and sha256 for every published distribution, resolved for any
# platform (task 23.4.1). The image installs from it with --require-hashes.
#
#   scripts/lock-checkov.sh          # after editing requirements-checkov.in
set -eu
cd "$(dirname "$0")/.."
uv pip compile --universal --generate-hashes --python-version 3.12 --no-header \
    -o requirements-checkov.txt requirements-checkov.in
printf '%s packages, %s hashes\n' \
    "$(grep -c '^[a-zA-Z0-9_.-]*==' requirements-checkov.txt)" \
    "$(grep -c -- '--hash=sha256' requirements-checkov.txt)"
