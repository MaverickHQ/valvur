#!/usr/bin/env sh
# Regenerate requirements-checkov.txt — Checkov and every transitive package,
# pinned by version and sha256 for every published distribution, resolved for any
# platform (task 23.4.1). The image installs from it with --require-hashes.
#
#   scripts/lock-checkov.sh          # after editing requirements-checkov.in
#   scripts/lock-checkov.sh --upgrade-package aiohttp --constraint pins.txt
#
# It is the lock's one writer (R42.3, R42.4): `lock.yml` runs it again on every pull
# request that changes the lock, and the lock must come back byte for byte. Extra
# arguments reach `uv pip compile` after the recipe's own, so a heal re-locks with
# the recipe itself. `--no-build`: resolving runs no package's code, and a package
# that has no wheel to read its metadata from is refused, by name. The existing lock
# is uv's preference, so only what an argument names, or forces, moves.
#
# uv's version is `pyproject.toml`'s `[tool.uv] required-version`, which uv enforces
# and `astral-sh/setup-uv` installs.
set -eu
cd "$(dirname "$0")/.."
uv --version
uv pip compile --universal --generate-hashes --python-version 3.12 --no-header \
    --no-build \
    --override requirements-checkov.overrides \
    -o requirements-checkov.txt requirements-checkov.in "$@"
printf '%s packages, %s hashes\n' \
    "$(grep -c '^[a-zA-Z0-9_.-]*==' requirements-checkov.txt)" \
    "$(grep -c -- '--hash=sha256' requirements-checkov.txt)"
