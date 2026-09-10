#!/usr/bin/env bash
# One local command that runs what CI runs (task 19.A.3).
#
# CI and release used to carry their own copies of these commands, and they drifted:
# CI linted `src tests` while release linted `src tests scripts`, so four scripts were
# first linted on tag day (task 19.A.2). Both workflows now call this file, which is
# what stops the divergence coming back — aligning two lists only fixes it until the
# next edit.
#
# Everything a container is required for lives in the e2e suite and is NOT run here.
# This is the fast half: the checks worth having before every push.
#
#   scripts/verify.sh              # everything
#   scripts/verify.sh lint types   # just those
#
set -uo pipefail

cd "$(dirname "$0")/.."

# Sandboxes and CI containers often have an unwritable or absent HOME, and every tool
# below defaults its cache there. Redirect them rather than failing, but never
# override a value the caller set deliberately.
if [ ! -w "${HOME:-/nonexistent}" ]; then
  _cache="${VALVUR_CACHE_ROOT:-${TMPDIR:-/tmp}/valvur-verify-cache}"
  mkdir -p "$_cache"
  export UV_CACHE_DIR="${UV_CACHE_DIR:-$_cache/uv}"
  export RUFF_CACHE_DIR="${RUFF_CACHE_DIR:-$_cache/ruff}"
  export MYPY_CACHE_DIR="${MYPY_CACHE_DIR:-$_cache/mypy}"
  export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$_cache/xdg}"
  echo "note: HOME is not writable; caches redirected to $_cache"
fi

# The same set the release workflow lints. `scripts` is here because it was the half
# that went unchecked.
LINT_PATHS=(src tests scripts)

FAILED=()
RAN=0
run() {
  local name="$1"; shift
  printf '\n\033[1m── %s\033[0m\n' "$name"
  RAN=$((RAN + 1))
  if "$@"; then
    printf '\033[32m   ok\033[0m  %s\n' "$name"
  else
    printf '\033[31m   FAILED\033[0m  %s\n' "$name"
    FAILED+=("$name")
  fi
}

# Selection is read from the script's own arguments, held here. The first version of
# this took "$@" as a parameter and then counted it inside the function, where $#
# included the check's own name — so nothing ever matched, every check was skipped,
# and the script printed "all checks passed" having run nothing at all. The guard at
# the bottom exists because of that: a verifier that can pass vacuously is worse than
# no verifier, which is the whole argument of this repository.
SELECTED=" $* "
want() {
  case "$SELECTED" in
    "  ") return 0 ;;
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

# --locked, not --frozen. Both install the lock rather than re-resolving, but only
# --locked FAILS when pyproject.toml has moved past it; --frozen silently ignores the
# drift. Measured: adding a dev dependency without re-locking passed under --frozen.
# The lockfile is only worth committing if something checks it is current.
printf '\033[1m── sync (from uv.lock)\033[0m\n'
if ! uv sync --extra dev --locked; then
  echo "::error::uv sync failed. If pyproject.toml changed, run 'uv lock' and commit uv.lock."
  exit 1
fi

want lint         && run "lint"         uv run ruff check "${LINT_PATHS[@]}"
want types        && run "types"        uv run mypy src
want traceability && run "traceability" uv run python scripts/check_traceability.py
want tests        && run "tests"        uv run pytest -q -m "not e2e"
want build        && run "build"        uv build --out-dir "${TMPDIR:-/tmp}/valvur-verify-dist"

printf '\n'
if [ "$RAN" -eq 0 ]; then
  printf '\033[31mno checks ran\033[0m — %s matched nothing. Known checks: lint types traceability tests build\n' "${*:-(no arguments)}"
  exit 1
fi
if [ "${#FAILED[@]}" -ne 0 ]; then
  printf '\033[31m%s check(s) failed:\033[0m %s\n' "${#FAILED[@]}" "${FAILED[*]}"
  exit 1
fi
printf '\033[32m%s check(s) passed\033[0m — e2e (container) tests were not run; CI runs those.\n' "$RAN"
