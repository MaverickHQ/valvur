"""Machine settings: what this machine decides (D11, R6.7).

Two files. Project policy is `.security-scan.toml`, committed with the project:
suppressions and `[scan] exclude`. Machine settings are
`$XDG_CONFIG_HOME/valvur/config.toml`, by default `~/.config/valvur/config.toml`:
the image, the cache, the runtime, fetching, the mirrors, how many Scanners at
once. Environment variables remain as overrides for the image, the cache, the
runtime, debugging, fetching and the mirrors, where a CI job or a one-off command
needs them; the others are retired to the file, still work through 1.x, and
say so once.

`fetch` is ADR-0025's (R6.6): `never` turns every fetch a scan would make off, for
air-gapped use; anything else lets a scan fetch what is absent and refresh what is
stale, announced and recorded.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

NEVER = "never"

#: Each setting, and the variable that overrides it.
ENVIRONMENT: dict[str, str] = {
    "image": "VALVUR_IMAGE",
    "cache": "VALVUR_CACHE",
    "runtime": "VALVUR_RUNTIME",
    "debug": "VALVUR_DEBUG",
    "fetch": "VALVUR_FETCH",
    # The mirrors (F10.5): where the database, the index, KEV and OSV come from.
    "db_repository": "VALVUR_DB_REPOSITORY",
    "db_insecure": "VALVUR_DB_INSECURE",
    "index_repository": "VALVUR_INDEX_REPOSITORY",
    "index_insecure": "VALVUR_INDEX_INSECURE",
    "name_index_url": "VALVUR_NAME_INDEX_URL",
    "kev_url": "VALVUR_KEV_URL",
    "osv_url": "VALVUR_OSV_URL",
    # Retired to the file by D11: they still work in this release, and say so.
    "jobs": "VALVUR_JOBS",
    "container_network": "VALVUR_CONTAINER_NETWORK",
    "selinux_relabel": "VALVUR_SELINUX_RELABEL",
}
RETIRED = frozenset({"jobs", "container_network", "selinux_relabel"})
FETCH_ENV = ENVIRONMENT["fetch"]

_read: tuple[Path, float, dict, str] | None = None
_warned: set[str] = set()


def path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "valvur" / "config.toml"


def _file() -> tuple[dict, str]:
    """The file's settings, and a sentence when it could not be read; read again
    only when it changes."""
    import tomllib

    global _read
    where = path()
    try:
        mtime = where.stat().st_mtime
    except OSError:
        return {}, ""
    if _read is not None and _read[0] == where and _read[1] == mtime:
        return _read[2], _read[3]
    try:
        values, problem = tomllib.loads(where.read_text(encoding="utf-8")), ""
    except (OSError, tomllib.TOMLDecodeError) as exc:
        values, problem = {}, f"{where} cannot be read ({exc}); its settings are not applied"
    _read = (where, mtime, values, problem)
    return values, problem


def get(key: str) -> str | None:
    """The setting's value: the variable if set, else the file, else None."""
    name = ENVIRONMENT[key]
    value = os.environ.get(name, "").strip()
    if value:
        if key in RETIRED and name not in _warned:
            _warned.add(name)
            print(f"valvur: {name} is retired; set `{key} = ...` in {path()} instead. "
                  "It still works in this release.", file=sys.stderr)
        return value
    found = _file()[0].get(key)
    return None if found is None or found == "" else str(found).strip()


def source(key: str) -> str:
    """Where `get(key)` came from: the variable's name, the file's path, or default."""
    if os.environ.get(ENVIRONMENT[key], "").strip():
        return ENVIRONMENT[key]
    return str(path()) if _file()[0].get(key) not in (None, "") else "default"


def effective() -> list[tuple[str, str, str]]:
    """Every setting that is set: key, value, and where it came from."""
    return [(key, value, source(key)) for key in ENVIRONMENT
            if (value := _quiet(key)) is not None]


def _quiet(key: str) -> str | None:
    """`get`, without the retirement notice: for reporting, not for use."""
    value = os.environ.get(ENVIRONMENT[key], "").strip()
    if value:
        return value
    found = _file()[0].get(key)
    return None if found in (None, "") else str(found).strip()


def problem() -> str:
    """Why the file's settings are not applied, or empty."""
    return _file()[1]


def fetch() -> str:
    """`never`, or `auto`."""
    return NEVER if (get("fetch") or "").lower() == NEVER else "auto"


def reset() -> None:
    """Test seam: forget the file read and the notices given."""
    global _read
    _read = None
    _warned.clear()
