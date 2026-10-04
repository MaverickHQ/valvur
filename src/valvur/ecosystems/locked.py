"""Locked versions, read from each ecosystem's lockfiles (D26, R11.5).

The malicious list names, for a quarter of its npm entries and most of its PyPI ones,
the versions that were malicious rather than every version: `@hyperion-util/cookies`
at 77.77.79 only. A declared name says nothing about which version will install, so
those entries are matched against what a lockfile pins, and a requirements line or a
`package.json` range that is one exact version. Every locked package is read, direct
or not: a malicious package three levels down still runs at install.

One walk of the File Set for every lockfile kind, never one walk each (29.0.1). A
lockfile that does not parse yields nothing: this reader adds findings, and the
Scanners that read the same files report what they could not.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable, Iterator
from fnmatch import fnmatch
from pathlib import Path

from .. import exclusions

Pins = Iterator[tuple[str, str]]

_EXACT = re.compile(r"=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)")
_REQUIREMENT = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)")
_GEM_SPEC = re.compile(r" {4}(\S+) \(([^)\s]+)\)$")


def _json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _table(value: object) -> dict:
    """`value` when it is a JSON object or TOML table, else empty: a lockfile is the
    project's text, and one of the wrong shape holds no pins (R27.4, found by fuzzing)."""
    return value if isinstance(value, dict) else {}


def _array(value: object) -> list:
    return value if isinstance(value, list) else []


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def package_lock(path: Path) -> Pins:
    """`packages` (lockfile v2 and v3) and `dependencies` (v1), nested."""
    data = _json(path)
    for key, entry in _table(data.get("packages")).items():
        if key and isinstance(entry, dict) and not entry.get("link") and entry.get("version"):
            yield entry.get("name") or key.rpartition("node_modules/")[2], str(entry["version"])

    def nested(dependencies: object) -> Pins:
        for name, entry in _table(dependencies).items():
            if isinstance(entry, dict):
                if entry.get("version"):
                    yield name, str(entry["version"])
                yield from nested(entry.get("dependencies"))

    yield from nested(data.get("dependencies"))


def package_json(path: Path) -> Pins:
    """A range that is one exact version pins it as a lockfile would."""
    data = _json(path)
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in _table(data.get(section)).items():
            exact = _EXACT.fullmatch(str(spec).strip())
            if exact:
                yield name, exact.group(1)


def _npm_name(spec: str) -> str:
    """`@scope/name@^1` and `name@npm:^1` to their name: the last `@` after the first
    character, since a scope begins with one."""
    spec = spec.strip().strip('"').strip("'").lstrip("/")
    at = spec.find("@", 1)
    return spec[:at] if at > 0 else spec


def yarn_lock(path: Path) -> Pins:
    """Yarn 1 (`version "1.2.3"`) and Berry (`version: 1.2.3`): a block's header
    names the package, its `version` line the version."""
    name = ""
    for line in _lines(path):
        if line and not line[0].isspace() and line.endswith(":"):
            name = _npm_name(line[:-1].split(",")[0])
        elif name and line.strip().startswith("version"):
            version = line.strip()[len("version"):].lstrip(":").strip().strip('"')
            if version:
                yield name, version
            name = ""


def pnpm_lock(path: Path) -> Pins:
    """The keys of `packages:` and `snapshots:`: `/name@1.2.3` (v6), `name@1.2.3`
    (v9), or `/name/1.2.3` (v5), a peer suffix in parentheses dropped."""
    section = ""
    for line in _lines(path):
        if line and not line[0].isspace():
            section = line.rstrip(":")
            continue
        if section not in ("packages", "snapshots") or not line.startswith("  ") \
                or line.startswith("   ") or not line.rstrip().endswith(":"):
            continue
        key = line.strip()[:-1].strip("'\"").lstrip("/").split("(")[0]
        at = key.find("@", 1)
        name, version = (key[:at], key[at + 1:]) if at > 0 else key.rpartition("/")[::2]
        if name and version:
            yield name, version


def requirements(path: Path) -> Pins:
    for line in _lines(path):
        pinned = _REQUIREMENT.match(line)
        if pinned:
            yield pinned.group(1), pinned.group(2)


def toml_packages(path: Path) -> Pins:
    """`[[package]]` tables: poetry.lock, uv.lock and Cargo.lock."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
        return
    for package in _array(data.get("package")):
        if isinstance(package, dict) and package.get("name") and package.get("version"):
            yield str(package["name"]), str(package["version"])


def pipfile_lock(path: Path) -> Pins:
    data = _json(path)
    for section in ("default", "develop"):
        for name, entry in _table(data.get(section)).items():
            version = str(entry.get("version", "")) if isinstance(entry, dict) else ""
            if version.startswith("=="):
                yield name, version[2:]


def composer_lock(path: Path) -> Pins:
    data = _json(path)
    for section in ("packages", "packages-dev"):
        for package in _array(data.get(section)):
            if isinstance(package, dict) and package.get("name") and package.get("version"):
                yield str(package["name"]), str(package["version"]).removeprefix("v")


def gemfile_lock(path: Path) -> Pins:
    for line in _lines(path):
        spec = _GEM_SPEC.match(line)
        if spec:
            yield spec.group(1), spec.group(2)


#: Each lockfile kind, by file name, and the ecosystem its packages belong to.
READERS: tuple[tuple[str, str, Callable[[Path], Pins]], ...] = (
    ("package-lock.json", "npm", package_lock),
    ("npm-shrinkwrap.json", "npm", package_lock),
    ("package.json", "npm", package_json),
    ("yarn.lock", "npm", yarn_lock),
    ("pnpm-lock.yaml", "npm", pnpm_lock),
    ("requirements*.txt", "pip", requirements),
    ("poetry.lock", "pip", toml_packages),
    ("uv.lock", "pip", toml_packages),
    ("Pipfile.lock", "pip", pipfile_lock),
    ("Cargo.lock", "cargo", toml_packages),
    ("composer.lock", "composer", composer_lock),
    ("Gemfile.lock", "gem", gemfile_lock),
)


def locked(workspace: Path, exclude: tuple[str, ...] = ()) -> set[tuple[str, str, str, str]]:
    """Every pinned package, as (ecosystem, name, version, lockfile path)."""
    found: set[tuple[str, str, str, str]] = set()
    for path in exclusions.walk_files(workspace, exclude):
        for pattern, ecosystem, read in READERS:
            if fnmatch(path.name, pattern):
                rel = path.relative_to(workspace).as_posix()
                try:
                    found |= {(ecosystem, name, version, rel) for name, version in read(path)}
                except (OSError, UnicodeError):
                    continue
    return found
