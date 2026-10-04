"""Reuse what cannot have changed (N1.5, D32, ADR-0030).

Trivy (`fs --scanners vuln`) and OSV-Scanner read a project's dependency files and
their own database, and nothing else of it: their answer cannot change while those do
not. So their raw output is kept in the host cache under a key of everything it
depends on, and a scan with the same key reuses it rather than starting them. A
Scanner that reads source is never reused: a source file's change is exactly what a
rescan is for, and it is not in the key.

The key: the Scanner, its version, its arguments, the Profile, the path and sha256
of every dependency file in the File Set, and the data it answered from (the
database's build time, or each OSV export's date). The arguments since R38: a result
made with the project's own ignores honoured was reused after they were turned off.
OSV-Scanner on `full` answers from api.osv.dev, which has no stamp to key on, so it is
reused on `offline` only.
"""

from __future__ import annotations

import hashlib
import json
import re
from fnmatch import translate
from pathlib import Path

from . import cache, locking, osv_offline
from .adapters.osv import VERSION as OSV
from .adapters.trivy import VERSION as TRIVY

#: The Scanners whose answer depends on dependency files and data alone.
TOOLS = frozenset({"trivy", "osv-scanner"})

#: Every file either tool reads for dependencies, by name: the lockfiles and manifests
#: of each ecosystem Trivy's and OSV-Scanner's documentation lists, the Java archives
#: Trivy opens, SBOMs they both read, and their own configuration. A name missing
#: here would let a change to it be reused past, so the list errs wide.
KEY_FILES = (
    # Python
    "requirements*.txt", "*requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock",
    "uv.lock", "pdm.lock", "pylock.toml", "pylock.*.toml", "pyproject.toml", "setup.py",
    "setup.cfg", "environment.yml", "environment.yaml",
    # JavaScript
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "bun.lock", "bun.lockb", "deno.lock",
    # Ruby, PHP, Rust, Go
    "Gemfile", "Gemfile.lock", "gems.rb", "gems.locked", "*.gemspec", "composer.json",
    "composer.lock", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "go.work",
    # JVM
    "pom.xml", "*.gradle", "*.gradle.kts", "gradle.lockfile", "*.lockfile",
    "verification-metadata.xml", "libs.versions.toml", "*.sbt.lock", "*.jar", "*.war",
    "*.ear", "*.par",
    # .NET, Dart, Elixir, Swift, C and C++, R, Julia, Haskell, Erlang
    "packages.lock.json", "packages.config", "*.deps.json", "*.csproj", "*.vbproj",
    "*.fsproj", "Packages.props", "Directory.Packages.props", "pubspec.lock",
    "mix.lock", "Podfile.lock", "Package.resolved", "conan.lock", "renv.lock",
    "Manifest.toml", "cabal.project.freeze", "stack.yaml.lock", "rebar.lock",
    # SBOMs, and the tools' own configuration
    "*.cdx.json", "*.spdx.json", "*.spdx", "bom.json", "sbom.json", ".trivyignore",
    ".trivyignore.yaml", "trivy.yaml", "osv-scanner.toml",
)


#: The list as one expression: the key reads every name in the File Set, 103,251 in
#: acceptance repository 1, and ninety patterns tried in turn cost seconds there.
_KEY_FILE = re.compile("|".join(f"(?:{translate(pattern)})" for pattern in KEY_FILES))


def reads(path: str) -> bool:
    """Whether `path` is a file the dependency Scanners read."""
    return _KEY_FILE.match(path.rsplit("/", 1)[-1]) is not None


def reusable(tool: str, profile: str) -> bool:
    return tool in TOOLS and not (tool == "osv-scanner" and profile != "offline")


def inputs(workspace: Path, files: list[str]) -> dict[str, str]:
    """Each dependency file of the File Set, by its relative path, to its sha256."""
    found = {}
    for relative in sorted(files):
        if reads(relative):
            try:
                found[relative] = hashlib.sha256((workspace / relative).read_bytes()).hexdigest()
            except OSError:
                found[relative] = "unreadable"
    return found


def key(*, tool: str, version: str, argv: tuple[str, ...], profile: str,
        inputs: dict[str, str], data: str) -> str:
    """The reuse key: equal only when nothing the answer depends on differs."""
    material = json.dumps({"tool": tool, "version": version, "argv": list(argv),
                           "profile": profile, "inputs": inputs, "data": data},
                          sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()


# ------------------------------------------------------------ the data stamp


def data(tool: str, files: list[str]) -> str:
    """What the Scanner answered from, as a stamp that changes when the data does:
    the vulnerability database's build time for Trivy (and its Java database's, when
    there is one); each OSV export's date and size for the ecosystems present."""
    if tool == "trivy":
        stamps = []
        for name in ("db", "java-db"):
            try:
                meta = json.loads((cache.trivy_db() / name / "metadata.json").read_text())
            except (OSError, ValueError):
                meta = {}
            stamps.append(f"{name}:{meta.get('UpdatedAt', '')}")
        return ";".join(stamps)
    return _osv_stamp(osv_offline.needed(files))


def _osv_stamp(names: list[str]) -> str:
    """Each named OSV export's date and size, as the offline database now holds it."""
    stamps = []
    for name in names:
        path = osv_offline.path(name)
        age = osv_offline._ages().get(name) or {}
        size = path.stat().st_size if path.is_file() else 0
        stamps.append(f"{name}:{age.get('last_modified', '')}:{size}")
    return ";".join(stamps)


# ------------------------------------------------------------ the store


def directory() -> Path:
    """Where reused results live: the host cache, under its lock (R14.4)."""
    return cache.root() / cache.REUSE


def _path(tool: str, key_: str) -> Path:
    return directory() / tool / f"{key_}.json"


def load(tool: str, key_: str) -> dict | None:
    """The stored result for `key_`: its raw report, version and the run that made it.
    A result reused is a result in use: its age restarts, so `--prune` keeps it."""
    import os

    path = _path(tool, key_)
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not (isinstance(stored, dict) and "raw" in stored):
        return None
    try:
        os.utime(path)
    except OSError:
        pass
    return stored


def save(tool: str, key_: str, *, raw: str, version: str, generation: str,
         data: str = "") -> None:
    """Keep a clean result under its key, written whole and renamed into place: two
    scans holding the shared cache lock may write the same key at once. The version
    and data stamp travel with it, so `--prune` can tell when it can never match."""
    import os
    import uuid

    target = _path(tool, key_)
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(f"{target.name}.{uuid.uuid4().hex}.tmp")
    partial.write_text(json.dumps({"tool": tool, "raw": raw, "version": version,
                                   "generation": generation, "data": data}),
                       encoding="utf-8")
    os.replace(partial, target)


#: A stored result unused this long is pruned, whatever its key.
UNUSED_DAYS = 30


def _versions() -> dict[str, str]:
    return {"trivy": TRIVY, "osv-scanner": OSV}


def _current(tool: str, stamp: str) -> bool:
    """Whether `stamp` is still what `tool` would answer from."""
    if tool == "trivy":
        return stamp == data("trivy", [])
    names = [part.split(":", 1)[0] for part in stamp.split(";") if part]
    return stamp == _osv_stamp(names)


def superseded() -> list[Path]:
    """Each stored result that can never match again, or that nobody has used for
    `UNUSED_DAYS`: its Scanner's version or its data has moved on since."""
    import time

    versions, found = _versions(), []
    for path in sorted(directory().rglob("*.json")) if directory().is_dir() else []:
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            found.append(path)
            continue
        tool = stored.get("tool") or path.parent.name
        if (stored.get("version") != versions.get(tool)
                or not _current(tool, str(stored.get("data", "")))
                or time.time() - path.stat().st_mtime > UNUSED_DAYS * 86400):
            found.append(path)
    return found


def prune() -> list[str]:
    """Remove what `superseded` names, under the exclusive cache lock, as
    `valvur update --prune` does the rest of the cache. Returns what went."""
    removed = []
    with locking.held(locking.cache_lock(cache.root()), exclusive=True, wait=True):
        for path in superseded():
            path.unlink(missing_ok=True)
            removed.append(str(path))
    return removed
