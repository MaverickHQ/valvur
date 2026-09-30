"""Reuse what cannot have changed (N1.5, D32, ADR-0030).

Trivy (`fs --scanners vuln`) and OSV-Scanner read a project's dependency files and
their own database, and nothing else of it: their answer cannot change while those do
not. So their raw output is kept in the host cache under a key of everything it
depends on, and a scan with the same key reuses it rather than starting them. A
Scanner that reads source is never reused: a source file's change is exactly what a
rescan is for, and it is not in the key.

The key: the Scanner, its version, the Profile, the path and sha256 of every
dependency file in the File Set, and the data it answered from (the database's build
time, or each OSV export's date). OSV-Scanner on `full` answers from api.osv.dev,
which has no stamp to key on, so it is reused on `offline` only.
"""

from __future__ import annotations

import hashlib
import json
from fnmatch import fnmatch
from pathlib import Path

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


def reads(path: str) -> bool:
    """Whether `path` is a file the dependency Scanners read."""
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch(name, pattern) for pattern in KEY_FILES)


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


def key(*, tool: str, version: str, profile: str, inputs: dict[str, str], data: str) -> str:
    """The reuse key: equal only when nothing the answer depends on differs."""
    material = json.dumps({"tool": tool, "version": version, "profile": profile,
                           "inputs": inputs, "data": data}, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()
