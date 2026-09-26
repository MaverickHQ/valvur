"""One vocabulary for ecosystem names, shared by every adapter.

Finding identity is `(ecosystem, package, version, vuln_id)` (ADR-0003). Scanners do
not agree on the first element: OSV says "PyPI", Trivy says "pip", and for lockfiles
Trivy reports the FORMAT rather than the ecosystem — "pnpm" and "yarn" for what is
all npm. Measured on a real project: the same 24 CVEs arrived as 24 "npm" findings
from osv-scanner and 24 "pnpm" findings from Trivy, and every one was reported twice
because the fingerprints could not match.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import parsers as _parsers
from . import registry as _registry
from .registry import (  # noqa: F401 — the package's surface
    BY_KEY,
    ECOSYSTEMS,
    INDEX_FILES,
    Ecosystem,
    get,
    index_form,
)

# Lockfile formats and scanner spellings, mapped to the ecosystem they describe.
_CANONICAL: dict[str, str] = {
    # npm — the format is not the ecosystem
    "npm": "npm", "pnpm": "npm", "yarn": "npm", "node-pkg": "npm",
    # python
    "pip": "pip", "pypi": "pip", "poetry": "pip", "pipenv": "pip",
    "python-pkg": "pip", "uv": "pip",
    # go
    "gomod": "gomod", "go": "gomod", "golang": "gomod",
    # rust
    "cargo": "cargo", "crates.io": "cargo", "rust-crate": "cargo",
    # jvm
    "maven": "maven", "gradle": "maven", "pom": "maven", "jar": "maven",
    # ruby
    "gem": "gem", "bundler": "gem", "rubygems": "gem",
    # others we may meet
    "composer": "composer", "packagist": "composer",
    "nuget": "nuget", "conan": "conan", "pub": "pub", "hex": "hex",
    "swifturl": "swift", "cocoapods": "swift",
}


def normalise(name: str) -> str:
    """Canonical ecosystem for a scanner's spelling. Unknown names pass through
    lowercased rather than being dropped: a wrong-but-consistent name still merges
    with itself, while an empty one silently merges unrelated findings."""
    key = (name or "").strip().lower()
    return _CANONICAL.get(key, key or "unknown")


@dataclass(frozen=True)
class Manifests:
    """Which dependency manifests belong to an ecosystem, and which of them valvur
    actually parses.

    `reads` is the honest half: a manifest listed there is inspected by the Dependency
    Reality Check. `sees` is recognised and **not** parsed — either because another
    manifest for the same ecosystem covers it (a lockfile's transitive dependencies
    are not the ones a language model invents) or because the ecosystem has no
    registry lookup implemented at all.

    Keyed by the same canonical names as `normalise` above, deliberately. Task 19.D.3
    built a parallel table keyed on *display labels* and immediately reproduced the bug
    this module's docstring describes: `pnpm-lock.yaml` and `package.json` were
    reported as two separate uncovered ecosystems, because "npm" and "npm (pnpm)" are
    different strings. The fix already existed here.
    """

    label: str
    reads: tuple[str, ...] = ()
    sees: tuple[str, ...] = ()


#: What Trivy reads for KNOWN VULNERABILITIES, per ecosystem — which is not the same
#: set as what the dependency-reality Check reads for existence, and the difference is
#: where a scan goes quiet. Measured 2026-09-12 with the image's Trivy 0.74 against a
#: directory holding only the named file (task 22.E.1, the public corpus's first
#: finding): `package.json` alone, `pyproject.toml` alone, `Gemfile` alone and
#: `Cargo.toml` alone each produced NO RESULTS — not zero vulnerabilities, no scan —
#: while `package-lock.json`, `requirements.txt`, `go.mod` and `pom.xml` each produced
#: findings. Express, which commits no lockfile, read `clean` with thirty dependencies
#: never checked. So the shim states this gap itself, as a coverage note.
#:
#: `requirements*.txt` is a check for its PINNED lines only (task 25.3): Trivy reads
#: `==` and nothing else, so a file of ranges is "present" here and checks nothing.
#: `coverage.vulnerability_gaps` reads the pins before trusting the name.
VULNERABILITY_MANIFESTS: dict[str, tuple[str, ...]] = {
    "pip": ("requirements*.txt", "Pipfile.lock", "poetry.lock", "uv.lock"),
    "npm": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
    "cargo": ("Cargo.lock",),
    "gomod": ("go.mod",),
    "maven": ("pom.xml", "gradle.lockfile"),
    "gem": ("Gemfile.lock",),
    "composer": ("composer.lock",),
}

#: What a dependency manifest on disk means, per ecosystem — derived from the
#: registry (27.3.2), which is where the rest of an ecosystem's truth lives too.
#: This was a second hand-maintained table until then, and the comments that
#: explained each entry are now beside the entry itself in `registry.py`.
MANIFESTS: dict[str, Manifests] = {
    e.key: Manifests(e.label, reads=e.reads, sees=e.sees) for e in _registry.ECOSYSTEMS
}


def declared(workspace: Path, exclude: tuple[str, ...] = ()) -> set[tuple[str, str, str]]:
    """Every directly-declared dependency, as (ecosystem, name, manifest path).

    Here rather than in `parsers.py` (28.0.5): this is the loop over the registry,
    and a parser module that imported the registry that imported it was the tree's
    only module-level cycle.

    Ecosystem travels with the name because the same string is a different package in
    two registries — and because the registry to ask is decided here, once, rather
    than guessed later.
    """
    found: set[tuple[str, str, str]] = set()
    for ecosystem in ECOSYSTEMS:
        for pattern, parse in ecosystem.parsers:
            for path in _parsers.manifests(workspace, pattern, exclude):
                found |= parse(path, workspace)

    # Never asked about, not merely unreported. A workspace member's name leaving the
    # machine buys nothing, and §3 is about what we transmit as much as what we say.
    local = defined_locally(workspace, exclude)
    return {(eco, name, src) for eco, name, src in found if (eco, name) not in local}


def defined_locally(workspace: Path, exclude: tuple[str, ...] = ()) -> set[tuple[str, str]]:
    """Package names this Workspace *defines*, as (ecosystem, name).

    A monorepo member is declared like any other dependency and resolved from the tree
    beside it — `uv`, Poetry and Hatch all do this for a plain `"demo-core"` when a
    member's `pyproject.toml` names it. Nothing in the dependency string says so, and
    the npm markers the parsers skip (`workspace:*`, `file:`, `link:`) have no Python
    equivalent.

    Measured on a real local monorepo: **three high-severity findings**, each telling a
    developer that a package they wrote was "almost certainly hallucinated". That is
    the worst finding this product can emit — someone who is told their own code is a
    supply-chain attack stops reading the report, and the real finding in it goes too.

    Keyed on what a manifest *defines*, not on what appears in one: a dependency that
    happens to share a name with something in the tree is still a dependency. Which
    manifest defines a package is the registry entry's `defines` (28.1.1) — it was a
    second per-ecosystem table in `parsers.py`, outside the one place.
    """
    return {
        (ecosystem.key, name)
        for ecosystem in ECOSYSTEMS
        for pattern, define in ecosystem.defines
        for path in _parsers.manifests(workspace, pattern, exclude)
        for name in define(path)
    }

