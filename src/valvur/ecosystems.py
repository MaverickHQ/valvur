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

#: What a dependency manifest on disk means, per ecosystem.
#:
#: An ecosystem with an empty `reads` has no existence check at all — its presence in
#: a Workspace is reported as missing coverage rather than passed over, because a
#: Check that says nothing is indistinguishable from one that found nothing.
MANIFESTS: dict[str, Manifests] = {
    "pip": Manifests(
        "Python",
        reads=("requirements*.txt", "pyproject.toml"),
        # Pipfile and setup.py declare dependencies in shapes we do not parse; the
        # lockfiles carry resolved transitive trees, which are not where hallucinated
        # names appear. Both are only a gap when nothing readable sits beside them.
        sees=("Pipfile", "setup.py", "setup.cfg", "poetry.lock", "uv.lock"),
    ),
    "npm": Manifests(
        "npm",
        reads=("package.json",),
        sees=("package-lock.json", "pnpm-lock.yaml", "yarn.lock"),
    ),
    # Read since 23.2.3: crates.io's list is streamed out of its database dump.
    "cargo": Manifests("Rust (Cargo)", reads=("Cargo.toml",), sees=("Cargo.lock",)),
    # Read since 22.A.4, on `full` only: neither registry publishes a name list that
    # could be fetched into the offline index (ADR-0018 records the numbers), so
    # existence is asked of the registry per name. The Coverage contract says so on
    # every Profile; on `offline` these are a stated Profile omission, not a gap.
    "gomod": Manifests("Go", reads=("go.mod",), sees=("go.sum",)),
    # Maven and Gradle resolve from the same registry, so they are one ecosystem with
    # two build tools — the distinction that produced the pnpm/yarn bug. The Gradle
    # version catalog is read too: a project that declares everything there and
    # references `libs.foo` from its build script would otherwise scan clean.
    "maven": Manifests(
        "JVM (Maven/Gradle)",
        reads=("pom.xml", "build.gradle", "build.gradle.kts", "gradle/libs.versions.toml"),
        sees=("settings.gradle", "settings.gradle.kts", "gradle.lockfile"),
    ),
    # Read since 23.2.2: RubyGems and Packagist each publish their whole list in one
    # request, and both are in the index.
    "gem": Manifests("Ruby (Bundler)", reads=("Gemfile", "*.gemspec"), sees=("Gemfile.lock",)),
    "composer": Manifests("PHP (Composer)", reads=("composer.json",), sees=("composer.lock",)),
}
