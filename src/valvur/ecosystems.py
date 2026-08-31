"""One vocabulary for ecosystem names, shared by every adapter.

Finding identity is `(ecosystem, package, version, vuln_id)` (ADR-0003). Scanners do
not agree on the first element: OSV says "PyPI", Trivy says "pip", and for lockfiles
Trivy reports the FORMAT rather than the ecosystem — "pnpm" and "yarn" for what is
all npm. Measured on a real project: the same 24 CVEs arrived as 24 "npm" findings
from osv-scanner and 24 "pnpm" findings from Trivy, and every one was reported twice
because the fingerprints could not match.
"""

from __future__ import annotations

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
