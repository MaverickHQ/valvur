"""Paths that are not the developer's code.

Found by scanning a real project: **30% of its findings came from numpy's own test
fixtures** inside `.aws-sam/build/`. Vendored and generated code is not something the
developer wrote, cannot be fixed by editing it, and reporting it is exactly the noise
Phase 5 exists to prevent. Our synthetic fixture has no vendored dependencies, so
this was invisible until a real codebase.

Dependency *vulnerabilities* are unaffected: those are reported against the manifest,
not against the vendored copy, so excluding these directories loses nothing real.
"""

from __future__ import annotations

from pathlib import Path

# Directory names, matched as whole path segments. Substring matching would exclude a
# legitimate `src/distribution/` for containing "dist".
VENDORED = frozenset({
    "node_modules", "bower_components", "jspm_packages",
    ".venv", "venv", "virtualenv", "site-packages", ".tox", ".nox", "__pypackages__",
    "vendor", "third_party", "thirdparty", "external",
    "dist", "build", "out", "target", ".output",
    ".aws-sam", ".serverless", ".terraform", ".next", ".nuxt", ".svelte-kit",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".git", ".hg", ".svn",
    "Pods", "Carthage", ".gradle", ".m2",
})


def is_vendored(path: str, extra: frozenset[str] = frozenset()) -> bool:
    """True when any path segment names a vendored or generated directory."""
    if not path:
        return False
    segments = set(Path(path.replace("\\", "/")).parts)
    return bool(segments & (VENDORED | extra))


def filter_findings(findings: list, extra: frozenset[str] = frozenset()) -> tuple[list, int]:
    """Drop findings in vendored paths. Returns (kept, dropped_count).

    The count is reported rather than discarded: silently dropping findings is how a
    scanner hides something, and a user who has vendored a genuinely vulnerable copy
    deserves to know we skipped it.
    """
    kept = [f for f in findings if not is_vendored(f.path, extra)]
    return kept, len(findings) - len(kept)


def scanner_skip_args(kind: str) -> list[str]:
    """Per-scanner exclusion flags, so we do not spend time scanning what we discard."""
    if kind == "trivy":
        return [arg for d in sorted(VENDORED) for arg in ("--skip-dirs", f"**/{d}")]
    if kind == "opengrep":
        return [arg for d in sorted(VENDORED) for arg in ("--exclude", d)]
    return []
