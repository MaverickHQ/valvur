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
# Our own Results Folder. Scanning it makes each run feed on the last one's output:
# findings.json quotes evidence from the repository, so a scan of it produces
# findings ABOUT findings, and the noise compounds every run. Caught by dogfooding —
# valvur reported two mutable-git-ref findings against its own findings.json.
RESULTS_DIR = ".security-scan"

VENDORED = frozenset({
    RESULTS_DIR,
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


def load_configured(workspace: Path) -> tuple[str, ...]:
    """Repo-relative path prefixes the project has chosen not to scan.

        [scan]
        exclude = ["tests/fixtures"]

    Deliberately NOT a built-in default. A project full of intentionally-vulnerable
    test data needs this; every other project would be harmed by having its tests
    silently skipped, and a scanner that hides findings by default is worse than no
    scanner. Putting it in the committed config makes the decision reviewable —
    someone can see it in the diff and ask why.
    """
    import tomllib

    path = workspace / ".security-scan.toml"
    if not path.is_file():
        return ()
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        # Malformed config is reported by the suppression loader, which reads the
        # same file. Failing twice for one cause helps nobody.
        return ()
    entries = (raw.get("scan") or {}).get("exclude") or []
    return tuple(
        str(e).strip().strip("/") for e in entries if str(e).strip().strip("/")
    )


def is_configured_out(path: str, prefixes: tuple[str, ...]) -> bool:
    """True when a repo-relative path sits under a configured prefix.

    Matched on segment boundaries, so "tests/fixtures" covers
    "tests/fixtures/broken-repo/app.py" but never "tests/fixtures-helper/app.py".
    """
    if not path or not prefixes:
        return False
    parts = Path(path.replace("\\", "/")).parts
    for prefix in prefixes:
        want = Path(prefix).parts
        if parts[: len(want)] == want:
            return True
    return False


def filter_configured(findings: list, prefixes: tuple[str, ...]) -> tuple[list, int]:
    """Drop findings the project excluded. Returns (kept, dropped_count).

    The count is reported, never discarded — an exclusion the reader cannot see is
    indistinguishable from a scanner that found nothing.
    """
    if not prefixes:
        return findings, 0
    kept = [f for f in findings if not is_configured_out(f.path, prefixes)]
    return kept, len(findings) - len(kept)


def scanner_skip_args(kind: str) -> list[str]:
    """Per-scanner exclusion flags, so we do not spend time scanning what we discard."""
    if kind == "trivy":
        return [arg for d in sorted(VENDORED) for arg in ("--skip-dirs", f"**/{d}")]
    if kind == "opengrep":
        return [arg for d in sorted(VENDORED) for arg in ("--exclude", d)]
    return []
