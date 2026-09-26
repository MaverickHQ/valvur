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
    # Package-manager caches, which hold third-party source rather than build output.
    # Added 2026-09-10 (task 19.F.3) after a real monorepo reported **17 of its 42
    # findings inside `.uv-cache/`** — `eval` and `exec` in pytest, hypothesis,
    # pygments and attrs, every one at high severity. Forty percent of that report was
    # other people's code, and a developer who meets that stops reading the rest.
    ".uv-cache", ".cache", ".npm", ".yarn", ".pnpm-store", ".cargo", ".bundle",
    ".nuget", ".ivy2", ".sbt", ".stack-work", ".direnv", ".eggs",
    ".conda", "conda-meta", ".pixi",
    ".turbo", ".parcel-cache", ".vite", ".angular", ".astro",
})

# This list is a denylist, and a denylist ages: uv did not exist when the first
# version was written, so `.uv-cache` became findings the moment a project used it.
# Two things limit the damage rather than pretending the list is complete. The count
# of dropped findings is always reported (`excluded_vendored` in `run.json`), so an
# over-broad entry is visible; and the entries are whole path segments, so a
# legitimate `src/cache/` module is untouched while a top-level `.cache/` is not.
#
# **Rejected: excluding whatever `.gitignore` covers.** It is the project's own
# statement about what is not its source, which is exactly the right signal — and it
# would stop valvur scanning `.env` files, which are gitignored precisely because they
# hold the credentials this tool exists to find.


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


# ------------------------------------------------ skipping at scan time (29.0.1)
#
# Until 2026-09-26 both lists above were applied to FINDINGS, after every Scanner
# had walked the whole tree. The first gate's participant watched Gitleaks spend
# 211.7 s producing 3,892 hits inside a 103,251-file excluded archive that were
# then dropped, and Checkov never finish. A `scanner_skip_args` had been written
# for this on 2026-08-31 and never called. Each form below was measured inside
# the image on a planted tree the same day; the finding filters above stay,
# because a Scanner that ignores its flag must not leak what the user excluded.

#: The excluded prefixes, into the Checks' container — one per line. An
#: environment variable rather than arguments, so that an image from before it
#: ignores it (the batch would read `--exclude` as a Check's name) and one that
#: knows it prunes its walk. Read by `valvur.checks.__main__`.
EXCLUDE_ENV = "VALVUR_EXCLUDE"

#: Where Gitleaks reads its generated config: the scratch mount, beside its
#: report. Gitleaks has no path flag; a config that extends the defaults with
#: an allowlist of path patterns is the one way to tell it what not to read.
GITLEAKS_CONFIG = "gitleaks.toml"


def excluded_prefixes(workspace: Path) -> tuple[str, ...]:
    """Every repo-relative prefix a scan skips before it starts: the committed
    `[scan] exclude` list."""
    return load_configured(workspace)


def exclude_env(prefixes: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    return ((EXCLUDE_ENV, "\n".join(prefixes)),) if prefixes else ()


def prefixes_from_env(value: str | None) -> tuple[str, ...]:
    return tuple(p for p in (value or "").split("\n") if p)


def skip_args(kind: str, prefixes: tuple[str, ...] = ()) -> list[str]:
    """The flags that make one Scanner skip the vendored directories and the
    excluded prefixes before it reads them. Measured 2026-09-26 inside the image
    on a tree with `a.py`, `archive/deep/…` and `node_modules/…`:

    - Trivy `--skip-dirs` takes globs relative to the scanned root: `**/name`
      for a directory anywhere, the prefix as written.
    - Checkov `--skip-path` is a regular expression searched in the path it
      reports (`/archive/Dockerfile`); unanchored, so `dist` alone would skip
      `distribution/` — the forms here bind both ends of a segment.
    - Syft `--exclude` takes globs: `**/name/**` and `./prefix/**`.
    - Opengrep `--exclude=PATTERN` skips any path with a matching component,
      and a pattern with a slash matches the same run of components.
    - OSV-Scanner `--experimental-exclude` takes a directory name exactly, or
      `r:` with a regular expression searched in the path.
    - Gitleaks has no flag: see `gitleaks_config`.
    """
    import re

    names = sorted(VENDORED)
    if kind == "trivy":
        return ([arg for d in names for arg in ("--skip-dirs", f"**/{d}")]
                + [arg for p in prefixes for arg in ("--skip-dirs", p)])
    if kind == "opengrep":
        return [f"--exclude={d}" for d in names] + [f"--exclude={p}" for p in prefixes]
    if kind == "checkov":
        return ([arg for d in names for arg in ("--skip-path", f"(^|/){re.escape(d)}(/|$)")]
                + [arg for p in prefixes for arg in ("--skip-path", f"(^|/){re.escape(p)}(/|$)")])
    if kind == "syft":
        return ([arg for d in names for arg in ("--exclude", f"**/{d}/**")]
                + [arg for p in prefixes for arg in ("--exclude", f"./{p}/**")])
    if kind == "osv-scanner":
        return ([arg for d in names for arg in ("--experimental-exclude", d)]
                + [arg for p in prefixes
                   for arg in ("--experimental-exclude", f"r:(^|/){re.escape(p)}(/|$)")])
    return []


def gitleaks_config(prefixes: tuple[str, ...] = ()) -> str:
    """A Gitleaks config that keeps every default rule and allowlists the paths
    the scan skips. Gitleaks reports `/workspace/archive/deep/x.txt`, so the
    prefix patterns accept the mount. Measured 2026-09-26: the bytes scanned
    halved on the probe tree and a planted token under `archive/` was not read."""
    import re

    patterns = [f"(^|/){re.escape(d)}(/|$)" for d in sorted(VENDORED)]
    patterns += [f"^(/workspace/)?{re.escape(p)}(/|$)" for p in prefixes]
    body = "".join(f"  '''{pattern}''',\n" for pattern in patterns)
    return (
        "# Generated by valvur for one scan: the default rules, plus the paths this\n"
        "# scan skips before reading them (vendored directories and [scan] exclude).\n"
        "[extend]\nuseDefault = true\n\n"
        "[[allowlists]]\n"
        'description = "paths excluded before the scan (valvur)"\n'
        f"paths = [\n{body}]\n"
    )


def walk_files(workspace: Path, prefixes: tuple[str, ...] = ()):
    """Every file under the Workspace that is neither vendored nor under an
    excluded prefix — without descending into what is skipped, which is the
    point: a 103,251-file archive costs one directory listing, not 103,251."""
    import os

    for dirpath, dirnames, filenames in os.walk(workspace):
        rel_dir = Path(dirpath).relative_to(workspace)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in VENDORED and not is_configured_out((rel_dir / d).as_posix(), prefixes)
        )
        for name in sorted(filenames):
            if not is_configured_out((rel_dir / name).as_posix(), prefixes):
                yield Path(dirpath) / name
