"""What a project chose not to scan, and valvur's own folder (ADR-0021).

Since R3.9 exclusion is decided once, by the File Set (`fileset.build`), before the
Snapshot: every Scanner reads only the Snapshot, so none is told what to skip. The
built-in vendored list, the per-tool skip flags, the generated Gitleaks config and
the `.gitignore` opt-in went with that (ADR-0021, ADR-0022): the git view leaves out
what the project told git is not source, and names what it left out.

What remains: the committed `[scan]` settings, the configured-path filter the
pipeline applies to Findings that do not come from the Snapshot (a secret read from
git history, R3.7), and the walk the Checks do inside the Scan Container.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Our own Results Folder. Scanning it makes each run feed on the last one's output:
# findings.json quotes evidence from the repository, so a scan of it produces
# findings ABOUT findings, and the noise compounds every run. Caught by dogfooding —
# valvur reported two mutable-git-ref findings against its own findings.json.
RESULTS_DIR = ".security-scan"

#: Never walked by a Check: version control's metadata and valvur's own folder.
_NEVER_WALKED = frozenset({RESULTS_DIR, ".git", ".hg", ".svn"})


@dataclass(frozen=True)
class ScanSettings:
    """The `[scan]` table of `.security-scan.toml` — what the project chose."""

    #: Repo-relative prefixes not to scan.
    exclude: tuple[str, ...] = ()
    #: Read git history for secrets (R3.7, D3). On unless `history = false`.
    history: bool = True


def _prefixes(entries) -> tuple[str, ...]:
    return tuple(str(e).strip().strip("/") for e in entries or [] if str(e).strip().strip("/"))


def load_scan_settings(workspace: Path) -> ScanSettings:
    """The `[scan]` table, or the defaults when there is no file or it is
    malformed — the suppression loader reads the same file and reports that."""
    import tomllib

    path = workspace / ".security-scan.toml"
    if not path.is_file():
        return ScanSettings()
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return ScanSettings()
    scan = raw.get("scan") or {}
    return ScanSettings(
        exclude=_prefixes(scan.get("exclude")),
        history=scan.get("history", True) is not False,
    )


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
    return load_scan_settings(workspace).exclude


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


def excluded_prefixes(workspace: Path) -> tuple[str, ...]:
    """Every repo-relative prefix the project excluded: the committed `[scan]
    exclude` list."""
    return load_scan_settings(workspace).exclude


PROJECT_GITLEAKS_CONFIG = ".gitleaks.toml"

#: Files a scan will read past which the pre-flight names the largest directory
#: (29.1.2): the synthetic gate tree's archive is 20,000, the gate's own 103,251.
LARGE_TREE = 20_000


def walk_files(workspace: Path, prefixes: tuple[str, ...] = ()):
    """Every file under the Workspace not under an excluded prefix, without
    descending into what is skipped. Inside the Scan Container the Workspace is
    the Snapshot, so this is the File Set; version control's metadata and
    valvur's own folder are never walked."""
    import os

    for dirpath, dirnames, filenames in os.walk(workspace):
        rel_dir = Path(dirpath).relative_to(workspace)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _NEVER_WALKED
            and not is_configured_out((rel_dir / d).as_posix(), prefixes)
        )
        for name in sorted(filenames):
            if not is_configured_out((rel_dir / name).as_posix(), prefixes):
                yield Path(dirpath) / name
