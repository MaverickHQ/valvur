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
    #: `tree` walks the working tree even in a repository (ADR-0021, decision 7);
    #: the git view otherwise.
    scope: str = "git"
    #: Write the SBOM, and check dependency licences from it (opt-in since
    #: 2026-09-28; D9).
    sbom: bool = False


def _prefixes(entries) -> tuple[str, ...]:
    entries = entries if isinstance(entries, list) else []
    return tuple(str(e).strip().strip("/") for e in entries if str(e).strip().strip("/"))


PROJECT_FILE = ".security-scan.toml"


def read_project(workspace: Path) -> tuple[dict, str | None]:
    """The project file, parsed: its tables, and why it could not be read, if it
    could not. Empty and None when there is none. A scan reads it once, into its
    scan context (D52d); `[scan]` and the suppressions are both drawn from it."""
    import tomllib

    path = workspace / PROJECT_FILE
    if not path.is_file():
        return {}, None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8")), None
    except (ValueError, OSError) as exc:
        # ValueError: TOML that does not parse, and text that is not UTF-8 (R27.4).
        return {}, f"{PROJECT_FILE} could not be read: {exc}"


def load_scan_settings(workspace: Path) -> ScanSettings:
    """The `[scan]` table, or the defaults when there is no file or it is
    malformed — the suppression loader reads the same file and reports that."""
    return scan_settings(read_project(workspace)[0])


def scan_settings(raw: dict) -> ScanSettings:
    """The `[scan]` table of a parsed project file, with its defaults."""
    scan = raw.get("scan")
    # A `[scan]` of the wrong shape is the defaults; `doctor` names the problem.
    scan = scan if isinstance(scan, dict) else {}
    return ScanSettings(
        exclude=_prefixes(scan.get("exclude")),
        history=scan.get("history", True) is not False,
        scope="tree" if str(scan.get("scope", "git")).strip().lower() == "tree" else "git",
        sbom=scan.get("sbom", False) is True,
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
