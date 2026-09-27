"""The File Set (ADR-0021, task R3.2): the exact files a Scan Run examines.

The git view when the Workspace is a repository — tracked files and untracked
files git does not ignore — and a walk otherwise. Never the Results Folder, never
version control's metadata. R3.2 grows this into the whole of ADR-0021.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .exclusions import RESULTS_DIR  # a leaf: importing results would close a cycle

_NEVER = frozenset({RESULTS_DIR, ".git", ".hg", ".svn"})


def git_view(workspace: Path) -> list[str] | None:
    """Tracked and untracked-not-ignored files, or None when git cannot say."""
    if not (workspace / ".git").exists():
        return None
    proc = subprocess.run(  # noqa: S603 — git, fixed arguments
        ["git", "-C", str(workspace), "ls-files", "-z", "--cached", "--others",
         "--exclude-standard"], capture_output=True, check=False)
    if proc.returncode != 0:
        return None
    names = [n for n in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if n]
    return sorted({n for n in names if not (set(Path(n).parts) & _NEVER)
                   and (workspace / n).is_file()})


def walk(workspace: Path) -> list[str]:
    import os

    found = []
    for dirpath, dirnames, filenames in os.walk(workspace):
        dirnames[:] = [d for d in dirnames if d not in _NEVER]
        rel = Path(dirpath).relative_to(workspace)
        found += [(rel / f).as_posix() for f in filenames]
    return sorted(found)


@dataclass
class FileSet:
    """What a Scan Run reads (ADR-0021)."""

    files: list[str]
    #: "git" for the git view, "tree" for a walk.
    scope: str
    #: What was left out, and why: (path, reason).
    skipped: list[tuple[str, str]] = field(default_factory=list)


def _kept_when_ignored(rel: str) -> bool:
    """An ignored file the scan still reads (ADR-0021): `.env*`, where a secret
    hides, and every agent-configuration file the AI Artifact Check knows."""
    from .exclusions import _kept_when_ignored as kept

    return kept(rel)


#: How far an ignored directory is searched for the files a scan reads anyway:
#: a small `config/` with a `.env` is found; a 100,000-file data directory costs
#: at most this many entries (ADR-0021, R3.2).
IGNORED_SEARCH_LIMIT = 5_000


def _bounded_walk(root: Path, limit: int) -> tuple[list[str], bool]:
    """Up to `limit` files under `root`, relative; True when it stopped short."""
    import os

    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _NEVER)
        rel = Path(dirpath).relative_to(root)
        for name in sorted(filenames):
            found.append((rel / name).as_posix())
            if len(found) >= limit:
                return found, True
    return found, False


def _ignored(workspace: Path) -> tuple[list[str], list[tuple[str, str]]]:
    """The ignored files the scan reads, and the ignored paths it names and skips.
    Git collapses an ignored directory to one entry, so a 100,000-file data
    directory costs one line; one that is agent configuration is walked."""
    proc = subprocess.run(  # noqa: S603 — git, fixed arguments
        ["git", "-C", str(workspace), "ls-files", "-z", "--others", "--ignored",
         "--exclude-standard", "--directory"], capture_output=True, check=False)
    kept: list[str] = []
    skipped: list[tuple[str, str]] = []
    for entry in (e for e in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if e):
        if set(Path(entry).parts) & _NEVER:
            continue
        if entry.endswith("/"):
            inside, cut = _bounded_walk(workspace / entry, IGNORED_SEARCH_LIMIT)
            chosen = [f"{entry}{rel}" for rel in inside if _kept_when_ignored(f"{entry}{rel}")]
            kept += chosen
            if cut:
                skipped.append((entry, f"ignored by git; searched for agent and .env "
                                       f"files only as far as {IGNORED_SEARCH_LIMIT:,} files"))
            elif len(chosen) < len(inside) or not inside:
                skipped.append((entry, "ignored by git"))
        elif _kept_when_ignored(entry):
            kept.append(entry)
        else:
            skipped.append((entry, "ignored by git"))
    return kept, skipped


def _excluded(result: FileSet, prefixes: tuple[str, ...]) -> FileSet:
    """The project's `[scan] exclude`, applied once, root-relative (ADR-0021)."""
    from .exclusions import is_configured_out

    if not prefixes:
        return result
    result.files = [f for f in result.files if not is_configured_out(f, prefixes)]
    result.skipped += [(p, "excluded by .security-scan.toml") for p in prefixes]
    return result


def build(workspace: Path) -> FileSet:
    from .exclusions import load_configured

    prefixes = load_configured(workspace)
    view = git_view(workspace)
    if view is not None:
        kept, skipped = _ignored(workspace)
        return _excluded(FileSet(sorted(set(view) | set(kept)), "git", skipped), prefixes)
    return _excluded(FileSet(walk(workspace), "tree"), prefixes)


def files(workspace: Path) -> list[str]:
    return build(workspace).files
