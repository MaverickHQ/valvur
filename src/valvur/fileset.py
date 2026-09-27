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


def build(workspace: Path) -> FileSet:
    view = git_view(workspace)
    if view is not None:
        return FileSet(view, "git")
    return FileSet(walk(workspace), "tree")


def files(workspace: Path) -> list[str]:
    return build(workspace).files
