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


def _submodules(workspace: Path) -> set[str]:
    """Paths git tracks as a gitlink (mode 160000): another repository's commit."""
    proc = subprocess.run(  # noqa: S603 — git, fixed arguments
        ["git", "-C", str(workspace), "ls-files", "-z", "--stage"],
        capture_output=True, check=False)
    found = set()
    for entry in proc.stdout.decode("utf-8", "surrogateescape").split("\0"):
        if entry.startswith("160000 "):
            found.add(entry.split("\t", 1)[1])
    return found


def _leaves(workspace: Path, rel: str) -> bool:
    """A symbolic link whose target resolves outside the Workspace."""
    path = workspace / rel
    if not path.is_symlink():
        return False
    try:
        path.resolve().relative_to(workspace.resolve())
    except ValueError:
        return True
    return False


def git_view(workspace: Path) -> tuple[list[str], list[tuple[str, str]]] | None:
    """Tracked and untracked-not-ignored files, with what was left out and why;
    None when git cannot say."""
    if not (workspace / ".git").exists():
        return None
    proc = subprocess.run(  # noqa: S603 — git, fixed arguments
        ["git", "-C", str(workspace), "ls-files", "-z", "--cached", "--others",
         "--exclude-standard"], capture_output=True, check=False)
    if proc.returncode != 0:
        return None
    names = {n for n in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if n
             and not (set(Path(n).parts) & _NEVER)}
    skipped = [(n, "a submodule, not entered") for n in sorted(_submodules(workspace))]
    kept = []
    for name in sorted(names):
        if _leaves(workspace, name):
            skipped.append((name, "a link leaving the repository, not followed"))
        elif (workspace / name).is_file():
            kept.append(name)
    return kept, skipped


#: What a walk skips in a directory that is not a repository (ADR-0021): installed
#: dependencies and tool caches, each named. Build output is read — a package's own
#: `build/` directory can be first-party code (the review's N2).
DEPENDENCY_CACHES = frozenset({
    "node_modules", ".venv", "venv", "__pycache__", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".gradle",
    # Package managers' own caches: other people's code. Measured on a real
    # monorepo, 17 of 42 findings were `eval` and `exec` inside `.uv-cache/`.
    ".uv-cache", ".cache", ".yarn", ".cargo", ".pnpm-store", ".npm", ".m2", ".ivy2",
    ".bundle", ".nuget", ".eggs", ".conda", ".pixi",
})


def walk(workspace: Path, skipped: list[tuple[str, str]] | None = None) -> list[str]:
    """Every file under `workspace`, never version control's metadata or the
    Results Folder, and — when `skipped` is given — no dependency cache either,
    each one named there."""
    import os

    found = []
    for dirpath, dirnames, filenames in os.walk(workspace):
        rel = Path(dirpath).relative_to(workspace)
        keep = []
        for name in sorted(dirnames):
            if name in _NEVER:
                continue
            if skipped is not None and name in DEPENDENCY_CACHES:
                skipped.append(((rel / name).as_posix(), "a dependency cache"))
                continue
            keep.append(name)
        dirnames[:] = keep
        found += [(rel / f).as_posix() for f in filenames]
    return sorted(found)


#: Past this many files a walk refuses and a git view warns (ADR-0021).
CEILING = 20_000


@dataclass
class FileSet:
    """What a Scan Run reads (ADR-0021)."""

    files: list[str]
    #: "git" for the git view, "tree" for a walk.
    scope: str
    #: What was left out, and why: (path, reason).
    skipped: list[tuple[str, str]] = field(default_factory=list)
    #: A git view past the ceiling: the largest directories and the exclude line.
    warning: str | None = None

    def manifest(self, workspace: Path) -> dict:
        """What the report states about the scope (ADR-0021): the scope, how many
        files, how many bytes, and the sha256 of the list, one path a line."""
        import hashlib

        size = 0
        for name in self.files:
            path = workspace / name
            size += path.lstat().st_size if path.is_symlink() else path.stat().st_size
        return {"scope": self.scope, "files": len(self.files), "bytes": size,
                "sha256": hashlib.sha256("\n".join(self.files).encode()).hexdigest()}


def _largest(files: list[str], count: int = 3) -> list[tuple[str, int]]:
    per_top: dict[str, int] = {}
    for name in files:
        top = name.split("/", 1)[0] if "/" in name else "."
        per_top[top] = per_top.get(top, 0) + 1
    return sorted(per_top.items(), key=lambda item: (-item[1], item[0]))[:count]


def _ceiling_sentence(files: list[str]) -> str:
    largest = _largest(files)
    named = ", ".join(f"{d} {n:,}" for d, n in largest)
    top = largest[0][0] if largest else "."
    return (f"{len(files):,} files; largest: {named}. If `{top}` is not source, add "
            f'`[scan] exclude = ["{top}"]` to .security-scan.toml')


def _kept_when_ignored(rel: str) -> bool:
    """An ignored file the scan still reads (ADR-0021): `.env*`, where a secret
    hides — a gitignored `.env` holds exactly the credentials a scan is for — and
    every agent-configuration file the AI Artifact Check knows (a `.mcp.json` a
    project keeps out of git is still what its agent obeys)."""
    from pathlib import PurePosixPath

    from .agent_surfaces import ARTIFACT_DIRS, ARTIFACT_NAMES

    path = PurePosixPath(rel)
    parents = set(path.parts[:-1])
    return (path.name.startswith(".env") or path.name in ARTIFACT_NAMES
            or bool(parents & ARTIFACT_DIRS) or ".kiro" in parents)


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
        tracked, left_out = view
        kept, skipped = _ignored(workspace)
        result = _excluded(FileSet(sorted(set(tracked) | set(kept)), "git",
                                   left_out + skipped), prefixes)
        if len(result.files) > CEILING:
            # Tracked source is the user's code, not a data directory: proceed.
            result.warning = _ceiling_sentence(result.files)
        return result
    walked_skips: list[tuple[str, str]] = []
    walked = walk(workspace, walked_skips)
    result = _excluded(FileSet(walked, "tree", sorted(walked_skips)), prefixes)
    if len(result.files) > CEILING:
        from .refusal import Refusal

        raise Refusal(f"Refused before any Scanner started: {workspace} is not a git "
                      f"repository and holds {_ceiling_sentence(result.files)}, or scan "
                      "a repository, whose ignored files are left out.")
    return result


def files(workspace: Path) -> list[str]:
    return build(workspace).files


def largest(files: list[str], n: int = 3) -> tuple[tuple[str, int], ...]:
    """The `n` top-level directories holding the most of `files`; "." for files at
    the root. What the pre-flight line and a budget refusal name (29.1.2)."""
    counts: dict[str, int] = {}
    for rel in files:
        top = rel.split("/", 1)[0] if "/" in rel else "."
        counts[top] = counts.get(top, 0) + 1
    return tuple(sorted(counts.items(), key=lambda dn: (-dn[1], dn[0]))[:n])
