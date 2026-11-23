"""A commit's tree, read with git's plumbing and never checked out (R50.2, D82k, ADR-0034).

`valvur scan --ref` scans a commit, and `gate --new-since` scans the base. Neither may
change the repository: `git worktree add` writes under `.git`, and a checkout would move
the developer's files. `git archive` drops what `export-ignore` names, so the tree it gives
is not the one a scan of the working tree reads. So: `rev-parse` for the commit, `ls-tree`
for its entries and `cat-file --batch` for the blobs, written into a directory the caller
gives, outside the repository. Measured as fast as reading the tree from disk (R50.1).
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import fileset

_LINK, _SUBMODULE, _EXECUTABLE = "120000", "160000", "100755"


class NotResolved(ValueError):
    """The ref names no commit in this repository."""


class NoGit(NotResolved):
    """There is no git to read a ref with: inside the image, by ADR-0005."""


@dataclass(frozen=True)
class Tree:
    """The commit a Scan Run read in place of the working tree, and the repository it is
    in, for the history pass."""

    repository: Path
    ref: str
    commit: str


def _run(repository: Path, *args: str, stdin: bytes | None = None) -> bytes | None:
    command = fileset.git()
    if command is None:
        return None
    done = subprocess.run([command, "-C", str(repository), *args],  # noqa: S603
                          input=stdin, capture_output=True, check=False)
    return done.stdout if done.returncode == 0 else None


def resolve(repository: Path, ref: str) -> Tree:
    """The commit `ref` names. A ref that starts with a dash is refused unread."""
    if fileset.git() is None:
        # Not the ref's fault, and the reader should not go looking at their branches.
        raise NoGit(f"git is not on PATH here, so `{ref}` cannot be read (the image "
                          "carries none, ADR-0005): run this from the host, where valvur "
                          "starts the container itself")
    found = None if ref.startswith("-") else _run(
        repository, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}")
    if not found or not found.strip():
        raise NotResolved(f"`{ref}` names no commit in {repository}")
    return Tree(repository, ref, found.decode().strip())


def root(tree: Tree) -> str:
    """The repository's first commit as that commit sees it: what names the repository,
    wherever it is checked out."""
    found = _run(tree.repository, "rev-list", "--max-parents=0", tree.commit)
    first = sorted((found or b"").decode().split())
    return first[0] if first else tree.commit


def export(tree: Tree, dest: Path) -> int:
    """Write the commit's files under `dest`, which must not exist; how many. A submodule
    is named by the commit and not entered, as in the working tree, so it is not written."""
    listing = _run(tree.repository, "ls-tree", "-r", "-z", tree.commit)
    if listing is None:
        raise NotResolved(f"the tree of {tree.commit} could not be read")
    entries = []
    for entry in listing.split(b"\0"):
        if entry:
            meta, raw_name = entry.split(b"\t", 1)
            mode, _kind, blob = meta.decode().split()
            if mode != _SUBMODULE:
                entries.append((mode, blob, os.fsdecode(raw_name)))
    blobs = _run(tree.repository, "cat-file", "--batch",
                 stdin="".join(f"{blob}\n" for _mode, blob, _name in entries).encode())
    if blobs is None:
        raise NotResolved(f"the files of {tree.commit} could not be read")
    dest.mkdir(parents=True)
    position = 0
    for mode, _blob, name in entries:
        end = blobs.index(b"\n", position)
        size = int(blobs[position:end].split()[2])
        data = blobs[end + 1:end + 1 + size]
        position = end + 1 + size + 1
        path = dest / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if mode == _LINK:
            path.symlink_to(os.fsdecode(data))
        else:
            path.write_bytes(data)
            if mode == _EXECUTABLE:
                path.chmod(0o755)
    return len(entries)
