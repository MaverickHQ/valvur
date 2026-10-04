"""Secrets in history (R3.7; D3, ADR-0021): what every commit added, for Gitleaks.

A secret removed from the working tree is still in every clone. The host reads
`git log -p --all` — the image has no `git`, which is GPL-2.0 (ADR-0005) — and
writes each commit's ADDED lines for each path as a file of its own, under a
numbered directory in valvur's scratch directory and under the path's own name, so
a Gitleaks hit maps back to the commit and the path by the file it is in. Removed
lines are not written: every one was added by an earlier commit, which is read.

One file per (commit, path), not one file for all (R10.9): a multi-line pattern
ran from one path's lines into the next. A placeholder key block read on into a
real key committed beside it, and Gitleaks reported the placeholder and missed the
key.

Bounded at 5,000 commits or 200 MB, whichever comes first, newest first, and the
bound is named when it is hit: a scan that read part of the history says so.
"""

from __future__ import annotations

import codecs
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import fileset

MAX_COMMITS = 5000
MAX_BYTES = 200 * 2**20
#: The line that opens each commit in `git log`'s output: a NUL, then the hash.
_MARK = b"\x00"


#: A run's file, as any reader names it: `<number>/<the path's own name>` at the end.
_RUN = re.compile(r"(?:^|/)(\d{6})/[^/]+$")


@dataclass
class History:
    #: The directory the runs are written under.
    path: Path
    commits: int = 0
    bytes: int = 0
    #: The bound that stopped the read, in words; None when all of it was read.
    bounded: str | None = None
    #: (commit, repo-relative path) for each run, by its number.
    runs: list[tuple[str, str]] = field(default_factory=list)

    def locate(self, file: str) -> tuple[str, str] | None:
        """The commit and the path whose added lines are `file`, however the reader
        names it: `/results/history/000012/config.py` or a relative path."""
        match = _RUN.search(file.replace("\\", "/"))
        if match is None or int(match.group(1)) >= len(self.runs):
            return None
        return self.runs[int(match.group(1))]


def _path(header: bytes) -> str | None:
    """The path after `+++ b/`, unquoted as git quotes an unusual name. Git ends a
    name holding a space with a tab, to mark where it stops."""
    raw = header[4:].rstrip(b"\n").removesuffix(b"\t")
    if raw == b"/dev/null":
        return None
    if raw.startswith(b'"') and raw.endswith(b'"'):
        raw = codecs.escape_decode(raw[1:-1])[0]
    text = raw.decode("utf-8", "replace")
    return text[2:] if text.startswith("b/") else text


def write(root: Path, dest: Path, *, max_commits: int = MAX_COMMITS,
          max_bytes: int = MAX_BYTES) -> History | None:
    """Write `root`'s history under the directory `dest`; None when `root` is not a
    repository, or when there is no `git` to read it with."""
    command = fileset.git()
    if command is None:
        return None
    inside = subprocess.run([command, "-C", str(root), "rev-parse",  # noqa: S603
                             "--is-inside-work-tree"],
                            capture_output=True, text=True, check=False)
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return None
    process = subprocess.Popen(  # noqa: S603 — a fixed argv; `root` is an argument
        [command, "-C", str(root), "-c", "core.quotePath=false", "log", "--all", "-p", "-U0",
         "--no-color", "--no-ext-diff", "--no-textconv", "--format=%x00%H",
         "-n", str(max_commits + 1)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    found = History(dest)
    commit, path, current, in_hunk = "", None, None, False
    dest.mkdir(parents=True, exist_ok=True)
    out = None
    try:
        for raw in process.stdout or ():
            if raw.startswith(_MARK):
                if found.commits == max_commits:
                    found.bounded = f"the {max_commits:,}-commit bound"
                    break
                found.commits += 1
                commit, path, in_hunk = raw[1:].strip().decode(), None, False
            elif raw.startswith(b"diff --git "):
                path, in_hunk = None, False
            elif not in_hunk and raw.startswith(b"+++ "):
                path = _path(raw)
            elif raw.startswith(b"@@"):
                in_hunk = True
            elif in_hunk and raw.startswith(b"+") and path is not None:
                content = raw[1:] if raw.endswith(b"\n") else raw[1:] + b"\n"
                if found.bytes + len(content) > max_bytes:
                    found.bounded = f"the {max_bytes:,}-byte bound"
                    break
                if current != (commit, path) or out is None:
                    current = (commit, path)
                    if out is not None:
                        out.close()
                    run = dest / f"{len(found.runs):06d}"
                    run.mkdir()
                    out = open(run / (Path(path).name or "file"), "wb")
                    found.runs.append((commit, path))
                out.write(content)
                found.bytes += len(content)
    finally:
        if out is not None:
            out.close()
        if process.poll() is None:
            process.kill()
        process.wait()
    return found
