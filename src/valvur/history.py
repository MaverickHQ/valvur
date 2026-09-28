"""Secrets in history (R3.7; D3, ADR-0021): what every commit added, for Gitleaks.

A secret removed from the working tree is still in every clone. The host reads
`git log -p --all` — the image has no `git`, which is GPL-2.0 (ADR-0005) — and
writes each commit's ADDED lines into one file in valvur's scratch directory,
keeping where each (commit, path) run of lines begins, so a Gitleaks hit on line
N maps back to the commit and the file. Removed lines are not written: every one
was added by an earlier commit, which is read.

Bounded at 5,000 commits or 200 MB, whichever comes first, newest first, and the
bound is named when it is hit: a scan that read part of the history says so.
"""

from __future__ import annotations

import bisect
import codecs
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

MAX_COMMITS = 5000
MAX_BYTES = 200 * 2**20
#: The line that opens each commit in `git log`'s output: a NUL, then the hash.
_MARK = b"\x00"


@dataclass
class History:
    path: Path
    commits: int = 0
    bytes: int = 0
    #: The bound that stopped the read, in words; None when all of it was read.
    bounded: str | None = None
    #: (first line, commit, repo-relative path) for each run of added lines.
    spans: list[tuple[int, str, str]] = field(default_factory=list)

    def locate(self, line: int) -> tuple[str, str] | None:
        """The commit and the path whose added lines include `line`."""
        at = bisect.bisect_right([s[0] for s in self.spans], line) - 1
        if at < 0:
            return None
        _, commit, path = self.spans[at]
        return commit, path


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
    """Write `root`'s history to `dest`; None when `root` is not a repository, or
    when there is no `git` to read it with."""
    from .fileset import git

    command = git()
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
    commit, path, current, in_hunk, line = "", None, None, False, 0
    try:
        with open(dest, "wb") as out:
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
                    if current != (commit, path):
                        current = (commit, path)
                        found.spans.append((line + 1, commit, path))
                    out.write(content)
                    found.bytes += len(content)
                    line += 1
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
    return found
