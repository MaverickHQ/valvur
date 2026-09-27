"""Where the unattended build stands (tasks.md §2, task R0.1).

A resuming session runs this to learn the current phase, its branch, the next
task, and whether another executor looks alive. It reads git and the task list;
it changes nothing.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

TASKS = ".kiro/specs/valvur/tasks.md"

_PHASE = re.compile(r"^### Phase R(\d+): (.+?)\s*$")
_TASK = re.compile(r"^- \[([ xX])\] \*\*(R\d+\.\d+)\*\*")


@dataclass(frozen=True)
class Position:
    phase: int
    title: str
    task: str


def position(tasks_text: str) -> Position | None:
    """The first unchecked task and the phase it belongs to; None when all are done."""
    phase, title = -1, ""
    for line in tasks_text.splitlines():
        if heading := _PHASE.match(line):
            phase, title = int(heading.group(1)), heading.group(2)
        elif (task := _TASK.match(line)) and task.group(1) == " ":
            return Position(phase, title, task.group(2))
    return None


def branch_name(phase: int, title: str) -> str:
    """`build/r<n>-<slug>`, the slug from the phase's title."""
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return f"build/r{phase}-{slug}"


def _git(repo: Path, *args: str) -> str:
    # A fixed `git` argument list, no shell; the arguments are this script's own.
    return subprocess.run(["git", *args], cwd=repo, capture_output=True,  # noqa: S603
                          text=True, check=False).stdout


def _origin_branch(repo: Path, phase: int) -> str | None:
    refs = _git(repo, "for-each-ref", "--format=%(refname:short)",
                f"refs/remotes/origin/build/r{phase}-*").split()
    return refs[0].removeprefix("origin/") if refs else None


def status(repo: Path) -> dict:
    """The build's position, read from `origin`: the phase's branch when it exists,
    `main` otherwise (tasks.md §2 step 2)."""
    on_main = position(_git(repo, "show", f"origin/main:{TASKS}"))
    if on_main is None:
        return {"phase": None, "next_task": None, "branch": None, "branch_exists": False}
    existing = _origin_branch(repo, on_main.phase)
    current = on_main
    if existing is not None:
        ahead = position(_git(repo, "show", f"origin/{existing}:{TASKS}"))
        current = ahead if ahead is not None and ahead.phase == on_main.phase else Position(
            on_main.phase, on_main.title, "")
    return {
        "phase": f"R{current.phase}",
        "title": current.title,
        "next_task": current.task or None,
        "branch": existing or branch_name(current.phase, current.title),
        "branch_exists": existing is not None,
    }
