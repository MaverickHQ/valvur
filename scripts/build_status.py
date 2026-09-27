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
#: A build commit carries a phase scope: `feat(r3.4): …`, `chore(r3): …`.
_BUILD_SUBJECT = re.compile(r"^[a-z]+\(r\d+(\.\d+)?\)!?: ")
#: Longer than a usage window plus the hourly schedule (tasks.md §2).
WINDOW_HOURS = 8.0

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


def newest_build_commit(repo: Path) -> int | None:
    """When the newest build commit on `origin/main` or a build branch was made."""
    refs = ["origin/main", *(f"origin/{b}" for b in _build_branches(repo))]
    times = []
    for line in _git(repo, "log", "--format=%ct %s", *refs).splitlines():
        stamp, _, subject = line.partition(" ")
        if _BUILD_SUBJECT.match(subject):
            times.append(int(stamp))
    return max(times, default=None)


def _build_branches(repo: Path) -> list[str]:
    refs = _git(repo, "for-each-ref", "--format=%(refname:short)",
                "refs/remotes/origin/build/").split()
    return [r.removeprefix("origin/") for r in refs]


def status(repo: Path, now: float | None = None) -> dict:
    """The build's position, read from `origin`: the phase's branch when it exists,
    `main` otherwise (tasks.md §2 step 2)."""
    import time

    now = time.time() if now is None else now
    commit = newest_build_commit(repo)
    commit_age = None if commit is None else (now - commit) / 3600
    alive = {"alive": commit_age is not None and commit_age < WINDOW_HOURS,
             "newest_build_commit_hours": None if commit_age is None else round(commit_age, 2)}
    on_main = position(_git(repo, "show", f"origin/main:{TASKS}"))
    if on_main is None:
        return {"phase": None, "next_task": None, "branch": None, "branch_exists": False,
                "action": "finish the build", **alive}
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
        "action": "continue the task" if current.task else "land the phase",
        **alive,
    }
