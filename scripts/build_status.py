"""Where the unattended build stands (tasks.md §2, task R0.1).

A resuming session runs this to learn the current phase, its branch, the next
task, and whether another executor looks alive. It reads git and the task list;
it changes nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

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
