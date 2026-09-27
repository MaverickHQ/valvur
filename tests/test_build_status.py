"""R0.1: `scripts/build_status.py` tells a resuming session where the build stands.

The script is what `tasks.md` §2 has a resuming session run: which phase is current,
on which branch, what the next task is, and whether another executor looks alive.
Tested against fixture task lists and real temporary git repositories.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_status.py"


def _module():
    import sys

    spec = importlib.util.spec_from_file_location("build_status", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    # Registered first: a dataclass looks its module up in sys.modules.
    sys.modules["build_status"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


TASKS = """\
# valvur: tasks

### Phase R0: pre-flight

- [x] **R0.1** **Resuming, armed** (§2). Behaviours:
- [ ] **R0.2** **The machine.** Record: the macOS version.
- [ ] **R0.3** **The toolchain and access.** Record each:

### Phase R1: the `0.6.0` safety release

- [ ] **R1.1** **A cancel stops the queue** (F1.11). Behaviours:
"""


def test_the_current_phase_is_the_first_with_an_unchecked_task():
    position = _module().position(TASKS)
    assert (position.phase, position.title, position.task) == (0, "pre-flight", "R0.2")


def _git(cwd: Path, *args: str) -> str:
    import subprocess

    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                          text=True).stdout


def _repo(tmp_path: Path, tasks: str) -> Path:
    """A clone of a bare origin whose `main` carries `tasks` at the real path."""
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work))
    for key, value in (("user.name", "t"), ("user.email", "t@example.invalid"),
                       ("commit.gpgsign", "false")):
        _git(work, "config", key, value)
    path = work / ".kiro/specs/valvur/tasks.md"
    path.parent.mkdir(parents=True)
    path.write_text(tasks)
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "docs: the plan")
    _git(work, "push", "-q", "origin", "main")
    return work


def test_with_no_phase_branch_the_list_on_main_decides_and_a_branch_is_named(tmp_path):
    work = _repo(tmp_path, TASKS)
    status = _module().status(work)
    assert (status["phase"], status["next_task"]) == ("R0", "R0.2")
    assert status["branch"] == "build/r0-pre-flight"
    assert status["branch_exists"] is False


def test_an_origin_phase_branch_is_read_ahead_of_main(tmp_path):
    work = _repo(tmp_path, TASKS)
    _git(work, "checkout", "-q", "-b", "build/r0-pre-flight")
    path = work / ".kiro/specs/valvur/tasks.md"
    path.write_text(TASKS.replace("- [ ] **R0.2**", "- [x] **R0.2**"))
    _git(work, "commit", "-q", "-am", "feat(r0.2): the machine, recorded")
    _git(work, "push", "-q", "origin", "build/r0-pre-flight")
    _git(work, "checkout", "-q", "main")
    status = _module().status(work)
    assert (status["next_task"], status["branch_exists"]) == ("R0.3", True)
