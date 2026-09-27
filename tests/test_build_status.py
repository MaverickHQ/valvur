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


def test_a_phase_finished_on_its_branch_but_not_landed_says_to_land_it(tmp_path):
    work = _repo(tmp_path, TASKS)
    _git(work, "checkout", "-q", "-b", "build/r0-pre-flight")
    path = work / ".kiro/specs/valvur/tasks.md"
    path.write_text(TASKS.replace("- [ ] **R0.", "- [x] **R0."))
    _git(work, "commit", "-q", "-am", "chore(r0): close phase R0")
    _git(work, "push", "-q", "origin", "build/r0-pre-flight")
    status = _module().status(work)
    assert (status["phase"], status["next_task"], status["action"]) == (
        "R0", None, "land the phase")


def _age_commit(work: Path, message: str, hours_ago: float, now: float) -> None:
    import os

    stamp = f"{int(now - hours_ago * 3600)} +0000"
    (work / "f.txt").write_text(message)
    _git(work, "add", "f.txt")
    env = {**os.environ, "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}
    import subprocess

    subprocess.run(["git", "commit", "-q", "-m", message], cwd=work, env=env, check=True)
    _git(work, "push", "-q", "origin", "HEAD")


def test_a_build_commit_under_eight_hours_old_means_another_executor_is_alive(tmp_path):
    import time

    now = time.time()
    work = _repo(tmp_path, TASKS)
    _age_commit(work, "feat(r0.2): the machine, recorded", hours_ago=3, now=now)
    status = _module().status(work, now=now)
    assert status["alive"] is True


def test_commits_without_a_phase_scope_do_not_count(tmp_path):
    import time

    now = time.time()
    work = _repo(tmp_path, TASKS)
    _age_commit(work, "feat(r0.2): the machine, recorded", hours_ago=12, now=now)
    _age_commit(work, "build(deps): bump something", hours_ago=1, now=now)
    _age_commit(work, "docs: the owner's own note", hours_ago=1, now=now)
    status = _module().status(work, now=now)
    assert status["alive"] is False


def test_a_recent_change_in_the_working_tree_means_another_executor_is_alive(tmp_path):
    import time

    now = time.time()
    work = _repo(tmp_path, TASKS)
    _age_commit(work, "feat(r0.2): the machine, recorded", hours_ago=12, now=now)
    (work / "half-done.py").write_text("# a slice in progress\n")
    status = _module().status(work, now=now)
    assert status["alive"] is True
