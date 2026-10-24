"""R42.1: the build reads every spec's task list, the main list first (N3.6).

`.kiro/specs/self-healing-supply-chain/tasks.md` continues the main list's phases. A
resuming session finds its tasks once the main list has none, and a ref the spec has
not reached yet reads as an empty list, never an error.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "build_status.py"

MAIN = """\
### Phase R41: model output reaching a sink

- [x] **R41.1** **Measured.**
"""

SPEC = """\
### Phase R42: the incident closed

- [x] **R42.1** **On the rails.**
- [ ] **R42.2** **The lock fix lands.**
"""


def _module():
    spec = importlib.util.spec_from_file_location("build_status", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["build_status"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                          text=True).stdout


def _repo(tmp_path: Path, lists: dict[str, str]) -> Path:
    """A clone of a bare origin whose `main` carries each spec's list."""
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work))
    for key, value in (("user.name", "t"), ("user.email", "t@example.invalid"),
                       ("commit.gpgsign", "false")):
        _git(work, "config", key, value)
    for name, text in lists.items():
        path = work / ".kiro/specs" / name / "tasks.md"
        path.parent.mkdir(parents=True)
        path.write_text(text)
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "docs: the plan")
    _git(work, "push", "-q", "origin", "main")
    return work


def test_with_the_main_list_done_the_next_spec_s_first_unchecked_task_is_current():
    position = _module().position(MAIN, SPEC)

    assert (position.phase, position.title, position.task) == (
        42, "the incident closed", "R42.2")


def test_the_main_list_comes_first_whatever_the_other_lists_hold():
    main = MAIN.replace("- [x] **R41.1**", "- [ ] **R41.1**")

    assert _module().position(main, SPEC).task == "R41.1"


def test_every_spec_on_a_ref_is_read_the_main_list_first_then_by_name(tmp_path):
    later = "### Phase R50: later\n\n- [ ] **R50.1** **Later.**\n"
    work = _repo(tmp_path, {"zz-later": later, "valvur": MAIN, "self-healing": SPEC})

    lists = _module().task_lists(work, "origin/main")

    assert lists == [MAIN, SPEC, later]
    assert _module().status(work)["next_task"] == "R42.2"


def test_a_ref_without_the_spec_reads_as_an_empty_list(tmp_path):
    work = _repo(tmp_path, {"valvur": MAIN})

    assert _module().task_lists(work, "origin/main") == [MAIN]
    assert _module().status(work)["action"] == "finish the build"


def test_a_phase_branch_is_read_with_every_spec_on_it(tmp_path):
    work = _repo(tmp_path, {"valvur": MAIN})
    _git(work, "checkout", "-q", "-b", "build/r42-the-incident-closed")
    path = work / ".kiro/specs/self-healing/tasks.md"
    path.parent.mkdir(parents=True)
    path.write_text(SPEC)
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "docs(spec): the spec")
    _git(work, "push", "-q", "origin", "build/r42-the-incident-closed")
    _git(work, "checkout", "-q", "main")

    assert _module().task_lists(work, "origin/build/r42-the-incident-closed") == [MAIN, SPEC]


def test_every_live_list_reads_as_the_resume_script_expects():
    module = _module()
    lists = sorted((REPO / module.SPECS).glob("*/tasks.md"))

    assert len(lists) >= 2
    for path in lists:
        assert (path.relative_to(REPO).as_posix(), module.shape_errors(path.read_text())) \
            == (path.relative_to(REPO).as_posix(), [])

