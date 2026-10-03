"""R24.3: no test writes the repository (D55b).

The plugin's and the power's copies of the skill were rewritten by the tests that
held them, under `UPDATE_SKILL=1`. `scripts/sync_skill.py` writes them now, and
`prepare_release.py` runs it; the tests only compare, byte for byte.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_it_makes_each_copy_the_packages_skill_and_nothing_else(tmp_path):
    sync = _load("sync_skill")
    (tmp_path / sync.SKILL / "references").mkdir(parents=True)
    (tmp_path / sync.SKILL / "SKILL.md").write_text("the skill\n")
    (tmp_path / sync.SKILL / "references" / "tools.md").write_text("the tools\n")
    for copy in sync.COPIES:
        (tmp_path / copy).mkdir(parents=True)
        (tmp_path / copy / "stale.md").write_text("gone\n")

    changed = sync.sync(tmp_path)

    assert changed == list(sync.COPIES)
    for copy in sync.COPIES:
        present = sorted(p.relative_to(tmp_path / copy).as_posix()
                         for p in (tmp_path / copy).rglob("*") if p.is_file())
        assert present == ["SKILL.md", "references/tools.md"]
        assert (tmp_path / copy / "SKILL.md").read_text() == "the skill\n"
    assert sync.sync(tmp_path) == []


def test_the_release_preparation_runs_it(tmp_path, monkeypatch):
    release = _load("prepare_release")
    ran: list[Path] = []
    monkeypatch.setattr(release.sync_skill, "sync", lambda root: ran.append(root) or [])
    monkeypatch.setattr(release.subprocess, "run", lambda *a, **k: None)

    release._apply(tmp_path, {}, "chore: release")

    assert ran == [tmp_path]


def test_no_test_writes_the_skills_copies():
    """The switch is gone, from the tests and from what they tell you to run."""
    for path in (REPO / "tests").glob("test_*.py"):
        if path.name != "test_sync_skill.py":
            assert "UPDATE_SKILL" not in path.read_text(encoding="utf-8"), path.name
