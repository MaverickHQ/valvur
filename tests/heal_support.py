"""What the heal's tests share (R44.2, R44.3): a tree whose lock the recipe itself wrote.

Resolution is real and hermetic, as in `test_checkov_lock_recipe.py`: a wheel for every
version a test names, read by uv from a directory and from no index. PyPI's facts about the
same versions are the fake registry's, answered by URL in the script's own process. `valvur
check` reads a Name Index in a `VALVUR_CACHE` made here. Nothing opens a socket.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from conftest import write_name_index
from fake_registry import FakePackageRegistry, pypi_answers
from test_checkov_lock_recipe import _tree, _wheel

REPO = Path(__file__).resolve().parent.parent
HEAL = REPO / "scripts" / "heal.py"
LOCK = "requirements-checkov.txt"


def tree(tmp_path: Path, monkeypatch, have: dict[str, str],
         projects: dict[str, dict[str, dict]], *, top: tuple[str, ...] = (),
         known: tuple[str, ...] | None = None) -> Path:
    """A copy of the recipe in a tree of its own, with a lock that holds `have`.

    `projects` maps a project to its versions, and a version to its facts: `uploaded`,
    `publisher`, `yanked` (`fake_registry.pypi_answers`) and `requires`, its `Requires-Dist`.
    `top` is what `requirements-checkov.in` names: every package of `have`, by default.
    The names `known` exist in the Name Index: every project's, by default, and with
    `known=()` there is no index at all."""
    FakePackageRegistry(tmp_path / "registry", pypi_answers(projects)).install(monkeypatch)
    cache = tmp_path / "cache"
    if known != ():
        write_name_index(cache / "valvur" / "names",
                         pip=list(projects if known is None else known))
    monkeypatch.setenv("VALVUR_CACHE", str(cache))
    made, wheels = _tree(tmp_path, "\n".join(top or tuple(have)))
    for name, versions in projects.items():
        for version, facts in versions.items():
            _wheel(wheels, name, version, tuple(facts.get("requires", ())))
    # uv reads no index but the wheels: its `--no-index` has no environment variable, so
    # a configuration file says it, for the recipe here and for the one the heal runs.
    config = tmp_path / "uv.toml"
    config.write_text(f'[pip]\nno-index = true\nfind-links = ["{wheels}"]\n')
    monkeypatch.setenv("UV_CONFIG_FILE", str(config))
    start = tmp_path / "start.txt"
    start.write_text("".join(f"{name}=={version}\n" for name, version in have.items()))
    first = subprocess.run(["sh", str(made / "scripts" / "lock-checkov.sh"), "--no-annotate",
                            "--constraint", str(start)], capture_output=True, text=True,
                           check=False)
    assert first.returncode == 0, first.stderr
    return made
