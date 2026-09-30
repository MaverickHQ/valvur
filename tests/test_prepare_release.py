"""R16.2: `scripts/prepare_release.py` (D33, N3.4).

A release is prepared by one command, in one commit: the version, the lock, the
README's *release in progress*, `SECURITY.md`'s series, the CHANGELOG's heading, and
since R15 the skill, the plugin and the power. `--published` makes the commit that
flips the README once the run has promoted. `--dry-run` says what either would change
and changes nothing. The tag and the brake stay the owner's.

Run here against a copy of the files the script edits, in a repository of its own.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "prepare_release.py"
COPIED = ("pyproject.toml", "uv.lock", "README.md", "SECURITY.md", "CHANGELOG.md",
          "src/valvur/data/skills", "plugins", "powers", "docs/examples")


def _script():
    spec = importlib.util.spec_from_file_location("prepare_release", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["prepare_release"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          check=True).stdout


@pytest.fixture
def tree(tmp_path) -> Path:
    root = tmp_path / "repo"
    for name in COPIED:
        source, target = REPO / name, root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if source.is_dir() else shutil.copy2)(source, target)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "test")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "chore: the tree before")
    return root


def _declared(root: Path) -> str:
    return re.search(r'^version = "([^"]+)"', (root / "pyproject.toml").read_text(), re.M)[1]


#: The version each test prepares: the next minor of whatever this tree is, so the
#: tests hold before a release is prepared and after.
MAJOR, MINOR, _ = (int(n) for n in _declared(REPO).split("."))
NEXT = f"{MAJOR}.{MINOR + 1}.0"
SERIES = f"{MAJOR}.{MINOR + 1}.x"


def test_one_commit_sets_every_version_surface(tree):
    before = _declared(tree)

    assert _script().main([NEXT, "--root", str(tree), "--date", "2026-10-01"]) == 0

    assert _git(tree, "status", "--porcelain") == ""
    assert _git(tree, "log", "--format=%s").splitlines()[:2] == [
        f"chore: release {NEXT}", "chore: the tree before"]
    assert _declared(tree) == NEXT
    assert re.search(r'name = "valvur"\nversion = "1\.2\.0"', (tree / "uv.lock").read_text())
    status = next(line for line in (tree / "README.md").read_text().splitlines()
                  if "**Status: `" in line)
    assert status.startswith(f"> **Status: `{NEXT}`** — release in progress")
    assert f"serves `{before}`" in status
    assert re.findall(r"^\| `([^`]+)` \|", (tree / "SECURITY.md").read_text(), re.M) == [SERIES]
    changelog = (tree / "CHANGELOG.md").read_text()
    assert f"## [Unreleased]\n\n## [{NEXT}] — 2026-10-01\n" in changelog
    for skill in ("src/valvur/data/skills/valvur", "plugins/valvur/skills/valvur",
                  "powers/valvur/skills/valvur"):
        assert f'version: "{NEXT}"' in (tree / skill / "SKILL.md").read_text(), skill
    assert (tree / "plugins/valvur/skills/valvur/SKILL.md").read_bytes() == \
        (tree / "src/valvur/data/skills/valvur/SKILL.md").read_bytes()
    for manifest in ("plugins/valvur/.claude-plugin/plugin.json", "powers/valvur/plugin.json"):
        assert json.loads((tree / manifest).read_text())["version"] == NEXT, manifest
    for server in ("plugins/valvur/.mcp.json", "powers/valvur/mcp.json"):
        args = json.loads((tree / server).read_text())["mcpServers"]["valvur"]["args"]
        assert f"valvur=={NEXT}" in args, server
    for example in ("docs/examples/github-actions.yml", "docs/examples/gitlab-ci.yml"):
        assert f"ghcr.io/maverickhq/valvur:{NEXT}" in (tree / example).read_text(), example


def test_published_flips_the_readme_once_the_run_has_promoted(tree):
    script = _script()
    assert script.main([NEXT, "--root", str(tree), "--date", "2026-10-01"]) == 0

    assert script.main(["--published", NEXT, "--root", str(tree),
                        "--date", "2026-10-02"]) == 0

    status = next(line for line in (tree / "README.md").read_text().splitlines()
                  if "**Status: `" in line)
    assert status.startswith(f"> **Status: `{NEXT}`** — published and installable")
    assert "release in progress" not in status
    assert _git(tree, "log", "-1", "--format=%s").strip() == f"docs: {NEXT} published"


def test_published_refuses_a_version_the_tree_is_not(tree, capsys):
    assert _script().main(["--published", "9.9.9", "--root", str(tree)]) == 2
    assert "9.9.9" in capsys.readouterr().err


def test_a_dry_run_changes_nothing_and_says_what_it_would(tree, capsys):
    head = _git(tree, "rev-parse", "HEAD")
    files = {p: p.read_bytes() for p in tree.rglob("*") if p.is_file() and ".git" not in p.parts}

    assert _script().main([NEXT, "--root", str(tree), "--dry-run"]) == 0
    out = capsys.readouterr().out

    assert _git(tree, "rev-parse", "HEAD") == head
    assert {p: p.read_bytes() for p in files} == files
    for name in ("pyproject.toml", "uv.lock", "README.md", "SECURITY.md", "CHANGELOG.md",
                 "powers/valvur/mcp.json"):
        assert name in out, name
