"""R45.2: a release the heal prepared merges itself only when it can be reproduced.

`scripts/heal_policy.py release` judges a release pull request from the base branch. It
runs `prepare_release.py`'s own plan on the base, with the opening `heal_release.py` writes
from the base's history and the date the commit's trailer names, and asks that the pull
request change exactly those files to exactly that text. The version must be the latest
tag's patch plus one, and the history since that tag a security patch's.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_prepare_release import _declared, _git, tree  # noqa: F401

REPO = Path(__file__).resolve().parent.parent
POLICY = REPO / "scripts" / "heal_policy.py"
sys.path.insert(0, str(REPO / "scripts"))
MAJOR, MINOR, PATCH = (int(n) for n in _declared(REPO).split("."))
NOW, NEXT = f"{MAJOR}.{MINOR}.{PATCH}", f"{MAJOR}.{MINOR}.{PATCH + 1}"
HEAL = ("fix: beta 1.1 in the Checkov lock, by the heal\n\nHeal-Pin: beta==1.1\n"
        "Heal-Advisory: CVE-2026-0001 beta published 2026-10-19T16:47:35Z\n"
        "Heal-Run: https://example.invalid/1\n")
RELEASE = f"chore: release {NEXT}\n\nRelease-Date: 2026-11-22\nHeal-Run: https://example.invalid/2\n"


@pytest.fixture
def base(tree):  # noqa: F811
    """The base branch: the last release's tag, and one heal commit since."""
    _git(tree, "config", "tag.gpgsign", "false")
    _git(tree, "config", "core.hooksPath", "/dev/null")
    (tree / "requirements-checkov.txt").write_text("beta==1.0 \\\n    --hash=sha256:00\n")
    _git(tree, "add", "-A")
    _git(tree, "commit", "-q", "-m", f"chore: release {NOW}")
    _git(tree, "tag", f"v{NOW}")
    (tree / "requirements-checkov.txt").write_text("beta==1.1 \\\n    --hash=sha256:00\n")
    _git(tree, "add", "-A")
    _git(tree, "commit", "-q", "-m", HEAL)
    return tree


def _prepared(base: Path, tmp_path: Path, version: str = NEXT, date: str = "2026-11-22"
              ) -> tuple[Path, list[str]]:
    """The pull request's files, as the heal's release job makes them: the plan of
    `prepare_release.py` with the heal's opening, written apart."""
    import heal_release
    import prepare_release

    plan = prepare_release.planned(base, version, date, heal_release.opening(base, f"v{NOW}"))
    head = tmp_path / "head"
    changed = []
    for path, text in plan.items():
        if (base / path).read_text() != text:
            (head / path).parent.mkdir(parents=True, exist_ok=True)
            (head / path).write_text(text)
            changed.append(str(path))
    return head, changed


def _judge(base: Path, head: Path, files: list[str], message: str = RELEASE, *,
           author: str = "valvur-heal[bot]") -> subprocess.CompletedProcess[str]:
    view = {"files": [{"path": path} for path in files],
            "commits": [{"sha": "0" * 40, "author": {"login": author},
                         "committer": {"login": "web-flow"},
                         "commit": {"message": message, "verification": {"verified": True}}}]}
    return subprocess.run([sys.executable, str(POLICY), "release", "--base", str(base),
                           "--head", str(head)], input=json.dumps(view), capture_output=True,
                          text=True, check=False)


def test_a_release_that_prepare_release_reproduces_on_the_base_is_eligible(base, tmp_path):
    head, files = _prepared(base, tmp_path)

    run = _judge(base, head, files)

    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.startswith(f"eligible: {NEXT} reproduced")
    assert "CHANGELOG.md" in files and "pyproject.toml" in files


def test_any_other_change_leaves_it_for_the_owner(base, tmp_path):
    head, files = _prepared(base, tmp_path)
    (head / "README.md").write_text((head / "README.md").read_text() + "\nOne more line.\n")
    edited = _judge(base, head, files)
    head, files = _prepared(base, tmp_path)
    (head / "src").mkdir(exist_ok=True)
    (head / "src" / "extra.py").write_text("print(1)\n")
    added = _judge(base, head, [*files, "src/extra.py"])
    missing = _judge(base, head, [f for f in files if f != "uv.lock"])

    assert edited.returncode == 1 and "README.md" in edited.stdout
    assert added.returncode == 1 and "src/extra.py" in added.stdout
    assert missing.returncode == 1 and "uv.lock" in missing.stdout


@pytest.mark.parametrize("version", [f"{MAJOR}.{MINOR + 1}.0", f"{MAJOR}.{MINOR}.{PATCH + 2}"])
def test_a_version_that_is_not_the_patch_plus_one_leaves_it_for_the_owner(
        base, tmp_path, version):
    head, files = _prepared(base, tmp_path, version)

    run = _judge(base, head, files, RELEASE.replace(NEXT, version))

    assert run.returncode == 1 and "patch plus one" in run.stdout


def test_history_that_check_refuses_leaves_it_for_the_owner(base, tmp_path):
    (base / "README.md").write_text((base / "README.md").read_text() + "\n")
    _git(base, "add", "-A")
    _git(base, "commit", "-q", "-m", "feat: a new command")
    head, files = _prepared(base, tmp_path)

    run = _judge(base, head, files)

    assert run.returncode == 1 and "feat" in run.stdout


@pytest.mark.parametrize("message, author, names", [
    (RELEASE.replace("Release-Date: 2026-11-22\n", ""), "valvur-heal[bot]", "Release-Date"),
    (RELEASE.replace("2026-11-22", "2026-11-23"), "valvur-heal[bot]", "CHANGELOG.md"),
    (RELEASE, "someone-else", "someone-else"),
    (RELEASE.replace("chore: release", "chore: releases"), "valvur-heal[bot]", "chore: release"),
])
def test_a_commit_that_is_not_the_heals_release_commit_is_refused(
        base, tmp_path, message, author, names):
    head, files = _prepared(base, tmp_path)

    run = _judge(base, head, files, message, author=author)

    assert run.returncode == 1 and names in run.stdout
