"""R44.3: the heal's commit reaches GitHub as GitHub signs it, on a heal branch alone.

`scripts/signed_push.py` restates the local commit through `createCommitOnBranch`. For the
heal it writes `heal/<UTC date>-<short tree hash>` and still nothing else: never `main`,
never a tag. The commit's trailers go with it, since the policy and the report read them.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("signed_push", REPO / "scripts" / "signed_push.py")
signed_push = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(signed_push)  # type: ignore[union-attr]

MESSAGE = ("fix: beta 1.1 in the Checkov lock, by the heal\n\n"
           "Heal-Pin: beta==1.1\n"
           "Heal-Advisory: CVE-2026-0001 beta published 2026-10-19T16:47:35Z\n"
           "Heal-Run: https://github.com/MaverickHQ/valvur/actions/runs/1\n")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    for key, value in (("user.name", "t"), ("user.email", "t@example.invalid"),
                       ("commit.gpgsign", "false"), ("core.hooksPath", "/dev/null")):
        _git(root, "config", key, value)
    (root / "requirements-checkov.txt").write_text("beta==1.0\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "chore: the start")
    (root / "requirements-checkov.txt").write_text("beta==1.1\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", MESSAGE)
    return root


def test_a_heal_branch_is_written_with_the_commits_trailers(repo):
    commit = signed_push.variables(repo, "MaverickHQ/valvur", "heal/2026-10-21-1a2b3c4")["input"]

    assert commit["branch"]["branchName"] == "heal/2026-10-21-1a2b3c4"
    assert commit["message"] == {
        "headline": "fix: beta 1.1 in the Checkov lock, by the heal",
        "body": "Heal-Pin: beta==1.1\n"
                "Heal-Advisory: CVE-2026-0001 beta published 2026-10-19T16:47:35Z\n"
                "Heal-Run: https://github.com/MaverickHQ/valvur/actions/runs/1"}


@pytest.mark.parametrize("branch", [
    "main", "heal", "heal/main", "heal/2026-10-21", "heal/2026-10-21-1a2b3c4/../main",
    "heal/2026-10-21-XYZ", "refs/heads/heal/2026-10-21-1a2b3c4", "v1.6.3", "refs/tags/v1.6.3",
    "build/r44", "release/heal/2026-10-21-1a2b3c4"])
def test_no_other_ref_is_written(repo, branch):
    with pytest.raises(ValueError):
        signed_push.variables(repo, "MaverickHQ/valvur", branch)
