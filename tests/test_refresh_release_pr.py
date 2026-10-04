"""R28.4: the monthly refresh opens a release pull request (D64c).

When the Scanner pins moved since the latest release and the Score held, `refresh.yml`
now prepares the next patch release with `prepare_release.py` and opens a pull request
of it, where it opened an issue asking the owner to. The commit is written through
GitHub's API, which signs it, so `main`'s signed history can take it by fast-forward.
It never tags: the tag and the brake stay the owner's (ADR-0020, D64e).
"""

from __future__ import annotations

import base64
import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = (REPO / ".github" / "workflows" / "refresh.yml").read_text()

_spec = importlib.util.spec_from_file_location("signed_push", REPO / "scripts" / "signed_push.py")
signed_push = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(signed_push)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.invalid")
    _git(root, "config", "user.name", "t")
    _git(root, "config", "commit.gpgsign", "false")
    (root / "pyproject.toml").write_text('version = "1.4.0"\n')
    (root / "gone.txt").write_text("x\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    (root / "pyproject.toml").write_text('version = "1.4.1"\n')
    (root / "docs").mkdir()
    (root / "docs" / "new.md").write_text("new\n")
    (root / "gone.txt").unlink()
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "chore: release 1.4.1")
    return root


def test_the_commit_is_restated_for_the_api_with_every_change(repo):
    variables = signed_push.variables(repo, "MaverickHQ/valvur", "release/v1.4.1")

    commit = variables["input"]
    assert commit["branch"] == {"repositoryNameWithOwner": "MaverickHQ/valvur",
                                "branchName": "release/v1.4.1"}
    assert commit["expectedHeadOid"] == _git(repo, "rev-parse", "HEAD~1")
    assert commit["message"] == {"headline": "chore: release 1.4.1"}
    additions = {a["path"]: base64.b64decode(a["contents"]).decode()
                 for a in commit["fileChanges"]["additions"]}
    assert additions == {"pyproject.toml": 'version = "1.4.1"\n', "docs/new.md": "new\n"}
    assert commit["fileChanges"]["deletions"] == [{"path": "gone.txt"}]


@pytest.mark.parametrize("branch", ["main", "v1.4.1", "refs/tags/v1.4.1", "release/../main",
                                    "release/v1.4"])
def test_it_writes_only_a_release_branch(repo, branch):
    """Never `main`, never a tag: only `release/vX.Y.Z`."""
    with pytest.raises(ValueError):
        signed_push.variables(repo, "MaverickHQ/valvur", branch)


def test_it_writes_nothing_but_a_branch_and_a_commit():
    text = (REPO / "scripts" / "signed_push.py").read_text()

    assert "createCommitOnBranch" in text and "git/refs" in text
    assert "refs/tags" not in text and "git push" not in text


# ---------------------------------------------------------------- the workflow

def _step(name: str) -> str:
    return WORKFLOW.split(f"- name: {name}", 1)[1].split("\n      - ", 1)[0]


def test_a_score_that_held_prepares_the_next_patch_and_opens_a_pull_request():
    step = _step("A release pull request for the owner")

    assert "steps.score.outcome == 'success'" in step.split("run:", 1)[0]
    assert 'scripts/prepare_release.py "$next"' in step
    assert "scripts/signed_push.py" in step
    assert "gh pr create" in step and '--head "$branch"' in step and "--base main" in step
    assert 'branch="release/v$next"' in step


def test_the_next_patch_is_the_latest_release_s_plus_one():
    step = _step("A release pull request for the owner")
    script = step.split("run: |", 1)[1]
    computed = re.search(r'^\s*(ver=.*\n\s*next=.*)$', script, re.M)[1]

    out = subprocess.run(["bash", "-c", f'SINCE=v1.4.0\n{computed}\necho "$next"'],
                         capture_output=True, text=True, check=True).stdout.strip()
    assert out == "1.4.1"


def test_a_score_that_fell_still_tells_the_owner_in_an_issue():
    step = _step("One issue for the owner")

    assert "steps.score.outcome != 'success'" in step.split("run:", 1)[0]


def test_it_never_tags_or_publishes():
    """It reads the latest tag (`git describe --tags`); it writes none."""
    assert not re.search(r"git (tag|push)|push\s+--tags|refs/tags|gh release|cosign|"
                         r"docker push", WORKFLOW)
    assert "git describe --tags" in WORKFLOW


def test_its_permissions_are_what_the_pull_request_needs():
    job = WORKFLOW.split("\n    permissions:\n", 1)[1].split("\n    timeout-minutes", 1)[0]
    granted = dict(line.split("#")[0].strip().split(": ") for line in job.splitlines())

    assert granted == {"contents": "write", "issues": "write", "actions": "write",
                       "pull-requests": "write"}
