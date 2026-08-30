import json
import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def workspace(tmp_path):
    """A disposable copy of the broken fixture repo."""
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURES / "broken-repo", ws)
    return ws


@pytest.fixture
def clean_workspace(tmp_path):
    ws = tmp_path / "clean"
    shutil.copytree(FIXTURES / "clean-repo", ws)
    return ws


GITLEAKS_ONE_SECRET = json.dumps([
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "File": "/workspace/config.py",
        "StartLine": 3,
        "Secret": "AKIAV7Q2XR4TVBN6WLKJ",
        "Match": 'AWS_ACCESS_KEY_ID = "AKIAV7Q2XR4TVBN6WLKJ"',
    }
])


class FakeRunner:
    """Stands in for the container runtime — a system boundary, so faking is fair game.

    SDK-style: one method per scanner operation, each returning one shape.
    """

    def __init__(self, gitleaks_stdout: str = "[]", exit_code: int = 0):
        self._stdout = gitleaks_stdout
        self._exit_code = exit_code

    def run_gitleaks(self, workspace: Path):
        from valvur.runner import ScannerOutput

        return ScannerOutput(
            tool="gitleaks", version="8.30.1",
            stdout=self._stdout, stderr="", exit_code=self._exit_code,
        )


@pytest.fixture
def runner_finding_one_secret():
    return FakeRunner(GITLEAKS_ONE_SECRET, exit_code=1)  # gitleaks exits 1 when it finds something


@pytest.fixture
def runner_finding_nothing():
    return FakeRunner("[]", exit_code=0)


@pytest.fixture
def git_workspace(workspace):
    """A Workspace that is a real git repo with a clean tree."""
    import subprocess

    def git(*args):
        subprocess.run(["git", *args], cwd=workspace, check=True,
                       capture_output=True, env={"HOME": str(workspace), "PATH": "/usr/bin:/bin"})

    git("init", "-q", "-b", "main")
    git("-c", "user.email=t@example.com", "-c", "user.name=t",
        "-c", "commit.gpgsign=false", "add", "-A")
    git("-c", "user.email=t@example.com", "-c", "user.name=t",
        "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
    return workspace
