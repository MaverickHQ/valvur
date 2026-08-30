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

    def _quiet(self, tool, version, payload):
        from valvur.runner import ScannerOutput

        return ScannerOutput(tool=tool, version=version, stdout=payload,
                             stderr="", exit_code=0)

    def run_trivy(self, workspace: Path):
        """Quiet by default. Tests exercising a Scanner use GoldenRunner instead."""
        return self._quiet("trivy", "0.74.0", '{"Results": []}')

    def run_osv(self, workspace: Path):
        return self._quiet("osv-scanner", "2.2.4", '{"results": []}')

    def run_checkov(self, workspace: Path):
        return self._quiet("checkov", "3.2.517", '{"results": {"failed_checks": []}}')

    def run_syft(self, workspace: Path):
        return self._quiet("syft", "1.51.1", "")

    def run_opengrep(self, workspace: Path):
        return self._quiet("opengrep", "1.29.0", '{"results": []}')

    def run_check(self, name: str, workspace: Path):
        """Runs valvur's own Checks in-process. They are pure functions of the
        Workspace, so there is nothing at the container boundary worth faking."""
        import json as _json

        from valvur.checks import REGISTRY
        from valvur.runner import ScannerOutput

        check = REGISTRY.get(name)
        payload = _json.dumps(check.run(workspace)) if check else "[]"
        return ScannerOutput(tool=name, version="0.1.0.dev0", stdout=payload,
                             stderr="", exit_code=0)


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


def gitleaks_output(*, line=3, file="/workspace/config.py", secret="AKIAV7Q2XR4TVBN6WLKJ",
                    rule="aws-access-token", match=None):
    """Build gitleaks-shaped output, so tests can vary one thing at a time."""
    return json.dumps([{
        "RuleID": rule,
        "Description": "AWS Access Token",
        "File": file,
        "StartLine": line,
        "Secret": secret,
        "Match": match if match is not None else f'AWS_ACCESS_KEY_ID = "{secret}"',
    }])


class CrashingAdapter:
    """A Scanner that dies. Not a mock of an internal collaborator — a real adapter
    whose tool fails, which is the only way to exercise fleet failure isolation."""

    name = "exploding-scanner"

    def __init__(self, reason="container exited 137 (OOM)"):
        self._reason = reason

    def run(self, runner, workspace):
        raise RuntimeError(self._reason)

    def parse(self, output):  # pragma: no cover - never reached
        return []


# Golden fixtures carry the Scanner version in the filename. If a Scanner is upgraded
# without recapturing, this mismatch fails loudly rather than silently re-baselining
# parsing behaviour (task 3.4.1).
PINNED_VERSIONS = {
    "trivy": "0.74.0", "gitleaks": "8.30.1", "osv-scanner": "2.2.4",
    "checkov": "3.2.517", "syft": "1.51.1", "opengrep": "1.29.0",
}


def golden(tool: str) -> str:
    version = PINNED_VERSIONS[tool]
    path = FIXTURES / "golden" / f"{tool}-{version}.json"
    if not path.is_file():
        raise AssertionError(
            f"No golden fixture for {tool} {version}. If you upgraded {tool}, "
            f"recapture it and review the diff — parsing behaviour may have changed."
        )
    return path.read_text(encoding="utf-8")


class GoldenRunner:
    """Serves captured real Scanner output, so adapters are tested against reality."""

    def __init__(self, **by_tool):
        self._by_tool = by_tool

    def _out(self, tool):
        from valvur.runner import ScannerOutput

        return ScannerOutput(tool, PINNED_VERSIONS.get(tool, ""),
                             self._by_tool.get(tool, ""), "", 0)

    def run_trivy(self, workspace):
        return self._out("trivy")

    def run_gitleaks(self, workspace):
        return self._out("gitleaks")

    def run_osv(self, workspace):
        return self._out("osv-scanner")

    def run_checkov(self, workspace):
        return self._out("checkov")

    def run_syft(self, workspace):
        return self._out("syft")

    def run_opengrep(self, workspace):
        return self._out("opengrep")

    def run_check(self, name, workspace):
        import json as _json

        from valvur.checks import REGISTRY
        from valvur.runner import ScannerOutput

        check = REGISTRY.get(name)
        return ScannerOutput(name, "0.1.0.dev0",
                             _json.dumps(check.run(workspace)) if check else "[]", "", 0)
