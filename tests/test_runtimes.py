"""Sub-phases 8.1 and 8.2 — portability and isolation across container runtimes.

The file-ownership tests are the reason ADR-0001 exists: container-written files land
with different ownership on every runtime, which is why the shim writes the Results
Folder itself rather than the container doing it.
"""

import os
import shutil
from pathlib import Path

import pytest

from valvur import scan
from valvur.adapters import GitleaksAdapter
from valvur.runner import _EXTRA_LOCATIONS, ContainerRunner, detect_runtime


def _available(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for location in _EXTRA_LOCATIONS:
        candidate = Path(location).expanduser() / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


RUNTIMES = [
    pytest.param(name, marks=pytest.mark.skipif(
        _available(name) is None, reason=f"{name} not installed"))
    for name in ("docker", "podman")
]


# ------------------------------------------------------------- 8.1 ownership

@pytest.mark.e2e
@pytest.mark.parametrize("runtime", RUNTIMES)
def test_results_are_owned_by_the_invoking_user(workspace, runtime):
    """F1.4 — the reason ADR-0001 exists.

    Under rootful Docker a container-written file lands owned by root; under rootless
    Podman it lands owned by a subuid the user cannot even read. The developer would
    need sudo to delete their own scan output. The shim writes these files instead,
    so ownership is correct by construction on every runtime.
    """
    scan(workspace, runner=ContainerRunner(runtime=_available(runtime)),
         adapters=[GitleaksAdapter()], profile="quick")

    written = [p for p in (workspace / ".security-scan").rglob("*") if p.is_file()]
    assert written

    mine = os.getuid()
    wrong = [p.name for p in written if p.stat().st_uid != mine]
    assert wrong == [], f"{runtime}: files not owned by the invoking user: {wrong}"


@pytest.mark.e2e
@pytest.mark.parametrize("runtime", RUNTIMES)
def test_a_scan_finds_the_same_things_on_every_runtime(workspace, runtime):
    """Portability is not just about permissions: the answer must match too."""
    run = scan(workspace, runner=ContainerRunner(runtime=_available(runtime)),
               adapters=[GitleaksAdapter()], profile="quick")

    assert "aws-access-token" in [f.rule for f in run.findings]


# ------------------------------------------------------------- 8.2 isolation

@pytest.mark.e2e
def test_the_container_cannot_write_to_the_workspace(workspace):
    """F1.1 — the mount IS the jail. Not a check we perform, a thing that cannot happen."""
    import subprocess

    runner = ContainerRunner()
    result = subprocess.run(
        [runner.runtime, "run", "--rm", "-v", f"{workspace}:/workspace:ro",
         "--entrypoint", "sh", runner.image, "-c", "touch /workspace/EVIDENCE"],
        capture_output=True, text=True, check=False,
    )

    assert result.returncode != 0
    assert not (workspace / "EVIDENCE").exists()


@pytest.mark.e2e
def test_a_workspace_path_containing_spaces_scans_correctly(tmp_path):
    from conftest import FIXTURES

    awkward = tmp_path / "my project (v2)" / "the repo"
    shutil.copytree(FIXTURES / "broken-repo", awkward)

    run = scan(awkward, runner=ContainerRunner(), adapters=[GitleaksAdapter()],
               profile="quick")

    assert run.findings


@pytest.mark.e2e
def test_a_symlink_pointing_outside_the_workspace_reaches_nothing(tmp_path):
    """The interesting case is not that symlinks work — it is that escape is
    structurally impossible. The link's target is simply not in the mount."""
    import subprocess

    from conftest import FIXTURES

    workspace = tmp_path / "ws"
    shutil.copytree(FIXTURES / "broken-repo", workspace)
    secret = tmp_path / "outside-secret.txt"
    secret.write_text("AKIAV7Q2XR4TVBN6WLKJ\n")
    (workspace / "escape.txt").symlink_to(secret)

    runner = ContainerRunner()
    result = subprocess.run(
        [runner.runtime, "run", "--rm", "-v", f"{workspace}:/workspace:ro",
         "--entrypoint", "sh", runner.image, "-c", "cat /workspace/escape.txt"],
        capture_output=True, text=True, check=False,
    )

    assert "AKIAV7Q2XR4TVBN6WLKJ" not in result.stdout


# --------------------------------------------------- 8.2.9 runtime detection

def test_runtime_detection_finds_installs_that_are_not_on_path(monkeypatch):
    """Podman Desktop puts a working runtime at /opt/podman/bin and leaves PATH
    alone. Telling that user to install what they already have is the worst kind of
    first-run failure."""
    monkeypatch.delenv("VALVUR_RUNTIME", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)

    if _available("podman") is None and _available("docker") is None:
        pytest.skip("no runtime installed anywhere")

    assert Path(detect_runtime()).is_file()


def test_no_runtime_produces_actionable_remediation(monkeypatch):
    """F1.5 — an error message is a usability surface."""
    from valvur.runner import NoContainerRuntime

    monkeypatch.delenv("VALVUR_RUNTIME", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)
    monkeypatch.setattr("valvur.runner._EXTRA_LOCATIONS", ())

    with pytest.raises(NoContainerRuntime) as excinfo:
        detect_runtime()

    message = str(excinfo.value)
    assert "brew install" in message
    assert "valvur scan" in message, "the message must name the exact next command"
