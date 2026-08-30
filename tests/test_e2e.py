"""End-to-end: the real container, the real scanner, no fakes.

Slow and runtime-dependent, hence the marker. Everything else runs against an
injected fake at the container boundary.
"""

import pytest

from valvur import scan
from valvur.adapters import GitleaksAdapter
from valvur.runner import ContainerRunner


@pytest.mark.e2e
def test_a_real_container_scan_finds_the_planted_secret(workspace):
    run = scan(workspace, runner=ContainerRunner())

    assert "aws-access-token" in [f.rule for f in run.findings]


@pytest.mark.e2e
def test_a_real_container_scan_redacts_the_secret_it_found(workspace):
    scan(workspace, runner=ContainerRunner())

    summary = (workspace / ".security-scan" / "SUMMARY.md").read_text()

    assert "AKIAV7Q2XR4TVBN6WLKJ" not in summary


@pytest.mark.e2e
def test_a_workspace_path_with_shell_metacharacters_scans_safely(tmp_path):
    """N2.3 — argument-list invocation means a path can never be reinterpreted as a
    command. The canary file must not exist afterwards."""
    import shutil

    from conftest import FIXTURES

    canary = tmp_path / "PWNED"
    nasty = tmp_path / f"repo; touch {canary}; echo 'x' && whoami #$(id)"
    shutil.copytree(FIXTURES / "broken-repo", nasty)

    run = scan(nasty, runner=ContainerRunner(), adapters=[GitleaksAdapter()])

    assert not canary.exists(), "the path was interpreted by a shell"
    assert len(run.findings) >= 1, "the scan should still work on an awkward path"
