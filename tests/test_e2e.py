"""End-to-end: the real container, the real scanner, no fakes.

Slow and runtime-dependent, hence the marker. Everything else runs against an
injected fake at the container boundary.
"""

import pytest

from valvur import scan
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
