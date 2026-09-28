"""R3.8: `full` adds one networked Scan Container (D4; N2.1, ADR-0010, ADR-0016).

The constraint tests hold the argv; this runs a real `full` scan through both
containers on the image and reads what came back.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.e2e
def test_a_full_scan_runs_both_containers_and_leaves_neither(mountable_tmp, monkeypatch):
    from valvur import api
    from valvur.engine_host import ContainerRuntime

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws = mountable_tmp / "ws"
    shutil.copytree(FIXTURES / "broken-repo", ws)

    def listed() -> set[str]:
        return set(subprocess.run(["docker", "ps", "-a", "--filter", "name=valvur-",
                                   "--format", "{{.Names}}"], capture_output=True,
                                  text=True, check=True).stdout.split())

    before = listed()
    run = api.scan(ws, runner=ContainerRuntime(), profile="full")
    by_tool = {s.tool: s for s in run.scanners}
    assert by_tool["osv-scanner"].ok, by_tool["osv-scanner"]
    assert by_tool["trivy"].ok, by_tool["trivy"]
    assert by_tool["dependency-reality"].ok, by_tool["dependency-reality"]
    assert run.network_used
    assert listed() - before == set()
