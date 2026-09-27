"""R1.1: a cancel stops the queue (F1.11; the second gate's C1).

At width 2 the fleet queued Scanners, and `scan_cancel` stopped only the ones
running: measured on the second gate, Scanners launched after the cancel and
`CANCELLED` was reported with a container still up. These tests run the fleet
one wide, so every Scanner after the first is queued when the cancel lands.
"""

from __future__ import annotations

import pytest
from conftest import LegacyDispatch

from valvur import api
from valvur.adapters import GitleaksAdapter, TrivyAdapter
from valvur.runner import ScannerOutput


class _Runner(LegacyDispatch):
    """Cancelled the way the real runner is: `kill()` sets the flag, and the
    Scanner that was running comes back with no report."""

    image = "x/y:1"

    def __init__(self, *, cancel_during: str):
        self.cancelled = False
        self.cancel_during = cancel_during
        self.calls: list[str] = []
        self.waited = False

    def kill(self) -> int:
        self.cancelled = True
        return 1

    def _scanner(self, tool: str, version: str, payload: str) -> ScannerOutput:
        self.calls.append(tool)
        if self.cancel_during == tool:
            self.kill()
            return ScannerOutput(tool, version, "", "killed", 137)
        return ScannerOutput(tool, version, payload, "", 0)

    def run_gitleaks(self, workspace):
        return self._scanner("gitleaks", "8.30.1", "[]")

    def run_trivy(self, workspace):
        return self._scanner("trivy", "0.74.0", '{"Results": []}')


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.setattr(cache, "db_present", lambda: True)
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("print('hi')\n")
    return ws


def test_a_scanner_queued_behind_a_cancel_is_never_launched(workspace):
    runner = _Runner(cancel_during="gitleaks")
    with pytest.raises(api.ScanCancelled):
        api.scan(workspace, runner=runner, adapters=[GitleaksAdapter(), TrivyAdapter()],
                 jobs=1)
    assert runner.calls == ["gitleaks"]
