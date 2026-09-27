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


class _Held(_Runner):
    """Gitleaks runs until it is cancelled; its container then stays listed by
    the runtime until the test releases it — the moment between `docker kill`
    returning and `--rm` removing the container."""

    def __init__(self):
        super().__init__(cancel_during="none")
        import threading

        self.in_gitleaks = threading.Event()
        self.waiting_for_runtime = threading.Event()
        self.runtime_empty = threading.Event()

    def run_gitleaks(self, workspace):
        import time

        self.calls.append("gitleaks")
        self.in_gitleaks.set()
        deadline = time.monotonic() + 5
        while not self.cancelled and time.monotonic() < deadline:
            time.sleep(0.01)
        return ScannerOutput("gitleaks", "8.30.1", "", "killed", 137)

    def wait_stopped(self) -> None:
        self.waiting_for_runtime.set()
        self.runtime_empty.wait(5)


def test_cancelled_is_reported_only_once_the_runtime_lists_none_of_its_containers(workspace):
    from valvur.mcp import jobs
    from valvur.mcp.jobs import State

    jobs.reset()
    runner = _Held()

    def work(ws, profile, progress):
        jobs.current(ws).canceller = runner.kill
        api.scan(ws, runner=runner, adapters=[GitleaksAdapter(), TrivyAdapter()], jobs=1)

    job = jobs.start(workspace, "offline", work)
    assert runner.in_gitleaks.wait(5)
    jobs.cancel(workspace)
    assert runner.waiting_for_runtime.wait(5)
    assert job.state is State.CANCELLING, "the runtime still lists a container"
    runner.runtime_empty.set()
    assert job.settled.wait(5)
    assert job.state is State.CANCELLED
    jobs.reset()


def test_the_real_runner_waits_until_the_runtime_no_longer_lists_its_container(monkeypatch):
    import subprocess

    from valvur.runner import ContainerRunner

    runner = ContainerRunner(image="x/y:1", runtime="/usr/local/bin/docker")
    runner._mine.add("valvur-abc")
    answers = iter(["valvur-abc\n", "valvur-abc\nvalvur-other\n", "valvur-other\n"])
    polls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        polls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, next(answers, ""), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("time.sleep", lambda _s: None)

    assert runner.wait_stopped(timeout=5) is True
    assert len(polls) == 3, "another runner's container does not hold this one's cancel"
