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


@pytest.mark.e2e
def test_a_real_cancel_at_width_two_launches_nothing_after_and_leaves_nothing_behind(
        mountable_tmp, monkeypatch):
    """The measurement behind R1.1, against the real image: two tools at a time,
    so the rest are queued when the cancel lands. Before the fix the fleet
    launched two or three containers after the client had gone (R0.6). Since
    R3.9 the queue is inside the one Scan Container, and the cancel stops it."""
    import shutil
    import subprocess
    import time
    from pathlib import Path

    from valvur.mcp import handlers, jobs
    from valvur.mcp.jobs import State
    from valvur.runner import detect_runtime

    runtime = detect_runtime()

    def live() -> set[str]:
        out = subprocess.run([runtime, "ps", "--filter", "name=valvur-", "--format",
                              "{{.Names}}"], capture_output=True, text=True, check=False,
                             timeout=30)
        return set(out.stdout.split())

    workspace = mountable_tmp / "ws"
    shutil.copytree(Path(__file__).parent / "fixtures" / "broken-repo", workspace)
    monkeypatch.setenv("VALVUR_JOBS", "2")
    jobs.reset()
    before = live()
    # Started as the MCP `scan` tool starts it, without waiting for its result.
    jobs.start(workspace.resolve(), "offline", handlers._work(None, fresh=False))

    def scanning() -> set[str]:
        """Scan Containers carry their generation; the image probes carry `none`."""
        out = subprocess.run([runtime, "ps", "--filter", "name=valvur-", "--format",
                              '{{.Names}} {{.Label "valvur.generation"}}'],
                             capture_output=True, text=True, check=False, timeout=30)
        return {n for n, _, g in (line.partition(" ") for line in out.stdout.splitlines())
                if g and g != "none"}

    seen: set[str] = set()
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:            # past the probe, into the scan
        seen |= live() - before
        if scanning() - before:
            break
        time.sleep(0.2)
    assert scanning() - before, f"the Scan Container never started: {sorted(seen)}"
    time.sleep(1.0)                               # two tools running, the rest queued

    handlers.cancel_scan({"workspace": str(workspace)})
    known = set(seen) | (live() - before)
    job = jobs.current(workspace.resolve())
    launched_after: set[str] = set()
    while not job.settled.is_set() and time.monotonic() < deadline:
        launched_after |= (live() - before) - known
        time.sleep(0.1)

    assert job.state is State.CANCELLED, job.error
    assert live() - before == set(), "CANCELLED was reported with a container still listed"
    assert launched_after == set(), f"launched after the cancel: {sorted(launched_after)}"
    jobs.reset()
