"""The server stops what it started (task 27.1.1, F1.11).

`server.main` returned when stdin closed, on Ctrl-C and on a broken pipe, and the
scan jobs it had started were daemon threads: they died with the process. The
containers those jobs launched did not — `runner.py`'s own comment records that the
container runtime owns their lifecycle, which is why `kill_running` and the
`--name valvur-<id>` registry exist (23.3.3). Nothing on the way out called either,
so a client that disconnected mid-scan left the whole fleet running with nobody to
read its result: measured before the fix, seven containers of a `full` scan, still
running after the server was gone.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from valvur.mcp import jobs, server

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _clean_registry():
    jobs.reset()
    yield
    jobs.reset()


class _Held:
    """A job that runs until released, and records being told to stop."""

    def __init__(self):
        self.release = threading.Event()
        self.stopped = threading.Event()
        self.running = threading.Event()

    def kill(self) -> int:
        self.stopped.set()
        self.release.set()
        return 3

    def work(self, workspace, profile, progress):
        jobs.current(workspace).canceller = self.kill
        self.running.set()
        self.release.wait(timeout=10)
        if self.stopped.is_set():
            raise RuntimeError("every Scanner failed")   # what a kill looks like
        return "scan finished normally"


def test_the_server_cancels_an_active_job_when_the_client_goes_away(tmp_path, monkeypatch):
    """The plain end: `serve` returns because stdin closed. Before this the job ran
    on, holding the workspace lock and its containers, with no client to tell."""
    held = _Held()
    job = jobs.start(tmp_path, "offline", held.work)
    held.running.wait(timeout=5)

    killed: list[str] = []
    monkeypatch.setattr("valvur.runner.kill_running", lambda: killed.append("backstop") or 0)
    monkeypatch.setattr(server.protocol, "serve", lambda handlers: None)
    monkeypatch.setattr(server, "SHUTDOWN_SECONDS", 5)

    assert server.main([]) == 0
    assert held.stopped.is_set(), "the job was never told to stop"
    assert job.settled.wait(timeout=5) and job.state is jobs.State.CANCELLED, job.state
    assert killed == ["backstop"], "kill_running is not the backstop it was built to be"


@pytest.mark.parametrize("raised", [KeyboardInterrupt, BrokenPipeError])
def test_every_way_the_server_ends_stops_the_fleet(tmp_path, monkeypatch, raised):
    """Ctrl-C and a client that closed the pipe under us settle the same way."""
    held = _Held()
    jobs.start(tmp_path, "offline", held.work)
    held.running.wait(timeout=5)

    def explode(handlers):
        raise raised()

    monkeypatch.setattr("valvur.runner.kill_running", lambda: 0)
    monkeypatch.setattr(server.protocol, "serve", explode)
    monkeypatch.setattr(server, "SHUTDOWN_SECONDS", 5)

    assert server.main([]) == 0
    assert held.stopped.is_set(), f"{raised.__name__} left the fleet running"


def test_a_shutdown_waits_for_the_job_to_settle_but_not_for_ever(tmp_path, monkeypatch):
    """A job that will not settle must not hang the exit: the wait is bounded and
    the server says what it gave up on, rather than blocking a client's restart."""
    stuck = threading.Event()

    def work(workspace, profile, progress):
        jobs.current(workspace).canceller = lambda: 0    # a kill that does nothing
        stuck.wait(timeout=10)
        return "never reached in time"

    jobs.start(tmp_path, "offline", work)
    time.sleep(0.05)
    monkeypatch.setattr("valvur.runner.kill_running", lambda: 0)
    monkeypatch.setattr(server.protocol, "serve", lambda handlers: None)
    monkeypatch.setattr(server, "SHUTDOWN_SECONDS", 0.3)

    started = time.monotonic()
    assert server.main([]) == 0
    elapsed = time.monotonic() - started
    stuck.set()
    assert elapsed < 3, f"the exit waited {elapsed:.1f}s on a job that never settles"


def test_a_server_with_nothing_running_exits_silently(tmp_path, monkeypatch, capsys):
    """The common case — no scan in flight — costs nothing and says nothing."""
    monkeypatch.setattr("valvur.runner.kill_running", lambda: 0)
    monkeypatch.setattr(server.protocol, "serve", lambda handlers: None)

    assert server.main([]) == 0
    assert capsys.readouterr().err == ""


def test_sigterm_runs_the_same_shutdown(tmp_path, monkeypatch):
    """A client that kills the server rather than closing its stdin — the default
    disposition for SIGTERM ends the process without unwinding, so `finally` never
    runs and the containers stay. The handler makes it an ordinary exit."""
    held = _Held()
    jobs.start(tmp_path, "offline", held.work)
    held.running.wait(timeout=5)

    installed: dict[int, object] = {}
    monkeypatch.setattr(signal, "signal", lambda sig, handler: installed.setdefault(sig, handler))
    monkeypatch.setattr("valvur.runner.kill_running", lambda: 0)
    monkeypatch.setattr(server, "SHUTDOWN_SECONDS", 5)

    def serve_until_signalled(handlers):
        installed[signal.SIGTERM](signal.SIGTERM, None)    # the signal arrives

    monkeypatch.setattr(server.protocol, "serve", serve_until_signalled)

    assert server.main([]) == 0
    assert signal.SIGTERM in installed, "SIGTERM is not handled, so `finally` never runs"
    assert held.stopped.is_set(), "SIGTERM left the fleet running"


@pytest.mark.e2e
def test_a_real_server_leaves_no_container_behind_when_its_client_disconnects(mountable_tmp):
    """The measurement, over stdio against the real image: start a scan through the
    MCP surface, close stdin mid-fleet, and assert the runtime has none of this
    scan's containers a moment later. `--name valvur-<id>` is what makes the
    question answerable (23.3.3)."""
    from valvur.runner import detect_runtime

    runtime = detect_runtime()
    workspace = mountable_tmp / "ws"
    shutil.copytree(FIXTURES / "broken-repo", workspace)

    def live() -> list[str]:
        out = subprocess.run(
            [runtime, "ps", "--filter", "name=valvur-", "--format", "{{.Names}}"],
            capture_output=True, text=True, check=False, timeout=30)
        return [n for n in out.stdout.split() if n]

    before = set(live())
    server_process = subprocess.Popen(
        [sys.executable, "-m", "valvur.mcp"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    try:
        for message in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "scan", "arguments": {"path": str(workspace)}}},
        ):
            server_process.stdin.write(json.dumps(message) + "\n")
            server_process.stdin.flush()
            server_process.stdout.readline()

        deadline = time.monotonic() + 120
        while time.monotonic() < deadline and not (set(live()) - before):
            time.sleep(0.5)
        started = set(live()) - before
        assert started, "no container ever started, so the test measures nothing"

        server_process.stdin.close()                      # the client goes away
        assert server_process.wait(timeout=60) == 0
    finally:
        server_process.kill()

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and (set(live()) & started):
        time.sleep(0.5)
    assert not (set(live()) & started), \
        f"containers outlived the server: {sorted(set(live()) & started)}"
