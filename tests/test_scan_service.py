"""One scan service (D51): the CLI's `scan` and the MCP tool run a scan through one
function, `service.run_scan`, which owns the runner, the locks, the budget and the
cancellation. The MCP job wraps that call in its thread and adds nothing else.

Until R23.4 the CLI called `api.scan` itself and MCP went through `operations`, the
jobs and a closure of its own, and one scan was summarised three times.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from valvur import cli, service
from valvur.api import ScanRun
from valvur.mcp import jobs
from valvur.provenance import ScannerRun

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def recorded(monkeypatch):
    """`service.run_scan` replaced by one that records how it was asked."""
    calls: list[dict] = []

    def run_scan(workspace, **asked):
        calls.append({"workspace": Path(workspace), **asked})
        return ScanRun(scanners=[ScannerRun("gitleaks", ok=True)], profile=asked["profile"])

    monkeypatch.setattr(service, "run_scan", run_scan)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    yield calls
    jobs.reset()


def _workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURES / "clean-repo", ws)
    return ws


def test_the_cli_scans_through_the_service(tmp_path, recorded):
    ws = _workspace(tmp_path)

    assert cli.main(["scan", str(ws), "--budget", "40", "--jobs", "2"]) == 0

    [call] = recorded
    assert (call["workspace"], call["profile"], call["budget_s"], call["jobs"]) == (
        ws, "offline", 40.0, 2)


def test_the_mcp_tool_scans_through_the_service(tmp_path, recorded):
    from conftest import McpSession

    ws = _workspace(tmp_path)
    session = McpSession()
    try:
        session.send({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "scan", "arguments": {
                          "workspace": str(ws), "profile": "full", "fresh": True}}})
        session.reply(1)
    finally:
        session.close()

    [call] = recorded
    # MCP's budget when the client names none (F2.6): five minutes.
    assert (call["workspace"], call["profile"], call["budget_s"], call["fresh"]) == (
        ws, "full", 300.0, True)


def test_operations_and_reply_import_nothing_from_the_mcp_surface():
    """What they need of a job, a call's progress or a client's roots is passed in."""
    import importlib.util
    import sys

    scripts = Path(__file__).resolve().parent.parent / "scripts"
    spec = importlib.util.spec_from_file_location("check_layers", scripts / "check_layers.py")
    layers = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["check_layers"] = layers
    spec.loader.exec_module(layers)  # type: ignore[union-attr]

    reaching = [f"{e.path}:{e.line} {e.target}" for e in layers.imports(layers.PACKAGE)
                if e.module in ("valvur.operations", "valvur.reply")
                and (e.target == "valvur.mcp" or e.target.startswith("valvur.mcp."))]

    assert reaching == []


def test_the_scan_is_summarised_once():
    """`Job.summary`, `operations._summarise`, `start_scan` and `_run_scan` were a
    third summary of every scan, read by nothing, and the start-and-poll entry
    point ADR-0024 replaced (R6.3)."""
    import dataclasses

    from valvur import operations

    assert "summary" not in {f.name for f in dataclasses.fields(jobs.Job)}
    for gone in ("_summarise", "start_scan", "_run_scan", "_scan_with_budget"):
        assert not hasattr(operations, gone), gone


def test_a_cancel_sent_before_the_scans_job_exists_stops_that_scan(tmp_path, monkeypatch):
    """R6's backlog row: a `scan_cancel` sent within milliseconds of `scan`, before
    the scan's job existed, cancelled nothing, and the scan then ran. The server
    reads calls in order, so it knows a scan is coming; the cancel is held for it."""
    import threading
    import time

    from conftest import McpSession

    from valvur import operations
    from valvur.mcp import handlers

    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    real_profile = operations.checked_profile

    def slow_profile(value):
        time.sleep(0.5)               # the scan's call is still on its way to its job
        return real_profile(value)

    stopped = threading.Event()

    def held(budget_s, *, fresh=False):
        def run(workspace, profile, progress):
            jobs.current(workspace).canceller = lambda: stopped.set() or 1
            assert stopped.wait(10), "the cancel never reached the scan"
            raise RuntimeError("stopped")        # what a killed fleet raises
        return run

    monkeypatch.setattr(operations, "checked_profile", slow_profile)
    monkeypatch.setattr(handlers, "_work", held)
    ws = _workspace(tmp_path)
    session = McpSession()
    try:
        session.send({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "scan", "arguments": {"workspace": str(ws)}}})
        session.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "scan_cancel", "arguments": {"workspace": str(ws)}}})
        cancelled = session.reply(2)["result"]["content"][0]["text"]
        scanned = session.reply(1)["result"]["structuredContent"]
    finally:
        session.close()
        jobs.reset()

    assert cancelled.startswith("Cancelling the offline scan"), cancelled
    assert scanned["state"] == "cancelled", scanned


def test_a_cancel_with_no_scan_coming_still_answers_at_once(tmp_path):
    from valvur.mcp import handlers

    assert handlers.cancel_scan({"workspace": str(tmp_path)}) == (
        f"No scan is running in {tmp_path}.")


def test_a_scan_refused_at_its_arguments_leaves_no_cancel_waiting(tmp_path, monkeypatch):
    """An announced scan whose call is refused before its handler runs must not
    leave a later cancel waiting for a job that will never come."""
    import threading

    from conftest import McpSession

    from valvur.mcp import handlers

    monkeypatch.setattr(jobs, "EXPECTED_WAIT_S", 600.0)    # a wait would hang the test
    session = McpSession()
    try:
        session.send({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "scan", "arguments": {"workspace": 7}}})
        assert session.reply(1)["result"]["isError"] is True
    finally:
        session.close()
    said: list[str] = []
    cancel = threading.Thread(target=lambda: said.append(
        handlers.cancel_scan({"workspace": str(tmp_path)})), daemon=True)
    cancel.start()
    cancel.join(10)

    assert said and said[0].startswith("No scan"), said


class _NoImage:
    """A runtime whose image is not local and cannot be pulled."""

    engine = True
    image = "valvur:dev"
    runtime = "docker"
    cancelled = False

    def image_present(self) -> bool:
        return False

    def pull_size_mb(self):
        return None

    def pull_image(self, on_line=None):
        from valvur.invocation import ScannerOutput

        return ScannerOutput("docker", "", "", "Error response from daemon: pull access "
                             "denied for valvur, repository does not exist", 1)

    def kill(self) -> int:
        return 0


def test_a_scan_whose_image_cannot_be_pulled_says_why_in_one_line(tmp_path, monkeypatch,
                                                                    capsys):
    """Found by the cloud pre-flight: `update` said so, and `scan` raised a traceback."""
    from valvur import owner

    monkeypatch.setattr(owner, "reap", lambda runtime: [])

    code = cli.main(["scan", str(_workspace(tmp_path))], runner=_NoImage())

    said = capsys.readouterr()
    # The pull's own progress line comes first, as on any first run; then the cause.
    lines = [line for line in said.err.splitlines() if line.lstrip().startswith("!")]
    assert code == 1
    assert len(lines) == 1, said.err
    assert "valvur:dev" in lines[0] and "could not be pulled" in lines[0]
    assert "pull access denied" in lines[0] and "docker pull valvur:dev" in lines[0]
    assert "Traceback" not in said.err + said.out


def test_a_scan_with_no_container_runtime_says_why_without_a_traceback(tmp_path,
                                                                         monkeypatch, capsys):
    from valvur import engine_host
    from valvur.runner import NoContainerRuntime

    def refuse():
        raise NoContainerRuntime("No container runtime found. Install Docker or Podman.")

    monkeypatch.setattr(engine_host, "for_scan", refuse)

    code = cli.main(["scan", str(_workspace(tmp_path))])

    said = capsys.readouterr()
    assert code == 1
    assert "No container runtime found" in said.err and "Traceback" not in said.err
