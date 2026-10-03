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
