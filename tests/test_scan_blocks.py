"""R6.3: `scan` blocks and returns (D6, ADR-0024; F9.1), over stdio.

Start-and-poll cost the second gate's agent sixteen turns and $1.08 (F9.1). R6.1
measured that Claude Code keeps a 150-second call's result, so one `scan` call now
returns the result, with progress notifications on the way; a client that drops
the call and calls again is attached to the same scan; `scan_status` attaches.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
from conftest import McpSession

from valvur import api, engine_host
from valvur.engine_host import LocalRuntime
from valvur.mcp import jobs

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"


def _call(request_id: int, tool: str, arguments: dict, token=None) -> dict:
    params: dict = {"name": tool, "arguments": arguments}
    if token is not None:
        params["_meta"] = {"progressToken": token}
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params}


@pytest.fixture
def ws(tmp_path, monkeypatch) -> Path:
    from valvur import cache
    from valvur.adapters import GitleaksAdapter

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.setattr(engine_host, "for_scan", lambda: LocalRuntime(FAKE_TOOLS))
    monkeypatch.setattr(api, "DEFAULT_ADAPTERS", [GitleaksAdapter()])
    root = tmp_path / "ws"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    yield root
    jobs.reset()


def test_one_call_returns_the_result_with_progress_on_the_way(ws):
    session = McpSession()
    try:
        session.send(_call(1, "scan", {"workspace": str(ws)}, token="t1"))
        result = session.reply(1)["result"]
    finally:
        session.close()

    fields = result["structuredContent"]
    assert (fields["schema"], fields["state"]) == (2, "done")
    assert fields["report"] and fields["generation"]
    progress = [m for m in session.seen if m.get("method") == "notifications/progress"]
    assert progress, "no progress was sent on the way"
    assert all(m["params"]["progressToken"] == "t1" for m in progress)
    values = [m["params"]["progress"] for m in progress]
    assert values == sorted(values) and len(set(values)) == len(values)


@pytest.fixture
def held(ws, monkeypatch):
    """A scan that waits for `release` before it runs, counting how many start."""
    from valvur.mcp import handlers

    release = threading.Event()
    started: list[int] = []
    real = handlers._work

    def slow(budget_s, *, fresh=False):
        work = real(budget_s, fresh=fresh)

        def run(workspace, profile, progress):
            started.append(1)
            progress("fleet: 1 Scanners, 1 at a time")
            assert release.wait(20), "the test never released the scan"
            return work(workspace, profile, progress)
        return run

    monkeypatch.setattr(handlers, "_work", slow)
    return release, started


def test_a_client_that_lets_go_and_calls_again_gets_the_same_scan(ws, held):
    release, started = held
    first = McpSession()
    first.send(_call(1, "scan", {"workspace": str(ws)}))
    _wait_until(lambda: started)
    first.send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": {"requestId": 1, "reason": "the client timed out"}})
    first.close()                                   # and then goes away altogether

    second = McpSession()
    try:
        second.send(_call(1, "scan", {"workspace": str(ws)}))
        release.set()
        fields = second.reply(1)["result"]["structuredContent"]
    finally:
        second.close()

    assert not [m for m in first.seen if m.get("id") == 1], "a cancelled call was answered"
    assert len(started) == 1, "the second call started a second scan"
    record = json.loads((ws / ".security-scan" / "run.json").read_text())
    assert fields["state"] == "done" and fields["generation"] == record["generation"]


def test_scan_status_attaches_to_the_running_scan_and_returns_its_result(ws, held):
    release, started = held
    session = McpSession()
    try:
        session.send(_call(1, "scan", {"workspace": str(ws)}))
        _wait_until(lambda: started)
        session.send(_call(2, "scan_status", {"workspace": str(ws)}, token="s"))
        threading.Timer(0.5, release.set).start()
        status = session.reply(2)["result"]["structuredContent"]
        scan = session.reply(1)["result"]["structuredContent"]
    finally:
        session.close()

    assert status["state"] == "done", "scan_status answered before the scan finished"
    assert status["generation"] == scan["generation"] and len(started) == 1
    assert [m for m in session.seen if m.get("method") == "notifications/progress"
            and m["params"]["progressToken"] == "s"], "scan_status sent no progress"


def _wait_until(condition, seconds: float = 10) -> None:
    import time

    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "the scan never started"
        time.sleep(0.02)
