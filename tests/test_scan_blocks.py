"""R6.3: `scan` blocks and returns (D6, ADR-0024; F9.1), over stdio.

Start-and-poll cost the second gate's agent sixteen turns and $1.08 (F9.1). R6.1
measured that Claude Code keeps a 150-second call's result, so one `scan` call now
returns the result, with progress notifications on the way; a client that drops
the call and calls again is attached to the same scan; `scan_status` attaches.
"""

from __future__ import annotations

import json
import queue
import threading
from pathlib import Path

import pytest

from valvur import api, engine_host
from valvur.engine_host import LocalRuntime
from valvur.mcp import jobs, protocol
from valvur.mcp.server import build
from valvur.mcp.tools import registry

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"


class Session:
    """A client over a live stdio pair: stdin stays open until it closes it, and
    every line the server writes is kept, in order."""

    def __init__(self) -> None:
        self._in: queue.Queue[str | None] = queue.Queue()
        self.out: queue.Queue[dict] = queue.Queue()
        self.seen: list[dict] = []
        server = self

        class _Out:
            def write(self, text: str) -> None:
                for line in text.splitlines():
                    if line.strip():
                        server.out.put(json.loads(line))

            def flush(self) -> None:
                pass

        def lines():
            while (line := self._in.get()) is not None:
                yield line

        self.thread = threading.Thread(
            target=protocol.serve, args=(build(registry()),),
            kwargs={"stdin": lines(), "stdout": _Out()}, daemon=True)
        self.thread.start()

    def send(self, message: dict) -> None:
        self._in.put(json.dumps(message) + "\n")

    def reply(self, request_id: int, seconds: float = 30) -> dict:
        while True:
            message = self.out.get(timeout=seconds)
            self.seen.append(message)
            if message.get("id") == request_id:
                return message

    def close(self) -> None:
        self._in.put(None)
        self.thread.join(timeout=15)


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
    session = Session()
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
