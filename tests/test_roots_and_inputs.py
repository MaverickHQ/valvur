"""R6.4: inputs from the client's roots (F9.1, N2.2).

The workspace is the client's project unless the call names one: Claude Code sets
`CLAUDE_PROJECT_DIR` and answers `roots/list`. A workspace outside the client's
roots is refused, since a scan writes into the folder it scans. Every tool's
schema closes its arguments, and every violation fails at the call with a `kind`
and one sentence, in both forms, so an agent reading only the structured form
still knows which argument to change.
"""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest
from conftest import McpSession

from valvur.mcp import jobs, protocol
from valvur.mcp.server import build
from valvur.mcp.tools import registry


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    jobs.reset()
    yield
    jobs.reset()


def _call(tool: str, arguments: dict) -> dict:
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": tool, "arguments": arguments}}
    stdout = io.StringIO()
    protocol.serve(build(registry()), stdin=io.StringIO(json.dumps(message) + "\n"),
                   stdout=stdout)
    return json.loads(stdout.getvalue().splitlines()[0])["result"]


def _initialize(session: McpSession, roots: bool) -> None:
    session.send({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"roots": {"listChanged": True}} if roots else {}}})
    session.reply(0)


def _answer_roots(session: McpSession, *roots: Path) -> None:
    """Wait for the server's `roots/list` and answer it, as Claude Code does."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        asked = [m for m in session.seen if m.get("method") == "roots/list"]
        if asked:
            session.send({"jsonrpc": "2.0", "id": asked[0]["id"], "result": {"roots": [
                {"uri": root.as_uri(), "name": root.name} for root in roots]}})
            return
        try:
            session.seen.append(session.out.get(timeout=0.1))
        except Exception:  # noqa: S110 — nothing yet
            pass
    raise AssertionError("the server never asked for the client's roots")


# ------------------------------------ behaviour 1: the workspace is the client's

def test_the_workspace_defaults_to_the_project_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))

    fields = _call("scan_status", {})["structuredContent"]

    assert fields["workspace"] == str(tmp_path.resolve())


def test_without_a_project_directory_it_is_the_first_of_the_clients_roots(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    session = McpSession()
    try:
        _initialize(session, roots=True)
        session.send({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "scan_status", "arguments": {}}})
        _answer_roots(session, first, second)
        fields = session.reply(1)["result"]["structuredContent"]
    finally:
        session.close()

    assert fields["workspace"] == str(first.resolve())
