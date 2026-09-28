"""R6.9: `doctor` and the reply tell the truth about the session (30.1.2, 30.1.3).

The second gate: the session's tools were the server Claude Code spawned when the
session started, while `.mcp.json` had since been changed, and `doctor` printed
the configured command under its own version and drew no conclusion (C5). And an
agent refused a `git status` told the user the results folder was not in
`.gitignore` and to add a line, when the folder holds its own (C6).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from valvur import doctor


@pytest.fixture
def served(monkeypatch):
    """`doctor` answering inside the MCP server, whose executable is this one."""
    running = Path("/opt/valvur-0.6/bin/valvur-mcp")
    monkeypatch.setattr(sys, "argv", [str(running)])
    monkeypatch.setattr(doctor, "_as_server", lambda: True)
    return running


def _session(workspace: Path):
    return [c for c in doctor.run(workspace) if c.name == "session"]


def test_doctor_says_the_server_is_not_the_one_the_configuration_names(tmp_path, served,
                                                                        monkeypatch):
    from valvur.version import __version__

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"valvur": {
        "command": "/opt/valvur-0.7/bin/valvur-mcp", "args": []}}}))

    [line] = _session(tmp_path)

    assert line.level == "warn"
    assert line.detail == (f"this server is {__version__} at {served}; .mcp.json names "
                           "/opt/valvur-0.7/bin/valvur-mcp; restart the client to use it")


def test_doctor_says_nothing_when_they_agree_or_cannot_be_compared(tmp_path, served,
                                                                    monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"valvur": {
        "command": str(served), "args": []}}}))
    assert [c.level for c in _session(tmp_path)] == ["ok"]

    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"valvur": {
        "command": "uvx", "args": ["--from", "valvur", "valvur-mcp"]}}}))
    assert [c.level for c in _session(tmp_path)] == ["ok"]


def test_on_the_command_line_there_is_no_session_to_check(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_as_server", lambda: False)

    assert _session(tmp_path) == []


# ------------------------------------------ 30.1.3: the folder ignores itself

CLAUSE = "the folder ignores itself; there is nothing to add to .gitignore"


def test_the_handshake_says_the_folder_ignores_itself():
    from valvur.mcp.tools import instructions

    assert CLAUSE in instructions().replace("\n", " ")


def test_a_finished_scans_reply_says_so_in_both_forms(tmp_path, monkeypatch):
    from valvur import api, cache, reply
    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import LocalRuntime

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")
    api.scan(ws, runner=LocalRuntime(Path(__file__).parent / "fixtures" / "fake-tools"),
             adapters=[GitleaksAdapter()])

    fields = reply.fields(ws)

    assert fields["results"] == {"path": str(ws / ".security-scan"), "ignores_itself": True}
    assert CLAUSE in reply.text(fields)
