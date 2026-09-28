"""R6.5: every MCP tool and its CLI command give the same answer (F9.3).

`test_every_mcp_tool_is_backed_by_a_shared_operation` holds the structure: both
surfaces call `valvur.operations`. This holds the answers, run on one scanned
workspace: for each tool, the CLI command that is its counterpart prints what the
tool's text says. A new tool must name its command here, or why it has none.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from valvur import api, cli, engine_host
from valvur.engine_host import LocalRuntime
from valvur.mcp import jobs

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"

#: Each MCP tool, and the CLI arguments that answer the same question; None where
#: the CLI's counterpart is not a command, with the reason.
PARITY: dict[str, list[str] | None] = {
    "scan": ["scan"],
    "scan_status": ["status"],
    "findings": ["findings"],
    "list_findings": ["findings"],
    "explain_finding": ["findings", "--fingerprint", "{fingerprint}"],
    "doctor": ["doctor"],
    "update": ["update"],     # its steps are one function, `updating.run`
    "scan_cancel": None,      # the CLI's cancel is Ctrl-C, on the scan it is running
}


@pytest.fixture
def scanned(tmp_path, monkeypatch) -> Path:
    from valvur import cache
    from valvur.adapters import GitleaksAdapter

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.setattr(engine_host, "for_scan", lambda: LocalRuntime(FAKE_TOOLS))
    monkeypatch.setattr(api, "DEFAULT_ADAPTERS", [GitleaksAdapter()])
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    root = tmp_path / "ws"
    shutil.copytree(Path(__file__).parent / "fixtures" / "broken-repo", root)
    assert cli.main(["scan", str(root)]) in (0, 1)
    yield root
    jobs.reset()


def _mcp(tool: str, arguments: dict) -> dict:
    import io

    from valvur.mcp import protocol
    from valvur.mcp.server import build
    from valvur.mcp.tools import registry

    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": tool, "arguments": arguments}}
    out = io.StringIO()
    protocol.serve(build(registry()), stdin=io.StringIO(json.dumps(message) + "\n"),
                   stdout=out)
    return json.loads(out.getvalue().splitlines()[0])["result"]


def test_every_tool_names_its_cli_counterpart():
    from valvur.mcp.tools import registry

    assert {tool.name for tool in registry()} == set(PARITY)


@pytest.mark.parametrize("tool", [t for t, command in PARITY.items()
                                  if command and t not in ("scan", "update")])
def test_each_reader_and_its_command_give_the_same_answer(scanned, capsys, tool):
    findings = json.loads((scanned / ".security-scan" / "findings.json").read_text())
    fingerprint = findings["findings"][0]["fingerprint"]
    arguments = {"workspace": str(scanned)}
    if tool == "explain_finding":
        arguments["fingerprint"] = fingerprint
    command = [a.format(fingerprint=fingerprint) for a in PARITY[tool]]
    capsys.readouterr()

    text = _mcp(tool, arguments)["content"][0]["text"]
    cli.main([command[0], str(scanned), *command[1:]])
    printed = capsys.readouterr().out

    assert printed.strip() == text.strip(), tool


def test_scan_and_its_command_reach_the_same_result(scanned, tmp_path):
    """The two write the same verdict and counts for the same tree; their words
    differ (a terminal's progress, an agent's reply) and the result does not."""
    other = tmp_path / "other"
    shutil.copytree(scanned, other, ignore=shutil.ignore_patterns(".security-scan"))

    from conftest import McpSession

    # A client whose stdin stays open: `scan` answers when the scan does (R6.3).
    session = McpSession()
    try:
        session.send({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "scan", "arguments": {"workspace": str(other)}}})
        fields = session.reply(1)["result"]["structuredContent"]
    finally:
        session.close()
    assert fields["state"] == "done"
    by_cli = json.loads((scanned / ".security-scan" / "run.json").read_text())

    assert (fields["verdict"], fields["counts"]["active"]) == (
        by_cli["status"], by_cli["findings"]["active"])
