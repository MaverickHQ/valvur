"""29.2.1 — every agent's IDE, by MCP.

The README gave one JSON block and named no file (the gate's B8). One table
(`valvur.mcp.clients`) now renders the README's section, says which handshakes
were measured and which are documented shapes, and a transcript per protocol
version — recorded through the real server — pins what any client speaking that
version gets back.
"""

from __future__ import annotations

import io
import json
import os
import re
import tomllib
from pathlib import Path

import pytest

from valvur.mcp import clients, protocol
from valvur.mcp.server import build
from valvur.mcp.tools import instructions, registry

REPO = Path(__file__).resolve().parent.parent
TRANSCRIPTS = REPO / "tests" / "fixtures" / "mcp" / "clients"
UPDATE = "UPDATE_MCP_CLIENT_TRANSCRIPTS"


@pytest.mark.parametrize("entry", clients.CLIENTS, ids=lambda c: c.key)
def test_every_client_has_a_file_a_snippet_that_parses_and_the_one_command(entry):
    assert entry.files and entry.after and entry.verified
    text = clients.snippet(entry)
    if entry.shape.startswith("json-"):
        top = entry.shape.split("-", 1)[1]
        data = json.loads(text)
        server = data[top]["valvur"]
        assert server["command"] == "uvx" and server["args"] == list(clients.ARGS)
    elif entry.shape == "toml":
        server = tomllib.loads(text)["mcp_servers"]["valvur"]
        assert server["command"] == "uvx" and server["args"] == list(clients.ARGS)
    else:
        assert "command: uvx" in text and "- name: valvur" in text
        for arg in clients.ARGS:
            assert f"      - {arg}\n" in text


def test_claude_code_and_kiro_are_the_measured_ones_and_say_so():
    measured = {c.key for c in clients.CLIENTS if c.verified.startswith("measured")}
    assert measured == {"claude-code", "kiro"}
    for entry in clients.CLIENTS:
        if entry.key not in measured:
            assert "not run here" in entry.verified, entry.key


def test_the_readme_carries_the_rendered_section_verbatim():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    start, end = readme.find(clients.README_START), readme.find(clients.README_END)
    assert start > 0 < end, "the README has no clients block"
    block = readme[start:end + len(clients.README_END)] + "\n"
    assert block == clients.readme_section(), (
        "the README's clients block differs from the table; regenerate it with "
        "`uv run python -c 'from valvur.mcp import clients; print(clients.readme_section())'`")
    for entry in clients.CLIENTS:
        assert clients.snippet(entry).rstrip("\n") in readme, entry.key


def _reply(request: dict) -> dict:
    stdin = io.StringIO(json.dumps(request) + "\n")
    stdout = io.StringIO()
    protocol.serve(build(registry(), instructions=instructions()), stdin=stdin, stdout=stdout)
    [reply] = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    reply["result"]["serverInfo"]["version"] = "<version>"
    return reply


@pytest.mark.parametrize("version", protocol.SUPPORTED_VERSIONS)
def test_a_client_speaking_each_published_version_gets_the_recorded_reply(version):
    """What Kiro, Claude Code, Codex, Cursor or VS Code sends at `initialize`
    differs mostly in this field; the server agrees to every version the spec has
    published and states its own to a version it does not know."""
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": version, "capabilities": {},
                          "clientInfo": {"name": "a client", "version": "0"}}}
    reply = _reply(request)
    assert reply["result"]["protocolVersion"] == version
    assert reply["result"]["instructions"], "the rules an agent is given before its first call"

    path = TRANSCRIPTS / f"{version}.json"
    rendered = json.dumps({"request": request, "reply": reply}, indent=2, sort_keys=True) + "\n"
    if os.environ.get(UPDATE):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        pytest.skip(f"recorded {path.name}")
    assert path.is_file(), f"no transcript for {version}; record it with {UPDATE}=1"
    assert path.read_text(encoding="utf-8") == rendered, (
        f"the reply to a {version} client changed; if that is intended, re-record with {UPDATE}=1")


def test_an_unknown_version_is_answered_with_the_servers_own():
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2099-01-01"}}
    assert _reply(request)["result"]["protocolVersion"] == protocol.PROTOCOL_VERSION


def test_the_table_names_one_command_and_it_is_the_published_shim():
    assert (clients.COMMAND, *clients.ARGS) == ("uvx", "--from", "valvur", "valvur-mcp")
    assert re.search(r"uvx --from valvur valvur-mcp", (REPO / "README.md").read_text())
