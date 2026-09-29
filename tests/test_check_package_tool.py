"""R12.3: `check_package`, the seventh MCP tool (D28, F9.11).

The tool an agent calls before it adds a dependency, and the rule that says so, where
an agent reads rules: the handshake's instructions, `SUMMARY.md`'s agent block, and
what `valvur init` prints. Read-only, and not open-world: it answers from this
machine's cache and asks nothing of anyone.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_mcp import _call, _exchange, _request

from valvur.mcp import tools
from valvur.mcp.server import USAGE
from valvur.name_index import malicious

REPO = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "malicious-packages"
RULE = "call `check_package`"


@pytest.fixture(autouse=True)
def index(name_index):
    directory = name_index(pip=["requests"], npm=["react", "atez"])
    assert malicious._main(["build-malicious", str(directory), str(FIXTURE)]) == 0
    return directory


def _listed() -> dict:
    [listed] = _exchange(_request("tools/list"), tools=tools.registry())
    return {tool["name"]: tool for tool in listed["result"]["tools"]}


def test_it_is_listed_with_its_schema_read_only_and_not_open_world():
    tool = _listed()["check_package"]

    packages = tool["inputSchema"]["properties"]["packages"]
    assert packages["maxItems"] == 50
    assert set(packages["items"]["properties"]) == {"ecosystem", "name", "version"}
    assert tool["inputSchema"]["required"] == ["packages"]
    assert tool["annotations"]["readOnlyHint"] is True
    assert tool["annotations"]["openWorldHint"] is False
    assert "outputSchema" in tool


def test_fifty_packages_answer_bounded_and_structured():
    asked = [{"ecosystem": "pip", "name": "reqeusts"}, {"ecosystem": "npm", "name": "atez"}]
    asked += [{"ecosystem": "npm", "name": f"made-up-{i}", "version": "1.0.0"}
              for i in range(48)]

    result = _call("check_package", {"packages": asked})

    structured = result["structuredContent"]
    assert result["isError"] is False
    assert len(structured["answers"]) == 50 and structured["flagged"] == 50
    assert structured["answers"][0]["near"] == "requests"
    assert structured["answers"][1]["ids"] == ["MAL-2022-1153"]
    assert len(result["content"][0]["text"]) < 12_000


def test_fifty_one_are_refused_by_the_schema():
    result = _call("check_package", {"packages": [{"ecosystem": "pip", "name": "x"}] * 51})

    assert result["isError"] is True
    assert "50" in result["content"][0]["text"]


def test_the_handshake_summary_and_init_tell_an_agent_to_call_it_first(tmp_path):
    from valvur import initialize
    from valvur.api import ScanRun
    from valvur.summary import render

    assert RULE in tools.instructions()
    assert RULE in render(ScanRun(findings=[]))
    assert RULE in initialize.render(tmp_path)


def test_the_readme_the_server_help_and_doctor_say_seven_tools():
    readme = (REPO / "README.md").read_text()

    assert "seven tools:" in readme and "| `check_package` |" in readme
    assert "check_package" in USAGE
    assert len(tools.registry()) == 7


def test_doctor_inside_the_server_names_the_tools_it_serves(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from valvur import doctor
    from valvur.mcp import protocol

    served = tuple(tool.name for tool in tools.registry())
    monkeypatch.setattr(protocol, "current_call", lambda: SimpleNamespace(served=served))

    line = doctor._check_session(tmp_path)

    assert "7 tools" in line.detail and "check_package" in line.detail


def test_the_reply_is_json_the_cli_also_gives(capsys):
    from valvur import cli

    result = _call("check_package", {"packages": [{"ecosystem": "npm", "name": "atez"}]})
    cli.main(["check", "npm", "atez", "--json"])

    assert result["structuredContent"]["answers"] == json.loads(
        capsys.readouterr().out)["answers"]
