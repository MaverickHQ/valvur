"""R1.2: a workspace must exist (F9.1, N2.2; the second gate's C2, the review's N5).

`scan` with a relative path resolved it against the server's directory, created
`relative/path/.security-scan/` inside the project and reported on an empty folder.
Driven through the real server over streams, as a client drives it.
"""

from __future__ import annotations

import io
import json

from valvur.mcp import protocol
from valvur.mcp.server import build
from valvur.mcp.tools import registry


def _call(tool_name: str, arguments: dict) -> dict:
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": tool_name, "arguments": arguments}}
    stdout = io.StringIO()
    protocol.serve(build(registry()), stdin=io.StringIO(json.dumps(message) + "\n"),
                   stdout=stdout)
    return json.loads(stdout.getvalue().splitlines()[0])["result"]


def _text(result: dict) -> str:
    return result["content"][0]["text"]


def test_a_scan_of_a_workspace_that_does_not_exist_is_refused_and_never_created(tmp_path):
    missing = tmp_path / "no" / "such" / "place"
    result = _call("scan", {"workspace": str(missing)})
    assert result["isError"] is True
    assert not (tmp_path / "no").exists()


def test_a_relative_workspace_resolves_against_the_project_directory(tmp_path, monkeypatch):
    from valvur.operations import resolve_workspace

    (tmp_path / "sub").mkdir()
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    assert resolve_workspace("sub") == (tmp_path / "sub").resolve()


def test_a_relative_workspace_with_no_project_directory_is_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    result = _call("scan", {"workspace": "relative/path"})
    assert result["isError"] is True
    assert "absolute path" in _text(result)
    assert not (tmp_path / "relative").exists()


import pytest  # noqa: E402


@pytest.mark.parametrize("tool", ["findings", "scan_status",
                                  "scan_cancel", "doctor"])
def test_every_tool_refuses_a_workspace_that_does_not_exist(tmp_path, tool):
    missing = tmp_path / "no" / "such" / "place"
    # Only the tool that takes one is given a fingerprint: since R6.4 an argument a
    # tool does not take is refused before the workspace is looked at.
    extra = {"fingerprint": "x"} if tool == "findings" else {}
    result = _call(tool, {"workspace": str(missing), **extra})
    assert result["isError"] is True, _text(result)
    assert "no directory" in _text(result)
    assert not (tmp_path / "no").exists()


def test_a_file_named_as_the_workspace_is_refused(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("# hi\n")
    result = _call("scan", {"workspace": str(readme)})
    assert result["isError"] is True
    assert "is a file" in _text(result)
    assert not (tmp_path / "README.md.security-scan").exists()


@pytest.mark.parametrize("command", [["scan"], ["findings"], ["status"], ["gate"],
                                     ["doctor"]])
def test_the_cli_refuses_a_workspace_that_does_not_exist(tmp_path, capsys, command):
    from valvur import cli

    missing = tmp_path / "no" / "such" / "place"
    with pytest.raises(SystemExit) as exited:     # a usage error, at parse time
        cli.main([*command, str(missing)])
    assert exited.value.code == 2
    assert "no directory" in capsys.readouterr().err
    assert not (tmp_path / "no").exists()
