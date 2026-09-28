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


# ------------------------------------------- behaviour 2: never outside the roots

def test_a_workspace_outside_the_clients_roots_is_refused(tmp_path):
    inside, outside = tmp_path / "project", tmp_path / "elsewhere"
    inside.mkdir()
    outside.mkdir()
    session = McpSession()
    try:
        _initialize(session, roots=True)
        session.send({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "scan", "arguments": {"workspace": str(outside)}}})
        _answer_roots(session, inside)
        result = session.reply(1)["result"]
    finally:
        session.close()

    assert result["isError"] is True
    assert result["structuredContent"]["error"]["kind"] == "outside-roots"
    assert str(inside) in result["content"][0]["text"]
    assert jobs.current(outside.resolve()) is None
    assert not (outside / ".security-scan").exists()


# ----------------------------------------- behaviour 3: every schema is closed

def test_every_tools_arguments_are_closed():
    for tool in registry():
        assert tool.schema.get("additionalProperties") is False, tool.name


# --------------------------------------- behaviour 4: a kind and one sentence

@pytest.mark.parametrize(("tool", "arguments", "kind"), [
    ("scan", {"verbose": True}, "unknown-argument"),
    ("scan", {"profile": "fast"}, "invalid-argument"),
    ("scan", {"budget_s": "ten"}, "invalid-argument"),
    ("scan", {"budget_s": -5}, "invalid-argument"),
    ("scan_status", {"workspace": 5}, "invalid-argument"),
    ("findings", {"limit": 0}, "invalid-argument"),
    ("findings", {"status": "fixed"}, "invalid-argument"),
    ("doctor", {"network": "yes"}, "invalid-argument"),
    ("scan", {"workspace": "relative/path"}, "relative-path"),
    ("scan", {"workspace": "/no/such/directory/anywhere"}, "no-directory"),
    ("findings", {}, "no-results"),
    ("findings", {"fingerprint": "nope"}, "no-results"),
])
def test_every_violation_fails_at_the_call_with_a_kind_and_one_sentence(
        tmp_path, tool, arguments, kind):
    if "workspace" not in arguments:
        arguments = {"workspace": str(tmp_path), **arguments}
    began = time.monotonic()
    result = _call(tool, arguments)
    text = result["content"][0]["text"]

    assert result["isError"] is True, text
    assert result["structuredContent"]["error"] == {"kind": kind, "message": text}
    assert "\n" not in text.strip() and text.rstrip().endswith("."), text
    assert time.monotonic() - began < 2, "it did not fail at the call"
    assert jobs.current(tmp_path.resolve()) is None, "a refused call started a job"


def test_a_file_named_as_the_workspace_is_not_a_directory(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("# a file\n")

    result = _call("scan", {"workspace": str(readme)})

    assert result["structuredContent"]["error"]["kind"] == "not-a-directory"


def test_a_missing_required_argument_is_its_own_kind():
    """No tool requires an argument since `explain_finding` went (R6's exit), so the
    check is held directly: a future tool that requires one gets it for free."""
    from valvur.mcp.server import _check_arguments
    from valvur.refusal import Refusal

    with pytest.raises(Refusal) as refused:
        _check_arguments({"type": "object", "required": ["fingerprint"],
                          "properties": {"fingerprint": {"type": "string"}}}, {})

    assert refused.value.kind == "missing-argument"
    assert str(refused.value) == "`fingerprint` is required."
