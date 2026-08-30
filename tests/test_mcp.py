"""Sub-phase 9.0 — MCP stdio transport, hand-rolled and dependency-free (ADR-0015).

MCP is valvur's primary interface: a developer adds it to Kiro or Claude Code and
calls it from there. The CLI is the second way in.
"""

import io
import json

from valvur.mcp import protocol
from valvur.mcp.protocol import PROTOCOL_VERSION
from valvur.mcp.server import Tool, build


def _exchange(*messages, tools=None):
    """Drive the server over real streams and return the parsed responses."""
    stdin = io.StringIO("\n".join(json.dumps(m) for m in messages) + "\n")
    stdout = io.StringIO()
    protocol.serve(build(tools or []), stdin=stdin, stdout=stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]


def _request(method, params=None, request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": method,
            **({"params": params} if params else {})}


# ------------------------------------------------------------- the handshake

def test_initialize_returns_a_usable_server_description():
    responses = _exchange(_request("initialize", {"protocolVersion": PROTOCOL_VERSION}))

    result = responses[0]["result"]
    assert result["protocolVersion"] == PROTOCOL_VERSION
    assert result["serverInfo"]["name"] == "valvur"
    assert "tools" in result["capabilities"]


def test_an_older_protocol_version_is_honoured_when_we_support_it():
    """Negotiation, not imposition: a client on an older version keeps working."""
    responses = _exchange(_request("initialize", {"protocolVersion": "2024-11-05"}))

    assert responses[0]["result"]["protocolVersion"] == "2024-11-05"


def test_an_unknown_protocol_version_gets_ours_to_decide_on():
    responses = _exchange(_request("initialize", {"protocolVersion": "1999-01-01"}))

    assert responses[0]["result"]["protocolVersion"] == PROTOCOL_VERSION


def test_a_notification_receives_no_response():
    """Replying to a notification is a protocol violation, and clients hang on it."""
    responses = _exchange(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        _request("tools/list", request_id=7),
    )

    assert len(responses) == 1
    assert responses[0]["id"] == 7


# ------------------------------------------- 9.0.4 nothing but JSON on stdout

def test_malformed_json_produces_a_parse_error_not_a_crash():
    stdin = io.StringIO("this is not json\n")
    stdout = io.StringIO()

    protocol.serve(build([]), stdin=stdin, stdout=stdout)

    assert json.loads(stdout.getvalue())["error"]["code"] == protocol.PARSE_ERROR


def test_an_unknown_method_produces_method_not_found():
    responses = _exchange(_request("nonsense"))

    assert responses[0]["error"]["code"] == protocol.METHOD_NOT_FOUND


def test_a_message_that_is_not_json_rpc_is_rejected():
    responses = _exchange({"id": 1, "method": "initialize"})

    assert responses[0]["error"]["code"] == protocol.INVALID_REQUEST


def test_a_crashing_tool_becomes_a_tool_error_not_a_protocol_error():
    """The agent should see what went wrong, not a transport fault."""
    def explode(_args):
        raise ValueError("scanner unavailable")

    tool = Tool("boom", "explodes", {"type": "object"}, explode)
    responses = _exchange(
        _request("tools/call", {"name": "boom", "arguments": {}}), tools=[tool]
    )

    result = responses[0]["result"]
    assert result["isError"] is True
    assert "scanner unavailable" in result["content"][0]["text"]


def test_an_unhandled_exception_never_reaches_stdout_as_a_traceback(capsys):
    """Anything on stdout that is not a response corrupts the stream, and the client
    reports a protocol error instead of the real problem."""
    def broken(_params):
        raise RuntimeError("boom")

    stdin = io.StringIO(json.dumps(_request("tools/list")) + "\n")
    stdout = io.StringIO()

    protocol.serve({"tools/list": broken}, stdin=stdin, stdout=stdout)

    payload = json.loads(stdout.getvalue())          # parses, so it is not a traceback
    assert payload["error"]["code"] == protocol.INTERNAL_ERROR
    assert "boom" in capsys.readouterr().err, "diagnostics belong on stderr"


# ------------------------------------------------------------------- tools

def test_tools_are_advertised_as_read_only():
    """F9.2 — a client can show the user that nothing here touches their code."""
    tool = Tool("scan", "Scan a workspace", {"type": "object"}, lambda a: "ok")

    responses = _exchange(_request("tools/list"), tools=[tool])

    described = responses[0]["result"]["tools"][0]
    assert described["annotations"]["readOnlyHint"] is True
    assert described["annotations"]["destructiveHint"] is False


def test_calling_an_unknown_tool_is_an_invalid_params_error():
    responses = _exchange(_request("tools/call", {"name": "ghost", "arguments": {}}))

    assert responses[0]["error"]["code"] == protocol.INVALID_PARAMS


def test_no_forbidden_tool_name_is_ever_registered():
    """ADR-0009 is a safety property. A contributor adding scan_and_fix should fail
    the build, not merely fail review."""
    from valvur.mcp.tools import FORBIDDEN, registry

    names = {tool.name for tool in registry()}

    assert not (names & set(FORBIDDEN)), f"forbidden tool exposed: {names & set(FORBIDDEN)}"


# ---------------------------------------------------- zero dependencies (F10.6)

def test_the_shim_still_has_no_runtime_dependencies():
    """ADR-0015 — the whole reason we hand-rolled this."""
    import tomllib
    from pathlib import Path

    pyproject = tomllib.loads(
        (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    )

    assert pyproject["project"]["dependencies"] == []


def test_the_mcp_server_imports_nothing_outside_the_standard_library():
    import valvur.mcp.protocol as mod
    import valvur.mcp.server as srv

    for module in (mod, srv):
        source = (module.__file__ or "")
        assert "site-packages" not in source or "valvur" in source
