"""`valvur mcp`: the MCP server, started the way the official MCP Registry starts one.

The registry names a PyPI package and no entry point: a client runs `uvx valvur==<version>
<packageArguments>`, so `uvx valvur==1.5.4` started the CLI, which speaks no MCP. Most
Python servers listed there give their CLI a subcommand; `valvur-mcp` stays what every
client configuration valvur writes names (measured 2026-10-25).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from valvur import cli
from valvur.version import __version__


def test_valvur_mcp_answers_the_handshake_over_stdio_as_valvur_mcp_does():
    server = subprocess.Popen(
        [sys.executable, "-c", "from valvur.cli import main; raise SystemExit(main(['mcp']))"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    try:
        server.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
        server.stdin.flush()
        reply = json.loads(server.stdout.readline())
        server.stdin.close()                       # the client goes away
        assert server.wait(timeout=60) == 0
        # stdout is the JSON-RPC channel: one prose line there breaks every client.
        assert server.stdout.read() == ""
    finally:
        server.kill()

    assert reply["id"] == 1
    assert reply["result"]["serverInfo"] == {"name": "valvur", "version": __version__}


@pytest.mark.parametrize("argument", ["--port", "--version", "serve"])
def test_valvur_mcp_takes_no_argument_so_a_configuration_s_typo_is_refused(argument, capsys):
    """`valvur-mcp` refuses an argument rather than start anyway (19.C.3); so does this."""
    with pytest.raises(SystemExit) as stopped:
        cli.main(["mcp", argument])

    said = capsys.readouterr()
    assert stopped.value.code == 2
    assert f"unrecognized arguments: {argument}" in said.err
    assert said.out == ""
