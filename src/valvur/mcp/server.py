"""The MCP server: initialize, tools/list, tools/call.

That is the entire protocol for a tools-only server, which is what valvur is. It
exposes no resources and no prompts, and it never asks the client to sample —
every one of those would be a way for a scanned repository to reach further than
reporting on itself.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any

from . import protocol
from .protocol import PROTOCOL_VERSION, SUPPORTED_VERSIONS, RpcError

SERVER_NAME = "valvur"


class Tool:
    """One exposed tool. Every tool valvur exposes is read-only (F9.2, ADR-0009)."""

    def __init__(self, name: str, description: str, schema: dict,
                 handler: Callable[[dict], str]):
        self.name = name
        self.description = description
        self.schema = schema
        self.handler = handler

    def describe(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.schema,
            # Advertised so a client can show the user that nothing here mutates
            # their code. ADR-0009 is a safety property, not a preference.
            "annotations": {"readOnlyHint": True, "destructiveHint": False},
        }


def version() -> str:
    from ..compat import shim_version

    return shim_version()


def build(tools: list[Tool]) -> dict[str, Callable[[dict], Any]]:
    by_name = {tool.name: tool for tool in tools}

    def initialize(params: dict) -> dict:
        # Negotiate: honour the client's version when we know it, otherwise state
        # ours and let the client decide whether it can proceed.
        wanted = params.get("protocolVersion")
        agreed = wanted if wanted in SUPPORTED_VERSIONS else PROTOCOL_VERSION
        return {
            "protocolVersion": agreed,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": version()},
        }

    def list_tools(_: dict) -> dict:
        return {"tools": [tool.describe() for tool in tools]}

    def call_tool(params: dict) -> dict:
        name = params.get("name")
        if not isinstance(name, str):
            raise RpcError(protocol.INVALID_PARAMS, "tool name must be a string")
        tool = by_name.get(name)
        if tool is None:
            raise RpcError(
                protocol.INVALID_PARAMS,
                f"unknown tool: {name}. Available: {', '.join(sorted(by_name)) or 'none'}",
            )
        try:
            text = tool.handler(params.get("arguments") or {})
        except RpcError:
            raise
        except Exception as exc:
            # A tool failing is a result, not a protocol error: the agent should see
            # what went wrong rather than a transport-level fault.
            return {
                "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                "isError": True,
            }
        return {"content": [{"type": "text", "text": text}], "isError": False}

    return {
        "initialize": initialize,
        "notifications/initialized": lambda _: None,
        "ping": lambda _: {},
        "tools/list": list_tools,
        "tools/call": call_tool,
    }


def main(argv: list[str] | None = None) -> int:
    # stderr, never stdout: stdout is the JSON-RPC channel, and a line of prose
    # there corrupts the stream for every client.
    from ..runner import unsupported_platform_warning
    from .tools import registry

    if warning := unsupported_platform_warning():
        print(warning, file=sys.stderr, flush=True)

    try:
        protocol.serve(build(registry()))
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        pass                      # the client went away; that is a normal end
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
