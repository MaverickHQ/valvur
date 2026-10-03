"""MCP server for valvur — stdio, zero dependencies (ADR-0015). The names below load
when first asked for (`valvur.lazy`), so the jobs and the clients' table load without
the server."""

from __future__ import annotations

from .. import lazy

__getattr__, __dir__ = lazy.exports(__name__, {
    "PROTOCOL_VERSION": "protocol",
    "Tool": "tool",
    "main": "server",
    **{module: module for module in ("clients", "handlers", "jobs", "protocol", "server",
                                      "tool", "tools")},
})
