"""MCP server for valvur — stdio, zero dependencies (ADR-0015)."""

from __future__ import annotations

from .protocol import PROTOCOL_VERSION
from .server import Tool, main

__all__ = ["PROTOCOL_VERSION", "Tool", "main"]
