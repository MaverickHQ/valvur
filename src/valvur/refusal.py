"""A request refused in one plain sentence (R1.2): the MCP server shows the
sentence, never the exception's class name. A leaf, so any module may raise it."""

from __future__ import annotations


class Refusal(ValueError):
    plain = True
