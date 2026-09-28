"""A request refused in one plain sentence (R1.2): the MCP server shows the
sentence, never the exception's class name. A leaf, so any module may raise it."""

from __future__ import annotations


class Refusal(ValueError):
    """The sentence, and what kind of refusal it is (R6.4): an agent reading only
    the structured form learns which argument to change."""

    plain = True

    def __init__(self, sentence: str, kind: str = "invalid-argument"):
        super().__init__(sentence)
        self.kind = kind
