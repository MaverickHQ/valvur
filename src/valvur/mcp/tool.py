"""One tool the MCP server exposes, and what it does to the machine it runs on: in
a module of its own, so the server and the registry of tools each import it and not
each other (R23.9)."""

from __future__ import annotations

from collections.abc import Callable


class Tool:
    """One exposed tool, and what it does to the machine it runs on.

    No tool touches the **source tree** — that is F9.2 and ADR-0009, structural
    and unchanged. `readOnlyHint` is a narrower claim in MCP's own words, "does
    not modify its environment", and until 27.1.2 all six tools declared it true:
    `scan` writes the Results Folder, pulls an image and starts containers, and
    `scan_cancel` kills them. A client may use these annotations to decide what
    to run without asking, so a hint that is wrong is worse than none — a prompt
    before a scan is the correct behaviour, not a regression.
    """

    def __init__(self, name: str, description: str, schema: dict,
                 handler: Callable[[dict], str | tuple[str, dict]], *,
                 read_only: bool = True, destructive: bool = False,
                 open_world: bool | None = None, output_schema: dict | None = None,
                 announce: Callable[[], None] | None = None,
                 settle: Callable[[], None] | None = None):
        self.name = name
        self.description = description
        # Closed, whatever the caller wrote (R6.4): an argument no tool takes is
        # refused at the call, never silently ignored.
        self.schema = {**schema, "additionalProperties": False}
        #: Answers the text every client renders — and, for a tool that declares
        #: `output_schema`, the same answer as a dict beside it, which the reply
        #: carries as `structuredContent` (MCP 2025-06-18; 28.2.2). One call
        #: produces both, so the two forms cannot disagree.
        self.handler = handler
        self.output_schema = output_schema
        #: The default is the safe one: a tool says nothing and is advertised as
        #: read-only, so a tool that ACTS has to declare it.
        self.read_only = read_only
        #: Nothing valvur exposes is destructive, and a test over the registry
        #: says so: a scan only adds, and a cancel writes nothing at all (F1.11).
        #: The field exists so the claim is stated rather than assumed.
        self.destructive = destructive
        #: Stated where it is known: `check_package` answers from this machine's
        #: cache and reaches no one (D28), which MCP's default, open-world, denies.
        self.open_world = open_world
        #: Said by the server's reader when a call to this tool is read, before the
        #: call's thread runs: `scan` says a job is coming (R23.4). The handler
        #: settles what it announced; `settle` is for a call refused before it.
        self.announce = announce
        self.settle = settle

    def describe(self) -> dict:
        described = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.schema,
            "annotations": {"readOnlyHint": self.read_only,
                            "destructiveHint": self.destructive,
                            **({} if self.open_world is None
                               else {"openWorldHint": self.open_world})},
        }
        if self.output_schema is not None:
            described["outputSchema"] = self.output_schema
        return described
