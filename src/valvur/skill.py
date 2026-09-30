"""The skill: how an agent runs valvur's workflow (D39, F9.12, ADR-0031).

One skill, `valvur`, in the open Agent Skills format, written once here in the
package. The Claude Code plugin and the Kiro power carry copies a test holds to it,
and `valvur init --write` writes it into a project (D40). Its frontmatter uses only
the standard's six fields, so the one file loads in every client of the standard.
"""

from __future__ import annotations

from pathlib import Path

#: The skill's directory, as the standard lays one out: `SKILL.md` and `references/`.
DIRECTORY = Path(__file__).parent / "data" / "skills" / "valvur"
SKILL = DIRECTORY / "SKILL.md"


def version(text: str | None = None) -> str | None:
    """The version a skill's frontmatter names, `metadata.version`: the package's
    own by default, or that of `text`, a copy in a project (R15.4's `doctor`)."""
    import re

    text = SKILL.read_text(encoding="utf-8") if text is None else text
    match = re.search(r'^  version: "([^"]+)"$', text.split("\n---\n", 1)[0], re.M)
    return match[1] if match else None


def _field(name: str, spec: dict, required: bool) -> str:
    kind = spec.get("type", "")
    kind = " or ".join(kind) if isinstance(kind, list) else kind
    if "enum" in spec:
        kind += ", one of " + ", ".join(f"`{v}`" for v in spec["enum"])
    note = f": {spec['description']}" if spec.get("description") else ""
    line = f"- `{name}` ({kind}{', required' if required else ''}){note}"
    items = spec.get("items") or {}
    for inner, inner_spec in (items.get("properties") or {}).items():
        line += "\n  " + _field(inner, inner_spec, inner in items.get("required", []))
    return line


def tools_reference() -> str:
    """`references/tools.md`: each MCP tool as the server describes it, and each
    field it takes, rendered from the registry so the two cannot disagree."""
    from .mcp.tools import registry

    lines = ["# valvur's MCP tools", "",
             "Rendered from the server's own list of tools; a test holds this file to it.",
             "Each tool takes only the fields listed: any other is refused, not ignored.",
             ""]
    for tool in registry():
        changes = ("It changes nothing." if tool.read_only else
                   "It changes this machine as its description says, and never the source.")
        lines += [f"## `{tool.name}`", "", tool.description, "", changes, ""]
        properties = tool.schema.get("properties") or {}
        required = tool.schema.get("required", [])
        lines += ([_field(name, spec, name in required) for name, spec in properties.items()]
                  or ["It takes no fields."])
        lines.append("")
    return "\n".join(lines)
