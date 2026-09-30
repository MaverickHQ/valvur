"""R15.1: the skill (D39, F9.12, ADR-0031).

One skill, `valvur`, in the open Agent Skills format, written once in the package and
shipped three ways (R15.2 to R15.4). It orchestrates the workflow an agent runs with
valvur's MCP tools. Its frontmatter holds only the standard's six fields, so the one
file loads in Claude Code, in Kiro and in any client of the standard; every tool and
command it names exists; and its rules are the handshake's, from one source.
"""

from __future__ import annotations

import re
from pathlib import Path

from valvur import skill

#: The Agent Skills standard's frontmatter fields (agentskills.io, 2026-09-30).
STANDARD_FIELDS = {"name", "description", "license", "compatibility", "metadata",
                   "allowed-tools"}


def _frontmatter(text: str) -> tuple[dict[str, str], str]:
    """The top-level fields, each to its value on the same line, and the body. The
    skill's frontmatter is plain enough to read without a YAML parser, which valvur
    does not depend on; a nested map's lines are indented and belong to its key."""
    assert text.startswith("---\n"), "a skill opens with its frontmatter"
    head, body = text[4:].split("\n---\n", 1)
    fields = {}
    for line in head.splitlines():
        match = re.match(r"([A-Za-z][\w-]*):\s*(.*)$", line)
        if match:
            fields[match[1]] = match[2]
        else:
            assert line.startswith("  "), f"not a field or a nested line: {line!r}"
    return fields, body


def test_the_frontmatter_holds_only_the_standards_fields():
    fields, _ = _frontmatter(skill.SKILL.read_text(encoding="utf-8"))

    assert set(fields) <= STANDARD_FIELDS, set(fields) - STANDARD_FIELDS
    assert {"name", "description"} <= set(fields)


def test_its_name_is_valid_and_is_its_directorys():
    fields, _ = _frontmatter(skill.SKILL.read_text(encoding="utf-8"))

    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", fields["name"])
    assert len(fields["name"]) <= 64
    assert fields["name"] == skill.SKILL.parent.name == "valvur"


def test_its_description_and_compatibility_are_within_the_standards_limits():
    fields, body = _frontmatter(skill.SKILL.read_text(encoding="utf-8"))

    assert 0 < len(fields["description"]) <= 1024
    assert len(fields.get("compatibility", "")) <= 500
    assert body.strip(), "a skill with no instructions"


def test_it_is_in_the_package_and_ships_in_the_wheel():
    """`init --write`, the plugin and the power all start from this file (D40)."""
    assert skill.SKILL == Path(skill.__file__).parent / "data" / "skills" / "valvur" / "SKILL.md"
    assert skill.SKILL.is_file()


def test_its_version_is_the_packages():
    """A version surface (R15.4's `doctor` compares a project's copy with it), so it
    moves with the release as every other one does."""
    from valvur.version import __version__

    text = skill.SKILL.read_text(encoding="utf-8")

    assert re.search(r'^  version: "([^"]+)"$', text, re.M)[1] == __version__ == skill.version()


# ------------------------------------------------ 2: every tool, and only tools

def _tools() -> set[str]:
    from valvur.mcp.tools import registry

    return {tool.name for tool in registry()}


def _texts() -> dict[str, str]:
    """The skill's files, by their path in it: `SKILL.md` and each reference."""
    return {path.relative_to(skill.DIRECTORY).as_posix(): path.read_text(encoding="utf-8")
            for path in sorted(skill.DIRECTORY.rglob("*.md"))}


def test_its_tools_table_is_every_tool_the_server_lists():
    _, body = _frontmatter(skill.SKILL.read_text(encoding="utf-8"))
    table = body.split("\n## Tools\n", 1)[1].split("\n## ", 1)[0]

    named = set(re.findall(r"^\| `(\w+)` \|", table, re.M))

    assert named == _tools()


def test_every_tool_it_tells_an_agent_to_call_exists():
    called = {name for text in _texts().values()
              for name in re.findall(r"[Cc]all `(\w+)`", text)}

    assert called and called <= _tools(), called - _tools()


def test_the_tools_reference_is_the_servers_own_description_of_each():
    """`references/tools.md`, rendered from the registry: each tool's description and
    each field it takes, so the skill cannot describe a field the server lacks."""
    import os

    path = skill.DIRECTORY / "references" / "tools.md"
    rendered = skill.tools_reference()
    if os.environ.get("UPDATE_SKILL"):
        path.write_text(rendered, encoding="utf-8")

    assert path.read_text(encoding="utf-8") == rendered, (
        "references/tools.md is not the registry's; regenerate it with "
        "`UPDATE_SKILL=1 uv run pytest tests/test_skill.py`")
    for name in _tools():
        assert f"## `{name}`" in rendered
