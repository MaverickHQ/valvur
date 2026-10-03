#!/usr/bin/env python3
"""Write each generated block of the docs from the code (D55a, R24.2).

A block is the text between `<!-- generated: <name> -->` and `<!-- /generated -->`,
and `BLOCKS` says what writes each one. A fact the code holds is written here
rather than compared with prose by a test of its own; `tests/test_generated_docs.py`
regenerates every block and names the one that differs.

    uv run python scripts/generate_docs.py           # rewrite every stale block
    uv run python scripts/generate_docs.py --check   # name them, and exit 1
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

BLOCK = re.compile(r"(<!-- generated: (?P<name>[\w-]+) -->\n)(?P<body>.*?)(<!-- /generated -->)",
                   re.S)
SKILL = REPO / "src" / "valvur" / "data" / "skills" / "valvur"


def mcp_tools() -> str:
    """Every MCP tool, its description and each field it takes, as the server lists them."""
    from valvur.mcp.tools import reference

    return reference()


def agent_rules() -> str:
    """The rules the server hands an agent at `initialize`, word for word."""
    from valvur.mcp.tools import instructions

    return instructions().strip("\n") + "\n"


def mcp_clients() -> str:
    """Each MCP client: the file valvur's server goes in, what to do after, and the
    snippet, from the clients' table."""
    from valvur.mcp.clients import readme_section

    return readme_section()


NUMBERS = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
           "ten", "eleven", "twelve")


def cli_commands() -> str:
    """The CLI's commands, as `valvur --help` names them: the retired ones that still
    parse for a release are not among them."""
    import argparse

    from valvur.cli import build_parser

    [sub] = [a for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction)]
    commands = [f"`{name}`" for name in sub.metavar.strip("{}").split(",")]
    listed = ", ".join(commands[:-1]) + f" and {commands[-1]}"
    return (f"{NUMBERS[len(commands)].capitalize()} commands in all: {listed}. `--help` on "
            "each says what it takes.\n")


BLOCKS: dict[str, Callable[[], str]] = {
    "mcp-tools": mcp_tools,
    "agent-rules": agent_rules,
    "mcp-clients": mcp_clients,
    "cli-commands": cli_commands,
}
FILES: tuple[Path, ...] = (
    REPO / "README.md",
    SKILL / "SKILL.md",
    SKILL / "references" / "tools.md",
)


def names(text: str) -> list[str]:
    return [match["name"] for match in BLOCK.finditer(text)]


def render(text: str, blocks: Mapping[str, Callable[[], str]]) -> str:
    """`text` with each block's body written afresh, set off by a blank line each side."""
    def body(match: re.Match[str]) -> str:
        if match["name"] not in blocks:
            raise SystemExit(f"no generator for the block {match['name']!r}")
        return f"{match[1]}\n{blocks[match['name']]()}\n{match[4]}"

    return BLOCK.sub(body, text)


def stale(files: Iterable[Path] = FILES,
          blocks: Mapping[str, Callable[[], str]] = BLOCKS) -> list[tuple[Path, str]]:
    """Each (file, block) whose text is not what the code writes."""
    found = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for old, new in zip(BLOCK.finditer(text), BLOCK.finditer(render(text, blocks)),
                            strict=True):
            if old[0] != new[0]:
                found.append((path, old["name"]))
    return found


def write(files: Iterable[Path] = FILES,
          blocks: Mapping[str, Callable[[], str]] = BLOCKS) -> list[tuple[Path, str]]:
    """Rewrite every stale block; return what was rewritten."""
    files = list(files)
    rewritten = stale(files, blocks)
    for path in {path for path, _ in rewritten}:
        path.write_text(render(path.read_text(encoding="utf-8"), blocks), encoding="utf-8")
    return rewritten


def main(argv: list[str]) -> int:
    rewritten = stale() if "--check" in argv else write()
    for path, name in rewritten:
        print(f"{'stale' if '--check' in argv else 'wrote'}: {name} in "
              f"{path.relative_to(REPO)}")
    return 1 if rewritten and "--check" in argv else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
