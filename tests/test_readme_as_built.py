"""R7.1: the README, rewritten against what exists (P6).

Three behaviours, each held here rather than by reading its prose: every number
the README cites is the acceptance set's or the code's own limit, its tool table
is the image's Scanners and Checks, and its client table is the one `doctor`
reads.
"""

from __future__ import annotations

from pathlib import Path

from valvur.mcp import clients

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"


def test_the_client_block_keeps_each_notes_case():
    """`str.capitalize()` lowercased every note after its first letter, so the README
    told Kiro's users to enable `kiroagent.configuremcp` and VS Code's that the key
    is not `mcpservers`. Only the first letter changes."""
    block = clients.readme_section()

    for entry in clients.CLIENTS:
        assert entry.after[1:] in block, entry.key
        assert entry.verified[1:] in block, entry.key


def _section(heading: str) -> str:
    text = README.read_text(encoding="utf-8")
    assert f"\n## {heading}\n" in text, f"the README has no section `{heading}`"
    return text.split(f"\n## {heading}\n", 1)[1].split("\n## ", 1)[0]


def _rows(section: str) -> list[list[str]]:
    """Body rows of every table in `section`, as cells."""
    rows = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not line.startswith("|") or set(cells[0]) <= {"-", ":"}:
            continue
        rows.append(cells)
    return rows


def _notice_licences() -> dict[str, str]:
    """NOTICE's licence for each tool the image carries, as an SPDX identifier."""
    import re

    spdx = {"Apache License 2.0": "Apache-2.0", "MIT License": "MIT"}
    found = {}
    lines = (REPO / "NOTICE").read_text().splitlines()
    for name, url, licence in zip(lines, lines[1:], lines[2:], strict=False):
        if url.strip().startswith("https://") and not name.startswith(" "):
            inner = re.search(r"\(([^)]+)\)", licence)
            found[name.strip().lower()] = inner.group(1) if inner else spdx.get(
                licence.strip(), licence.strip())
    return found


def test_the_tool_table_is_the_images_scanners_and_checks():
    """Every Scanner the orchestrator runs is a row, with the licence NOTICE gives
    it and a binary the Dockerfile installs; every Check is named beside them; and
    nothing else is."""
    import re

    from valvur.adapters import DEFAULT_ADAPTERS, CheckAdapter

    rows = _rows(_section("What does the scanning"))
    tools = {re.sub(r"^\[([^\]]+)\].*", r"\1", r[0]).lower(): r for r in rows
             if r[0].startswith("[")}
    checks = {r[0].strip("`") for r in rows if r[0].startswith("`")}
    scanners = {a.name for a in DEFAULT_ADAPTERS if not isinstance(a, CheckAdapter)}

    assert set(tools) == scanners
    assert checks == {a.name for a in DEFAULT_ADAPTERS if isinstance(a, CheckAdapter)}
    licences, dockerfile = _notice_licences(), (REPO / "Dockerfile").read_text()
    for name, row in tools.items():
        assert row[1] == licences[name], (name, row[1], licences[name])
        assert f"/usr/local/bin/{name}" in dockerfile, name
