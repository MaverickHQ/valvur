"""R7.1: the README, rewritten against what exists (P6).

Three behaviours, each held here rather than by reading its prose: every number
the README cites is the acceptance set's or the code's own limit, its tool table
is the image's Scanners and Checks, and its client table is the one `doctor`
reads.
"""

from __future__ import annotations

import re
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


_NUMBER = r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?"
_UNIT = r"s|seconds?|minutes?|KB|MB|GB|GiB|files|commits"
#: A unit's kind: `22 s` and `22 seconds` cite the same measurement.
_FAMILY = {"s": "time", "second": "time", "seconds": "time", "minute": "time",
           "minutes": "time", "KB": "size", "MB": "size", "GB": "size", "GiB": "size",
           "files": "files", "commits": "commits"}
#: A table header cell that gives its column a unit: `s`, `Mac s`, `seconds`, `MB`.
_HEADER = {"time": r"(?<![\w'\u2019])(s|seconds?|minutes?)(?![\w'\u2019])",
           "size": r"\b(KB|MB|GB|GiB)\b", "files": r"\bfiles\b", "commits": r"\bcommits\b"}


def _with_units(text: str) -> list[tuple[str, str]]:
    """Every number `text` gives a unit, with the unit's kind; a range or a list
    before one unit, `3.0 to 14.8 s`, gives it to each number."""
    import re

    chain = re.compile(rf"(?<![\w.])((?:{_NUMBER})(?:\s*(?:to|\u2013|and|or|,)\s*(?:{_NUMBER}))*)"
                       rf"\s?({_UNIT})\b")
    return [(n, _FAMILY[m.group(2)]) for m in chain.finditer(text)
            for n in re.findall(_NUMBER, m.group(1))]


def _cited() -> list[tuple[str, str]]:
    return _with_units(README.read_text(encoding="utf-8"))


def _recorded() -> set[tuple[str, str]]:
    """What `docs/acceptance/` measured: each number with a unit in its text, and
    each number in a table column whose header names a unit."""
    import re

    found: set[tuple[str, str]] = set()
    for path in sorted((REPO / "docs" / "acceptance").glob("*.md")):
        header: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            found.update(_with_units(line))
            if not line.startswith("|"):
                header = []
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not header:
                header = cells
                continue
            for title, cell in zip(header, cells, strict=False):
                for family, says in _HEADER.items():
                    if re.search(says, title):
                        found.update((n, family) for n in re.findall(_NUMBER, cell))
    return found


def _limits() -> set[tuple[str, str]]:
    """The code's own limits, which the README states and no measurement produces."""
    from valvur import fileset, history, operations, runner

    budget = f"{operations.MCP_BUDGET_S:.0f}"
    return {(budget, "time"), (f"{history.MAX_COMMITS:,}", "commits"),
            (f"{history.MAX_BYTES // 2**20}", "size"),
            (f"{runner.SCAN_CEILING_BYTES // 2**30}", "size"),
            (f"{fileset.CEILING:,}", "files")}


def test_every_number_the_readme_cites_is_the_acceptance_sets():
    """A time, a size or a count in the README is either one of the code's limits
    or a figure `docs/acceptance/` records with the same kind of unit, where the
    run that produced it is written down. The README had cited eleven dated
    measurements from four releases."""
    known = _recorded() | _limits()
    cited = _cited()

    assert cited, "the README cites no measurement at all"
    unsourced = sorted({f"{n} ({kind})" for n, kind in cited if (n, kind) not in known})
    assert not unsourced, f"not in docs/acceptance/ and not a limit: {unsourced}"


def test_the_static_analysis_claim_is_tracks_1_and_2_as_the_baseline_records_them():
    """R13.7: what valvur says of static analysis is the Score's two tracks, measured,
    and nothing beyond them."""
    import json
    import re

    baseline = json.loads((REPO / "tests" / "eval" / "baseline.json").read_text())["tracks"]
    readme = (REPO / "README.md").read_text()
    paragraph = re.search(r"^- \*\*Static analysis[^\n]*\n(?:  [^\n]*\n)*", readme, re.M)
    evaluating = (REPO / "docs" / "EVALUATING.md").read_text()

    assert paragraph, "the README has no static-analysis paragraph"
    for track in ("sast-python", "sast-js"):
        assert f"**{baseline[track]}**" in paragraph.group(0), track
        assert f"| {track} |" in evaluating and f"{baseline[track]}" in evaluating, track


# --------------------------------------------------- R16.4: the README as built

def test_the_readme_names_every_tool_and_every_command():
    from test_seven_commands import SEVEN

    from valvur.mcp.tools import registry

    text = README.read_text()
    tools = re.findall(r"^\| `(\w+)` \|", _section("For AI coding agents: the primary way in"),
                       re.M)
    commands = re.search(r"Nine commands in all: (.+?)\. ", text, re.S)

    assert sorted(tools) == sorted(t.name for t in registry())
    assert commands and sorted(re.findall(r"`(\w+)`", commands[1])) == \
        sorted([*SEVEN, "init", "check"])


def test_the_skill_is_installed_from_where_it_ships():
    import json

    from valvur import skill

    text = README.read_text()
    marketplace = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text())
    [plugin] = marketplace["plugins"]

    assert f"`/plugin install {plugin['name']}@{marketplace['name']}`" in text
    power = re.search(r"https://github\.com/MaverickHQ/valvur/tree/main/(powers/\w+)", text)
    assert power and (REPO / power[1] / "plugin.json").is_file()
    for where in skill.LOCATIONS.values():
        assert f"`{where}/`" in text, where


def test_the_score_the_readme_cites_is_the_baselines():
    import json

    baseline = json.loads((REPO / "tests" / "eval" / "baseline.json").read_text())

    assert f"**{baseline['score']}** out of 100" in README.read_text()
