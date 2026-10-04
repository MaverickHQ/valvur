"""R21.3: the first run in a new project (D58).

The owner's first run on a new project worked through the plugin, and under Claude
Code's *don't ask* mode the `scan` tool and the shell were both refused. So the
README's first screen gives the plugin's two commands before `uvx valvur scan`; the
README and the skill give the allow rules for a mode that refuses unlisted tools,
each naming a tool the server lists, and never `update`; and the skill says what to
do when a tool is refused, with a pinned command the release moves. valvur writes
no permission rule anywhere: a rule in a project's settings grants every
contributor's agent.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
#: The README's first screen, in lines, as `test_demo.py` counts it.
FIRST_SCREEN = 24
#: What D58b allows: the read-only tools, `scan` and `scan_cancel`. Never `update`.
ALLOWED = {"check_package", "findings", "scan_status", "doctor", "scan", "scan_cancel"}
RULE = re.compile(r"mcp__(?:plugin_valvur_valvur|valvur)__(\w+)")


def test_the_readme_s_first_screen_gives_the_plugin_first_and_uvx_second():
    marketplace = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text())
    [plugin] = marketplace["plugins"]
    first = "\n".join((REPO / "README.md").read_text().splitlines()[:FIRST_SCREEN])

    add = first.find("/plugin marketplace add MaverickHQ/valvur")
    install = first.find(f"/plugin install {plugin['name']}@{marketplace['name']}")
    uvx = first.find("uvx valvur scan")

    assert -1 < add < install < uvx, (add, install, uvx)


def _rules(text: str) -> set[str]:
    return set(RULE.findall(text))


def test_the_readme_and_the_skill_give_allow_rules_for_tools_the_server_lists():
    from valvur.mcp.tools import registry
    from valvur.skill import DIRECTORY

    listed = {tool.name for tool in registry()}
    readme = _rules((REPO / "README.md").read_text())
    skill = set().union(*(_rules(p.read_text())
                          for p in sorted((DIRECTORY / "references").glob("*.md"))))

    assert readme == skill == ALLOWED, (readme, skill)
    assert ALLOWED <= listed and "update" in listed - ALLOWED
