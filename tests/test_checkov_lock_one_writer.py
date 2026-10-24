"""R42.3 (D81p): the Checkov lock has one writer, its recipe (N3.7).

Both of Dependabot's updaters wrote `requirements-checkov.txt`: #231 and #236 came from
`uv`, #232 and #237 from `pip`, each a re-lock the recipe would not make (asteval 1.0.6
past its override, the `win32` markers dropped). Dependabot leaves the recipe's three
files alone, and the auto-merge leaves any pull request that changes them for the owner.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DEPENDABOT = REPO / ".github" / "dependabot.yml"
RECIPE_FILES = {"requirements-checkov.in", "requirements-checkov.overrides",
                "requirements-checkov.txt"}


def _entries() -> dict[str, list[str]]:
    """Each ecosystem's first update entry, as lines, read line by line: no YAML parser
    is among the dependencies."""
    entries: dict[str, list[str]] = {}
    current: list[str] = []
    for line in DEPENDABOT.read_text().splitlines():
        if match := re.match(r"^  - package-ecosystem: (\S+)", line):
            current = []
            entries.setdefault(match.group(1), current)
        current.append(line)
    return entries


def _excluded(lines: list[str]) -> set[str]:
    excluded, inside = set(), False
    for line in lines:
        if re.match(r"^    exclude-paths:\s*$", line):
            inside = True
        elif inside and (item := re.match(r'^      - "?([^"#\s]+)"?', line)):
            excluded.add(item.group(1))
        elif inside and not line.lstrip().startswith("#"):
            inside = False
    return excluded


@pytest.mark.parametrize("ecosystem", ["pip", "uv"])
def test_neither_dependabot_updater_writes_the_checkov_recipe_s_files(ecosystem):
    assert RECIPE_FILES <= _excluded(_entries()[ecosystem])

