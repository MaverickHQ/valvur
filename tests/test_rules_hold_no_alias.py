"""R53.2: no rule reuses a block through a YAML alias.

Opengrep 2.0.0 resolves no alias. A rule that names its sources as `*request-sources` is
refused there, *Expected a list for pattern-sources*, and never runs: measured on
2026-11-24, nine taint rules were refused and three tracks of the Score fell by 9, 25 and
42 points. 1.31.0 resolved them. Written out in full, a rule means what it meant, on both.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RULES = sorted((REPO / "rules").rglob("*.yaml"))
#: A key whose value is an alias, alone on its line or as a list item's.
ALIAS = re.compile(r"^\s*(?:- )?[\w-]+:\s*\*[\w-]+\s*$", re.M)


def test_no_rule_file_reuses_a_block_through_an_alias():
    found = {str(path.relative_to(REPO)): ALIAS.findall(path.read_text(encoding="utf-8"))
             for path in RULES}

    assert len(RULES) >= 4
    assert {name: aliases for name, aliases in found.items() if aliases} == {}


def test_an_alias_is_seen_where_one_is_written():
    assert ALIAS.findall("    pattern-sources: *request-sources\n")
    assert ALIAS.findall("      - pattern-either: *python-model-sources\n")
    assert not ALIAS.findall("    pattern-sources: &request-sources\n")
    assert not ALIAS.findall("      - pattern: $X * 2\n")
