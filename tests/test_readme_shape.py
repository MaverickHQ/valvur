"""R39.2 (D78b): the README is a front door, and the detail lives in the guides.

An evaluator reads the README before running anything, so it says what valvur is, how to
start, what it finds and why it can be trusted, in a fixed order and under 250 lines.
What it held before R39 (655 lines) moved into the guides under `docs/`, which every
claim test reads beside it (`user_docs.py`).
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
#: The sections, in the order a newcomer needs them.
SECTIONS = [
    "Why valvur",
    "What it finds",
    "How it works",
    "Measured, not claimed",
    "Use it",
    "Built on open-source scanners",
    "What it does not do",
    "Platforms",
    "Privacy",
    "Documentation",
    "Community and support",
    "Licence",
]
BUDGET = 250


def test_the_sections_come_in_order():
    assert re.findall(r"^## (.+)$", README.read_text(encoding="utf-8"), re.M) == SECTIONS


def test_it_stays_under_its_budget():
    assert len(README.read_text(encoding="utf-8").splitlines()) <= BUDGET


def test_every_relative_link_resolves():
    from user_docs import broken_links

    assert broken_links(README) == []
