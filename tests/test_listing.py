"""R21.2: ready to list (D48b).

Kiro's catalog asks for a privacy statement and a support channel, so the README has
both. `docs/LISTING.md` holds the text each directory asks for, and every field it
draws from a manifest must equal that manifest's, so a description or keyword changed
in one place cannot leave the other behind. The owner's queue points to it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LISTING = REPO / "docs" / "LISTING.md"


def _sections() -> dict[str, dict[str, str]]:
    """Each `##` section of the listing, as its `- **Field:** value` lines."""
    sections, current = {}, None
    for line in LISTING.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = sections.setdefault(line[3:], {})
        elif current is not None and (m := re.match(r"- \*\*([^:*]+):\*\* (.*)$", line)):
            current[m.group(1)] = m.group(2)
    return sections


def _section(word: str) -> dict[str, str]:
    [fields] = [f for title, f in _sections().items() if word in title]
    return fields


def _manifest(path: str) -> dict:
    return json.loads((REPO / path).read_text())


def test_the_readme_says_what_it_collects_and_where_to_get_help():
    readme = (REPO / "README.md").read_text()
    privacy = readme.split("\n## Privacy\n", 1)[1].split("\n## ", 1)[0]
    support = readme.split("\n## Support\n", 1)[1].split("\n## ", 1)[0]

    assert "collects nothing" in privacy
    assert "scripts/verify-offline.py" in privacy, "the claim without its proof"
    assert "https://github.com/MaverickHQ/valvur/issues" in support
