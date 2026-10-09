"""The documents a user reads, for the tests that hold what they claim (R39, D78).

Before R39 every claim lived in the README. The README is now a front door, and the
detail moved into four guides, so a test of what valvur *documents* reads all of them,
and a test of what the README itself must show reads the README alone.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
#: The guides the README's detail moved into, in the order the README links them.
GUIDES = tuple(REPO / "docs" / name for name in
               ("AGENTS.md", "CLI.md", "CI.md", "HOW-IT-WORKS.md"))


def user_docs() -> str:
    """The README and the guides, as one text."""
    return "\n\n".join(path.read_text(encoding="utf-8") for path in (README, *GUIDES))


def guide(name: str) -> str:
    return (REPO / "docs" / name).read_text(encoding="utf-8")


#: A Markdown link's target, or an HTML `src` or `srcset`.
_LINK = re.compile(r"\]\(([^)\s]+)\)|\b(?:src|srcset)=\"([^\"]+)\"")
_FENCE = re.compile(r"^```.*?^```", re.M | re.S)


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"[`*_]|\[([^\]]*)\]\([^)]*\)", r"\1", heading).strip().lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def anchors(path: Path) -> set[str]:
    text = _FENCE.sub("", path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for heading in re.findall(r"^#{1,6} (.+)$", text, re.M):
        slug, n = _slug(heading), 1
        while slug in found:
            slug = f"{_slug(heading)}-{n}"
            n += 1
        found.add(slug)
    return found


def broken_links(path: Path) -> list[str]:
    """Every relative link in `path` whose file, or whose anchor in it, does not exist."""
    text = _FENCE.sub("", path.read_text(encoding="utf-8"))
    broken = []
    for match in _LINK.finditer(text):
        target = match.group(1) or match.group(2)
        if re.match(r"[a-z][a-z0-9+.-]*:", target):
            continue
        file, _, anchor = target.partition("#")
        where = (path.parent / file).resolve() if file else path
        if not where.exists():
            broken.append(target)
        elif anchor and where.suffix == ".md" and anchor not in anchors(where):
            broken.append(target)
    return broken
