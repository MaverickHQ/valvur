"""The skill: how an agent runs valvur's workflow (D39, F9.12, ADR-0031).

One skill, `valvur`, in the open Agent Skills format, written once here in the
package. The Claude Code plugin and the Kiro power carry copies a test holds to it,
and `valvur init --write` writes it into a project (D40). Its frontmatter uses only
the standard's six fields, so the one file loads in every client of the standard.
"""

from __future__ import annotations

from pathlib import Path

#: The skill's directory, as the standard lays one out: `SKILL.md` and `references/`.
DIRECTORY = Path(__file__).parent / "data" / "skills" / "valvur"
SKILL = DIRECTORY / "SKILL.md"


def version(text: str | None = None) -> str | None:
    """The version a skill's frontmatter names, `metadata.version`: the package's
    own by default, or that of `text`, a copy in a project (R15.4's `doctor`)."""
    import re

    text = SKILL.read_text(encoding="utf-8") if text is None else text
    match = re.search(r'^  version: "([^"]+)"$', text.split("\n---\n", 1)[0], re.M)
    return match[1] if match else None
