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




def files() -> dict[str, bytes]:
    """Every file of the skill, by its path in the skill's directory: what the
    plugin and the power copy, and what `init --write` writes into a project."""
    return {path.relative_to(DIRECTORY).as_posix(): path.read_bytes()
            for path in sorted(DIRECTORY.rglob("*")) if path.is_file()}


#: Where each client reads a project's skills: Claude Code's `.claude/skills/`, and
#: Kiro's `.kiro/skills/` (kiro.dev/docs/skills/, read 2026-09-30). `init --write`
#: writes the skill there, and `doctor` looks there (R15.4, D40).
LOCATIONS = {"claude-code": ".claude/skills/valvur", "kiro": ".kiro/skills/valvur"}


def write_into(workspace: Path, client: str) -> str:
    """The skill into `client`'s place in `workspace`, a line saying what was done.
    Never over what is there: a directory that exists is left whole, since a copy
    half this valvur's and half another's would be worse than either."""
    where = LOCATIONS[client]
    target = workspace / where
    if target.exists():
        present = target / "SKILL.md"
        found = version(present.read_text(encoding="utf-8")) if present.is_file() else None
        return (f"left {where}/ as it is: it exists"
                + (f", version {found}" if found else ""))
    for relative, data in files().items():
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_bytes(data)
    return f"wrote the skill to {where}/"
