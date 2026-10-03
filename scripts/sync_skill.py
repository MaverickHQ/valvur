#!/usr/bin/env python3
"""Make the plugin's and the power's copies of the skill the package's (D55b, R24.3).

Claude Code and Kiro load the skill from the repository, so each holds a copy of
`src/valvur/data/skills/valvur`, byte for byte; the tests compare and never write.
Run after changing the skill, or `scripts/generate_docs.py` writing its blocks;
`prepare_release.py` runs it.

    uv run python scripts/sync_skill.py
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILL = Path("src/valvur/data/skills/valvur")
#: The skill's copies, which Claude Code and Kiro load from the repository (R15).
COPIES = (Path("plugins/valvur/skills/valvur"), Path("powers/valvur/skills/valvur"))


def _files(directory: Path) -> dict[str, bytes]:
    return {p.relative_to(directory).as_posix(): p.read_bytes()
            for p in sorted(directory.rglob("*")) if p.is_file()} if directory.is_dir() else {}


def sync(root: Path = REPO) -> list[Path]:
    """Copy the skill over each copy that differs; return the copies rewritten."""
    wanted = _files(root / SKILL)
    changed = []
    for copy in COPIES:
        if (root / copy).parent.is_dir() and _files(root / copy) != wanted:
            shutil.rmtree(root / copy, ignore_errors=True)
            shutil.copytree(root / SKILL, root / copy)
            changed.append(copy)
    return changed


def main() -> int:
    for copy in sync():
        print(f"wrote {copy}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
