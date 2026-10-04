"""Copy a test fixture with its real file names (R27.2, D63a).

    python3 scripts/fixtures.py broken-repo <target>

A manifest planted under `tests/fixtures` for valvur's own tests to find is stored as
`<name>.fixture`, a name no scanner reads as a manifest, so Scorecard and GitHub do not
count its advisories as the repository's (R27.1: 43 of 44). Every test, the acceptance
set and CI copy a fixture through `copy`, which gives each such file its real name
back in the copy; nothing is ever renamed in the tree. Standard library alone.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"
#: What a stored manifest's name ends with, and its real name does not.
SUFFIX = ".fixture"


def restore(root: Path) -> list[Path]:
    """Give each `<name>.fixture` under `root` its real name; the restored paths."""
    restored = []
    for path in sorted(root.rglob(f"*{SUFFIX}")):
        real = path.with_name(path.name[: -len(SUFFIX)])
        path.rename(real)
        restored.append(real)
    return restored


def copy(source: str | Path, target: Path, *, dirs_exist_ok: bool = False) -> Path:
    """Copy the fixture `source` (a name under `tests/fixtures`, or a path) to
    `target`, with its manifests' real names."""
    origin = FIXTURES / source if isinstance(source, str) else source
    shutil.copytree(origin, target, dirs_exist_ok=dirs_exist_ok)
    restore(target)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("fixture", help="a directory under tests/fixtures")
    parser.add_argument("target", type=Path)
    args = parser.parse_args(argv)
    copy(args.fixture, args.target)
    print(args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
