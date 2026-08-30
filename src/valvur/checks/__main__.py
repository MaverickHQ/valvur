"""In-container entry point: `python -m valvur.checks <name> <workspace>`.

Emits JSON on stdout. Nothing else may be written there, or the host cannot parse it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from . import REGISTRY


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 2:
        print("usage: python -m valvur.checks <check-name> <workspace>", file=sys.stderr)
        return 2

    name, workspace = args
    check = REGISTRY.get(name)
    if check is None:
        print(f"unknown check: {name}", file=sys.stderr)
        return 2

    json.dump(check.run(Path(workspace)), sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
