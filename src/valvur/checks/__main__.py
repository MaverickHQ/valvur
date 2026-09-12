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

    try:
        findings = check.run(Path(workspace))
    except RuntimeError as exc:
        # A Check's own refusal — no index, no reachable registry — is a sentence
        # for the person reading `SUMMARY.md`, not a traceback for the runner to
        # truncate at 200 characters with the fix cut off. Anything else is a bug
        # and keeps its traceback.
        print(str(exc), file=sys.stderr)
        return 1

    json.dump(findings, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
