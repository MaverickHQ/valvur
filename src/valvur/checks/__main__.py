"""In-container entry point.

    python -m valvur.checks <name> <workspace>            one Check, findings as JSON

Emits JSON on stdout. Nothing else may be written there, or the host cannot parse it.
Each Check is its own process in the one Scan Container (ADR-0022), so one refusing
costs nothing to the others (F2.5). The batch of 23.4.2, three Checks in one
container, ended with R3.9: every tool shares one container now.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .. import exclusions
from . import REGISTRY


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    # What the scan excluded (29.0.1), one prefix per line, through the
    # environment rather than the arguments so an older image ignores it.
    exclude = exclusions.prefixes_from_env(os.environ.get(exclusions.EXCLUDE_ENV))
    if len(args) != 2:
        print("usage: python -m valvur.checks <check-name> <workspace>", file=sys.stderr)
        return 2

    name, workspace = args
    check = REGISTRY.get(name)
    if check is None:
        print(f"unknown check: {name}", file=sys.stderr)
        return 2

    try:
        findings = check.run(Path(workspace), exclude=exclude)
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
