"""In-container entry point.

    python -m valvur.checks <name> <workspace>            one Check, findings as JSON
    python -m valvur.checks batch <workspace> <name>...   several, one container

Emits JSON on stdout. Nothing else may be written there, or the host cannot parse it.

The batch (task 23.4.2) is why a scan starts one container for its Checks rather
than three: measured, each cost 12-16s on a Mac and 2-3s on Linux for milliseconds
of work. Each Check's result is kept apart — its own findings, its own error — so
one refusing costs nothing to the others (F2.5), and dependency-reality, the only
Check that may reach out, runs last.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from . import REGISTRY

#: Runs after every other Check in a batch: the one that may use a network.
LAST = "dependency-reality"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) >= 3 and args[0] == "batch":
        json.dump(batch(Path(args[1]), args[2:]), sys.stdout)
        return 0
    if len(args) != 2:
        print("usage: python -m valvur.checks <check-name> <workspace>\n"
              "       python -m valvur.checks batch <workspace> <check-name>...",
              file=sys.stderr)
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


def batch(workspace: Path, names: list[str]) -> dict[str, dict]:
    """Every named Check, each isolated, `LAST` last. The shape the runner reads:
    `{name: {ok, findings, error, duration_s}}`, in the order run."""
    ordered = [n for n in names if n != LAST] + [n for n in names if n == LAST]
    results: dict[str, dict] = {}
    for name in ordered:
        check = REGISTRY.get(name)
        if check is None:
            results[name] = {"ok": False, "findings": [], "error": f"unknown check: {name}",
                             "duration_s": 0.0}
            continue
        started = time.monotonic()
        try:
            findings = check.run(workspace)
        except RuntimeError as exc:
            results[name] = {"ok": False, "findings": [], "error": str(exc),
                             "duration_s": round(time.monotonic() - started, 3)}
            continue
        results[name] = {"ok": True, "findings": findings, "error": "",
                         "duration_s": round(time.monotonic() - started, 3)}
    return results


if __name__ == "__main__":
    sys.exit(main())
