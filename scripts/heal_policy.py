#!/usr/bin/env python3
"""Whether a heal's pull request may merge itself (R44.4, D81, Requirement 8).

    python3 scripts/heal_policy.py lock --base . --head "$RUNNER_TEMP/head" < view.json

It is run from the base branch, never from the pull request's code. On stdin, one JSON
object: `files`, as `gh pr view --json files` gives them, and `commits`, as GitHub's REST
API lists a pull request's (`repos/<repo>/pulls/<n>/commits`), since only that says who
committed and whether the signature was verified. `--head` is a directory that holds the
pull request's `requirements-checkov.txt` and `CHANGELOG.md`, read as data.

A heal is eligible only when it is exactly what the recipe makes. The checks run in this
order and stop at the first that fails, naming it:

1. every changed file is the lock or the CHANGELOG;
2. the recipe, run on the base's lock with the commits' own `Heal-Pin` trailers, writes
   the pull request's lock, byte for byte.

Exit 0 when eligible, 1 when it is left for the owner, 2 when the input cannot be read.
The first line printed says which, and why. No file of the pull request is ever run: the
recipe and everything it reads come from the base.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import TextIO

sys.path.insert(0, str(Path(__file__).resolve().parent))

import heal

ENVELOPE = (heal.LOCK, heal.CHANGELOG)
_PIN = re.compile(r"^Heal-Pin: ([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.!+_-]+)$", re.M)


class Unreadable(Exception):
    """The input is not what the policy is given to judge."""


def pins(commits: list[dict]) -> dict[str, str]:
    """Every `Heal-Pin` trailer of the pull request's commits, by package."""
    found: dict[str, str] = {}
    for commit in commits:
        message = (commit.get("commit") or {}).get("message") or ""
        found.update(dict(_PIN.findall(message)))
    return found


def decide(view: dict, base: Path, head: Path) -> tuple[bool, str]:
    """(eligible, why) for a heal of the Checkov lock."""
    files = [f.get("path", "") for f in view.get("files") or []]
    commits = view.get("commits") or []
    if not files or not commits:
        raise Unreadable("no files or no commits to judge")
    others = sorted(path for path in files if path not in ENVELOPE)
    if others:
        return False, f"changes files a heal never changes: {', '.join(others)}"
    if heal.LOCK not in files:
        return False, f"does not change {heal.LOCK}"
    asked = pins(commits)
    base_lock = (base / heal.LOCK).read_text(encoding="utf-8")
    written = heal.relock(base, base_lock, asked)
    if written is None:
        return False, "the recipe fails on the base's lock with the commits' pins"
    if written != (head / heal.LOCK).read_text(encoding="utf-8"):
        return False, ("the lock is not what the recipe writes from the base's with "
                       + ", ".join(f"{name}=={version}" for name, version in sorted(asked.items())))
    return True, f"eligible: the recipe's lock with {len(asked)} pin(s), and nothing else"


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    lock = commands.add_parser("lock", help="judge a heal of the Checkov lock")
    lock.add_argument("--base", type=Path, default=Path.cwd(), help="the base branch's tree")
    lock.add_argument("--head", type=Path, required=True,
                      help="the pull request's two files, as data")
    args = parser.parse_args(argv)
    try:
        view = json.load(stdin or sys.stdin)
        if not isinstance(view, dict):
            raise Unreadable("the input is not a JSON object")
        eligible, why = decide(view, args.base.resolve(), args.head)
    except (OSError, ValueError, Unreadable) as error:
        print(f"cannot judge the pull request: {error}")
        return 2
    print(why if eligible else f"left for the owner: {why}")
    return 0 if eligible else 1


if __name__ == "__main__":
    sys.exit(main())
