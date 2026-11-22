#!/usr/bin/env python3
"""Whether a release is the heal's to prepare (R45.2, D81g, Requirement 9).

    python3 scripts/heal_release.py check --since v1.6.2

A security patch is a patch. `check` reads the commits since a tag, and what they changed,
and says `eligible` only when both of these hold:

- every commit is patch-class: a Conventional Commit of type `fix`, `docs`, `test`, `chore`,
  `ci`, `build`, `refactor`, `perf` or `style`, with no `!` and no `BREAKING CHANGE`. A heal
  commit is a `fix`, and a Dependabot update squashed by its workflow is a `chore`. A
  feature or a breaking change makes the release minor or major, which is the owner's.
- of the release machinery (`prepare_release.MACHINERY`), only the Checkov lock changed.

Otherwise it prints `release-needs-owner:` and why, which the heal escalates under that
reason. Standard library and `git`. Exit 0 when eligible, 1 when it is the owner's, 2 when
the repository or the tag could not be read.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import prepare_release

#: Requirement 9.2's types: none of them adds a feature.
PATCH_CLASS = ("fix", "docs", "test", "chore", "ci", "build", "refactor", "perf", "style")
#: The one piece of release machinery a security patch may have moved.
LOCK = "requirements-checkov.txt"
_SUBJECT = re.compile(r"([a-z]+)(\([^)]*\))?(!)?: \S")


class Unreadable(Exception):
    """The repository, or the tag, could not be read."""


def _git(root: Path, *args: str) -> str:
    run = subprocess.run(["git", "-C", str(root), *args], capture_output=True,  # noqa: S603
                         text=True, check=False)
    if run.returncode != 0:
        raise Unreadable(run.stderr.strip() or f"git {' '.join(args)} failed")
    return run.stdout


def commits(root: Path, since: str, until: str = "HEAD") -> list[tuple[str, str, str]]:
    """Each commit after `since`, oldest first: (short hash, subject, body)."""
    _git(root, "rev-parse", "--verify", "--quiet", f"{since}^{{commit}}")
    log = _git(root, "log", "--reverse", "--format=%h%x00%s%x00%b%x01", f"{since}..{until}")
    return [tuple(entry.strip("\n").split("\x00", 2))  # type: ignore[misc]
            for entry in log.split("\x01") if entry.strip()]


def not_patch_class(subject: str, body: str) -> str:
    """Why a commit is not patch-class, or ""."""
    read = _SUBJECT.match(subject)
    if not read:
        return "not a Conventional Commit"
    if read.group(1) not in PATCH_CLASS:
        return f"type {read.group(1)}"
    if read.group(3):
        return "a breaking change (!)"
    if re.search(r"^BREAKING[ -]CHANGE:", body, re.M):
        return "a BREAKING CHANGE"
    return ""


def check(root: Path, since: str, until: str = "HEAD") -> tuple[bool, str]:
    """(eligible, why) for a security patch of everything after `since`."""
    made = commits(root, since, until)
    if not made:
        return False, f"no commit since {since}: nothing to release"
    for sha, subject, body in made:
        why = not_patch_class(subject, body)
        if why:
            return False, f"{sha} is {why}: {subject[:80]}"
    changed = _git(root, "diff", "--name-only", since, until, "--",
                   *prepare_release.MACHINERY).split()
    others = sorted(path for path in changed if path != LOCK)
    if others:
        return False, f"release machinery changed beside the Checkov lock: {', '.join(others)}"
    return True, f"{len(made)} commits since {since}, all patch-class; machinery: " \
                 f"{LOCK if changed else 'unchanged'}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check_cmd = commands.add_parser("check", help="is everything since a tag a security patch")
    check_cmd.add_argument("--since", required=True, help="the latest release's tag")
    check_cmd.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        eligible, why = check(args.root.resolve(), args.since)
    except (OSError, Unreadable) as error:
        print(f"heal release: {error}", file=sys.stderr)
        return 2
    print(f"eligible: {why}" if eligible else f"release-needs-owner: {why}")
    return 0 if eligible else 1


if __name__ == "__main__":
    raise SystemExit(main())
