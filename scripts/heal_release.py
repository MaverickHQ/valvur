#!/usr/bin/env python3
"""Whether a release is the heal's to prepare (R45.2, D81g, Requirement 9).

    python3 scripts/heal_release.py check --since v1.6.2

A security patch is a patch. `check` reads the commits since a tag, and what they changed,
and says `eligible` only when both of these hold:

- every commit is patch-class: a Conventional Commit of type `fix`, `docs`, `test`, `chore`,
  `ci`, `build`, `refactor`, `perf` or `style`, with no `!` and no `BREAKING CHANGE`. A heal
  commit is a `fix`, and a Dependabot update squashed by its workflow is a `chore`. A
  feature or a breaking change makes the release minor or major, which is the owner's.
- of the release machinery (`prepare_release.MACHINERY`), only the Checkov lock changed, or
  the Dockerfile inside its envelope (`image_heal.py envelope`: R45.6, D81aa);
- no Scanner's version moved, and the image gate accepts nothing the tag did not.

Otherwise it prints `release-needs-owner:` and why, which the heal escalates under that
reason. A release with no heal commit in it is not the heal's either.

    python3 scripts/heal_release.py opening --since v1.6.2
    python3 scripts/heal_release.py verify --tag v1.6.3

`opening` prints the CHANGELOG entry's first paragraph, from one template and the heal
commits' trailers. `verify` is for `release.yml`, on a tag the heal signed: `check` from the
release before the tag up to it, the version that release's patch plus one, and the tagged
tree declaring that version.

Standard library and `git`. Exit 0 when eligible, 1 when it is the owner's, 2 when the
repository or the tag could not be read.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import image_gate
import image_heal
import prepare_release
import scanner_pins

#: Requirement 9.2's types: none of them adds a feature.
PATCH_CLASS = ("fix", "docs", "test", "chore", "ci", "build", "refactor", "perf", "style")
#: The one piece of release machinery a security patch may have moved.
LOCK = "requirements-checkov.txt"
DOCKERFILE = "Dockerfile"
ACCEPTED = ".github/image-accepted.yaml"
_SUBJECT = re.compile(r"([a-z]+)(\([^)]*\))?(!)?: \S")
#: A heal commit's trailers (design.md, *Trailers*), the lock's and the image's.
_TRAILER = re.compile(r"^Heal-(Pin|Raise|Drop|Base|Go|Advisory): (.+)$", re.M)
_VERSION = re.compile(r"v(\d+)\.(\d+)\.(\d+)")
#: What a reader calls the thing a Go raise is in.
prepare_names = {"GITLEAKS_RAISE": "Gitleaks", "TRIVY_RAISE": "Trivy",
                 "OSV_SCANNER_RAISE": "OSV-Scanner", "SYFT_RAISE": "Syft"}


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
    if not any(_TRAILER.search(body) for _sha, _subject, body in made):
        return False, f"no heal commit since {since}: this is not the heal's release"
    changed = _git(root, "diff", "--name-only", since, until, "--",
                   *prepare_release.MACHINERY).split()
    others = sorted(path for path in changed if path not in (LOCK, DOCKERFILE))
    if others:
        return False, f"release machinery changed beside the Checkov lock: {', '.join(others)}"
    moved = []
    if DOCKERFILE in changed:
        where = image_heal.differs_outside(_git(root, "show", f"{since}:{DOCKERFILE}"),
                                           _git(root, "show", f"{until}:{DOCKERFILE}"))
        if where:
            return False, f"the {DOCKERFILE} {where}"
        moved.append(f"the {DOCKERFILE}, inside its envelope")
    if LOCK in changed:
        moved.append(LOCK)
    refused = _a_scanner_moved(root, since, until) or _newly_accepted(root, since, until)
    if refused:
        return False, refused
    return True, f"{len(made)} commits since {since}, all patch-class; machinery: " \
                 f"{' and '.join(moved) or 'unchanged'}"


def _a_scanner_moved(root: Path, since: str, until: str) -> str:
    """Which Scanner's version differs between two commits, or "" (Requirement 21.3). A
    new Scanner version changes what valvur reports, and that is never a security patch."""
    try:
        before = scanner_pins.pins(scanner_pins.at_ref(root, since))
        after = scanner_pins.pins(scanner_pins.at_ref(root, until))
    except (ValueError, subprocess.CalledProcessError) as error:
        return f"a Scanner's pin could not be read: {error}"
    for tool in sorted(before):
        if before[tool] != after.get(tool):
            return f"a Scanner's version moved: {tool} {before[tool]} to {after.get(tool)}"
    return ""


def _newly_accepted(root: Path, since: str, until: str) -> str:
    """An entry `.github/image-accepted.yaml` holds at `until` and did not at `since`, or
    "": an acceptance is the owner's judgement, and so is the release that first carries it."""
    def held(ref: str) -> set[tuple[str, str]]:
        shown = subprocess.run(["git", "-C", str(root), "show", f"{ref}:{ACCEPTED}"],  # noqa: S603
                               capture_output=True, text=True, check=False)
        if shown.returncode != 0:
            return set()
        return {(entry["id"], entry.get("package", ""))
                for entry in image_gate.accepted_entries(shown.stdout)}
    try:
        new = sorted(held(until) - held(since))
    except image_gate.Unreadable as error:
        return f"{ACCEPTED} could not be read: {error}"
    if new:
        return ("the image gate accepts " + ", ".join(f"{vid} {package}" for vid, package in new)
                + ", which the latest release did not")
    return ""


def _listed(words: list[str]) -> str:
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


def opening(root: Path, since: str, until: str = "HEAD") -> str:
    """The CHANGELOG entry's opening, from one template and the heal commits' trailers:
    what moved in the Checkov lock, with the version each package was at `since`, what
    changed in the image, and every advisory answered. Wrapped as the CHANGELOG is."""
    locked = dict(re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)",
                             _git(root, "show", f"{since}:{LOCK}"), re.M))
    before = {re.sub(r"[-_.]+", "-", name).lower(): version for name, version in locked.items()}
    pins: dict[str, str] = {}
    image: list[str] = []
    answered: set[str] = set()
    for _sha, _subject, body in commits(root, since, until):
        for kind, value in _TRAILER.findall(body):
            words = value.split()
            if kind == "Pin":
                name, _, version = value.partition("==")
                pins[name] = version
            elif kind == "Advisory":
                answered.add(words[0])
            elif kind == "Go":
                image.append("Go " + value.split(":", 1)[1].split("-", 1)[0])
            elif kind == "Base":
                image.append("the base's new digest")
            elif kind == "Raise" and len(words) == 2:
                package, _, version = words[1].replace("@", "=", 1).partition("=")
                where = prepare_names.get(words[0])
                image.append(f"{package} {version}" + (f" in {where}" if where else ""))
    if not pins and not image:
        raise Unreadable(f"no heal commit since {since} to write an opening from")
    parts = []
    if pins:
        moved = [f"{name} {before.get(name, 'an earlier version')} to {version}"
                 for name, version in sorted(pins.items())]
        parts.append(f"{_listed(moved)} in the Checkov lock")
    if image:
        parts.append(f"{_listed(list(dict.fromkeys(image)))}, in the image")
    text = f"A security patch, released by the heal (ADR-0032): {'; '.join(parts)}"
    text += (", past " if len(parts) == 1 else "; past ") + _listed(sorted(answered)) + "."
    return textwrap.fill(text, width=96, break_long_words=False, break_on_hyphens=False) + "\n"


def verify(root: Path, tag: str) -> tuple[bool, str]:
    """(eligible, why) for a tag the heal signed: `check` up to the tag from the release
    before it, the version that release's patch plus one, and the tree declaring it."""
    _git(root, "rev-parse", "--verify", "--quiet", f"{tag}^{{commit}}")
    previous = _git(root, "describe", "--tags", "--abbrev=0", "--match", "v*", f"{tag}^").strip()
    was, now = _VERSION.fullmatch(previous), _VERSION.fullmatch(tag)
    if not was or not now:
        return False, f"{tag} or {previous} is not a version tag, vX.Y.Z"
    wanted = (int(was.group(1)), int(was.group(2)), int(was.group(3)) + 1)
    if tuple(int(n) for n in now.groups()) != wanted:
        return False, (f"{tag} is not {previous}'s patch plus one, "
                       f"v{'.'.join(str(n) for n in wanted)}")
    declares = re.search(r'^version = "([^"]+)"', _git(root, "show", f"{tag}:pyproject.toml"),
                         re.M)
    if not declares or f"v{declares.group(1)}" != tag:
        return False, f"{tag}'s tree declares {declares.group(1) if declares else 'no version'}"
    eligible, why = check(root, previous, tag)
    return eligible, (f"{tag} is {previous}'s patch plus one; {why}" if eligible else why)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check_cmd = commands.add_parser("check", help="is everything since a tag a security patch")
    check_cmd.add_argument("--since", required=True, help="the latest release's tag")
    check_cmd.add_argument("--root", type=Path, default=Path.cwd())
    opening_cmd = commands.add_parser("opening", help="print the CHANGELOG entry's opening")
    opening_cmd.add_argument("--since", required=True, help="the latest release's tag")
    opening_cmd.add_argument("--root", type=Path, default=Path.cwd())
    verify_cmd = commands.add_parser("verify", help="is a tag a security patch's, for release.yml")
    verify_cmd.add_argument("--tag", required=True, help="the tag being released, vX.Y.Z")
    verify_cmd.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        if args.command == "opening":
            sys.stdout.write(opening(args.root.resolve(), args.since))
            return 0
        if args.command == "verify":
            eligible, why = verify(args.root.resolve(), args.tag)
        else:
            eligible, why = check(args.root.resolve(), args.since)
    except (OSError, Unreadable) as error:
        print(f"heal release: {error}", file=sys.stderr)
        return 2
    print(f"eligible: {why}" if eligible else f"release-needs-owner: {why}")
    return 0 if eligible else 1


if __name__ == "__main__":
    raise SystemExit(main())
