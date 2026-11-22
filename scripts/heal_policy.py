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
2. every commit is by the heal App, committed by GitHub with a verified signature, and
   carries a `Heal-Pin` trailer;
3. the recipe, run on the base's lock with the commits' own `Heal-Pin` trailers, writes
   the pull request's lock, byte for byte;
4. no package was added or removed, no major version moved, Checkov did not move, and no
   package under an override moved;
5. the CHANGELOG, when changed, only gains lines, and only under `[Unreleased]`.

    python3 scripts/heal_policy.py image --base . --head "$RUNNER_TEMP/head" < view.json

An image heal (R44.13) is judged the same way, on the pull request's `Dockerfile`. It must
be the base's with exactly what the commits' trailers state (`Heal-Base`, `Heal-Go`,
`Heal-Raise`, `Heal-Drop`) written into its envelope, and identical outside it. The policy
cannot ask the network what a fix is, so it holds each trailer to a heal's shape, a Go raise
to a tagged version, and every change to raising. Whether the result is free of what blocked
is the image gate's to say, as a required check.

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
import image_heal

ENVELOPE = (heal.LOCK, heal.CHANGELOG)
#: The heal App's account, and the committer of a commit made through GitHub's API.
APP = "valvur-heal[bot]"
GITHUB = "web-flow"
OVERRIDES = "requirements-checkov.overrides"
DOCKERFILE = "Dockerfile"
_IMAGE = re.compile(r"^Heal-(Base|Go|Raise|Drop): (.+)$", re.M)
#: An Alpine raise, `name=version`, and a Go raise at a tagged version: never a
#: pseudo-version, which is a commit a person chose.
_ALPINE_ENTRY = re.compile(r"[a-z0-9][a-z0-9+._-]*=[0-9][A-Za-z0-9._-]*")
_GO_ENTRY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~/-]*@v\d+\.\d+\.\d+")
#: The package each line of the overrides file names, whatever it asks of it.
_OVERRIDDEN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", re.M)
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


def _not_the_apps(commit: dict, trailer: re.Pattern[str] | None = None) -> str:
    """Why this commit is not one the App made through GitHub's API, or ""."""
    sha = str(commit.get("sha", ""))[:7]
    author = (commit.get("author") or {}).get("login", "")
    committer = (commit.get("committer") or {}).get("login", "")
    inner = commit.get("commit") or {}
    if author != APP:
        return f"commit {sha} is by {author or 'no account'}, not {APP}"
    if committer != GITHUB:
        return (f"commit {sha} was not committed by GitHub ({GITHUB}), "
                f"but by {committer or 'no account'}")
    if (inner.get("verification") or {}).get("verified") is not True:
        return f"commit {sha} has no verified signature"
    if not (trailer or _PIN).search(inner.get("message") or ""):
        return (f"commit {sha} carries no Heal-Pin trailer" if trailer is None else
                f"commit {sha} carries no trailer of an image heal")
    return ""


def _outside_the_envelope(before: dict[str, str], after: dict[str, str], overrides: str) -> str:
    """Why a lock the recipe did write is still not a heal's to merge, or ""."""
    added, removed = sorted(set(after) - set(before)), sorted(set(before) - set(after))
    if added or removed:
        return ("the package set changed: "
                + ", ".join([f"{name} added" for name in added]
                            + [f"{name} removed" for name in removed]))
    moved = sorted(name for name in before if before[name] != after[name])
    if heal.CHECKOV in moved:
        return f"Checkov moved, {before[heal.CHECKOV]} to {after[heal.CHECKOV]}"
    major = [name for name in moved
             if heal.release_line(before[name]) != heal.release_line(after[name])]
    if major:
        return "a major version moved: " + ", ".join(
            f"{name} {before[name]} to {after[name]}" for name in major)
    under = {re.sub(r"[-_.]+", "-", name).lower() for name in _OVERRIDDEN.findall(overrides)}
    overridden = sorted(under & set(moved))
    if overridden:
        return "a package under an override moved: " + ", ".join(overridden)
    return ""


def _more_than_added(before: str, after: str) -> str:
    """Why a CHANGELOG does more than add lines under `[Unreleased]`, or ""."""
    kept = iter(after.splitlines())
    if not all(line in kept for line in before.splitlines()):
        return "the CHANGELOG removes or changes a line"
    heading = re.search(r"^## \[Unreleased\][^\n]*\n", before, re.M)
    if not heading:
        return "the base's CHANGELOG has no `## [Unreleased]` section"
    following = re.search(r"^## ", before[heading.end():], re.M)
    end = heading.end() + following.start() if following else len(before)
    above, below = before[:heading.end()], before[end:]
    if not after.startswith(above) or not after.endswith(below):
        return "the CHANGELOG adds lines outside `[Unreleased]`"
    between = after[len(above):len(after) - len(below)]
    if re.search(r"^## ", between, re.M):
        return "the CHANGELOG adds a section, so lines fall outside `[Unreleased]`"
    return ""


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
    for commit in commits:
        refused = _not_the_apps(commit)
        if refused:
            return False, refused
    asked = pins(commits)
    base_lock = (base / heal.LOCK).read_text(encoding="utf-8")
    written = heal.relock(base, base_lock, asked)
    if written is None:
        return False, "the recipe fails on the base's lock with the commits' pins"
    if written != (head / heal.LOCK).read_text(encoding="utf-8"):
        return False, ("the lock is not what the recipe writes from the base's with "
                       + ", ".join(f"{name}=={version}" for name, version in sorted(asked.items())))
    outside = _outside_the_envelope(heal.parse_lock(base_lock), heal.parse_lock(written),
                                    (base / OVERRIDES).read_text(encoding="utf-8"))
    if outside:
        return False, outside
    if heal.CHANGELOG in files:
        more = _more_than_added((base / heal.CHANGELOG).read_text(encoding="utf-8"),
                                (head / heal.CHANGELOG).read_text(encoding="utf-8"))
        if more:
            return False, more
    return True, f"eligible: the recipe's lock with {len(asked)} pin(s), and nothing else"


def _higher(arg: str, held: list[str], entry: str) -> bool:
    """Whether `entry` raises its package past what `arg` already holds of it, or adds it."""
    key = image_heal.apk_key if arg == "ALPINE_RAISE" else image_heal._go_key
    name = image_heal._named(entry)
    new = key(entry[len(name) + 1:])
    for had in held:
        if image_heal._named(had) == name:
            old = key(had[len(name) + 1:])
            return new is not None and (old is None or new > old)
    return new is not None


def image_plan(commits: list[dict], dockerfile: str) -> dict | str:
    """The plan the commits' trailers state, for `image_heal.apply`. Or why a trailer is
    not one a heal writes: the policy cannot ask the network what a fix is, so it holds
    each trailer to its shape, and to raising and never lowering."""
    plan_: dict = {"raises": [], "drops": [], "base": None, "go": None}
    pythons = set(image_heal._PYTHON.findall(dockerfile))
    gos = set(image_heal._GO.findall(dockerfile))
    if len(pythons) != 1 or len(gos) != 1:
        raise Unreadable("the base's Dockerfile does not hold one Python base and one Go pin")
    (tag, digest), (minor, patch, suffix, go_digest) = next(iter(pythons)), next(iter(gos))
    for commit in commits:
        message = (commit.get("commit") or {}).get("message") or ""
        for kind, value in _IMAGE.findall(message):
            if kind == "Base":
                if not re.fullmatch(rf"python:{re.escape(tag)}@sha256:[0-9a-f]{{64}}", value):
                    return f"Heal-Base names another base than the Dockerfile's python:{tag}"
                plan_["base"] = {"from": f"python:{tag}@{digest}", "to": value}
                continue
            if kind == "Go":
                read = re.fullmatch(r"golang:(\d+\.\d+)\.(\d+)-(\S+?)@sha256:[0-9a-f]{64}", value)
                if not read or read.group(1) != minor or read.group(3) != suffix:
                    return f"Heal-Go leaves Go's minor {minor} or its image -{suffix}"
                if int(read.group(2)) <= int(patch):
                    return f"Heal-Go does not raise Go past {minor}.{patch}"
                plan_["go"] = {"from": f"golang:{minor}.{patch}-{suffix}@{go_digest}",
                               "to": value}
                continue
            arg, _, entry = value.partition(" ")
            if arg not in image_heal.ARGS:
                return f"Heal-{kind} names {arg}, which is not a raise argument"
            shape = _ALPINE_ENTRY if arg == "ALPINE_RAISE" else _GO_ENTRY
            if not shape.fullmatch(entry):
                return (f"Heal-{kind} {arg} has an entry that is not a heal's shape"
                        + ("" if arg == "ALPINE_RAISE" else
                           ": a Go raise names a tagged version, vN.N.N"))
            if kind == "Drop":
                if arg != "ALPINE_RAISE":
                    return "only an Alpine raise is dropped, when a new base carries it"
                plan_["drops"].append({"arg": arg, "entry": entry})
            elif not _higher(arg, image_heal._entries(dockerfile, arg), entry):
                return f"Heal-Raise {arg} {entry} does not raise what the Dockerfile holds"
            else:
                plan_["raises"].append({"arg": arg, "entry": entry})
    return plan_


def decide_image(view: dict, base: Path, head: Path) -> tuple[bool, str]:
    """(eligible, why) for a heal of the image: the Dockerfile's envelope, and nothing else."""
    files = [f.get("path", "") for f in view.get("files") or []]
    commits = view.get("commits") or []
    if not files or not commits:
        raise Unreadable("no files or no commits to judge")
    others = sorted(path for path in files if path not in (DOCKERFILE, heal.CHANGELOG))
    if others:
        return False, f"changes files an image heal never changes: {', '.join(others)}"
    if DOCKERFILE not in files:
        return False, f"does not change the {DOCKERFILE}"
    for commit in commits:
        refused = _not_the_apps(commit, _IMAGE)
        if refused:
            return False, refused
    before = (base / DOCKERFILE).read_text(encoding="utf-8")
    after = (head / DOCKERFILE).read_text(encoding="utf-8")
    outside = image_heal.differs_outside(before, after)
    if outside:
        return False, f"the Dockerfile {outside}"
    stated = image_plan(commits, before)
    if isinstance(stated, str):
        return False, stated
    try:
        applied = image_heal.apply(stated, before)
    except image_heal.Refused as error:
        return False, f"the trailers do not fit the base's Dockerfile: {error}"
    if applied != after:
        return False, "the Dockerfile is not the base's with the trailers applied"
    if heal.CHANGELOG in files:
        more = _more_than_added((base / heal.CHANGELOG).read_text(encoding="utf-8"),
                                (head / heal.CHANGELOG).read_text(encoding="utf-8"))
        if more:
            return False, more
    count = (len(stated["raises"]) + len(stated["drops"]) + bool(stated["base"])
             + bool(stated["go"]))
    return True, f"eligible: the Dockerfile's envelope with {count} stated change(s), no more"


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    lock = commands.add_parser("lock", help="judge a heal of the Checkov lock")
    lock.add_argument("--base", type=Path, default=Path.cwd(), help="the base branch's tree")
    lock.add_argument("--head", type=Path, required=True,
                      help="the pull request's two files, as data")
    image = commands.add_parser("image", help="judge a heal of the image's Dockerfile")
    image.add_argument("--base", type=Path, default=Path.cwd(), help="the base branch's tree")
    image.add_argument("--head", type=Path, required=True,
                       help="the pull request's Dockerfile and CHANGELOG, as data")
    args = parser.parse_args(argv)
    try:
        view = json.load(stdin or sys.stdin)
        if not isinstance(view, dict):
            raise Unreadable("the input is not a JSON object")
        judge = decide_image if args.command == "image" else decide
        eligible, why = judge(view, args.base.resolve(), args.head)
    except (OSError, ValueError, Unreadable, heal.Refused, image_heal.Refused) as error:
        print(f"cannot judge the pull request: {error}")
        return 2
    print(why if eligible else f"left for the owner: {why}")
    return 0 if eligible else 1


if __name__ == "__main__":
    sys.exit(main())
