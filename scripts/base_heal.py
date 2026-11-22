#!/usr/bin/env python3
"""The heal for a base image whose tag has died (R44.9, D81u, Requirement 17).

    python3 scripts/base_heal.py plan --dockerfile Dockerfile \\
        --now 2026-10-24T08:00:00Z --out base-plan.json

Dependabot follows a tag's digest. It cannot see that the tag itself has stopped receiving
updates while a newer Alpine suffix carries them: `python:3.12-alpine3.22` last moved on
2026-04-19, and 1.5.3 shipped six months of OS fixes short. Docker's official images keep
two Alpine suffixes moving at once and retire one about every five months, and a retired
tag stays listed for years (measured 2026-11-22: `3.12-alpine3.17`, unmoved since
2023-12-01, is still there). So being listed says nothing, and the date does.

`plan` reads each `FROM <image>:<version>-alpine<release>@<digest>` of the Dockerfile and
Docker Hub's tags of that image and version. A tag is **dead** when it has not moved for 30
days. It is replaced by the tag of the same image and version with the newest Alpine release
that moved within 30 days, by its index digest. The version never changes: a Python minor is
the owner's. A tag that still moves is Dependabot's, and is left alone.

The replacement's index must cover `linux/amd64` and `linux/arm64`. If it does not, no plan
is written and the run fails, which files it as any scheduled failure is filed.

Standard library alone. It asks Docker Hub and no other host. Exit 0 when the plan was
written, whatever it holds; 1 when a replacement was refused; 2 when an input could not be
read.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCHEMA = 1
HUB = "https://hub.docker.com/v2/repositories/library"
#: How long a tag may go unmoved before it is dead, and how lately a replacement must have
#: moved (Requirement 17.2).
DEAD = timedelta(days=30)
ARCHITECTURES = ("amd64", "arm64")

_FROM = re.compile(
    r"^FROM ([a-z0-9]+):([^\s@]*?)-alpine(\d+)\.(\d+)@(sha256:[0-9a-f]{64})(?= |$)", re.M)


class Unreadable(Exception):
    """An input, or Docker Hub's answer, is not what it should be."""


class Refused(Exception):
    """A replacement exists and cannot be taken."""


def _when(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.split(".")[0].rstrip("Z")).replace(tzinfo=UTC)


def tags(image: str, prefix: str) -> list[dict]:
    """Docker Hub's tags of an official image that start with `prefix`."""
    url: str | None = f"{HUB}/{image}/tags?page_size=100&name={prefix}"
    found: list[dict] = []
    while url:
        if not url.startswith(HUB + "/"):
            raise Unreadable(f"{url}: not Docker Hub's list of an official image's tags")
        try:
            with urllib.request.urlopen(url, timeout=60) as answer:  # noqa: S310 — https, HUB
                page = json.loads(answer.read())
            found += [tag for tag in page.get("results") or [] if isinstance(tag, dict)]
            url = page.get("next")
        except (urllib.error.URLError, TimeoutError, ValueError, AttributeError) as error:
            raise Unreadable(f"Docker Hub's tags of {image}: {error}") from error
    return found


def _covers_both(tag: dict) -> bool:
    held = {image.get("architecture") for image in tag.get("images") or []
            if isinstance(image, dict) and image.get("os") == "linux"}
    return all(architecture in held for architecture in ARCHITECTURES)


def plan(dockerfile: str, *, now: str) -> dict:
    today = _when(now)
    moves = []
    for image, version, major, minor, digest in sorted(set(_FROM.findall(dockerfile))):
        name = f"{version}-alpine{major}.{minor}"
        listed = {}
        for tag in tags(image, f"{version}-alpine"):
            read = re.fullmatch(rf"{re.escape(version)}-alpine(\d+)\.(\d+)", str(tag.get("name")))
            if read and tag.get("last_updated"):
                listed[(int(read.group(1)), int(read.group(2)))] = tag
        mine = listed.get((int(major), int(minor)))
        if mine is None:
            raise Unreadable(f"Docker Hub lists no {image}:{name}")
        moved = _when(mine["last_updated"])
        if today - moved <= DEAD:
            continue
        alive = {release: tag for release, tag in listed.items()
                 if release > (int(major), int(minor))
                 and today - _when(tag["last_updated"]) <= DEAD}
        if not alive:
            continue
        release = max(alive)
        newer = alive[release]
        to = f"{image}:{version}-alpine{release[0]}.{release[1]}"
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(newer.get("digest") or "")):
            raise Unreadable(f"Docker Hub gives no digest for {to}")
        if not _covers_both(newer):
            raise Refused(f"{to} does not cover linux/amd64 and linux/arm64")
        moves.append({"from": f"{image}:{name}@{digest}", "to": f"{to}@{newer['digest']}",
                      "last_moved": moved.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "days": (today - moved).days,
                      "rule": "unmoved for 30 days, and a newer Alpine suffix moved within 30"})
    return {"schema": SCHEMA, "made": now, "moves": moves}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    plan_cmd = commands.add_parser("plan", help="write the plan for each dead base tag")
    plan_cmd.add_argument("--dockerfile", type=Path, default=Path("Dockerfile"))
    plan_cmd.add_argument("--now", required=True, help="YYYY-MM-DDTHH:MM:SSZ")
    plan_cmd.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        made = plan(args.dockerfile.read_text(encoding="utf-8"), now=args.now)
    except Refused as error:
        print(f"base heal: refused: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, Unreadable) as error:
        print(f"base heal: {error}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(made, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
