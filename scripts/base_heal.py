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

    python3 scripts/base_heal.py apply --plan base-plan.json --out base-out

`apply` rewrites every place the base is named, as 1.5.4's move did by hand: the Dockerfile's
stages, the base the licence check diffs against in `ci.yml` and `release.yml`, that script
and its test. It writes them under `--out`, never into the tree, with the CHANGELOG's item,
and prints the commit's message. Two of the five are workflows and the tag is outside the
Dockerfile's envelope, so the policy never merges such a pull request: it is the owner's.

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
DOCKERFILE = "Dockerfile"
#: Every file that names the base, as 1.5.4's move found them (`89ec9d8`).
NAMED = (DOCKERFILE, ".github/workflows/ci.yml", ".github/workflows/release.yml",
         "scripts/check_image_licences.py", "tests/test_licences.py")

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


def rewrite(text: str, move: dict) -> str:
    """`text` with the old base's every mention moved: with its digest where it is pinned,
    and the tag alone where it is only named."""
    old, new = move["from"], move["to"]
    old_tag, new_tag = old.split("@")[0], new.split("@")[0]
    text = text.replace(old, new)
    return re.sub(rf"{re.escape(old_tag)}(?![@\w.])", new_tag, text)


def apply(plan_: dict, tree: Path) -> dict[str, str]:
    """The files a base move changes, by path: every place 1.5.4's move rewrote."""
    files = {name: (tree / name).read_text(encoding="utf-8") for name in NAMED}
    for move in plan_["moves"]:
        if f"FROM {move['from']}" not in files[DOCKERFILE]:
            raise Refused(f"the Dockerfile has no stage `FROM {move['from']}`")
        files = {name: rewrite(text, move) for name, text in files.items()}
    return files


def message(plan_: dict, run: str) -> str:
    tags = [move["to"].split("@")[0] for move in plan_["moves"]]
    headline = (f"fix: the image's base moves to {' and '.join(tags)}, "
                "from a tag that stopped moving")
    trailers = [f"Heal-Base-Tag: {move['from'].split('@')[0]} {move['to']}"
                for move in plan_["moves"]]
    return headline + "\n\n" + "\n".join([*trailers, f"Heal-Run: {run}"]) + "\n"


def items(plan_: dict) -> list[str]:
    return [f"- **The image's base on `{move['to'].split('@')[0]}`,** from "
            f"`{move['from'].split('@')[0]}`, whose tag last moved on "
            f"{move['last_moved'][:10] or 'a date Docker Hub did not give'}."
            for move in plan_["moves"]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    plan_cmd = commands.add_parser("plan", help="write the plan for each dead base tag")
    plan_cmd.add_argument("--dockerfile", type=Path, default=Path("Dockerfile"))
    plan_cmd.add_argument("--now", required=True, help="YYYY-MM-DDTHH:MM:SSZ")
    plan_cmd.add_argument("--out", type=Path, required=True)
    apply_cmd = commands.add_parser("apply", help="write the files a plan changes, apart")
    apply_cmd.add_argument("--plan", type=Path, required=True)
    apply_cmd.add_argument("--tree", type=Path, default=Path.cwd())
    apply_cmd.add_argument("--out", type=Path, required=True)
    apply_cmd.add_argument("--run", default="", help="this run's URL, for the commit")
    args = parser.parse_args(argv)
    try:
        if args.command == "apply":
            return _apply(args)
        made = plan(args.dockerfile.read_text(encoding="utf-8"), now=args.now)
    except Refused as error:
        print(f"base heal: refused: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, Unreadable) as error:
        print(f"base heal: {error}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(made, indent=2) + "\n", encoding="utf-8")
    return 0



def _apply(args: argparse.Namespace) -> int:
    """`apply`: each rewritten file under `--out`, at its path, with the CHANGELOG, and the
    commit's message on stdout. Nothing at all for a plan with no move."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import heal  # deferred: `plan` needs none of the lock's heal

    plan_ = json.loads(args.plan.read_text(encoding="utf-8"))
    if not plan_["moves"]:
        return 0
    tree = args.tree.resolve()
    files = apply(plan_, tree)
    try:
        files[heal.CHANGELOG] = heal.changelog(
            (tree / heal.CHANGELOG).read_text(encoding="utf-8"), plan_, items(plan_))
    except heal.Refused as error:
        raise Refused(str(error)) from error
    for name, text in files.items():
        (args.out / name).parent.mkdir(parents=True, exist_ok=True)
        (args.out / name).write_text(text, encoding="utf-8")
    sys.stdout.write(message(plan_, args.run))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
