#!/usr/bin/env python3
"""The heal for the image (R44.12, D81x): plan what the Dockerfile's envelope should become.

    python3 scripts/image_heal.py plan --verdict amd64.json --verdict arm64.json \\
        --dockerfile Dockerfile --now 2026-11-21T06:41:00Z --out image-plan.json

1.6.2 was three kinds of edit to one file, made by hand from the image gate's output. Each is
mechanical. `plan` reads the gate's verdict on the image built from `main`, one file for each
architecture (`scripts/image_gate.py --out`), and the Dockerfile. By the kind Trivy gave each
blocking entry:

- **an Alpine package** is raised in `ALPINE_RAISE` to the version Alpine's index holds for
  both architectures, when that is the fixed version or later. Alpine keeps one version of
  a package, so there is no other to choose. Otherwise it is escalated as `no-alpine-fix`.
- **a Go module** is raised in the `_RAISE` of the Scanner whose binary holds it, to the
  lowest fixed version in the major it is installed at. A fix only in a new major is
  `go-major`. One with no tagged version is `go-untagged`: the heal never writes a
  pseudo-version. The Scanner's own module is `scanner-version`: its next release's.
- **Go's standard library** moves the one `golang:` pin the four stages share to the newest
  patch of its minor, by digest. A fix only in another minor is `go-major`.
- **anything else** is listed as `unplanned`, with why, and never dropped.

The base comes first. When an Alpine package blocks and Docker Hub's tag has moved past the
digest the Dockerfile pins, the plan moves the digest, reads the new base's own package
database in a container with no network, and plans no raise for what the new base carries:
neither a new one, nor one the Dockerfile already holds, which is then dropped.

What it reads from the network, and nothing else: Alpine's `APKINDEX` for the base's release,
Go's module proxy for a module's tagged versions, and Docker Hub's list of an official
image's tags.
What comes back is data. Standard library alone. Exit 0 when the plan was written, whatever
it holds; 2 when an input could not be read.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scanner_pins

SCHEMA = 1
ALPINE = "https://dl-cdn.alpinelinux.org/alpine"
#: Alpine's name for each architecture the image is built for.
ARCHITECTURES = ("x86_64", "aarch64")
REPOSITORIES = ("main", "community")
GOPROXY = "https://proxy.golang.org"
HUB = "https://hub.docker.com/v2/repositories/library"
HOSTS = (ALPINE, GOPROXY, HUB)
_PYTHON = re.compile(r"^FROM python:(\S+?)@(sha256:[0-9a-f]{64})", re.M)
_RAISED = re.compile(r'^ARG ALPINE_RAISE="([^"]*)"', re.M)
_GO = re.compile(r"^FROM golang:(\d+\.\d+)\.(\d+)-(\S+?)@(sha256:[0-9a-f]{64})", re.M)
#: Trivy's name for Go's standard library in a binary.
STDLIB = "stdlib"
#: Each Scanner built from source: its `ARG` prefix, and its own module.
SCANNERS = {name: (prefix, module) for name, prefix, _image, module in scanner_pins.SOURCES}

_BASE = re.compile(r"^FROM python:[^\s@]*alpine(\d+\.\d+)@sha256:[0-9a-f]{64}", re.M)
_APK_VERSION = re.compile(
    r"(\d+(?:\.\d+)*)([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?")
#: How a suffix orders against the bare version: before it, or after.
_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4,
           "p": 5}


class Unreadable(Exception):
    """An input, or an answer from the network, is not what it should be."""


def apk_key(version: str) -> tuple | None:
    """An Alpine version as something that orders the way `apk version -t` does, for the
    shapes Alpine's packages take. None for one this does not read: nothing is assumed of it."""
    read = _APK_VERSION.fullmatch(version)
    if not read:
        return None
    numbers, letter, suffixes, revision = read.groups()
    tail = [(_SUFFIX[name], int(count or 0))
            for name, count in re.findall(r"_([a-z]+)(\d*)", suffixes)]
    return (tuple(int(n) for n in numbers.split(".")), letter, (*tail, (0, 0)),
            int(revision or 0))


def _get(url: str) -> bytes | None:
    """The bytes at `url`; None for a 404. Only the three hosts named at the top are ever
    asked: an answer that names another, such as a next page, is refused here."""
    if not url.startswith(tuple(f"{host}/" for host in HOSTS)):
        raise Unreadable(f"{url}: not a host the image's heal asks")
    try:
        with urllib.request.urlopen(url, timeout=60) as answer:  # noqa: S310 — https, named above
            return answer.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise Unreadable(f"{url}: HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise Unreadable(f"{url}: {error}") from error


def alpine_index(release: str, architecture: str) -> dict[str, str]:
    """Each package of Alpine `release` for one architecture, at the one version it holds."""
    held: dict[str, str] = {}
    for repository in REPOSITORIES:
        data = _get(f"{ALPINE}/v{release}/{repository}/{architecture}/APKINDEX.tar.gz")
        if data is None:
            continue
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                member = archive.extractfile("APKINDEX")
                text = member.read().decode("utf-8", "replace") if member else ""
        except (tarfile.TarError, KeyError, OSError) as error:
            raise Unreadable(f"Alpine's {repository} index for {architecture}: {error}") from error
        name = ""
        for line in text.splitlines():
            if line.startswith("P:"):
                name = line[2:]
            elif line.startswith("V:") and name:
                held.setdefault(name, line[2:])
    if not held:
        raise Unreadable(f"Alpine v{release} has no index for {architecture}")
    return held


def _alpine(entries: list[dict], release: str) -> tuple[list[dict], list[dict]]:
    """(raises, escalations) for the blocking Alpine entries, by package."""
    indexes = [alpine_index(release, architecture) for architecture in ARCHITECTURES]
    raises, escalations = [], []
    for package in sorted({e["package"] for e in entries}):
        about = [e for e in entries if e["package"] == package]
        answers = sorted({e["id"] for e in about})
        held = {index.get(package) for index in indexes}
        version = next(iter(held)) if len(held) == 1 else None
        fixed = [apk_key(e["fixed"]) for e in about]
        have = apk_key(version) if version else None
        if have is None or None in fixed or have < max(fixed):  # type: ignore[type-var]
            escalations.append({"subject": package, "reason": "no-alpine-fix",
                                "answers": answers})
            continue
        raises.append({"arg": "ALPINE_RAISE", "entry": f"{package}={version}",
                       "package": package, "from": about[0]["installed"], "answers": answers,
                       "rule": "alpine-index"})
    return raises, escalations


def _go_key(version: str) -> tuple[int, ...] | None:
    """A Go version's numbers, or None for a pseudo-version or anything else untagged."""
    read = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version)
    return tuple(int(n) for n in read.groups()) if read else None


def go_tags(module: str) -> set[str]:
    """The versions Go's module proxy lists for `module`: its tagged releases."""
    escaped = re.sub(r"[A-Z]", lambda capital: "!" + capital.group().lower(), module)
    data = _get(f"{GOPROXY}/{escaped}/@v/list")
    return set(data.decode("utf-8", "replace").split()) if data else set()


def _modules(entries: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """(raises, escalations, unplanned) for the blocking Go modules, by Scanner and module.

    A module is raised to the lowest fixed version in the major it is installed at, which
    must be one the proxy lists: the heal never writes a pseudo-version, a commit that a
    person would have had to choose."""
    raises, escalations, unplanned = [], [], []
    groups: dict[tuple[str, str], list[dict]] = {}
    for entry in entries:
        scanner = Path(entry.get("target", "")).name
        if scanner not in SCANNERS:
            unplanned.append(_unplanned(entry, "a binary no `_RAISE` builds"))
        else:
            groups.setdefault((scanner, entry["package"]), []).append(entry)
    for (scanner, module), about in sorted(groups.items()):
        prefix, own = SCANNERS[scanner]
        answers = sorted({e["id"] for e in about})
        if module == own:
            escalations.append({"subject": scanner, "reason": "scanner-version",
                                "answers": answers})
            continue
        subject = f"{module} ({scanner})"
        installed = re.match(r"v?(\d+)\.", about[0]["installed"])
        floors, reason = [], ""
        for entry in about:
            fixes = [fix.strip() for fix in entry["fixed"].split(",") if fix.strip()]
            in_major = [fix for fix in fixes
                        if installed and re.match(rf"v?{installed.group(1)}\.", fix)]
            keys = [_go_key(fix) for fix in in_major]
            if not in_major:
                reason = "go-major"
            elif None in keys:
                reason = reason or "go-untagged"
            else:
                floors.append(min(keys))  # type: ignore[type-var]
        if not reason:
            version = "v" + ".".join(str(n) for n in max(floors))
            if version not in go_tags(module):
                reason = "go-untagged"
        if reason:
            escalations.append({"subject": subject, "reason": reason, "answers": answers})
            continue
        raises.append({"arg": f"{prefix}_RAISE", "entry": f"{module}@{version}",
                       "package": module, "from": about[0]["installed"], "answers": answers,
                       "rule": "go-fixed-version"})
    return raises, escalations, unplanned


def hub_tags(repository: str, prefix: str) -> dict[str, str]:
    """Docker Hub's tags of an official image that start with `prefix`, each with the
    digest of its index."""
    url: str | None = f"{HUB}/{repository}/tags?page_size=100&name={prefix}"
    found: dict[str, str] = {}
    while url:
        data = _get(url)
        try:
            page = json.loads(data) if data else {}
            for tag in page.get("results") or []:
                if re.fullmatch(r"sha256:[0-9a-f]{64}", str(tag.get("digest") or "")):
                    found[str(tag["name"])] = tag["digest"]
            url = page.get("next")
        except (ValueError, AttributeError, KeyError, TypeError) as error:
            raise Unreadable(f"Docker Hub's tags of {repository}: {error}") from error
        if url and not url.startswith(HUB + "/"):
            raise Unreadable(f"Docker Hub's next page is elsewhere: {url}")
    return found


def _stdlib(entries: list[dict], dockerfile: str) -> tuple[dict | None, list[dict]]:
    """(the move of the one Go pin, escalations) for blocking entries in Go's standard
    library: the newest patch of the pinned minor, with the pin's own Alpine suffix, when
    it is at or past every fix in that minor."""
    pins = set(_GO.findall(dockerfile))
    if len(pins) != 1:
        raise Unreadable("the Dockerfile's Go stages do not share one pin by digest")
    minor, patch, suffix, digest = next(iter(pins))
    answers = sorted({e["id"] for e in entries})
    needed = []
    for entry in entries:
        fixes = [_go_key(fix.strip()) for fix in entry["fixed"].split(",")]
        ours = [fix for fix in fixes if fix and f"{fix[0]}.{fix[1]}" == minor]
        if not ours:
            return None, [{"subject": "go", "reason": "go-major", "answers": answers}]
        needed.append(min(ours)[2])
    offered = {}
    for name, held in hub_tags("golang", f"{minor}.").items():
        read = re.fullmatch(rf"{re.escape(minor)}\.(\d+)-{re.escape(suffix)}", name)
        if read:
            offered[int(read.group(1))] = (name, held)
    newest = max(offered, default=-1)
    if newest < max(needed) or newest <= int(patch):
        return None, [{"subject": "go", "reason": "go-major", "answers": answers}]
    name, held = offered[newest]
    return ({"from": f"golang:{minor}.{patch}-{suffix}@{digest}", "to": f"golang:{name}@{held}",
             "answers": answers, "rule": "newest-patch-of-the-minor"}, [])


def installed_in(image: str, docker: str) -> dict[str, str]:
    """Each Alpine package `image` holds, at its version, read from its own database in a
    container with no network."""
    try:
        run = subprocess.run(  # noqa: S603
            [docker, "run", "--rm", "--network", "none", "--entrypoint", "cat", image,
             "/lib/apk/db/installed"], capture_output=True, text=True, check=False, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Unreadable(f"{image}'s packages could not be read: {error}") from error
    if run.returncode != 0:
        raise Unreadable(f"{image}'s packages could not be read: {run.stderr.strip()[-200:]}")
    held, name = {}, ""
    for line in run.stdout.splitlines():
        if line.startswith("P:"):
            name = line[2:]
        elif line.startswith("V:") and name:
            held[name] = line[2:]
    return held


def _base_move(dockerfile: str, docker: str) -> tuple[dict | None, dict[str, str]]:
    """(the move of the base's digest, the packages the new base holds) when Docker Hub's
    tag has moved past the digest the Dockerfile pins. (None, {}) when it has not."""
    pins = set(_PYTHON.findall(dockerfile))
    if len(pins) != 1:
        raise Unreadable("the Dockerfile's Python stages do not share one base by digest")
    tag, digest = next(iter(pins))
    now = hub_tags("python", tag).get(tag)
    if not now or now == digest:
        return None, {}
    move = {"from": f"python:{tag}@{digest}", "to": f"python:{tag}@{now}", "answers": [],
            "rule": "the-tags-digest-moved"}
    return move, installed_in(f"python@{now}", docker)


def _carried(held: dict[str, str], package: str, version: str) -> bool:
    """Whether the new base holds `package` at `version` or later."""
    have, wanted = apk_key(held.get(package, "")), apk_key(version)
    return have is not None and wanted is not None and have >= wanted


def _unplanned(entry: dict, why: str) -> dict:
    return {"id": entry["id"], "package": entry["package"], "kind": entry.get("kind", ""),
            "target": entry.get("target", ""), "why": why}


def plan(verdicts: list[dict], dockerfile: str, *, now: str, docker: str = "docker") -> dict:
    blocking: dict[tuple[str, str, str], dict] = {}
    for verdict in verdicts:
        for entry in verdict.get("blocking") or []:
            blocking.setdefault((entry["id"], entry["package"], entry.get("target", "")), entry)
    base = _BASE.search(dockerfile)
    if not base:
        raise Unreadable("the Dockerfile names no `python:…-alpine<release>` base by digest")
    found = sorted(blocking.values(), key=lambda e: (e["id"], e["package"], e.get("target", "")))
    alpine = [e for e in found if e.get("kind") == "alpine"]
    # The base first: a new digest of its tag may carry a fix, and a raise it carries is
    # one the build would refuse. Asked only when an Alpine package blocks.
    move, held = _base_move(dockerfile, docker) if alpine else (None, {})
    drops = []
    if move:
        answered = [e for e in alpine if _carried(held, e["package"], e["fixed"])]
        move["answers"] = sorted({e["id"] for e in answered})
        alpine = [e for e in alpine if e not in answered]
        raised = _RAISED.search(dockerfile)
        for entry in (raised.group(1).split() if raised else []):
            package, _, version = entry.partition("=")
            if _carried(held, package, version):
                drops.append({"arg": "ALPINE_RAISE", "entry": entry,
                              "why": f"the new base carries {package} {held[package]}"})
    raises, escalations = _alpine(alpine, base.group(1)) if alpine else ([], [])
    modules = [e for e in found if e.get("kind") == "gobinary" and e["package"] != STDLIB]
    more = _modules(modules)
    std = [e for e in found if e.get("kind") == "gobinary" and e["package"] == STDLIB]
    go, go_escalations = _stdlib(std, dockerfile) if std else (None, [])
    unplanned = more[2] + [
        _unplanned(e, "a Python package: the Checkov lock's heal, or Dependabot"
                   if e.get("kind") == "python-pkg" else "a kind the image's heal does not plan")
        for e in found if e.get("kind") not in ("alpine", "gobinary")]
    return {"schema": SCHEMA, "made": now,
            "raises": sorted(raises + more[0], key=lambda r: (r["arg"], r["entry"])),
            "base": move, "drops": drops, "go": go,
            "escalations": escalations + more[1] + go_escalations,
            "unplanned": sorted(unplanned, key=lambda u: (u["id"], u["package"]))}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    plan_cmd = commands.add_parser("plan", help="write the image's plan from the gate's verdicts")
    plan_cmd.add_argument("--verdict", type=Path, action="append", required=True,
                          help="the image gate's verdict for one architecture; once for each")
    plan_cmd.add_argument("--dockerfile", type=Path, default=Path("Dockerfile"))
    plan_cmd.add_argument("--now", required=True, help="YYYY-MM-DDTHH:MM:SSZ")
    plan_cmd.add_argument("--out", type=Path, required=True)
    plan_cmd.add_argument("--docker", default="docker",
                          help="the container runtime that reads a new base's packages")
    args = parser.parse_args(argv)
    try:
        verdicts = [json.loads(path.read_text(encoding="utf-8")) for path in args.verdict]
        made = plan(verdicts, args.dockerfile.read_text(encoding="utf-8"), now=args.now,
                    docker=args.docker)
    except (OSError, ValueError, KeyError, Unreadable) as error:
        print(f"image heal: {error}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(made, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
