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
- **anything else** is listed as `unplanned`, with why, and never dropped.

What it reads from the network, and nothing else: Alpine's `APKINDEX` for the base's release,
and Go's module proxy for a module's tagged versions.
What comes back is data. Standard library alone. Exit 0 when the plan was written, whatever
it holds; 2 when an input could not be read.
"""

from __future__ import annotations

import argparse
import io
import json
import re
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
    """The bytes at `url`; None for a 404."""
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


def _unplanned(entry: dict, why: str) -> dict:
    return {"id": entry["id"], "package": entry["package"], "kind": entry.get("kind", ""),
            "target": entry.get("target", ""), "why": why}


def plan(verdicts: list[dict], dockerfile: str, *, now: str) -> dict:
    blocking: dict[tuple[str, str, str], dict] = {}
    for verdict in verdicts:
        for entry in verdict.get("blocking") or []:
            blocking.setdefault((entry["id"], entry["package"], entry.get("target", "")), entry)
    base = _BASE.search(dockerfile)
    if not base:
        raise Unreadable("the Dockerfile names no `python:…-alpine<release>` base by digest")
    found = sorted(blocking.values(), key=lambda e: (e["id"], e["package"], e.get("target", "")))
    alpine = [e for e in found if e.get("kind") == "alpine"]
    raises, escalations = _alpine(alpine, base.group(1)) if alpine else ([], [])
    modules = [e for e in found if e.get("kind") == "gobinary" and e["package"] != STDLIB]
    more = _modules(modules)
    unplanned = more[2] + [
        _unplanned(e, "a Python package: the Checkov lock's heal, or Dependabot"
                   if e.get("kind") == "python-pkg" else "a kind the image's heal does not plan")
        for e in found if e.get("kind") not in ("alpine", "gobinary")]
    return {"schema": SCHEMA, "made": now,
            "raises": sorted(raises + more[0], key=lambda r: (r["arg"], r["entry"])),
            "escalations": escalations + more[1],
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
    args = parser.parse_args(argv)
    try:
        verdicts = [json.loads(path.read_text(encoding="utf-8")) for path in args.verdict]
        made = plan(verdicts, args.dockerfile.read_text(encoding="utf-8"), now=args.now)
    except (OSError, ValueError, KeyError, Unreadable) as error:
        print(f"image heal: {error}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(made, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
