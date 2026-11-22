#!/usr/bin/env python3
"""The heal for the Checkov lock (R44, D81): plan what may move, mechanically.

    python3 scripts/heal.py plan --findings findings.json --lock requirements-checkov.txt \\
        --now 2026-10-21T06:41:00Z --out plan.json

`plan` reads a Scan Run's active dependency Findings at the lock. For each package it asks
PyPI which versions exist and when each was uploaded (`scripts/pypi_facts.py`), and writes
`plan.json`: a pin for each package it may move, and an escalation for each it may not.

A version is chosen by rule, never by judgement (D81d, D81e): the newest final release at
or above the fix, in the major version the lock holds, that is older than the cooldown. With
none that old, the lowest such release, when it is a day old and every one of its files is
attested by the Trusted Publisher that attested the version it replaces.

Each fix is then re-locked by the recipe itself, `scripts/lock-checkov.sh`, in a scratch copy.
A package the resolution moves with it is a floor the fix forces: it is chosen by the same
rule, among the versions that resolve, and pinned too. Every version a fix would move to
is then put to `valvur check`, and a fix with a flagged one is escalated.

Standard library, and `valvur`'s own version ordering, so a pin and the report that asked
for it agree on which version is higher. Exit 0 when the plan was written, whatever it holds;
2 when an input could not be read.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pypi_facts

from valvur import verdict
from valvur.versions import release_line, version_key

SCHEMA = 1
#: D81d: as `.github/dependabot.yml` has it.
COOLDOWN = timedelta(days=7)
#: D81e: the least age of a version taken before the cooldown, on its publisher's word.
YOUNG = timedelta(hours=24)
LOCK = "requirements-checkov.txt"
#: The one package the heal never moves: a new Checkov is the owner's to take (D81q).
CHECKOV = "checkov"
RECIPE = "scripts/lock-checkov.sh"
#: What the recipe reads beside the lock it rewrites.
RECIPE_READS = (RECIPE, "requirements-checkov.in", "requirements-checkov.overrides")

_PINNED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)", re.M)


def _name(package: str) -> str:
    """A project's name as PyPI compares it (PEP 503)."""
    return re.sub(r"[-_.]+", "-", package).lower()


def _when(stamp: str) -> datetime:
    return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def locked(text: str) -> dict[str, str]:
    """Each package the lock pins, by its normalised name."""
    return {_name(name): version for name, version in _PINNED.findall(text)}


def _at_lock(findings: list[dict], lock: str) -> list[dict]:
    """The active dependency Findings whose path is the lock."""
    return [f for f in findings
            if verdict.active(f) and f.get("path") == lock
            and (f.get("dependency") or {}).get("package")]


def relock(tree: Path, lock_text: str, pins: dict[str, str]) -> str | None:
    """The lock the recipe writes from `lock_text` with each pin on `--upgrade-package`,
    in a copy of the tree's recipe, so the tree is never written. None when the recipe
    fails: the pins cannot be resolved together."""
    with tempfile.TemporaryDirectory(prefix="valvur-heal-") as scratch:
        copy = Path(scratch)
        (copy / "scripts").mkdir()
        for name in RECIPE_READS:
            shutil.copy(tree / name, copy / name)
        (copy / LOCK).write_text(lock_text, encoding="utf-8")
        arguments = [word for name, version in sorted(pins.items())
                     for word in ("--upgrade-package", f"{name}=={version}")]
        run = subprocess.run(["sh", str(copy / RECIPE), *arguments],  # noqa: S603
                             capture_output=True, text=True, check=False)
        return (copy / LOCK).read_text(encoding="utf-8") if run.returncode == 0 else None


def _choose(project: str, have: str, offered: list[pypi_facts.Release], now: datetime,
            resolves: Callable[[str], bool] = lambda _version: True) -> dict | str:
    """The pin for one package from the releases `offered`: the newest past the cooldown,
    else the lowest that resolves, when the young rule holds for it. Otherwise the reason
    the package is escalated."""
    young = offered
    settled = [r for r in offered if now - _when(r.uploaded) >= COOLDOWN]
    if settled:
        best = max(settled, key=lambda r: version_key(r.version))
        if resolves(best.version):
            return {"to": best.version, "rule": "cooldown", "uploaded": best.uploaded}
        young = [r for r in offered if version_key(r.version) > version_key(best.version)]
    lowest = next((r for r in sorted(young, key=lambda r: version_key(r.version))
                   if resolves(r.version)), None)
    if lowest is None:
        return "resolution-failed"
    replaced = next((r for r in pypi_facts.releases(project) if r.version == have), None)
    was = pypi_facts.publisher(project, replaced) if replaced else None
    old_enough = now - _when(lowest.uploaded) >= YOUNG
    if old_enough and was and pypi_facts.publisher(project, lowest) == was:
        return {"to": lowest.version, "rule": "young-attested", "uploaded": lowest.uploaded,
                "publisher": was}
    return "young-unattested"


def flagged(pins: list[dict], tree: Path) -> bool:
    """Whether `valvur check` flags any version the pins move to: a name that does not
    exist, a near-miss of a popular one, or one published as malicious. The real CLI,
    offline, as a developer would run it before an install. It must say `exists` of each
    or flag it: without a Name Index it answers `unknown`, which is no check at all."""
    run = subprocess.run(  # noqa: S603
        [sys.executable, "-c", "from valvur.cli import main; raise SystemExit(main())",
         "check", "pip", *(f"{pin['package']}@{pin['to']}" for pin in pins),
         "--project", str(tree), "--json"],
        capture_output=True, text=True, check=False)
    try:
        answers = json.loads(run.stdout)["answers"] if run.returncode in (0, 1) else None
    except (ValueError, KeyError):
        answers = None
    if answers is None:
        raise pypi_facts.Unreadable(f"valvur check did not answer: {run.stderr.strip()}")
    unchecked = sorted(a["name"] for a in answers if a["verdict"] == "unknown")
    if unchecked:
        raise pypi_facts.Unreadable(
            f"valvur check could not check {', '.join(unchecked)}: run `valvur update`")
    return any(a["verdict"] != "exists" for a in answers)


def _in_major(project: str, have: str) -> list[pypi_facts.Release]:
    return [r for r in pypi_facts.releases(project)
            if release_line(r.version) == release_line(have)]


def _with_its_floors(fix: dict, tree: Path, lock_text: str, have: dict[str, str],
                     now: datetime) -> list[dict] | str:
    """The fix's pin and one for each package the resolution moves with it, each chosen by
    the same rule. Or the reason the fix cannot land by itself."""
    pins = [fix]
    for _ in range(len(have)):
        asked = {pin["package"]: pin["to"] for pin in pins}
        text = relock(tree, lock_text, asked)
        if text is None:
            return "resolution-failed"
        after = locked(text)
        if set(after) != set(have):
            return "new-package"
        moved = sorted(p for p in have if after[p] != have[p] and p not in asked)
        if CHECKOV in moved:
            return "checkov"
        if not moved:
            return "check-failed" if flagged(pins, tree) else pins
        package = moved[0]
        above = [r for r in _in_major(package, have[package])
                 if version_key(r.version) > version_key(have[package])]
        chosen = _choose(
            package, have[package], above, now,
            lambda version, package=package, asked=asked:
                relock(tree, lock_text, {**asked, package: version}) is not None)
        if isinstance(chosen, str):
            return chosen
        pins.append({"package": package, "from": have[package],
                     "why": f"floor of {fix['package']} {fix['to']}", **chosen})
    return "resolution-failed"


def plan(findings: list[dict], lock_text: str, *, lock: str, now: str, tree: Path) -> dict:
    at_lock = _at_lock(findings, lock)
    have = locked(lock_text)
    floors: dict[str, str] = {}
    reported: dict[str, list[str]] = {}
    for finding in at_lock:
        dependency = finding["dependency"]
        fixed = dependency.get("fixed_version") or ""
        package = _name(dependency["package"])
        reported.setdefault(package, []).append(finding.get("fingerprint", ""))
        if fixed:
            floors[package] = max(floors.get(package, "0"), fixed, key=version_key)
    pins: dict[str, dict] = {}
    escalations = []
    for package in sorted(reported):
        chosen: dict | str | list[dict] = "no-fix"
        if package == CHECKOV:
            chosen = "checkov"
        elif package in floors:
            fixing = [r for r in _in_major(package, have[package])
                      if version_key(r.version) >= version_key(floors[package])]
            chosen = _choose(package, have[package], fixing, _when(now)) if fixing else "major"
        if isinstance(chosen, dict):
            fix = {"package": package, "from": have[package], "why": "fix", **chosen}
            chosen = _with_its_floors(fix, tree, lock_text, have, _when(now))
        if isinstance(chosen, str):
            escalations.append({"package": package, "reason": chosen,
                                "findings": sorted(reported[package])})
            continue
        for pin in chosen:
            held = pins.get(pin["package"])
            if held is None or version_key(pin["to"]) > version_key(held["to"]):
                pins[pin["package"]] = pin
    return {
        "schema": SCHEMA, "made": now, "lock": lock,
        "findings": [{"rule": f["rule"], "fingerprint": f.get("fingerprint", ""),
                      "package": _name(f["dependency"]["package"]),
                      "version": f["dependency"].get("version", ""),
                      "fixed_version": f["dependency"].get("fixed_version", ""),
                      "severity": f.get("severity", ""),
                      "advisory_published": f["dependency"].get("advisory_published", "")}
                     for f in at_lock],
        "pins": [pins[package] for package in sorted(pins)], "escalations": escalations,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    plan_cmd = commands.add_parser("plan", help="write plan.json from a Scan Run's Findings")
    plan_cmd.add_argument("--findings", type=Path, required=True)
    plan_cmd.add_argument("--lock", type=Path, required=True)
    plan_cmd.add_argument("--now", required=True, help="YYYY-MM-DDTHH:MM:SSZ")
    plan_cmd.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        findings = json.loads(args.findings.read_text(encoding="utf-8"))["findings"]
        made = plan(findings, args.lock.read_text(encoding="utf-8"),
                    lock=args.lock.name, now=args.now, tree=args.lock.resolve().parent)
    except (OSError, ValueError, KeyError, pypi_facts.Unreadable) as error:
        print(f"heal: {error}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(made, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
