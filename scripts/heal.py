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

Standard library, and `valvur`'s own version ordering, so a pin and the report that asked
for it agree on which version is higher. Exit 0 when the plan was written, whatever it holds;
2 when an input could not be read.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
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


def _choose(project: str, have: str, floor: str, now: datetime) -> dict | str:
    """The pin for one package, from PyPI's releases at or above `floor` in the major
    version of `have`: the newest past the cooldown, else the lowest when the young rule
    holds. Otherwise the reason it is escalated."""
    releases = pypi_facts.releases(project)
    offered = [r for r in releases
               if version_key(r.version) >= version_key(floor)
               and release_line(r.version) == release_line(have)]
    settled = [r for r in offered if now - _when(r.uploaded) >= COOLDOWN]
    if settled:
        best = max(settled, key=lambda r: version_key(r.version))
        return {"to": best.version, "rule": "cooldown", "uploaded": best.uploaded}
    lowest = min(offered, key=lambda r: version_key(r.version))
    replaced = next((r for r in releases if r.version == have), None)
    was = pypi_facts.publisher(project, replaced) if replaced else None
    old_enough = now - _when(lowest.uploaded) >= YOUNG
    if old_enough and was and pypi_facts.publisher(project, lowest) == was:
        return {"to": lowest.version, "rule": "young-attested", "uploaded": lowest.uploaded,
                "publisher": was}
    return "young-unattested"


def plan(findings: list[dict], lock_text: str, *, lock: str, now: str) -> dict:
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
    pins, escalations = [], []
    for package in sorted(reported):
        chosen = (_choose(package, have[package], floors[package], _when(now))
                  if package in floors else "no-fix")
        if isinstance(chosen, str):
            escalations.append({"package": package, "reason": chosen,
                                "findings": sorted(reported[package])})
        else:
            pins.append({"package": package, "from": have[package], "why": "fix", **chosen})
    return {
        "schema": SCHEMA, "made": now, "lock": lock,
        "findings": [{"rule": f["rule"], "fingerprint": f.get("fingerprint", ""),
                      "package": _name(f["dependency"]["package"]),
                      "version": f["dependency"].get("version", ""),
                      "fixed_version": f["dependency"].get("fixed_version", ""),
                      "severity": f.get("severity", ""),
                      "advisory_published": f["dependency"].get("advisory_published", "")}
                     for f in at_lock],
        "pins": pins, "escalations": escalations,
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
                    lock=args.lock.name, now=args.now)
    except (OSError, ValueError, KeyError, pypi_facts.Unreadable) as error:
        print(f"heal: {error}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(made, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
