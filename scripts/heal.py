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

    python3 scripts/heal.py apply --plan plan.json --out heal-out

`apply` runs the recipe with the plan's pins and writes the files a heal changes into a
directory of its own, never into the tree. It refuses its own result when a package moved
that the plan does not name: exit 1.

    python3 scripts/heal.py verify --plan plan.json --dir heal-out

`verify` checks such a directory as data, in a job that holds a token: the two files and no
other, a lock that is pins, hashes and comments, every move in the plan, and the CHANGELOG
the plan gives. It runs no recipe and no package's code.

Standard library, and `valvur`'s own version ordering, so a pin and the report that asked
for it agree on which version is higher. Exit 0 when the plan was written, whatever it holds;
1 when the heal refuses its own result; 2 when an input could not be read.
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
CHANGELOG = "CHANGELOG.md"
#: The longest headline a heal commit takes before it counts its fixes instead.
HEADLINE = 72
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


class Refused(Exception):
    """The heal's own result is not what its plan says."""


def unplanned(before: dict[str, str], after: dict[str, str], pins: list[dict]) -> list[str]:
    """What differs between two locks that the pins do not account for, one line each."""
    planned = {pin["package"]: (pin["from"], pin["to"]) for pin in pins}
    found = []
    for package in sorted(set(before) | set(after)):
        was, now = before.get(package), after.get(package)
        if planned.get(package, (was, was)) != (was, now):
            found.append(f"{package}: {was or 'absent'} to {now or 'absent'}")
    return found


def _listed(words: list[str]) -> str:
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


def items(plan_: dict) -> list[str]:
    """One `### Security` item for each package the plan moves: the two versions, and the
    advisories it answers or the fix that requires it."""
    made = []
    for pin in sorted(plan_["pins"], key=lambda pin: pin["package"]):
        if pin["why"] == "fix":
            rules = sorted({f["rule"] for f in plan_["findings"]
                            if f["package"] == pin["package"]})
            reason = f"past {_listed(rules)}" if rules else "for its fix"
        else:
            reason = f"which {pin['why'].removeprefix('floor of ')} requires"
        made.append(f"- **{pin['package']} {pin['to']} in the Checkov lock,** "
                    f"from {pin['from']}, {reason}.")
    return made


def message(plan_: dict, run: str) -> str:
    """The heal commit's message: a headline that names each fix while it fits in a line,
    then the trailers the policy and the report read (design.md, *Trailers*)."""
    pins = sorted(plan_["pins"], key=lambda pin: pin["package"])
    fixes = [f"{pin['package']} {pin['to']}" for pin in pins if pin["why"] == "fix"]
    headline = f"fix: {_listed(fixes)} in the Checkov lock, by the heal"
    if len(headline) > HEADLINE:
        headline = f"fix: {len(fixes)} packages in the Checkov lock, by the heal"
    trailers = [f"Heal-Pin: {pin['package']}=={pin['to']}" for pin in pins]
    trailers += [f"Heal-Advisory: {f['rule']} {f['package']} published "
                 f"{f.get('advisory_published') or 'unknown'}"
                 for f in sorted(plan_["findings"], key=lambda f: (f["package"], f["rule"]))
                 if any(pin["package"] == f["package"] for pin in pins)]
    trailers.append(f"Heal-Run: {run}")
    return headline + "\n\n" + "\n".join(trailers) + "\n"


def _cell(text: object) -> str:
    """A value as one table cell. An advisory's ID, a version and a publisher's repository
    are text someone else chose, so anything that could be Markdown, or a keyword that
    closes an issue, is replaced."""
    return re.sub(r"[^A-Za-z0-9._/@:+ =-]", "?", str(text)).strip() or "?"


def _evidence(pin: dict, made: datetime) -> str:
    age = made - _when(pin["uploaded"])
    day = pin["uploaded"][:10]
    if pin["rule"] == "cooldown":
        return f"cooldown: uploaded {day}, {age.days} days before this plan"
    who = pin.get("publisher") or {}
    return (f"young-attested: uploaded {day}, {int(age.total_seconds() // 3600)} hours before "
            f"this plan, attested by `{_cell(who.get('repository', ''))}` "
            f"(`{_cell(who.get('workflow', ''))}`)")


def body(plan_: dict, run: str) -> str:
    """The pull request's body: the plan as tables (Requirement 7.6). Each advisory with
    its severity, each version chosen with why and by which rule, and what was left."""
    made = _when(plan_["made"])
    pins = sorted(plan_["pins"], key=lambda pin: pin["package"])
    moved = {pin["package"] for pin in pins}
    lines = [
        "A heal of the Checkov lock, made by rule from the plan below (`scripts/heal.py`). "
        "No person and no model chose a version.",
        "", "## What moves", "",
        "| package | from | to | why | the rule, and its evidence |", "|---|---|---|---|---|",
        *(f"| {_cell(pin['package'])} | {_cell(pin['from'])} | {_cell(pin['to'])} | "
          f"{_cell(pin['why'])} | {_evidence(pin, made)} |" for pin in pins),
        "", "## The advisories it answers", "",
        "| advisory | package | severity | published |", "|---|---|---|---|",
        *(f"| {_cell(f['rule'])} | {_cell(f['package'])} | {_cell(f.get('severity', ''))} | "
          f"{_cell((f.get('advisory_published') or 'unknown')[:10])} |"
          for f in sorted(plan_["findings"], key=lambda f: (f["package"], f["rule"]))
          if f["package"] in moved),
    ]
    if plan_["escalations"]:
        lines += ["", "## What it could not heal", "", "| package | reason |", "|---|---|",
                  *(f"| {_cell(e['package'])} | {_cell(e['reason'])} |"
                    for e in plan_["escalations"])]
    lines += ["", f"Planned at {_cell(plan_['made'])}, in {run}."]
    return "\n".join(lines) + "\n"


def changelog(text: str, plan_: dict) -> str:
    """`text` with the plan's items under `[Unreleased]`, in its `### Security` section,
    which is made at the section's end when it has none. Lines are only ever added."""
    heading = re.search(r"^## \[Unreleased\][^\n]*\n", text, re.M)
    if not heading:
        raise Refused("the CHANGELOG has no `## [Unreleased]` section")
    following = re.search(r"^## ", text[heading.end():], re.M)
    end = heading.end() + following.start() if following else len(text)
    section = text[heading.end():end]
    added = "\n".join(items(plan_)) + "\n"
    security = re.search(r"^### Security[^\n]*\n", section, re.M)
    if security:
        after = re.search(r"^### ", section[security.end():], re.M)
        stop = security.end() + after.start() if after else len(section)
        body = section[:stop].rstrip("\n") + "\n"
        section = body + added + "\n" + section[stop:]
    else:
        body = section.strip("\n")
        section = ("\n" + body + "\n" if body else "") + "\n### Security\n\n" + added + "\n"
    return text[:heading.end()] + section + text[end:]


def apply(plan_: dict, tree: Path) -> dict[str, str]:
    """The files a heal changes, by name: the lock the recipe writes with the plan's pins,
    and the CHANGELOG with an item for each. Refused when anything moved that the plan does
    not name."""
    lock_text = (tree / LOCK).read_text(encoding="utf-8")
    pins = plan_["pins"]
    text = relock(tree, lock_text, {pin["package"]: pin["to"] for pin in pins})
    if text is None:
        raise Refused("the recipe failed with the plan's pins")
    stray = unplanned(locked(lock_text), locked(text), pins)
    if stray:
        raise Refused("the re-lock moved what the plan does not name: " + "; ".join(stray))
    return {LOCK: text,
            CHANGELOG: changelog((tree / CHANGELOG).read_text(encoding="utf-8"), plan_)}


_REQUIREMENT = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.!+_-]+)( ; [^\\]+)? \\")
_HASH = re.compile(r"    --hash=sha256:[0-9a-f]{64}( \\)?")


def parse_lock(text: str) -> dict[str, str]:
    """Each package a lock pins, read strictly: a line is a pin, one of its hashes, or an
    indented comment, as the recipe writes them. Anything else is refused, with its line:
    an option, a URL or an editable install has no place in a lock that is data."""
    pinned: dict[str, str] = {}
    hashes = 0
    for number, line in enumerate(text.splitlines(), start=1):
        requirement = _REQUIREMENT.fullmatch(line)
        if requirement:
            if pinned and not hashes:
                raise Refused(f"the lock pins a package with no hash, above line {number}")
            pinned[_name(requirement.group(1))] = requirement.group(2)
            hashes = 0
        elif _HASH.fullmatch(line) and pinned:
            hashes += 1
        elif not re.fullmatch(r"    #.*", line):
            raise Refused(f"the lock's line {number} is not a pin, a hash or a comment")
    if not pinned or not hashes:
        raise Refused("the lock pins nothing, or its last package has no hash")
    return pinned


def verify(plan_: dict, tree: Path, directory: Path) -> None:
    """Refuse an artifact that is not what `apply` writes from this plan, read as data: no
    recipe runs here and no package's code. The policy runs the recipe again (R44.4)."""
    held = sorted(path.name for path in directory.iterdir())
    if held != sorted((LOCK, CHANGELOG)):
        raise Refused(f"the artifact holds {', '.join(held) or 'nothing'}: "
                      f"only {LOCK} and {CHANGELOG} belong in it")
    for name in held:
        if (directory / name).is_symlink() or not (directory / name).is_file():
            raise Refused(f"the artifact's {name} is not a plain file")
    before = parse_lock((tree / LOCK).read_text(encoding="utf-8"))
    after = parse_lock((directory / LOCK).read_text(encoding="utf-8"))
    stray = unplanned(before, after, plan_["pins"])
    if stray:
        raise Refused("the lock differs from the plan: " + "; ".join(stray))
    wanted = changelog((tree / CHANGELOG).read_text(encoding="utf-8"), plan_)
    if (directory / CHANGELOG).read_text(encoding="utf-8") != wanted:
        raise Refused("the CHANGELOG is not the tree's with the plan's items added")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    plan_cmd = commands.add_parser("plan", help="write plan.json from a Scan Run's Findings")
    plan_cmd.add_argument("--findings", type=Path, required=True)
    plan_cmd.add_argument("--lock", type=Path, required=True)
    plan_cmd.add_argument("--now", required=True, help="YYYY-MM-DDTHH:MM:SSZ")
    plan_cmd.add_argument("--out", type=Path, required=True)
    apply_cmd = commands.add_parser("apply", help="write the files a plan changes, apart")
    apply_cmd.add_argument("--plan", type=Path, required=True)
    apply_cmd.add_argument("--tree", type=Path, default=Path.cwd())
    apply_cmd.add_argument("--out", type=Path, required=True)
    apply_cmd.add_argument("--run", default="", help="this run's URL, for the commit")
    body_cmd = commands.add_parser("body", help="print the pull request's body")
    body_cmd.add_argument("--plan", type=Path, required=True)
    body_cmd.add_argument("--run", default="", help="this run's URL")
    verify_cmd = commands.add_parser("verify", help="check an artifact against its plan")
    verify_cmd.add_argument("--plan", type=Path, required=True)
    verify_cmd.add_argument("--tree", type=Path, default=Path.cwd())
    verify_cmd.add_argument("--dir", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "body":
            sys.stdout.write(body(json.loads(args.plan.read_text(encoding="utf-8")), args.run))
            return 0
        if args.command == "verify":
            verify(json.loads(args.plan.read_text(encoding="utf-8")), args.tree.resolve(),
                   args.dir)
            return 0
        if args.command == "apply":
            read = json.loads(args.plan.read_text(encoding="utf-8"))
            files = apply(read, args.tree.resolve())
            args.out.mkdir(parents=True, exist_ok=True)
            for name, text in files.items():
                (args.out / name).write_text(text, encoding="utf-8")
            sys.stdout.write(message(read, args.run))
            return 0
        findings = json.loads(args.findings.read_text(encoding="utf-8"))["findings"]
        made = plan(findings, args.lock.read_text(encoding="utf-8"),
                    lock=args.lock.name, now=args.now, tree=args.lock.resolve().parent)
    except Refused as error:
        print(f"heal: refused: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, pypi_facts.Unreadable) as error:
        print(f"heal: {error}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(made, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
