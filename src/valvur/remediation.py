"""REMEDIATION.md — a ranked proposal, never an execution script (ADR-0009).

A **Remediation Item** is one *action*, not one **Finding** (F7.14). Four CVEs in
`loader-utils@1.4.0` are one change — "upgrade webpack" — and emitting four items
would be exactly the noise Phase 5 removed.

The developer chooses which of these to apply and when to rescan. Each item is
therefore independently applicable, because they will cherry-pick.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import grouping as _grouping
from . import verdict
from .findings import Finding
from .text import cut
from .versions import release_line, version_key


@dataclass
class Item:
    action: str
    where: str
    findings: list[Finding] = field(default_factory=list)
    #: A flood of machine-written data (R5.4): its action is a decision about a
    #: directory, and the item carries the exclude line.
    flood: bool = False

    @property
    def rank(self) -> int:
        return min((f.rank or 10**9) for f in self.findings)

    @property
    def exploited(self) -> bool:
        return any(f.exploit and f.exploit.kev for f in self.findings)


def group(findings: list[Finding]) -> list[Item]:
    """Collapse Findings into the changes that resolve them."""
    floods = {g.id: g for g in _grouping.describe(findings) if g.machine_written}
    items: dict[tuple[str, str], Item] = {}
    for finding in findings:
        flood = floods.get(finding.group or "")
        key, action, where = (_flood_key(flood.directory, floods.values()) if flood
                              else _key(finding))
        item = items.setdefault((key, where),
                                Item(action=action, where=where, flood=flood is not None))
        item.findings.append(finding)
    for item in items.values():
        _retarget(item)
    return sorted(items.values(), key=lambda i: i.rank)


def _retarget(item: Item) -> None:
    """Name the upgrade that clears every CVE in this group, not whichever finding
    happened to be grouped first. Four CVEs on one release line have four different
    minimal fixes; only the highest resolves all four, and stopping at the lowest
    leaves the developer believing they are done.

    Per package, since 23.5.5. A root group — "upgrade webpack" — holds findings on
    several transitive packages, and the old rule took the highest fix across all
    of them and wrote it after whichever package the first finding named: *"so
    `json5` reaches 1.4.2"*, loader-utils' version on json5's name. One action, one
    target per package it must reach."""
    fixes: dict[str, str] = {}      # package, lowercased -> the highest fix named
    names: dict[str, str] = {}      # -> the spelling to print
    for f in item.findings:
        d = f.dependency
        if not (d and d.package and d.fixed_version):
            continue
        key = d.package.lower()
        names.setdefault(key, d.package)
        fixes[key] = max((fixes.get(key, "0"), d.fixed_version), key=version_key)
    match = re.match(r"Upgrade `([^`]+)`", item.action)
    if not fixes or not match:
        return
    target = match.group(1)
    direct = fixes.pop(target.lower(), "")
    reach = " and ".join(f"`{names[k]}` reaches {v}" for k, v in sorted(fixes.items()))
    item.action = (
        f"Upgrade `{target}`" + (f" to {direct}" if direct else "")
        + (f" so {reach}" if reach else "")
    )


def _flood_key(directory: str, floods) -> tuple[str, str, str]:
    """A flood is one decision about a directory, not thousands of credentials to
    rotate (R5.4): whether it is generated data or the project's own. Every flood
    under it is the same decision, since one exclude line resolves them all."""
    here = [f for f in floods if f.directory == directory]
    count = sum(f.count for f in here)
    rules = " and ".join(sorted(f.rule for f in here))
    files = max(f.files for f in here)
    return (f"flood:{directory}",
            f"Decide what `{directory}` is: {count:,} hits of {rules} in {files:,} or more "
            "data files, possibly machine-written" if len(here) > 1 else
            f"Decide what `{directory}` is: {count:,} {rules} hits in {files:,} data files, "
            "possibly machine-written", directory)


def _key(finding: Finding) -> tuple[str, str, str]:
    """The change that fixes this, and where it is made."""
    dependency = finding.dependency
    if dependency and dependency.package:
        # Group by the package the developer can actually change — the Dependency
        # Path root where there is one (5.4). "Upgrade json5" is useless when
        # something else pins it.
        root = dependency.path[0] if len(dependency.path) > 1 else ""
        target = root.split("@")[0] if root else dependency.package
        # Distinct major lines of one package are distinct upgrades. A pnpm tree can
        # carry brace-expansion 1.x, 2.x and 5.x at once, and one instruction cannot
        # serve all three without telling somebody to downgrade.
        line = "" if root else f":{release_line(dependency.version)}"
        fix = dependency.fixed_version
        action = (
            f"Upgrade `{target}`" + (f" so `{dependency.package}` reaches {fix}"
                                     if root and fix else f" to {fix}" if fix else "")
        ) if fix or root else f"Replace or remove `{dependency.package}` — no fix available"
        # Group on the lowercased name. Scanners disagree on case for the same
        # package — Trivy says "Pillow", OSV says "pillow" on some advisories — and
        # ungrouped they became two actions for one dependency, the second advising
        # 10.0.1 after the first advised 12.3.0. Following both in order downgrades.
        # Fingerprints already normalise case, so only the proposal was affected.
        return (f"dep:{target.lower()}{line}", action, finding.path)

    path = finding.path
    if finding.rule.startswith("valvur.dependency."):
        return (f"slopsquat:{path}", "Remove the hallucinated dependencies", path)
    if finding.rule.startswith("valvur.ai-artifact."):
        return (f"agent:{path}", f"Review the agent instruction file `{path}`", path)
    if finding.rule.startswith("valvur.licence."):
        return ("licence", "Resolve licensing", path)
    if finding.rule in {"aws-access-token", "generic-api-key"} or "secret" in finding.rule:
        return (f"secret:{path}", f"Rotate the credentials in `{path}`", path)
    return (f"code:{finding.path}", f"Fix the issues in `{finding.path}`", finding.path)


def render(findings: list[Finding], *, top: int = 25) -> str:
    # A coverage note is a statement about valvur — what it did not inspect or could
    # not read — and nothing in the user's code resolves it, so it is not an action.
    # Until 23.5.5 every note went through `_key`, and the lockfile gap came out as
    # "Remove the hallucinated dependencies" on every repository without one.
    notes = [f for f in findings if verdict.note(f)]
    findings = [f for f in findings if not verdict.note(f)]
    items = group(findings)
    lines = [
        "# Remediation proposal",
        "",
        "> **This is a proposal, not a script.** Each item below is independently",
        "> applicable — apply the ones you judge worth applying, in any order, then",
        "> rescan. valvur never changes your code (ADR-0009).",
        "",
        "> A finding disappearing is **not** proof it was fixed. Deleting code and",
        "> correctly fixing it look identical from here.",
        "",
    ]
    aside = (
        f"_{len(notes)} coverage note(s) — what valvur did not inspect or could not "
        "read — are not actions here; they are listed in `SUMMARY.md`._"
    ) if notes else ""
    if not items:
        lines += ["No findings. Nothing to remediate.", ""]
        if aside:
            lines += [aside, ""]
        return "\n".join(lines)

    lines.append(f"**{len(items):,} action(s)** resolve **{len(findings):,} finding(s)**.")
    if aside:
        lines.append(aside)
    lines.append("")

    for number, item in enumerate(items[:top], start=1):
        lines += _item(number, item)

    if len(items) > top:
        lines.append(f"_{len(items) - top} further action(s) in `findings.json`._")
        lines.append("")
    return "\n".join(lines)


#: An action reference as zizmor quotes it: `owner/repo[/path]@ref` (R21.4).
_ACTION = re.compile(r"(?<![\w./-])([\w.-]+)/([\w.-]+)((?:/[\w./-]*)?)@([\w./-]+)")


def _lookup(finding: Finding) -> list[str]:
    """For a fix that needs what only the network knows, the command that asks and
    the line to write with its answer (D59c). For `unpinned-uses`, the commit the
    tag names today. Printed for the human to run; valvur runs none of it."""
    match = _ACTION.search(finding.evidence or "") if finding.rule == "unpinned-uses" else None
    if match is None:
        return []
    owner, repo, path, ref = match.groups()
    return [f"  look up the commit: `gh api repos/{owner}/{repo}/commits/{ref} --jq .sha`, "
            f"then write `uses: {owner}/{repo}{path}@<sha> # {ref}`"]


def _item(number: int, item) -> list[str]:
    """One action: what it resolves, what it does not, and, for a flood, the line
    that would leave the directory out and whose decision that is."""
    out: list[str] = []
    flag = " **[known exploited]**" if item.exploited else ""
    out.append(f"## {number}. {item.action}{flag}")
    out.append("")
    unfixed = sum(
        1 for f in item.findings
        if f.dependency and f.dependency.package and not f.dependency.fixed_version
    )
    # Never claim an upgrade resolves a finding whose advisory has no published
    # fix. Overstating this is how a developer stops looking at a live issue.
    resolved = len(item.findings) - unfixed
    out.append(f"Resolves {resolved} finding(s) in `{item.where}`:")
    if unfixed:
        out.append("")
        out.append(
            f"> ⚠ {unfixed} further finding(s) here have **no published fix** and "
            "this upgrade does not resolve them."
        )
    out.append("")
    if item.flood and item.where != "./":
        # The exclude line, and whose decision it is: an exclusion hides the
        # directory from every Scanner, as a suppression hides one Finding, and
        # an agent told to reach zero has no cheaper path (CLAUDE.md §4).
        out += [
            "If it is generated data rather than the project's own, the line that "
            "leaves it out is, in `.security-scan.toml`:",
            "",
            "```toml",
            "[scan]",
            f'exclude = ["{item.where.rstrip("/")}"]',
            "```",
            "",
            "**Ask the human before adding it**: an exclusion hides the directory from "
            "every Scanner. If it is the project's own, every hit is in `findings.json` "
            "under its group.",
            "",
        ]
    for finding in sorted(item.findings, key=lambda f: f.rank or 10**9)[:8]:
        out.append(f"- {finding.rule} — {cut(finding.title, 100)}")
        out += _lookup(finding)
    if len(item.findings) > 8:
        out.append(f"- _…and {len(item.findings) - 8} more_")
    out.append("")
    return out
