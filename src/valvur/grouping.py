"""Groups: one rule firing many times under one directory (R5.1; F7.5, F7.14).

A flood of identical hits is one thing to look at, not thousands. The gate's scan
reported 3,890 `generic-api-key` hits in machine-written JSON under one directory,
and eight distinct findings under them. A group drops no Finding and changes no
identity: `findings.json` keeps each one with its group id, and a group's facts
are derived from its members, never stored beside them.

Data files group apart from code under the same directory, so a real key in
`src/settings.py` never hides in a flood under `src/fixtures/`; only a group of
data files is labelled machine-written and ranked below every distinct Finding.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace

from .coverage import NOTE_RULES
from .findings import Finding

#: Hits of one rule under one top-level directory that make a group. The corpus's
#: most repeated rule reaches 17 in one directory (measured 2026-09-28), so a real
#: repository's findings stay ungrouped and a flood is always one.
GROUP_MIN = 25

#: What machine-written data is usually stored as. A minified bundle is written by
#: a machine too, and floods the same way.
DATA_SUFFIXES = (".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".txt", ".log", ".xml",
                 ".dat", ".min.js", ".min.css", ".map")


@dataclass(frozen=True)
class Group:
    id: str
    rule: str
    directory: str
    count: int
    files: int
    machine_written: bool
    #: The best rank among its members.
    rank: int

    @property
    def label(self) -> str:
        what = (f"{self.count:,} {self.rule} hits in {self.files:,} files under "
                f"`{self.directory}`")
        if self.machine_written:
            return f"{what}: possibly machine-written data, not {self.count:,} separate findings"
        return what


def _directory(path: str) -> str:
    return path.split("/", 1)[0] + "/" if "/" in path else "./"


def _data(path: str) -> bool:
    return path.lower().endswith(DATA_SUFFIXES)


def _key(finding: Finding) -> tuple[str, str, bool]:
    return finding.rule, _directory(finding.path), _data(finding.path)


def _eligible(finding: Finding) -> bool:
    """An accepted risk is not part of a flood, and a coverage note is about
    valvur, not the code."""
    return not finding.suppressed and finding.rule not in NOTE_RULES


def _id(rule: str, directory: str, data: bool) -> str:
    return f"{rule} in {directory}" + (" (data files)" if data else "")


def assign(findings: list[Finding]) -> list[Finding]:
    """Each Finding in a flood, stamped with its group's id; the rest unchanged."""
    counts = Counter(_key(f) for f in findings if _eligible(f))
    return [replace(f, group=_id(*_key(f)))
            if _eligible(f) and counts[_key(f)] >= GROUP_MIN else f
            for f in findings]


def flooded(finding: Finding) -> bool:
    """In a group of data files: ranked below every distinct Finding."""
    return finding.group is not None and _data(finding.path)


def describe(findings: list[Finding]) -> list[Group]:
    """The groups among these Findings, best-ranked first."""
    members: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.group:
            members.setdefault(finding.group, []).append(finding)
    groups = []
    for group_id, found in members.items():
        rule, directory, data = _key(found[0])
        groups.append(Group(id=group_id, rule=rule, directory=directory, count=len(found),
                            files=len({f.path for f in found}), machine_written=data,
                            rank=min(f.rank or 10**9 for f in found)))
    return sorted(groups, key=lambda g: (g.rank, g.id))
