#!/usr/bin/env python3
"""The acceptance harness (task R2.2): scan each acceptance repository, judge it
against its `expected.toml`, report.

    python3 scripts/acceptance.py [--set DIR] [--only N] [--generate] [--out DIR]

Every phase from R2 on is judged by this, on this Mac and on Linux (tasks.md §4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

#: An unexpected finding at these severities fails a repository (R2.2).
BLOCKING = frozenset({"high", "critical"})


@dataclass
class Verdict:
    ok: bool = True
    missing: list[str] = field(default_factory=list)
    #: Findings no `must` names, as "rule at path (severity)".
    unexpected: list[str] = field(default_factory=list)
    blocking: list[str] = field(default_factory=list)


def _matches(rule: str, finding: dict) -> bool:
    found = str(finding.get("rule", ""))
    return found == rule or found.endswith(rule)


def judge(results: Path, expected: dict, tasks_text: str) -> Verdict:
    """What a scan wrote into `results`, against what the repository expects."""
    import json

    findings = json.loads((results / "findings.json").read_text())["findings"]
    verdict = Verdict()
    musts = expected.get("must", [])

    def named(finding: dict) -> bool:
        return any(_matches(m["rule"], finding)
                   and (m.get("path") is None or finding.get("path") == m.get("path"))
                   for m in musts)

    for must in musts:
        path = must.get("path")
        if not any(_matches(must["rule"], f) and (path is None or f.get("path") == path)
                   for f in findings):
            verdict.missing.append(f"{must['rule']} at {path or 'any path'}")
    allowed = expected.get("run", {}).get("unexpected") == "allowed"
    for finding in findings:
        if finding.get("suppressed") or named(finding):
            continue
        line = f"{finding.get('rule')} at {finding.get('path')} ({finding.get('severity')})"
        verdict.unexpected.append(line)
        if not allowed and str(finding.get("severity")) in BLOCKING:
            verdict.blocking.append(line)
    verdict.ok = not verdict.missing and not verdict.blocking
    return verdict
