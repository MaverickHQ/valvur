#!/usr/bin/env python3
"""The acceptance harness (task R2.2): scan each acceptance repository, judge it
against its `expected.toml`, report.

    python3 scripts/acceptance.py [--set DIR] [--only N] [--generate] [--out DIR]

Every phase from R2 on is judged by this, on this Mac and on Linux (tasks.md §4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Verdict:
    ok: bool = True
    missing: list[str] = field(default_factory=list)


def _matches(rule: str, finding: dict) -> bool:
    found = str(finding.get("rule", ""))
    return found == rule or found.endswith(rule)


def judge(results: Path, expected: dict, tasks_text: str) -> Verdict:
    """What a scan wrote into `results`, against what the repository expects."""
    import json

    findings = json.loads((results / "findings.json").read_text())["findings"]
    verdict = Verdict()
    for must in expected.get("must", []):
        path = must.get("path")
        if not any(_matches(must["rule"], f) and (path is None or f.get("path") == path)
                   for f in findings):
            verdict.missing.append(f"{must['rule']} at {path or 'any path'}")
    verdict.ok = not verdict.missing
    return verdict
