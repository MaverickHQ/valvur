#!/usr/bin/env python3
"""The acceptance harness (task R2.2): scan each acceptance repository, judge it
against its `expected.toml`, report.

    python3 scripts/acceptance.py [--set DIR] [--only N] [--generate] [--out DIR]

Every phase from R2 on is judged by this, on this Mac and on Linux (tasks.md §4).
"""

from __future__ import annotations

import re
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
    #: Expectations a later task delivers, while that task is open.
    pending: list[str] = field(default_factory=list)
    #: Finding paths under a `must_not` prefix.
    forbidden: list[str] = field(default_factory=list)
    incomplete: bool = False


def ticked(tasks_text: str) -> set[str]:
    """The task ids `tasks.md` has ticked."""
    return set(re.findall(r"^- \[[xX]\] \*\*(R\d+\.\d+)\*\*", tasks_text, re.M))


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

    done = ticked(tasks_text)
    for must in musts:
        path = must.get("path")
        found = any(_matches(must["rule"], f) and (path is None or f.get("path") == path)
                    for f in findings)
        until = must.get("until")
        if until and until not in done:
            if not found:
                verdict.pending.append(f"{must['rule']} at {path or 'any path'} "
                                       f"(until {until})")
            continue
        if not found:
            verdict.missing.append(f"{must['rule']} at {path or 'any path'}")
    for forbid in expected.get("must_not", []):
        prefix = forbid["path_prefix"]
        verdict.forbidden += [f["path"] for f in findings
                              if str(f.get("path", "")).startswith(prefix)]
    run = json.loads((results / "run.json").read_text())
    verdict.incomplete = bool(expected.get("run", {}).get("complete")) and not run.get(
        "complete")
    allowed = expected.get("run", {}).get("unexpected") == "allowed"
    for finding in findings:
        if finding.get("suppressed") or named(finding):
            continue
        line = f"{finding.get('rule')} at {finding.get('path')} ({finding.get('severity')})"
        verdict.unexpected.append(line)
        if not allowed and str(finding.get("severity")) in BLOCKING:
            verdict.blocking.append(line)
    verdict.ok = not (verdict.missing or verdict.blocking or verdict.forbidden
                      or verdict.incomplete)
    return verdict


@dataclass
class RepoResult:
    name: str
    verdict: Verdict
    seconds: float
    containers_after: int

    @property
    def ok(self) -> bool:
        return self.verdict.ok and self.containers_after == 0


def _cli_scan(workspace: Path) -> None:
    """`valvur scan <workspace>` through the CLI, as a user runs it."""
    import subprocess
    import sys

    subprocess.run([sys.executable, "-c",  # noqa: S603 — this interpreter, the CLI
                    "from valvur.cli import main; raise SystemExit(main())",
                    "scan", str(workspace)], check=False, capture_output=True)


def _containers_alive() -> int:
    """How many `valvur-` containers the runtime still lists."""
    import subprocess

    out = subprocess.run(["docker", "ps", "--filter", "name=valvur-", "--format",
                          "{{.Names}}"], capture_output=True, text=True, check=False)
    return len(out.stdout.split())


def run_repo(root: Path, *, scan=_cli_scan, containers=_containers_alive,
             tasks_text: str | None = None) -> RepoResult:
    """Scan one acceptance repository and judge it (R2.2)."""
    import time
    import tomllib

    if tasks_text is None:
        tasks_text = (Path(__file__).resolve().parent.parent
                      / ".kiro/specs/valvur/tasks.md").read_text()
    started = time.monotonic()
    scan(root)
    seconds = time.monotonic() - started
    expected = tomllib.loads((root / "expected.toml").read_text())
    verdict = judge(root / ".security-scan", expected, tasks_text)
    return RepoResult(root.name, verdict, round(seconds, 1), containers())
