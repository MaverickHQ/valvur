"""Opengrep — static analysis against valvur's own bundled rules.

Opengrep rather than Semgrep (ADR-0004), and our own rules rather than the community
registry, so nothing under a competing-use restriction is redistributed.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .. import fingerprint as _fp
from ..findings import Finding
from ..runner import ScannerOutput
from .base import container_relative


class OpengrepAdapter:
    kind = "scanner"
    name = "opengrep"

    def run(self, runner, workspace: Path) -> ScannerOutput:
        return runner.run_opengrep(workspace)

    def parse(self, output: ScannerOutput) -> list[Finding]:
        report = json.loads(output.stdout or "{}")
        findings: list[Finding] = []

        # The SAST class is the only one needing a content hash, so it is the only
        # one that can collide. Identical matches in one file are separated by
        # ordinal, assigned in file order so it is stable across runs (design 3.1).
        seen: Counter[tuple[str, str, str]] = Counter()

        for item in sorted(
            report.get("results") or [],
            key=lambda r: (r.get("path", ""), r.get("start", {}).get("line", 0)),
        ):
            rule = _short_rule(item.get("check_id", ""))
            path = container_relative(str(item.get("path", "")))
            matched = str(item.get("extra", {}).get("lines", "")).strip()

            key = (rule, path, matched)
            ordinal = seen[key]
            seen[key] += 1

            findings.append(
                Finding(
                    rule=rule,
                    path=path,
                    line=item.get("start", {}).get("line", 0),
                    title=str(item.get("extra", {}).get("message", "")).strip(),
                    evidence=matched,
                    fingerprint=_fp.for_sast(rule, path, matched, ordinal),
                    sources=(output.tool,),
                )
            )
        return findings


def _short_rule(check_id: str) -> str:
    """Opengrep prefixes rule ids with the config path. Strip it, or the identity
    would change whenever the rules directory moved."""
    marker = "valvur."
    index = check_id.find(marker)
    return check_id[index:] if index >= 0 else check_id
