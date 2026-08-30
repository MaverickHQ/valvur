"""Adapter for valvur's own Checks.

Because Checks run in the container and emit JSON (ADR-0013), they fit the *existing*
adapter contract exactly: `run` invokes the container, `parse` reads the JSON. The
orchestrator needed no change — Checks inherit failure isolation, Profile selection,
concurrency and Provenance from the fleet.

`kind` is what separates them, and it is not cosmetic: we credit **Scanners** by name
and licence (P4), and must never imply that detection we perform ourselves came from
a third-party tool, nor the reverse.
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import fingerprint as _fp
from ..findings import Finding
from ..runner import ScannerOutput


class CheckAdapter:
    kind = "check"

    def __init__(self, name: str):
        self.name = name

    def run(self, runner, workspace: Path) -> ScannerOutput:
        return runner.run_check(self.name, workspace)

    def parse(self, output: ScannerOutput) -> list[Finding]:
        findings = []
        for item in json.loads(output.stdout or "[]"):
            identity = tuple(item.get("identity") or (item.get("rule", ""), item.get("path", "")))
            findings.append(
                Finding(
                    rule=item.get("rule", ""),
                    path=item.get("path", ""),
                    line=item.get("line", 0),
                    title=item.get("title", ""),
                    evidence=item.get("evidence", ""),
                    fingerprint=_fp.derive(*identity),
                    sources=(output.tool,),
                )
            )
        return findings
