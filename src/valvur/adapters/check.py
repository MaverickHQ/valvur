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

from .. import coverage as _coverage
from .. import fingerprint as _fp
from ..coverage import Coverage
from ..findings import Finding
from ..runner import ScannerOutput
from .base import ScannerAdapter


class CheckAdapter(ScannerAdapter):
    kind = "check"

    def __init__(self, name: str, *, needs_network: bool = False):
        self.name = name
        self.needs_network = needs_network

    def run(self, runner, workspace: Path) -> ScannerOutput:
        return runner.run_check(self.name, workspace, network=self.needs_network)

    def coverage(self, workspace: Path, exclude: tuple[str, ...] = ()) -> Coverage:
        """Only dependency-reality has limits worth stating, and they are the ones
        that matter: it is the Check nothing else in the product substitutes for."""
        if self.name != "dependency-reality":
            return Coverage()

        from .. import ecosystems as _ecosystems

        reads, ignores = [], []
        for manifests in _ecosystems.MANIFESTS.values():
            if manifests.reads:
                reads.append(f"{manifests.label}: {', '.join(manifests.reads)}")
            else:
                ignores.append(f"{manifests.label}: no existence check")
        # Stated rather than left implicit: names are checked for existence in both
        # ecosystems, but the near-miss typosquat comparison needs a corpus of popular
        # package names and only PyPI's ships in the image.
        ignores.append("npm: no typosquat near-miss comparison (no popular-npm corpus)")
        return Coverage(
            inspects=tuple(sorted(reads)),
            ignores=tuple(sorted(ignores)),
            gaps=tuple(_coverage.dependency_gaps(workspace, exclude)),
        )

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
                    # Checks may state their own severity. Without this every Check
                    # finding ranked identically, so a coverage note and a
                    # hallucinated dependency arrived at the same weight.
                    **({"severity": item["severity"]} if item.get("severity") else {}),
                )
            )
        return findings
