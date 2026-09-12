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
from ..coverage import Coverage
from ..findings import Finding
from ..runner import ScannerOutput
from .base import ScannerAdapter


class CheckAdapter(ScannerAdapter):
    kind = "check"

    def __init__(self, name: str, *, uses_network: bool = False, network: bool = False):
        self.name = name
        #: Whether this Check does more WITH a network — not whether it needs one.
        #: dependency-reality answers existence from the local index either way and
        #: asks a registry for first-publish age only when allowed (ADR-0018).
        self.uses_network = uses_network
        #: What this instance was actually granted. False until `for_profile` says
        #: otherwise, so an adapter taken straight from the registry never reaches out.
        self.network = network

    def for_profile(self, *, network: bool) -> CheckAdapter:
        if not self.uses_network:
            return self
        return CheckAdapter(self.name, uses_network=True, network=network)

    def run(self, runner, workspace: Path) -> ScannerOutput:
        return runner.run_check(self.name, workspace, network=self.network)

    def coverage(self, workspace: Path, exclude: tuple[str, ...] = ()) -> Coverage:
        """Forwarded to the Check, which is the only thing that knows (22.D.3). The
        adapter used to answer this itself by testing `self.name` — ADR-0013's
        boundary crossed the wrong way, and a second place a Check's limits could
        be stated and drift from the first."""
        from ..checks import REGISTRY

        check = REGISTRY.get(self.name)
        if check is None:
            return Coverage()
        return check.coverage(workspace, exclude, network=self.network)

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
