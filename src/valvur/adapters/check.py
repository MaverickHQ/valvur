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
        """Only dependency-reality has limits worth stating, and they are the ones
        that matter: it is the Check nothing else in the product substitutes for."""
        if self.name != "dependency-reality":
            return Coverage()

        from .. import ecosystems as _ecosystems
        from ..name_index import FILES as _INDEXED

        reads, ignores = [], []
        for key, manifests in _ecosystems.MANIFESTS.items():
            if not manifests.reads:
                ignores.append(f"{manifests.label}: no existence check")
            elif key in _INDEXED or self.network:
                reads.append(f"{manifests.label}: {', '.join(manifests.reads)}")
            else:
                # Read, but only where a registry can be asked (22.A.4): neither
                # Maven Central nor the Go proxy publishes a name list an offline
                # index could be built from. A Profile omission, stated as one.
                ignores.append(f"{manifests.label}: existence checked on `full` only "
                               "(no offline index exists for this registry)")
        # Stated rather than left implicit: names are checked for existence in both
        # ecosystems, but the near-miss typosquat comparison needs a corpus of popular
        # package names and only PyPI's ships in the image.
        ignores.append("npm: no typosquat near-miss comparison (no popular-npm corpus)")
        if not self.network:
            # The one question the local index cannot answer (ADR-0018).
            ignores.append("first-publish age: not checked without a network "
                           "(run `--profile full`)")
        else:
            ignores.append("JVM and Go: existence only, no first-publish age "
                           "(neither registry states first publication)")
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
