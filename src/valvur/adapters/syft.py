"""Syft — SBOM generation.

Produces an artifact rather than Findings. The orchestrator writes whatever an
adapter declares in `artifact` straight into the Results Folder.
"""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from ..invocation import NOTHING_TO_SCAN, Invocation, ScannerOutput
from .base import ScannerAdapter

VERSION = "1.51.1"


class SyftAdapter(ScannerAdapter):
    kind = "scanner"
    name = "syft"
    version = VERSION
    artifact = "sbom.cdx.json"

    def command(self, workspace: Path) -> Invocation:
        # The SBOM is a release artifact, so a configured exclusion has to reach
        # it: since R3.9 it does by construction, because Syft reads the Snapshot
        # and the File Set was shaped by the exclusion before it (ADR-0021).
        return Invocation(
            tool=self.name, version=VERSION,
            argv=("syft", "scan", "dir:/workspace", "-o", "cyclonedx-json=/results/sbom.json",
                  "-q"),
            report="sbom.json", timeout=600, empty_when=NOTHING_TO_SCAN,
        )

    def parse(self, output: ScannerOutput) -> list[Finding]:
        return []  # an SBOM is inventory, not a Finding
