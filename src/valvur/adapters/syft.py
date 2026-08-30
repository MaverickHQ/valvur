"""Syft — SBOM generation.

Produces an artifact rather than Findings. The orchestrator writes whatever an
adapter declares in `artifact` straight into the Results Folder.
"""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from ..runner import ScannerOutput


class SyftAdapter:
    name = "syft"
    artifact = "sbom.cdx.json"

    def run(self, runner, workspace: Path) -> ScannerOutput:
        return runner.run_syft(workspace)

    def parse(self, output: ScannerOutput) -> list[Finding]:
        return []  # an SBOM is inventory, not a Finding
