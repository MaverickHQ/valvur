"""Syft — SBOM generation.

Produces an artifact rather than Findings. The orchestrator writes whatever an
adapter declares in `artifact` straight into the Results Folder.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..findings import Finding
from ..invocation import NOTHING_TO_SCAN, Invocation, ScannerOutput
from .base import ScannerAdapter

if TYPE_CHECKING:
    from ..scancontext import ScanContext

VERSION = "1.52.0"

#: Why a scan ran no Syft (the owner's decision, 2026-09-28; D9): said wherever a
#: skipped Scanner is named, with the two ways to ask.
OPT_IN = ("the SBOM, and with it the dependency licence check, is opt-in: `valvur scan "
          "--sbom`, or `sbom = true` under `[scan]` in `.security-scan.toml`")


class SyftAdapter(ScannerAdapter):
    kind = "scanner"
    name = "syft"
    version = VERSION
    artifact = "sbom.cdx.json"

    def __init__(self, enabled: bool = False):
        #: Asked for on this scan (`--sbom`); the project may ask in its own file.
        self.enabled = enabled

    def applies_to(self, workspace: Path,
                   context: ScanContext | None = None) -> tuple[bool, str]:
        from ..exclusions import load_scan_settings

        settings = context.settings if context is not None else load_scan_settings(workspace)
        if self.enabled or settings.sbom:
            return True, ""
        return False, OPT_IN

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
