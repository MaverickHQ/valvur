"""Checkov — infrastructure-as-code misconfiguration."""

from __future__ import annotations

import json
from pathlib import Path

from .. import fingerprint as _fp
from ..findings import Finding
from ..runner import ScannerOutput
from .base import container_relative


class CheckovAdapter:
    kind = "scanner"
    name = "checkov"

    def run(self, runner, workspace: Path) -> ScannerOutput:
        return runner.run_checkov(workspace)

    def parse(self, output: ScannerOutput) -> list[Finding]:
        report = json.loads(output.stdout or "{}")
        # Checkov emits a list when several frameworks matched, an object otherwise.
        blocks = report if isinstance(report, list) else [report]
        findings: list[Finding] = []

        for block in blocks:
            for check in block.get("results", {}).get("failed_checks") or []:
                path = container_relative(str(check.get("file_path", "")))
                # Terraform hands us a stable resource address — far better identity
                # than any line hash (ADR-0003).
                resource = str(check.get("resource", ""))
                findings.append(
                    Finding(
                        rule=check.get("check_id", ""),
                        path=path,
                        line=(check.get("file_line_range") or [0])[0],
                        title=check.get("check_name", ""),
                        evidence=resource,
                        fingerprint=_fp.for_iac(check.get("check_id", ""), path, resource),
                        sources=(output.tool,),
                    )
                )
        return findings
