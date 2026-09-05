"""Checkov — infrastructure-as-code misconfiguration."""

from __future__ import annotations

import json
from pathlib import Path

from .. import fingerprint as _fp
from ..findings import Finding
from ..runner import ScannerOutput
from .base import ScannerAdapter, container_relative


class CheckovAdapter(ScannerAdapter):
    kind = "scanner"
    name = "checkov"

    def applies_to(self, workspace: Path) -> tuple[bool, str]:
        """Checkov costs 11.2s of fixed startup — measured 2026-09-05, more than
        every other Scanner in `offline` combined — and a repository with no
        infrastructure code pays all of it for nothing.

        Biased towards running: anything unrecognised counts as infrastructure. The
        skip is reported, never silent.
        """
        from ..applicability import iac_present

        found, evidence = iac_present(workspace)
        if found:
            return True, evidence
        return False, "no Dockerfile, terraform, Kubernetes, CI or template files found"

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
                        severity=str(check.get("severity") or "medium").lower(),
                    )
                )
        return findings
