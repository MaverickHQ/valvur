"""Trivy — dependency vulnerabilities.

Runs against a host-cached vulnerability DB with --skip-db-update, so the scan itself
makes no network connection (ADR-0012, N2.1).
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import fingerprint as _fp
from ..findings import Finding
from ..runner import ScannerOutput
from .base import container_relative


class TrivyAdapter:
    kind = "scanner"
    name = "trivy"

    def run(self, runner, workspace: Path) -> ScannerOutput:
        return runner.run_trivy(workspace)

    def parse(self, output: ScannerOutput) -> list[Finding]:
        report = json.loads(output.stdout or "{}")
        findings: list[Finding] = []

        for result in report.get("Results") or []:
            # Trivy reports a target, not always a path — a lockfile, an image layer,
            # or an OS package database. container_relative handles the path case.
            target = container_relative(str(result.get("Target", "")))
            ecosystem = str(result.get("Type", "unknown"))

            for vuln in result.get("Vulnerabilities") or []:
                package = vuln["PkgName"]
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion") or ""
                findings.append(
                    Finding(
                        rule=vuln["VulnerabilityID"],
                        path=target,
                        line=0,  # a dependency has no line; identity never uses one
                        title=f"{package} {installed} — {vuln.get('Title', 'vulnerability')}",
                        evidence=(
                            f"upgrade {package} to {fixed}" if fixed
                            else f"no fixed version available for {package}"
                        ),
                        fingerprint=_fp.for_dependency_vuln(
                            ecosystem, package, installed, vuln["VulnerabilityID"]
                        ),
                        sources=(output.tool,),
                    )
                )
        return findings
