"""Checkov — infrastructure-as-code misconfiguration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from .. import fingerprint as _fp
from ..findings import Finding, Severity
from ..invocation import NOTHING_TO_SCAN, Invocation, ScannerOutput
from .base import ScannerAdapter, container_relative

if TYPE_CHECKING:
    from ..scancontext import ScanContext

VERSION = "3.3.19"


class CheckovAdapter(ScannerAdapter):
    kind = "scanner"
    name = "checkov"
    version = VERSION

    def applies_to(self, workspace: Path,
                   context: ScanContext | None = None) -> tuple[bool, str]:
        """Checkov costs 11.2s of fixed startup — measured 2026-09-05, more than
        every other Scanner in `offline` combined — and a repository with no
        infrastructure code pays all of it for nothing.

        Biased towards running: anything unrecognised counts as infrastructure. The
        skip is reported, never silent.
        """
        from ..applicability import iac_present

        found, evidence = iac_present(workspace,
                                      context.files if context is not None else None)
        if found:
            return True, evidence
        return False, ("no Dockerfile, terraform, Kubernetes, CI or template files found; "
                       "GitHub Actions workflows are zizmor's")

    def command(self, workspace: Path) -> Invocation:
        return Invocation(
            tool=self.name, version=VERSION,
            argv=("checkov", "--directory", "/workspace", "--output", "json",
                  "--output-file-path", "/results", "--quiet", "--compact",
                  # No network, ever: skip external data downloads outright.
                  "--skip-download",
                  # Workflows are zizmor's (R4.3, ADR-0023): without this one
                  # write-all permission would be two Findings. Secrets are
                  # Gitleaks' (R10.2, D31): a secret's identity carries its rule,
                  # so the same key found by both could never merge, and R5's
                  # planted flood came back as 3,694 findings and 3,890 more.
                  "--skip-framework", "github_actions", "secrets"),
            report="results_json.json", timeout=600, empty_when=NOTHING_TO_SCAN,
        )

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
                        severity=Severity.parse(check.get("severity") or "medium"),
                    )
                )
        return findings
