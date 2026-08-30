"""Gitleaks — secrets, including git history."""

from __future__ import annotations

import json
from pathlib import Path

from .. import fingerprint as _fp
from .. import redact as _redact
from ..findings import Finding
from ..runner import ScannerOutput
from .base import container_relative


class GitleaksAdapter:
    kind = "scanner"
    name = "gitleaks"

    def run(self, runner, workspace: Path) -> ScannerOutput:
        return runner.run_gitleaks(workspace)

    def parse(self, output: ScannerOutput) -> list[Finding]:
        findings = []
        for item in json.loads(output.stdout or "[]"):
            path = container_relative(item["File"])
            secret = item.get("Secret", "")
            findings.append(
                Finding(
                    rule=item["RuleID"],
                    path=path,
                    line=item["StartLine"],
                    title=item["Description"],
                    # Redact at the boundary — the raw secret never enters the model.
                    evidence=_redact.redact(item.get("Match", ""), secret),
                    fingerprint=_fp.for_secret(item["RuleID"], path, secret),
                    sources=(output.tool,),
                    # A live credential in a repository is not a matter of degree.
                    severity="critical",
                )
            )
        return findings
