"""Gitleaks — secrets, including git history."""

from __future__ import annotations

import json
from pathlib import Path

from .. import fingerprint as _fp
from .. import redact as _redact
from ..findings import Finding
from ..invocation import Invocation, ScannerOutput
from .base import ScannerAdapter, container_relative

VERSION = "8.30.1"


class GitleaksAdapter(ScannerAdapter):
    kind = "scanner"
    name = "gitleaks"
    version = VERSION

    def command(self, workspace: Path) -> Invocation:
        # `--exit-code 0`: gitleaks exits 1 when it finds something, which is a
        # successful run (F2.4); the report says what it found.
        return Invocation(
            tool=self.name, version=VERSION,
            argv=("gitleaks", "dir", "/workspace",
                  "--report-format", "json",
                  "--report-path", "/results/gitleaks.json",
                  "--no-banner", "--exit-code", "0"),
            report="gitleaks.json", timeout=300,
        )

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
