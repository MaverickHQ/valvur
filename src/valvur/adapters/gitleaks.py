"""Gitleaks — secrets, including git history."""

from __future__ import annotations

import json
from pathlib import Path

from .. import fingerprint as _fp
from .. import redact as _redact
from ..findings import Finding, Severity
from ..invocation import Invocation, ScannerOutput
from .base import ScannerAdapter, container_relative

VERSION = "8.30.1"


class GitleaksAdapter(ScannerAdapter):
    kind = "scanner"
    name = "gitleaks"
    version = VERSION

    def command(self, workspace: Path) -> Invocation:
        from .. import exclusions

        # `--exit-code 0`: gitleaks exits 1 when it finds something, which is a
        # successful run (F2.4); the report says what it found.
        prefixes = exclusions.excluded_prefixes(workspace)
        return Invocation(
            tool=self.name, version=VERSION,
            argv=("gitleaks", "dir", "/workspace",
                  "--report-format", "json",
                  "--report-path", "/results/gitleaks.json",
                  "--no-banner", "--exit-code", "0",
                  # What not to read (29.0.1): a generated config in the scratch
                  # mount, since Gitleaks has no path flag. Measured before this:
                  # 3,892 hits inside an excluded archive, produced then dropped.
                  "--config", f"/results/{exclusions.GITLEAKS_CONFIG}"),
            report="gitleaks.json", timeout=300,
            files=((exclusions.GITLEAKS_CONFIG, exclusions.gitleaks_config(
                prefixes,
                project_config=(workspace / exclusions.PROJECT_GITLEAKS_CONFIG).is_file())),),
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
                    severity=Severity.CRITICAL,
                )
            )
        return findings
