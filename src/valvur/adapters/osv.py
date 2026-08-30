"""OSV-Scanner — dependencies against OSV.dev.

Overlaps Trivy deliberately. Where they agree, Findings merge and keep both sources;
where they disagree, that is signal about data quality, not noise (F5.8).
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import fingerprint as _fp
from ..findings import Finding
from ..runner import ScannerOutput
from .base import container_relative


class OsvAdapter:
    kind = "scanner"
    name = "osv-scanner"

    def run(self, runner, workspace: Path) -> ScannerOutput:
        return runner.run_osv(workspace)

    def parse(self, output: ScannerOutput) -> list[Finding]:
        report = json.loads(output.stdout or "{}")
        findings: list[Finding] = []

        for result in report.get("results") or []:
            source = container_relative(str(result.get("source", {}).get("path", "")))
            for package in result.get("packages") or []:
                info = package.get("package", {})
                name = info.get("name", "")
                version = info.get("version", "")
                # OSV names ecosystems like "PyPI"; Trivy says "pip". Normalise so
                # the two agree on identity and their Findings actually merge.
                ecosystem = _ECOSYSTEM.get(info.get("ecosystem", ""), info.get("ecosystem", ""))
                for vuln in package.get("vulnerabilities") or []:
                    vid = _preferred_id(vuln)
                    findings.append(
                        Finding(
                            rule=vid,
                            path=source,
                            line=0,
                            title=f"{name} {version} — {vuln.get('summary', 'vulnerability')}",
                            evidence=f"{ecosystem} package {name}@{version}",
                            fingerprint=_fp.for_dependency_vuln(ecosystem, name, version, vid),
                            sources=(output.tool,),
                        )
                    )
        return findings


# OSV and Trivy name the same ecosystems differently. Without this, identical
# vulnerabilities would never merge and every one would be reported twice.
_ECOSYSTEM = {
    "PyPI": "pip", "npm": "npm", "Go": "gomod",
    "crates.io": "cargo", "Maven": "maven", "RubyGems": "gem",
}


def _preferred_id(vuln: dict) -> str:
    """Prefer the CVE, so OSV and Trivy findings share an identity."""
    for alias in vuln.get("aliases") or []:
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "")
