"""OSV-Scanner — dependencies against OSV.dev.

Overlaps Trivy deliberately. Where they agree, Findings merge and keep both sources;
where they disagree, that is signal about data quality, not noise (F5.8).
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import ecosystems as _ecosystems
from .. import fingerprint as _fp
from ..findings import Dependency, Exploit, Finding, Severity
from ..invocation import NOTHING_TO_SCAN, Invocation, ScannerOutput
from ..versions import version_key as _version_key
from .base import ScannerAdapter, container_relative

VERSION = "2.6.0"


class OsvAdapter(ScannerAdapter):
    kind = "scanner"
    name = "osv-scanner"
    version = VERSION

    def command(self, workspace: Path) -> Invocation:
        # OSV queries api.osv.dev, so it is a `full` Scanner only — absent from
        # `offline`, which must stay offline (N2.1). `network=True` here is what
        # the Profile grants by selecting it at all.
        return Invocation(
            tool=self.name, version=VERSION,
            argv=("osv-scanner", "scan", "source", "--recursive",
                  # `--output-file`: 2.6.0 deprecates `--output` with a warning.
                  "--format", "json", "--output-file", "/results/osv.json", "/workspace"),
            report="osv.json", network=True, timeout=600, empty_when=NOTHING_TO_SCAN,
        )

    def parse(self, output: ScannerOutput) -> list[Finding]:
        report = json.loads(output.stdout or "{}")
        findings: list[Finding] = []

        for result in _one_block_per_path(report.get("results") or []):
            source = container_relative(str(result.get("source", {}).get("path", "")))
            for package in result.get("packages") or []:
                info = package.get("package", {})
                name = info.get("name", "")
                version = info.get("version", "")
                # OSV names ecosystems like "PyPI"; Trivy says "pip". Normalise so
                # the two agree on identity and their Findings actually merge.
                ecosystem = _ecosystems.normalise(info.get("ecosystem", ""))
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
                            severity=_severity(vuln),
                            exploit=Exploit(cve=vid if vid.startswith("CVE-") else ""),
                            dependency=Dependency(
                                ecosystem=ecosystem,
                                package=name,
                                version=version,
                                fixed_version=_fixed_version(vuln, name, version),
                            ),
                        )
                    )
        return findings


def _one_block_per_path(results: list) -> list:
    """OSV-Scanner 2.6.0 reports `requirements.txt` twice: the lockfile extractor's
    block, and a second of `source.type: unknown` from the generic extractor with
    PEP 440-normalised versions — `pyyaml 5.1` beside `pyyaml 5.1.0`, six advisories
    each, two identities. Where a path has a typed block, the `unknown` one for the
    same path is dropped; a path only the generic extractor read keeps its block.
    Measured on the golden fixture, 2026-09-20 (2.2.4 → 2.6.0 by Dependabot)."""
    typed = {
        str((r.get("source") or {}).get("path", ""))
        for r in results if (r.get("source") or {}).get("type") not in (None, "", "unknown")
    }
    return [
        r for r in results
        if not ((r.get("source") or {}).get("type") == "unknown"
                and str((r.get("source") or {}).get("path", "")) in typed)
    ]


def _fixed_version(vuln: dict, name: str, version: str) -> str:
    """The single most actionable field in a dependency finding — "upgrade to X" is
    the whole remediation. OSV publishes a fix per affected release line, so
    brace-expansion 1.1.15 carries fixes 1.1.16, 2.1.2 AND 5.0.7. Taking the first
    listed would advise a major-version jump when a patch release clears it. Take
    the smallest fix above the installed version: the minimal upgrade that works,
    and never a downgrade."""
    installed = _version_key(version)
    candidates = [
        fixed
        for affected in vuln.get("affected") or []
        if (affected.get("package") or {}).get("name") in (name, None, "")
        for rng in affected.get("ranges") or []
        for event in rng.get("events") or []
        if (fixed := event.get("fixed")) and _version_key(fixed) > installed
    ]
    return min(candidates, key=_version_key, default="")


def _preferred_id(vuln: dict) -> str:
    """Prefer the CVE, so OSV and Trivy findings share an identity."""
    for alias in vuln.get("aliases") or []:
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "")


# OSV speaks GitHub's vocabulary, which calls medium "moderate". Left unmapped it
# falls outside our scale entirely and sorts BELOW low — so real npm advisories ranked
# beneath an unknown-licence note. Normalise on every path, not just the first.
_OSV_SEVERITY = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "MODERATE": "medium", "LOW": "low",
}


def _normalise(value: str) -> str | None:
    return _OSV_SEVERITY.get(str(value).strip().upper())


def _severity(vuln: dict) -> Severity:
    """OSV reports severity inconsistently across ecosystems; take what is there."""
    for entry in vuln.get("severity") or []:
        mapped = _normalise(entry.get("score", ""))
        if mapped:
            return Severity.parse(mapped)
    db = (vuln.get("database_specific") or {}).get("severity", "")
    return Severity.parse(_normalise(db))
