"""The Finding model. Every Scanner and Check normalises into this."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .fingerprint import FP_VERSION

# Ordered worst-first. Scanners disagree on vocabulary, so adapters map onto this.
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


@dataclass(frozen=True)
class Exploit:
    """Whether a vulnerability is exploited in reality, as opposed to in theory.

    Deliberately separate from `severity`: severity is what a Scanner asserts, this
    is what the world reports. Conflating them is what makes CVSS-sorted output
    useless, and keeping them apart is what makes the ranking auditable.
    """

    cve: str = ""
    kev: bool | None = None          # None = not yet looked up, distinct from False
    ransomware: bool = False
    epss: float | None = None
    epss_date: str = ""


@dataclass(frozen=True)
class Dependency:
    ecosystem: str = ""
    package: str = ""
    version: str = ""
    fixed_version: str = ""
    purl: str = ""
    scope: str = "unknown"           # production | development | unknown
    direct: bool | None = None
    path: tuple[str, ...] = ()       # your-app -> webpack@4 -> lodash@4.17.11


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    title: str
    evidence: str = ""
    fingerprint: str = ""
    fp_version: int = FP_VERSION
    status: str = "new"
    sources: tuple[str, ...] = ()

    # --- Enrichment. Additive only: none of it feeds the Fingerprint, because a
    # --- fingerprint shift would invalidate every shared Suppression (ADR-0003).
    severity: str = "unknown"
    rank: int = 0
    exploit: Exploit | None = None
    dependency: Dependency | None = None
    # Populated when a committed Suppression matches. Policy, not identity:
    # it never affects the Fingerprint or the Status diff.
    suppressed: str | None = None


def merge(findings: list[Finding]) -> list[Finding]:
    """Collapse Findings sharing a Fingerprint, keeping every reporting source.

    Trivy and OSV-Scanner overlap heavily. Disagreement between them is signal about
    data quality, so sources accumulate rather than the later one winning (F5.8).
    """
    by_fp: dict[str, Finding] = {}
    for finding in findings:
        existing = by_fp.get(finding.fingerprint)
        if existing is None:
            by_fp[finding.fingerprint] = finding
            continue
        combined = tuple(dict.fromkeys(existing.sources + finding.sources))
        # Keep the worse severity and whichever record carries more detail: when two
        # Scanners disagree, under-reporting is the dangerous direction.
        severity = min(
            (existing.severity, finding.severity),
            key=lambda s: SEVERITIES.index(s) if s in SEVERITIES else len(SEVERITIES),
        )
        by_fp[finding.fingerprint] = replace(
            existing,
            sources=combined,
            severity=severity,
            dependency=existing.dependency or finding.dependency,
            exploit=existing.exploit or finding.exploit,
        )
    return list(by_fp.values())
