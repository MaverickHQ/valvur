"""The Finding model. Every Scanner and Check normalises into this."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .fingerprint import FP_VERSION


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
        by_fp[finding.fingerprint] = replace(existing, sources=combined)
    return list(by_fp.values())
