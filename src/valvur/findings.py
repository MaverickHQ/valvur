"""The Finding model. Every Scanner and Check normalises into this (F5.1)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum

from .fingerprint import FP_VERSION


class Severity(StrEnum):
    """What a Scanner asserts about a Finding, in one vocabulary (28.4.1). Ordered
    worst-first; Scanners disagree on the words, so adapters `parse` onto this.
    A `str`, so every JSON artifact and every comparison against the literal is
    unchanged — the goldens hold it byte for byte."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, text: object) -> Severity:
        """A Scanner's word for it, or UNKNOWN — never a guess. `MODERATE` is not
        `medium` until an adapter says so."""
        try:
            return cls(str(text or "").strip().lower())
        except ValueError:
            return cls.UNKNOWN


class Status(StrEnum):
    """A Finding's status against the previous run (F5.6). `fixed` is not here: a
    fixed Finding is absent, and the run lists it by fingerprint."""

    NEW = "new"
    PERSISTING = "persisting"
    REGRESSED = "regressed"


# Ordered worst-first, as the enum is; kept as a name because `.index` is how the
# ranking, the gate and the merge compare two severities.
SEVERITIES = tuple(Severity)


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


#: An EPSS score from here up earns a badge on the one-line surfaces.
EPSS_BADGE_THRESHOLD = 0.10


def exploit_badge(exploit: Exploit | Mapping[str, object] | None) -> str:
    """The one word a reader gets beside a Finding about its exploitation: known
    exploited and used by ransomware, known exploited, or a probability worth
    saying. One decision for both one-line surfaces — `SUMMARY.md`'s Markdown and
    the CLI/MCP reply's plain text — which each decided it alone until 28.1.1 and
    had already drifted. The *mark* (bold, brackets) is the surface's; the word is
    not. Empty when there is nothing to say."""
    if exploit is None:
        return ""
    read = exploit.get if isinstance(exploit, Mapping) else lambda k: getattr(exploit, k, None)
    if read("ransomware"):
        return "KEV·RANSOMWARE"
    if read("kev"):
        return "KEV"
    epss = read("epss")
    if isinstance(epss, int | float) and epss >= EPSS_BADGE_THRESHOLD:
        return f"EPSS {epss:.0%}"
    return ""


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
    status: Status = Status.NEW
    sources: tuple[str, ...] = ()

    # --- Enrichment. Additive only: none of it feeds the Fingerprint, because a
    # --- fingerprint shift would invalidate every shared Suppression (ADR-0003).
    severity: Severity = Severity.UNKNOWN
    rank: int = 0
    exploit: Exploit | None = None
    dependency: Dependency | None = None
    # Populated when a committed Suppression matches. Policy, not identity:
    # it never affects the Fingerprint or the Status diff.
    suppressed: str | None = None

    def __post_init__(self) -> None:
        """Neutralise evidence at the MODEL boundary, not per-adapter.

        Redaction already works this way, and evidence should too: leaving it to each
        adapter is how SAST findings ended up carrying raw workspace lines while the
        AI-artifact check fenced its own. One place, applied to everything (F3.13).
        """
        from .defang import neutralise

        if self.evidence:
            object.__setattr__(self, "evidence", neutralise(self.evidence))
        # The vocabulary, whatever a caller passed (28.4.1): a Scanner's word
        # becomes the enum here, once, and an unknown status is an error rather
        # than a string nothing downstream would recognise.
        object.__setattr__(self, "severity", Severity.parse(self.severity))
        object.__setattr__(self, "status", Status(self.status))


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
