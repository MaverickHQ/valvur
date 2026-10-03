"""The Finding model. Every Scanner and Check normalises into this (F5.1)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum

from .defang import neutralise
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
    #: The commit that added it, for a secret read from git history (R3.7). Not
    #: identity: the same secret in the tree and in history is one Finding.
    commit: str | None = None
    #: The group it belongs to when one rule floods one directory (R5.1). Not
    #: identity: grouping drops nothing and changes no Fingerprint.
    group: str | None = None
    #: The weaknesses its rule declares, as `CWE-n` (F5.10, R13.4). Not identity,
    #: and neither ranking nor grouping reads it.
    cwe: tuple[str, ...] = ()
    #: Its path's class (D56): `source`, `test`, `fixture`, `docs`, `example`,
    #: `vendored` or `generated`. Not identity: a test's secret is the same Finding
    #: whatever its directory is called.
    context: str = ""
    #: A sink its rule names for review, not a finding by itself (D47a): reported,
    #: and counted under *Sinks to review*, but never active. Not identity.
    inventory: bool = False

    def __post_init__(self) -> None:
        """Neutralise evidence at the MODEL boundary, not per-adapter.

        Redaction already works this way, and evidence should too: leaving it to each
        adapter is how SAST findings ended up carrying raw workspace lines while the
        AI-artifact check fenced its own. One place, applied to everything (F3.13).
        """
        if self.evidence:
            object.__setattr__(self, "evidence", neutralise(self.evidence))
        # The vocabulary, whatever a caller passed (28.4.1): a Scanner's word
        # becomes the enum here, once, and an unknown status is an error rather
        # than a string nothing downstream would recognise.
        object.__setattr__(self, "severity", Severity.parse(self.severity))
        object.__setattr__(self, "status", Status(self.status))


def merge(findings: list[Finding],
          index_form: Callable[[str, str], str] | None = None) -> list[Finding]:
    """Collapse Findings sharing a Fingerprint, keeping every reporting source.

    Trivy and OSV-Scanner overlap heavily. Disagreement between them is signal about
    data quality, so sources accumulate rather than the later one winning (F5.8).
    `index_form` spells a package's name as its registry identifies it, so one
    malicious package reported two ways is one finding; the pipeline passes the
    ecosystems' (D50: the model reaches no registry code itself).
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
            cwe=existing.cwe or finding.cwe,
        )
    return _fold_repeats(_fold_malicious(list(by_fp.values()), index_form))


#: The rule the dependency-reality Check reports a known-malicious package under
#: (D26), which a Scanner's `MAL-` advisory for the same package folds into.
MALICIOUS_RULE = "valvur.dependency.malicious"


def _fold_repeats(findings: list[Finding]) -> list[Finding]:
    """One flaw, one finding (R13): a vendored rule's finding on a line where one of
    valvur's own rules reports the same weakness folds into valvur's, at the worse of
    the two severities. Two rule ids on one line for one weakness were two findings
    that never merged, since a SAST finding's identity carries its rule (ADR-0003)."""
    def places(finding: Finding) -> set[tuple[str, int, str]]:
        return {(finding.path, finding.line, c) for c in finding.cwe} if finding.line else set()

    own = {place: i for i, f in enumerate(findings) if f.rule.startswith("valvur.")
           for place in places(f)}
    if not own:
        return findings
    kept = list(findings)
    dropped: set[int] = set()
    for i, finding in enumerate(findings):
        if finding.rule.startswith("valvur.") or "opengrep" not in finding.sources:
            continue
        target = next((own[place] for place in sorted(places(finding)) if place in own), None)
        if target is None:
            continue
        into = kept[target]
        kept[target] = replace(into, severity=min(
            (into.severity, finding.severity),
            key=lambda s: SEVERITIES.index(s) if s in SEVERITIES else len(SEVERITIES)))
        dropped.add(i)
    return [f for i, f in enumerate(kept) if i not in dropped]


def _fold_malicious(findings: list[Finding],
                    index_form: Callable[[str, str], str] | None) -> list[Finding]:
    """OSV-Scanner reports a malicious package as its `MAL-` advisory, and the
    dependency-reality Check as `MALICIOUS_RULE`, under identities of two classes
    (ADR-0003): a vulnerability's has the version, a package's does not. One package
    is one finding (F3.14), so the advisory folds into the Check's: its Scanner is
    named, its identifier kept, and the Check's finding stands for both."""

    def key(dependency: Dependency) -> tuple[str, str]:
        if index_form is None:
            return dependency.ecosystem, dependency.package
        try:
            return dependency.ecosystem, index_form(dependency.ecosystem, dependency.package)
        except KeyError:
            return dependency.ecosystem, dependency.package

    malicious = {key(f.dependency): i for i, f in enumerate(findings)
                 if f.rule == MALICIOUS_RULE and f.dependency}
    if not malicious:
        return findings
    folded = list(findings)
    dropped: set[int] = set()
    for i, finding in enumerate(findings):
        target = (malicious.get(key(finding.dependency))
                  if finding.rule.startswith("MAL-") and finding.dependency else None)
        if target is None:
            continue
        into = folded[target]
        folded[target] = replace(
            into, sources=tuple(dict.fromkeys(into.sources + finding.sources)),
            title=into.title if finding.rule in into.title
            else into.title.replace(")", f", {finding.rule})", 1))
        dropped.add(i)
    return [f for i, f in enumerate(folded) if i not in dropped]
