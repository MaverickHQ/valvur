"""The Score's formula (ADR-0026, N4.1).

A track is scored as the OWASP Benchmark scores a tool: per category, the rate at
which vulnerable cases are flagged minus the rate at which safe ones are, averaged
over the categories and put on 0 to 100. A tool that flags everything scores 0, as
one that flags nothing does; only telling the two apart scores.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Case:
    """A path labelled vulnerable or safe, and what a finding must be to flag it."""

    id: str
    track: str
    category: str
    path: str
    vulnerable: bool
    #: A finding flags the case when it matches any one of these: its rule ID, a
    #: prefix of its rule ID, its advisory (the rule or the CVE it carries), a CWE
    #: its rule declares, or the Scanner that reported it.
    rules: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()
    advisories: tuple[str, ...] = ()
    cwes: tuple[int, ...] = ()
    sources: tuple[str, ...] = ()
    #: What the case is about, where its premise needs it: a declared package name.
    subject: str = ""


@dataclass
class Rates:
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0

    @property
    def tpr(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0


@dataclass
class TrackResult:
    score: float
    categories: dict[str, Rates] = field(default_factory=dict)


def _active(finding: dict) -> bool:
    """What `findings.json` counts toward the verdict: neither suppressed nor fixed."""
    return not finding.get("suppressed") and finding.get("status") != "fixed"


def _lands_on(case: Case, finding: dict) -> bool:
    """On the case's file, or anywhere under the case's directory."""
    path = str(finding.get("path", ""))
    return path == case.path or path.startswith(case.path.rstrip("/") + "/")


def _no_cwe(finding: dict) -> set[int]:
    return set()


def _of_its_kind(case: Case, finding: dict, cwe_of: Callable[[dict], set[int]]) -> bool:
    rule = str(finding.get("rule", ""))
    cve = (finding.get("exploit") or {}).get("cve")
    return (rule in case.rules
            or any(rule.startswith(prefix) for prefix in case.prefixes)
            or bool({rule, cve} & set(case.advisories))
            or bool(cwe_of(finding) & set(case.cwes))
            or bool(set(finding.get("sources") or ()) & set(case.sources)))


def flagged(case: Case, findings: Iterable[dict],
            cwe_of: Callable[[dict], set[int]] = _no_cwe) -> bool:
    return any(_active(f) and _lands_on(case, f) and _of_its_kind(case, f, cwe_of)
               for f in findings)


def score_track(cases: list[Case], findings: list[dict],
                cwe_of: Callable[[dict], set[int]] = _no_cwe) -> TrackResult:
    categories: dict[str, Rates] = {}
    for case in cases:
        rates = categories.setdefault(case.category, Rates())
        hit = flagged(case, findings, cwe_of)
        if case.vulnerable:
            rates.tp += hit
            rates.fn += not hit
        else:
            rates.fp += hit
            rates.tn += not hit
    judged = [r for r in categories.values() if r.tp + r.fn]
    mean = sum(r.tpr - r.fpr for r in judged) / len(judged) if judged else 0.0
    return TrackResult(round(100 * mean, 1), categories)
