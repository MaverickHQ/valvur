"""The Score's formula (ADR-0026, N4.1).

A track is scored as the OWASP Benchmark scores a tool: per category, the rate at
which vulnerable cases are flagged minus the rate at which safe ones are, averaged
over the categories and put on 0 to 100. A tool that flags everything scores 0, as
one that flags nothing does; only telling the two apart scores.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Case:
    """A path labelled vulnerable or safe, and what a finding must be to flag it."""

    id: str
    track: str
    category: str
    path: str
    vulnerable: bool
    #: Any of these rule IDs flags the case.
    rules: tuple[str, ...] = ()


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


def flagged(case: Case, findings: Iterable[dict]) -> bool:
    return any(finding.get("path") == case.path and finding.get("rule") in case.rules
               for finding in findings)


def score_track(cases: list[Case], findings: list[dict]) -> TrackResult:
    categories: dict[str, Rates] = {}
    for case in cases:
        rates = categories.setdefault(case.category, Rates())
        hit = flagged(case, findings)
        if case.vulnerable:
            rates.tp += hit
            rates.fn += not hit
        else:
            rates.fp += hit
            rates.tn += not hit
    judged = [r for r in categories.values() if r.tp + r.fn]
    mean = sum(r.tpr - r.fpr for r in judged) / len(judged) if judged else 0.0
    return TrackResult(round(100 * mean, 1), categories)
