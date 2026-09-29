"""Track 8 of the Score: precision on real code (ADR-0026, D21).

The corpus's thirteen projects are real and maintained, so most of what is found on
them is not a vulnerability. Every active finding of a rule valvur owns, and of
Gitleaks, whose noise users meet first, carries a label in
`tests/eval/labels/corpus.toml`: `tp` when a maintainer would act on it (change
code, rotate, pin), `fp` otherwise, and a reason either way. The labels are the
executor's, committed for the owner to read. A finding without one fails the track
and is named, so a new rule cannot arrive unjudged.
"""

from __future__ import annotations

import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

VERDICTS = ("tp", "fp")


def owned(finding: dict) -> bool:
    """Judged here: a rule of valvur's own, or a Gitleaks secret."""
    return str(finding.get("rule", "")).startswith("valvur.") or \
        "gitleaks" in (finding.get("sources") or ())


def _active(finding: dict) -> bool:
    return not finding.get("suppressed") and finding.get("status") != "fixed"


def load(path: Path) -> dict[tuple[str, str], tuple[str, str]]:
    """(repo, fingerprint) to (verdict, reason). A label with no reason, or a verdict
    other than `tp` or `fp`, is refused."""
    labels = {}
    for entry in tomllib.loads(path.read_text(encoding="utf-8")).get("label", []):
        key = (entry.get("repo", ""), entry.get("fingerprint", ""))
        if entry.get("verdict") not in VERDICTS or not str(entry.get("reason", "")).strip():
            raise ValueError(f"label {key[0]} {key[1]}: needs a verdict of tp or fp and a reason")
        labels[key] = (entry["verdict"], entry["reason"])
    return labels


@dataclass
class Precision:
    tp: int = 0
    fp: int = 0
    unlabelled: list[str] = field(default_factory=list)
    #: Other Scanners' active findings, counted and not judged.
    others: dict[str, int] = field(default_factory=dict)

    @property
    def score(self) -> float:
        return round(100 * self.tp / (self.tp + self.fp), 1) if self.tp + self.fp else 0.0


def judge(findings_by_repo: dict[str, list[dict]],
          labels: dict[tuple[str, str], tuple[str, str]]) -> Precision:
    result, others = Precision(), Counter[str]()
    for repo, findings in sorted(findings_by_repo.items()):
        for finding in findings:
            if not _active(finding):
                continue
            if not owned(finding):
                others.update((finding.get("sources") or ["?"])[:1])
                continue
            label = labels.get((repo, str(finding.get("fingerprint"))))
            if label is None:
                result.unlabelled.append(f"{repo}: {finding.get('rule')} at "
                                         f"{finding.get('path')} ({finding.get('fingerprint')})")
            elif label[0] == "tp":
                result.tp += 1
            else:
                result.fp += 1
    result.others = dict(sorted(others.items()))
    return result
