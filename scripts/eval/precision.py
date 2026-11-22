"""Track 8 of the Score: precision on real code (ADR-0026, D21).

The corpus's projects (forty-eight since R29.2) are real and maintained, so most of what is found on
them is not a vulnerability. Every active finding of a rule valvur owns, and of
Gitleaks, whose noise users meet first, carries a label in
`tests/eval/labels/corpus.toml`: `tp` when a maintainer would act on it (change
code, rotate, pin), `fp` otherwise, and a reason either way. The labels are the
executor's, committed for the owner to read. A finding without one fails the track
and is named, so a new rule cannot arrive unjudged. The score is smoothed precision
(`Precision.score`).
"""

from __future__ import annotations

import functools
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

VERDICTS = ("tp", "fp")
#: The Scanners judged in a table of their own (R48.3, D82a), and how many of one rule's
#: Findings on the corpus are judged: the ones with the lowest Fingerprints (D82b).
HYGIENE = ("checkov", "zizmor")
SAMPLE = 25


def note(finding: dict) -> bool:
    """A coverage note: what valvur did not inspect, never a claim about the code."""
    from valvur.coverage import NOTE_RULES

    return finding.get("rule") in NOTE_RULES


@functools.cache
def _vendored() -> frozenset[str]:
    """The ids of the rules valvur vendors (R13.3), from each set's manifest."""
    import json

    root = Path(__file__).resolve().parents[2] / "rules" / "vendor"
    return frozenset(rule["id"] for manifest in sorted(root.glob("*/manifest.json"))
                     for rule in json.loads(manifest.read_text()).get("rules", []))


def owned(finding: dict) -> bool:
    """Judged here: a rule of valvur's own or one it vendors, or a Gitleaks secret."""
    rule = str(finding.get("rule", ""))
    return rule.startswith("valvur.") or rule in _vendored() or \
        "gitleaks" in (finding.get("sources") or ())


def _active(finding: dict) -> bool:
    """As `score._active`: what counts toward the verdict (D47a's inventory does not)."""
    return (not finding.get("suppressed") and finding.get("status") != "fixed"
            and not finding.get("inventory"))


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
    #: Coverage notes, counted and not judged.
    notes: int = 0
    #: (Scanner, rule) to its true and false counts, for each rule with a judged Finding
    #: (R48.2, D82a). The bar on maintained code is set from these, rule by rule.
    by_rule: dict[tuple[str, str], list[int]] = field(default_factory=dict)
    #: Scanner to its active Findings on the corpus, and how many of them were judged.
    by_scanner: dict[str, dict[str, int]] = field(default_factory=dict)
    #: Checkov's and zizmor's Findings, by rule: judged in their own table, never pooled
    #: into `tp` and `fp`, with the judged ones that have no label.
    hygiene: list[dict] = field(default_factory=list)
    hygiene_unlabelled: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Precision with one imaginary true positive, times 100 (ADR-0026, amended by
        R9.5): silence scores 100 and each false alarm costs, which plain precision
        cannot say where maintained code offers nothing true to find."""
        return round(100 * (self.tp + 1) / (self.tp + self.fp + 1), 1)


def _listed(finding: dict) -> bool:
    """In `findings.json` and not active: inventory, by its rule's file or the tier table.
    Not a suppressed Finding, and not a fixed one."""
    return bool(finding.get("inventory")) and not finding.get("suppressed") \
        and finding.get("status") != "fixed"


def judge(findings_by_repo: dict[str, list[dict]],
          labels: dict[tuple[str, str], tuple[str, str]],
          hygiene: dict[tuple[str, str], tuple[str, str]] | None = None) -> Precision:
    """The track is about what is active. The measurement by rule is about the rule: a
    Finding the tier table lists (R49.2) is not active, and its label still counts for its
    rule in `by_rule` and `hygiene`, so the table can be held to the measurement. A listed
    Finding with no label is passed over, as a sink is (D47a)."""
    result, others = Precision(), Counter[str]()
    theirs: dict[tuple[str, str], list[tuple[str, str, dict]]] = {}
    for repo, findings in sorted(findings_by_repo.items()):
        for finding in findings:
            active = _active(finding)
            if not active and not _listed(finding):
                continue
            if note(finding):
                result.notes += active
                continue
            scanner = str((finding.get("sources") or ["?"])[0])
            counted = result.by_scanner.setdefault(
                scanner, {"findings": 0, "judged": 0, "tp": 0, "fp": 0})
            counted["findings"] += active
            if scanner in HYGIENE:
                theirs.setdefault((scanner, str(finding.get("rule"))), []).append(
                    (str(finding.get("fingerprint")), repo, finding))
            if not owned(finding):
                if active:
                    others.update([scanner])
                continue
            label = labels.get((repo, str(finding.get("fingerprint"))))
            if label is None:
                if active:
                    result.unlabelled.append(
                        f"{repo}: {finding.get('rule')} at {finding.get('path')} "
                        f"({finding.get('fingerprint')})")
                continue
            verdict = label[0]
            counted["judged"] += 1
            counted[verdict] += 1
            result.by_rule.setdefault((scanner, str(finding.get("rule"))), [0, 0])[
                VERDICTS.index(verdict)] += 1
            if active:
                result.tp += verdict == "tp"
                result.fp += verdict == "fp"
    for (scanner, rule), found in sorted(theirs.items()):
        row = {"scanner": scanner, "rule": rule, "findings": len(found), "judged": 0, "tp": 0,
               "fp": 0, "sampled": len(found) > SAMPLE}
        for fingerprint, repo, finding in sorted(found, key=lambda f: f[:2])[:SAMPLE]:
            label = (hygiene or {}).get((repo, fingerprint))
            if label is None:
                if _active(finding):
                    result.hygiene_unlabelled.append(
                        f"{repo}: {rule} at {finding.get('path')} ({fingerprint})")
                continue
            row["judged"] += 1
            row[label[0]] += 1
            result.by_scanner[scanner]["judged"] += 1
            result.by_scanner[scanner][label[0]] += 1
        result.hygiene.append(row)
    result.others = dict(sorted(others.items()))
    result.by_scanner = dict(sorted(result.by_scanner.items()))
    return result


def label_changes(path: Path, recorded: dict[str, str]) -> list[str]:
    """Each label whose verdict differs from the one the baseline records, with no
    `changed = "<date>: <reason>"` beside it (R48.3, Requirement 5.2). A label the baseline
    does not know is new, and one it knows that is gone was dropped: neither is a verdict
    that changed. So a label cannot be bent to meet a target without saying why."""
    found = []
    for entry in tomllib.loads(path.read_text(encoding="utf-8")).get("label", []):
        key = f"{entry.get('repo', '')} {entry.get('fingerprint', '')}"
        was = recorded.get(key)
        if was is not None and was != entry.get("verdict") and \
                not str(entry.get("changed", "")).strip():
            found.append(f"{key}: {entry.get('verdict')}, where the baseline records {was}, "
                         "with no `changed` reason")
    return found


def verdicts(path: Path) -> dict[str, str]:
    """Each label's verdict, as the baseline records it: `<repo> <fingerprint>` to `tp` or
    `fp`."""
    return {f"{repo} {fingerprint}": verdict
            for (repo, fingerprint), (verdict, _reason) in sorted(load(path).items())}
