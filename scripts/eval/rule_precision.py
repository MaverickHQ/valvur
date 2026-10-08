"""Each shipped rule's precision, read from the Score's own scans (R29.3, D65b).

Track 1 (the OWASP Benchmark for Python), track 2 (the JavaScript twins) and the
corpus are scanned by the Score already, so a rule is judged by what valvur reports,
path classes and the inventory included, never by a raw Opengrep run. Per rule:

- on a track, a **true positive** is a finding on a vulnerable case its CWE answers, a
  **false positive** one on a safe case of that weakness, and a finding on a case of
  another weakness is **outside**, as `per_rule.tally` counts a candidate (D29);
- on the corpus, a finding is what its label says (`tests/eval/labels/corpus.toml`); an
  inventory finding has no label to read until it is demoted, and is **unjudged**.

A vendored rule's true positive is **new** when none of valvur's own rules reports its
line (D29 as amended by R13.6). The bar is D29's: one true positive, precision of at
least 0.5, and for a vendored rule one of them new.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

import cwe  # type: ignore[import-not-found]
import score  # type: ignore[import-not-found]

#: The places a rule is measured, in the order `docs/RULES.md` gives them.
PLACES = ("sast-python", "sast-js", "corpus")
#: A rule's metadata line that keeps it out of the verdict (D47a).
_INVENTORY = re.compile(r"^\s+inventory:\s*true\b", re.M)
#: Why R29.3 demoted it, when it did: one quoted line in its metadata.
_DEMOTED = re.compile(r"""^\s+demoted:\s*["'](.+)["']\s*$""", re.M)


@dataclass
class Tally:
    tp: int = 0
    fp: int = 0
    outside: int = 0
    new: int = 0
    unjudged: int = 0


def shipped(rules_dir: Path) -> dict[str, dict]:
    """Every rule under `rules_dir`: its file, whether it is vendored, whether it is in
    the inventory, and why it was demoted there, if it was."""
    found = {}
    for path in sorted(rules_dir.rglob("*.yaml")):
        blocks = cwe._ID.split(path.read_text(encoding="utf-8"))[1:]
        for rule, body in zip(blocks[::2], blocks[1::2], strict=True):
            demoted = _DEMOTED.search(body)
            found[rule] = {"file": path.relative_to(rules_dir.parent).as_posix(),
                           "vendored": "vendor" in path.relative_to(rules_dir).parts,
                           "inventory": bool(_INVENTORY.search(body)),
                           "demoted": demoted.group(1) if demoted else ""}
    return found


def _counted(finding: dict) -> bool:
    return not finding.get("suppressed") and finding.get("status") != "fixed"


def _own_lines(findings: list[dict], rules: dict[str, dict]) -> set[tuple[str, int]]:
    return {(str(f.get("path")), int(f.get("line") or 0)) for f in findings
            if f.get("rule") in rules and not rules[f["rule"]]["vendored"]}


def _new(finding: dict, rules: dict[str, dict], own: set[tuple[str, int]]) -> bool:
    place = (str(finding.get("path")), int(finding.get("line") or 0))
    return rules[finding["rule"]]["vendored"] and place not in own


def from_track(cases: list, findings: list[dict], cwe_of, rules: dict[str, dict]
               ) -> dict[str, Tally]:
    """Each rule's findings on one track of labelled cases."""
    tallies: dict[str, Tally] = {}
    own = _own_lines(findings, rules)
    for finding in findings:
        if finding.get("rule") not in rules or not _counted(finding):
            continue
        tally = tallies.setdefault(finding["rule"], Tally())
        case = next((c for c in cases if score._lands_on(c, finding)), None)
        if case is None or not cwe_of(finding) & set(case.cwes):
            tally.outside += 1
        elif case.vulnerable:
            tally.tp += 1
            tally.new += _new(finding, rules, own)
        else:
            tally.fp += 1
    return tallies


def from_corpus(findings_by_repo: dict[str, list[dict]],
                labels: dict[tuple[str, str], tuple[str, str]], rules: dict[str, dict]
                ) -> dict[str, Tally]:
    """Each rule's findings on the corpus, by their labels."""
    tallies: dict[str, Tally] = {}
    for repo, findings in sorted(findings_by_repo.items()):
        own = _own_lines(findings, rules)
        for finding in findings:
            if finding.get("rule") not in rules or not _counted(finding):
                continue
            tally = tallies.setdefault(finding["rule"], Tally())
            label = labels.get((repo, str(finding.get("fingerprint"))))
            if label is None:
                tally.unjudged += 1
            elif label[0] == "tp":
                tally.tp += 1
                tally.new += _new(finding, rules, own)
            else:
                tally.fp += 1
    return tallies


def measure(places: dict[str, dict[str, Tally]], rules: dict[str, dict],
            rule_cwes: dict[str, set[int]]) -> dict[str, dict]:
    """Every shipped rule's row: its counts in each place, its totals and precision."""
    rows = {}
    for rule, meta in sorted(rules.items()):
        counts = {place: asdict(places.get(place, {}).get(rule, Tally()))
                  for place in PLACES if place in places}
        tp = sum(c["tp"] for c in counts.values())
        fp = sum(c["fp"] for c in counts.values())
        new = sum(c["new"] for c in counts.values())
        rows[rule] = {**meta, "cwe": sorted(rule_cwes.get(rule, ())), "places": counts,
                      "tp": tp, "fp": fp, "new": new,
                      "precision": round(tp / (tp + fp), 3) if tp + fp else 0.0}
    return rows


def meets_bar(row: dict) -> bool:
    """D29's bar, over the three places together."""
    if row["tp"] < 1 or row["precision"] < 0.5:
        return False
    return row["new"] >= 1 if row["vendored"] else True


def state(row: dict) -> str:
    """Where the rule stands: in the inventory and why, active, or under the bar."""
    if row["inventory"]:
        return f"inventory: {row['demoted']}" if row["demoted"] else \
            "inventory: a sink to review (D47a)"
    if row["tp"] + row["fp"] == 0:
        return "active, unmeasured"
    return "active" if meets_bar(row) else "**under the bar**"
