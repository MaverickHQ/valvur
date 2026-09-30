"""Each candidate static-analysis rule, measured before any ships (R13.2, D29).

The rules in a directory run through the image's own Opengrep over track 1 (the OWASP
Benchmark for Python), track 2 (the JavaScript twins) and the corpus, each target
copied with the `.semgrepignore` a scan hands Opengrep, so tests and build trees are
read as a scan reads them. Per rule:

- a **true positive** is a match on a vulnerable case of the rule's weakness;
- a **false positive** is one on a safe case of that weakness, or anywhere in the
  corpus unless a label says a maintainer would act on it;
- a match on a case of another weakness is **outside**: that case's label says
  nothing about this rule.

A child weakness answers its parent, as the Score counts it (`cwe.PARENTS`). A true
positive is **new** when none of valvur's own rules reports its line. A rule meets
D29's bar, as R13.6 amended it, with one new true positive and precision of at least
0.5: a rule whose every true positive sits on a line valvur already reports only
makes a second finding for one flaw, under another rule id, that never merges.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import cwe  # type: ignore[import-not-found]
from score import Case  # type: ignore[import-not-found]

__all__ = ["Case", "Counts", "measure", "readable", "tally", "tally_corpus", "times"]

#: What a scan writes at the root of the Snapshot for Opengrep (`adapters/opengrep.py`).
IGNORE_NOTHING = ("# valvur: the File Set decides what a scan reads (ADR-0021); this file\n"
                  "# turns Opengrep's default ignore list off.\n")


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    outside: int = 0
    #: True positives at lines no rule of valvur's own reports.
    new: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def ships(self) -> bool:
        return self.new >= 1 and self.precision >= 0.5

    def add(self, other: Counts) -> None:
        self.tp, self.fp, self.outside, self.new = (
            self.tp + other.tp, self.fp + other.fp, self.outside + other.outside,
            self.new + other.new)


def _line(result: dict) -> int:
    return int((result.get("start") or {}).get("line", 0))


def _rule(check_id: str) -> str:
    return check_id.rsplit(".", 1)[-1]


def _path(path: str) -> str:
    return path.removeprefix("/src/")


def _answers(weaknesses: set[int]) -> set[int]:
    return weaknesses | {cwe.PARENTS[n] for n in weaknesses if n in cwe.PARENTS}


def tally(report: dict, cases: list[Case], rule_cwes: dict[str, set[int]],
          own: frozenset[tuple[str, int]] | set = frozenset()) -> dict[str, Counts]:
    """Each rule's matches over one track's cases; `own` is where valvur's own rules
    report, as (path, line)."""
    counts: dict[str, Counts] = defaultdict(Counts)
    for result in report.get("results") or []:
        rule, path = _rule(result["check_id"]), _path(result["path"])
        case = next((c for c in cases if path == c.path
                     or path.startswith(c.path.rstrip("/") + "/")), None)
        if case is None or not _answers(rule_cwes.get(rule, set())) & set(case.cwes):
            counts[rule].outside += 1
        elif case.vulnerable:
            counts[rule].tp += 1
            counts[rule].new += (path, _line(result)) not in own
        else:
            counts[rule].fp += 1
    return dict(counts)


def tally_corpus(repo: str, report: dict, labels: dict[tuple[str, str, str], str],
                 own: frozenset[tuple[str, int]] | set = frozenset()) -> dict[str, Counts]:
    """Each rule's matches over one corpus project: against it unless labelled `tp`."""
    counts: dict[str, Counts] = defaultdict(Counts)
    for result in report.get("results") or []:
        rule, path = _rule(result["check_id"]), _path(result["path"])
        if labels.get((repo, rule, path)) == "tp":
            counts[rule].tp += 1
            counts[rule].new += (path, _line(result)) not in own
        else:
            counts[rule].fp += 1
    return dict(counts)


def reported(report: dict) -> frozenset[tuple[str, int]]:
    """Where a report's matches are, as (path, line)."""
    return frozenset((_path(r["path"]), _line(r)) for r in report.get("results") or [])


def times(report: dict) -> dict[str, float]:
    """Each rule's matching time, summed over every file."""
    spent: dict[str, float] = defaultdict(float)
    for target in (report.get("time") or {}).get("targets") or []:
        for check_id, seconds in target.get("match_times") or []:
            spent[_rule(check_id)] += float(seconds)
    return {rule: round(total, 3) for rule, total in spent.items()}


def readable(target: Path, dest: Path) -> Path:
    """A copy of `target` without its `.git`, with the scan's `.semgrepignore`."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(target, dest, ignore=shutil.ignore_patterns(".git"), symlinks=True)
    (dest / ".semgrepignore").write_text(IGNORE_NOTHING, encoding="utf-8")
    return dest


def opengrep(rules: Path, target: Path, image: str) -> dict:
    """The image's Opengrep over `target` with `rules`, with no network."""
    done = subprocess.run(  # noqa: S603 — the runtime, fixed arguments
        # `-w /src`: Opengrep reads `.semgrepignore` from its working directory, and
        # from anywhere else it applies its own default list, which skips `tests/`.
        ["docker", "run", "--rm", "--network=none", "-w", "/src", "-v", f"{rules}:/rules:ro",
         "-v", f"{target}:/src:ro", "--entrypoint", "opengrep", image, "scan",
         "--config", "/rules", "--json", "--time", "--quiet", "--no-git-ignore", "/src"],
        capture_output=True, text=True, check=False, timeout=3600)
    if not done.stdout.strip():
        raise RuntimeError(f"opengrep gave no report: {done.stderr.strip()[-400:]}")
    return json.loads(done.stdout)


def measure(rules: Path, rule_cwes: dict[str, set[int]], tracks: list[tuple[str, Path,
            list[Case]]], corpus: list[tuple[str, Path]],
            labels: dict[tuple[str, str, str], str], scratch: Path, *,
            run=opengrep, image: str = "valvur:dev", own_rules: Path | None = None) -> dict:
    """Every rule in `rules`, over each track and corpus project: per rule, the counts
    on each, the totals, its time, and whether it meets D29's bar. With `own_rules`,
    valvur's own rules run over each target too, so a true positive at a line they
    already report is not new."""
    rows: dict[str, dict] = {rule: {"cwe": sorted(cwes), "tracks": {}, "seconds": 0.0}
                             for rule, cwes in rule_cwes.items()}
    totals: dict[str, Counts] = defaultdict(Counts)

    def record(where: str, counts: dict[str, Counts], report: dict) -> None:
        for rule, found in counts.items():
            rows.setdefault(rule, {"cwe": [], "tracks": {}, "seconds": 0.0})
            rows[rule]["tracks"][where] = vars(found)
            totals[rule].add(found)
        for rule, seconds in times(report).items():
            rows.setdefault(rule, {"cwe": [], "tracks": {}, "seconds": 0.0})
            rows[rule]["seconds"] = round(rows[rule]["seconds"] + seconds, 3)

    def owned(copy: Path) -> frozenset[tuple[str, int]]:
        return reported(run(own_rules, copy, image)) if own_rules is not None else frozenset()

    for name, target, cases in tracks:
        copy = readable(target, scratch / name)
        report = run(rules, copy, image)
        record(name, tally(report, cases, rule_cwes, owned(copy)), report)
    for repo, target in corpus:
        copy = readable(target, scratch / f"corpus-{repo}")
        report = run(rules, copy, image)
        record(f"corpus:{repo}", tally_corpus(repo, report, labels, owned(copy)), report)
    for rule, row in rows.items():
        total = totals[rule]
        row.update(tp=total.tp, fp=total.fp, outside=total.outside, new=total.new,
                   precision=round(total.precision, 3), ships=total.ships)
    return {"rules": dict(sorted(rows.items())),
            "ships": sorted(rule for rule, row in rows.items() if row["ships"])}
