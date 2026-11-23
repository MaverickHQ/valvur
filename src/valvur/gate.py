"""`valvur gate` — one exit code from a scan's results (task 23.3.5).

The CLI exits zero when Findings exist (N3.2): a scan that found things did its
job. A release gate wants the opposite question answered — *may this ship?* — and
until now every answer was a Python heredoc reading `run.json`, one copy in
`ci.yml` and one in `release.yml`, drifting. This is that heredoc, once, with the
three conditions it always had and the threshold it never had:

1. **The run completed.** A Scanner that crashed makes "no findings" meaningless,
   and that is how a clean result gets faked. Fails at every threshold.
2. **No active Finding at or above `--fail-on`.** Active is 19.C.1's word: not a
   suppressed one, which is a decision the project already recorded, and not a
   coverage note, which is valvur's missing feature rather than the user's problem.
3. **No lapsed suppression.** An expired one re-reports the Finding; if nothing
   fails the build then "mandatory expiry" is decoration. Fails at every threshold.

And one the heredocs never asked: `--no-inconclusive`, for a team that wants a
scan whose data was too old to be evidence, or that never inspected part of the
tree, to fail rather than pass by omission.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import verdict
from .findings import SEVERITIES
from .results import RESULTS_DIR, findings_of

#: `--fail-on` accepts a severity, or `any` — every active Finding, N2.5's own bar.
THRESHOLDS = (*SEVERITIES[:4], "any")
DEFAULT_THRESHOLD = "high"

#: Findings that are the suppression file's hygiene, not the code's: they fail the
#: gate at every threshold, because they are the gate's own rules lapsing.
SUPPRESSION_RULES = frozenset({"valvur.suppression.expired", "valvur.suppression.stale"})


@dataclass(frozen=True)
class Verdict:
    failures: list[str] = field(default_factory=list)
    summary: str = ""
    #: 0 passed, 1 failed, 2 nothing to gate (no results).
    exit_code: int = 0

    @property
    def passed(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class Base:
    """The tree a gate compares with (`--new-since`, R50.3): the ref as given, the commit
    it named, and the directory that holds that commit's Results Folder."""

    ref: str
    commit: str
    results: Path


#: Two instants are of one copy of a dataset when they are this close, in seconds: each
#: is an age subtracted from a clock, a moment apart.
_SAME_COPY = 5


def differences(run: dict, base: dict) -> list[str]:
    """Why two Scan Runs cannot be compared: each of image, Profile and data that is not
    the same in both. A Finding one has and the other lacks would then say nothing about
    the code."""
    found = []
    if run.get("profile") != base.get("profile"):
        found.append(f"Profile: {run.get('profile')} here, {base.get('profile')} for the base")
    if (run.get("build") or {}).get("image") != (base.get("build") or {}).get("image"):
        found.append("image: the two were scanned with different builds of valvur's image")
    ours, theirs = run.get("data_built") or {}, base.get("data_built") or {}
    moved = sorted(name for name in ours.keys() | theirs.keys()
                   if name not in ours or name not in theirs
                   or abs(ours[name] - theirs[name]) > _SAME_COPY)
    if moved:
        found.append(f"data: {', '.join(moved)} is not the same copy in both")
    return found


def evaluate(workspace: Path, *, fail_on: str = DEFAULT_THRESHOLD,
             no_inconclusive: bool = False, base: Base | None = None) -> Verdict:
    """The verdict on the last Scan Run of `workspace`. With `base`, only a Finding whose
    Fingerprint the base's Scan Run does not hold, in any state, can fail it (D82l)."""
    if fail_on not in THRESHOLDS:
        raise ValueError(f"--fail-on must be one of {', '.join(THRESHOLDS)}; got {fail_on!r}")
    results = Path(workspace).resolve() / RESULTS_DIR
    try:
        run = json.loads((results / "run.json").read_text(encoding="utf-8"))
        document = json.loads((results / "findings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return Verdict([f"no scan results in {results}; run `valvur scan` first"],
                       "gate: nothing to gate", 2)
    findings = findings_of(document)
    if findings is None or not isinstance(run, dict):
        return Verdict([f"{results / 'findings.json'} is not a valvur result; run "
                        "`valvur scan` again"], "gate: nothing to gate", 2)

    failures: list[str] = []

    if not run.get("complete"):
        broken = [s for s in run.get("scanners", []) if not s.get("ok")]
        named = "; ".join(f"{s['tool']} did not complete ({s.get('reason', '').strip()})"
                          for s in broken) or "a Scanner did not complete"
        failures.append(f"incomplete: {named}, so this result proves nothing")

    if no_inconclusive and run.get("status") == "inconclusive":
        failures.append(f"inconclusive: {run.get('status_reason') or 'reason not recorded'}")

    already: set[str] = set()
    if base is not None:
        said, already = _against(run, base)
        failures += said

    active = [f for f in findings if verdict.active(f)]
    at_or_above = [f for f in active if _at_or_above(f.get("severity", "unknown"), fail_on)
                   and f.get("rule") not in SUPPRESSION_RULES]
    over = [f for f in at_or_above if f.get("fingerprint") not in already]
    lapsed = [f for f in active if f.get("rule") in SUPPRESSION_RULES]
    failures += [_line(f) for f in over]
    failures += [_line(f) + " (a lapsed suppression fails at every threshold)" for f in lapsed]

    suppressed = sum(1 for f in findings if f.get("suppressed"))
    excluded = (run.get("excluded_by_config") or {}).get("findings_dropped", 0)
    hidden = (run.get("excluded_by_gitignore") or {}).get("findings_dropped", 0)
    generation = run.get("generation")
    judged = f"; generation {generation}" if generation else ""
    counted = (f"gate: {len(over)} finding(s) at or above {fail_on}; " if base is None else
               f"gate: {len(over)} new finding(s) at or above {fail_on} since {base.ref} "
               f"({base.commit[:7]}); {len(at_or_above) - len(over)} were already there "
               "and were not gated on; ")
    summary = (counted
               + f"{len(active) - len(at_or_above) - len(lapsed)} below the threshold; "
               f"{suppressed} suppressed; {excluded} excluded by .security-scan.toml"
               + (f"; {hidden} excluded by .gitignore" if hidden else "")
               + f"{judged}")
    return Verdict(failures, summary, 1 if failures else 0)


def _against(run: dict, base: Base) -> tuple[list[str], set[str]]:
    """What stops the comparison with the base, and the Fingerprints the base holds. A
    base that cannot be trusted holds none, so every Finding is gated on."""
    folder = base.results / RESULTS_DIR
    try:
        theirs = json.loads((folder / "run.json").read_text(encoding="utf-8"))
        held = findings_of(json.loads((folder / "findings.json").read_text(encoding="utf-8")))
    except (OSError, ValueError):
        theirs, held = None, None
    if not isinstance(theirs, dict) or held is None:
        return [f"the Scan Run of the base {base.ref} ({base.commit[:7]}) left no result "
                "to compare with"], set()
    if not theirs.get("complete"):
        return [f"the Scan Run of the base {base.ref} ({base.commit[:7]}) is incomplete, so "
                "what it lacks proves nothing about what is new"], set()
    differing = differences(run, theirs)
    if differing:
        return [f"the base {base.ref} ({base.commit[:7]}) cannot be compared with this "
                f"result ({'; '.join(differing)}): scan the working tree again"], set()
    return [], {str(f.get("fingerprint")) for f in held}


def _at_or_above(severity: str, threshold: str) -> bool:
    if threshold == "any":
        return True
    rank = SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)
    return rank <= SEVERITIES.index(threshold)


def _line(finding: dict) -> str:
    return (f"{finding.get('severity', 'unknown')}: {finding.get('rule')} in "
            f"{finding.get('path')} — {finding.get('title')}")


def render(verdict: Verdict, *, annotations: bool = False) -> str:
    """One line per failure — as `::error::` annotations under GitHub Actions, so
    each appears on the run's summary — then the counts, then the verdict."""
    prefix = "::error::" if annotations else ""
    lines = [f"{prefix}{failure}" for failure in verdict.failures]
    lines.append(verdict.summary)
    if verdict.exit_code == 0:
        lines.append("gate: passed")
    elif verdict.exit_code == 1:
        lines.append(f"gate: FAILED — {len(verdict.failures)} reason(s) above")
    return "\n".join(lines)
