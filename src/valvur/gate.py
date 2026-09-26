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

from .coverage import NOTE_RULES
from .findings import SEVERITIES
from .results import RESULTS_DIR

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


def evaluate(workspace: Path, *, fail_on: str = DEFAULT_THRESHOLD,
             no_inconclusive: bool = False) -> Verdict:
    if fail_on not in THRESHOLDS:
        raise ValueError(f"--fail-on must be one of {', '.join(THRESHOLDS)}; got {fail_on!r}")
    results = Path(workspace).resolve() / RESULTS_DIR
    try:
        run = json.loads((results / "run.json").read_text(encoding="utf-8"))
        findings = json.loads((results / "findings.json").read_text(encoding="utf-8"))["findings"]
    except (OSError, ValueError, KeyError):
        return Verdict([f"no scan results in {results}; run `valvur scan` first"],
                       "gate: nothing to gate", 2)

    failures: list[str] = []

    if not run.get("complete"):
        broken = [s for s in run.get("scanners", []) if not s.get("ok")]
        named = "; ".join(f"{s['tool']} did not complete ({s.get('reason', '').strip()})"
                          for s in broken) or "a Scanner did not complete"
        failures.append(f"incomplete: {named}, so this result proves nothing")

    if no_inconclusive and run.get("status") == "inconclusive":
        failures.append(f"inconclusive: {run.get('status_reason') or 'reason not recorded'}")

    active = [f for f in findings if not f.get("suppressed") and f.get("rule") not in NOTE_RULES]
    over = [f for f in active if _at_or_above(f.get("severity", "unknown"), fail_on)
            and f.get("rule") not in SUPPRESSION_RULES]
    lapsed = [f for f in active if f.get("rule") in SUPPRESSION_RULES]
    failures += [_line(f) for f in over]
    failures += [_line(f) + " (a lapsed suppression fails at every threshold)" for f in lapsed]

    suppressed = sum(1 for f in findings if f.get("suppressed"))
    excluded = (run.get("excluded_by_config") or {}).get("findings_dropped", 0)
    hidden = (run.get("excluded_by_gitignore") or {}).get("findings_dropped", 0)
    generation = run.get("generation")
    judged = f"; generation {generation}" if generation else ""
    summary = (f"gate: {len(over)} finding(s) at or above {fail_on}; "
               f"{len(active) - len(over) - len(lapsed)} below the threshold; "
               f"{suppressed} suppressed; {excluded} excluded by .security-scan.toml"
               + (f"; {hidden} excluded by .gitignore" if hidden else "")
               + f"{judged}")
    return Verdict(failures, summary, 1 if failures else 0)


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
