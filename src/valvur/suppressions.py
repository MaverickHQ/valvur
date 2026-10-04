"""Suppressions — recorded, shared and reviewed risk acceptances.

Read from `.security-scan.toml` at the **Workspace** root, which is **committed**
(unlike the Results Folder), because an accepted risk is a team decision rather than
a local one.

**valvur never writes this file** (F8.7). It can print one (F8.8), because printing
is not writing and nobody will hand-copy a 32-character hash.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

# F8.1: read from the Workspace root; the project file, named once.
from .exclusions import PROJECT_FILE as SUPPRESSION_FILE
from .findings import Finding, Severity
from .fingerprint import derive

# Context is mandatory, not decorative. A pull request containing only a hash tells a
# reviewer nothing about what is being accepted, which throws away the whole reason
# for per-class identity (F8.2, ADR-0003).
REQUIRED = ("fingerprint", "rule", "path", "expires", "reason")


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    rule: str
    path: str
    expires: date
    reason: str

    def is_expired(self, today: date | None = None) -> bool:
        """Expiry is inclusive and UTC: a suppression expiring today is valid today.

        Pinned so two machines cannot disagree about whether a build passes.
        """
        return (today or datetime.now(UTC).date()) > self.expires

    def describe(self) -> str:
        return f"{self.rule} at {self.path} (expires {self.expires.isoformat()})"


@dataclass(frozen=True)
class Problem:
    """A malformed suppression. Reported as a Finding rather than ignored (F8.3)."""

    detail: str
    entry: dict


@dataclass(frozen=True)
class Policy:
    suppressions: list[Suppression]
    problems: list[Problem]

    def by_fingerprint(self) -> dict[str, Suppression]:
        return {s.fingerprint: s for s in self.suppressions}


def load(workspace: Path, project: tuple[dict, str | None] | None = None) -> Policy:
    """The suppressions in the project file; from `project`, the file as a scan
    context already parsed it (D52d), when given."""
    if project is None:
        path = workspace / SUPPRESSION_FILE
        if not path.is_file():
            return Policy([], [])
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:  # not TOML, or not UTF-8 (R27.4)
            return Policy([], [Problem(f"{SUPPRESSION_FILE} could not be read: {exc}", {})])
    else:
        raw, problem = project
        if problem is not None:
            return Policy([], [Problem(problem, {})])

    suppressions: list[Suppression] = []
    problems: list[Problem] = []

    entries = raw.get("suppress") or []
    if not isinstance(entries, list):
        return Policy([], [Problem("suppress must be an array of tables, [[suppress]]", {})])
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem(f"a suppression must be a table (got {entry!r})", {}))
            continue
        missing = [field for field in REQUIRED if not entry.get(field)]
        if missing:
            problems.append(Problem(
                f"suppression is missing {', '.join(missing)}", entry
            ))
            continue
        expires = entry["expires"]
        if isinstance(expires, datetime):
            expires = expires.date()
        if not isinstance(expires, date):
            problems.append(Problem(
                f"expires must be a date (got {expires!r})", entry
            ))
            continue
        suppressions.append(Suppression(
            fingerprint=str(entry["fingerprint"]),
            rule=str(entry["rule"]),
            path=str(entry["path"]),
            expires=expires,
            reason=str(entry["reason"]),
        ))

    return Policy(suppressions, problems)


def apply(findings, policy: Policy, *, today: date | None = None):
    """Mark matching Findings suppressed. Never remove them (F8.6).

    Reporting them in a distinct section keeps the decision visible; omitting them
    would let an accepted risk quietly become an invisible one.
    """
    from dataclasses import replace

    active = policy.by_fingerprint()
    out = []
    for finding in findings:
        suppression = active.get(finding.fingerprint)
        if suppression and not suppression.is_expired(today):
            out.append(replace(finding, suppressed=suppression.describe()))
        else:
            out.append(finding)
    return out


def unmatched(findings, policy: Policy) -> list[Suppression]:
    """Suppressions matching nothing — stale, and worth saying so (F8.5)."""
    present = {f.fingerprint for f in findings}
    return [s for s in policy.suppressions if s.fingerprint not in present]


def expired(policy: Policy, today: date | None = None) -> list[Suppression]:
    """Suppressions whose expiry has passed. A lapsed risk acceptance is a decision
    someone must retake — which is the entire purpose of mandatory expiry (F8.4)."""
    return [s for s in policy.suppressions if s.is_expired(today)]


def policy_findings(policy: Policy, findings, *, today: date | None = None):
    """Report the suppression file's own problems as Findings.

    An unexpiring or stale suppression is exactly how a real finding gets buried for
    years. Reporting it in the same place as everything else is what stops that.
    """
    out = []

    for problem in policy.problems:
        shown = problem.entry.get("fingerprint", "<none>")
        out.append(Finding(
            rule="valvur.suppression.invalid",
            path=SUPPRESSION_FILE,
            line=0,
            title=f"Suppression rejected — {problem.detail}",
            evidence=f"fingerprint: {shown}",
            fingerprint=derive("suppression", "invalid", str(shown), problem.detail),
            severity=Severity.MEDIUM,
            sources=("valvur",),
        ))

    for lapsed in expired(policy, today):
        out.append(Finding(
            rule="valvur.suppression.expired",
            path=SUPPRESSION_FILE,
            line=0,
            title=(
                f"Suppression for {lapsed.rule} expired on "
                f"{lapsed.expires.isoformat()} — the finding is reported again"
            ),
            evidence=f"reason given: {lapsed.reason}",
            fingerprint=derive("suppression", "expired", lapsed.fingerprint),
            severity=Severity.MEDIUM,
            sources=("valvur",),
        ))

    for stale in unmatched(findings, policy):
        if stale.is_expired(today):
            continue                      # already reported as expired
        out.append(Finding(
            rule="valvur.suppression.stale",
            path=SUPPRESSION_FILE,
            line=0,
            title=f"Suppression matches nothing — {stale.describe()}",
            evidence=(
                "The finding it accepted is gone. Remove the suppression, or it will "
                "silently accept a future finding that happens to match."
            ),
            fingerprint=derive("suppression", "stale", stale.fingerprint),
            severity=Severity.LOW,
            sources=("valvur",),
        ))

    return out
