"""Rank Findings by whether attackers are actually exploiting them (F6.5).

Every scanner in this space sorts by severity, and that is why developers mute them.
Severity is an assertion about how bad a vulnerability *would* be; KEV and EPSS are
observations about whether anyone is *using* it. When the two disagree, the
observation wins.
"""

from __future__ import annotations

from dataclasses import replace

from . import grouping as _grouping
from .findings import SEVERITIES, Finding

# A floor for classes that are real but rarely urgent, so they cannot crowd out
# things being exploited today. An unknown dependency licence matters at release
# time; it does not matter more than a hallucinated package.
CLASS_WEIGHT = {
    "valvur.dependency.malicious": 0,        # it runs at install (D26)
    "valvur.dependency.nonexistent": 0,      # someone can register that name today
    "valvur.ai-artifact.prompt-injection": 0,
    # R5.6: Cisco mcp-scanner's classes, beside the one they extend.
    "valvur.ai-artifact.coercive-directive": 0,
    "valvur.ai-artifact.exfiltration-directive": 0,
    "valvur.ai-artifact.credential-harvesting": 0,
    "valvur.ai-artifact.hidden-unicode": 0,
    "valvur.dependency.near-miss": 1,
    "valvur.ai-artifact.permission-bypass": 1,
    "valvur.ai-artifact.hook-runs-command": 1,
    "valvur.ai-artifact.blanket-auto-approve": 2,
    "valvur.ai-artifact.mcp-mutable-ref": 2,
    "valvur.licence.missing": 3,
    "valvur.licence.mismatch": 3,
    "valvur.licence.dependency-unknown": 5,  # the noisiest class we ship
    "valvur.licence.copyleft-in-permissive": 4,
}
DEFAULT_WEIGHT = 2


def _exploit_tier(finding: Finding) -> int | None:
    """Urgency from what the world reports — or None when the world says nothing.

    None, not a default. Returning a default here let `min()` prefer it over any
    class floor above it, so the floor on noisy classes was silently discarded: a
    licence-unknown finding weighted 5 still ranked at 2.
    """
    exploit = finding.exploit
    if not exploit:
        return None
    if exploit.ransomware:
        return 0
    if exploit.kev:
        return 1
    if exploit.epss is not None:
        if exploit.epss >= 0.10:
            return 2
        if exploit.epss >= 0.01:
            return 3
        return 4
    return None


#: What a `[[context]]` entry may say of a path, and how it reads (R50.6, ADR-0036).
#: valvur cannot know either of these, and does not pretend to: the project says so.
DECLARABLE = {("exposure", "internet"): "is internet-facing",
              ("data", "sensitive"): "holds sensitive data"}


def declarations(project: dict[str, object] | None) -> list[tuple[str, str]]:
    """Each declared path, with a trailing slash, and what the project says of it. An
    entry that says anything else is passed over here; `doctor` names it."""
    found = []
    entries = (project or {}).get("context")
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            continue
        said = [words for (key, value), words in DECLARABLE.items() if entry.get(key) == value]
        path = entry["path"].strip("/")
        if said and path:
            found.append((path + "/", said[0]))
    return found


def declared(finding: Finding, known: list[tuple[str, str]]) -> str:
    """The declaration a Finding's path is under, by whole segments, or ""."""
    for path, said in known:
        if (finding.path + "/").startswith(path):
            return f"`{path}` {said}"
    return ""


def sort_key(finding: Finding,
             flooded: frozenset[str] = frozenset()) -> tuple[object, ...]:
    exploit = finding.exploit
    epss = exploit.epss if exploit and exploit.epss is not None else 0.0

    severity_index = (
        SEVERITIES.index(finding.severity)
        if finding.severity in SEVERITIES
        else len(SEVERITIES)
    )

    # Development-only dependencies are demoted a full tier: the vulnerability is
    # real, but it never ships (F6.6).
    dev_penalty = 1 if (finding.dependency and finding.dependency.scope == "development") else 0

    # The better of the two urgencies wins. A Finding with no CVE is not therefore
    # unimportant — a hallucinated dependency has no EPSS score and is one of the
    # most urgent things we report, because anyone can register that name today.
    # Scoring exploit signals ahead of everything sank them below any CVE with a
    # non-zero EPSS, which real output made obvious.
    class_tier = CLASS_WEIGHT.get(finding.rule, DEFAULT_WEIGHT)
    exploit_tier = _exploit_tier(finding)
    # With no exploit evidence the class floor governs alone. Where there is evidence,
    # the better of the two wins — a hallucinated package has no EPSS and is still
    # among the most urgent things we report.
    tier = class_tier if exploit_tier is None else min(exploit_tier, class_tier)

    # A suppressed Finding occupying a top slot crowds out a live one — the exact
    # noise problem F6.5 exists to solve. It is still reported, just never first.
    suppressed_penalty = 1 if finding.suppressed else 0
    # A flood of machine-written data ranks below every distinct Finding (R5.1):
    # 3,890 hits in generated JSON buried eight real ones on the gate.
    flood_penalty = 1 if finding.group in flooded else 0

    return (
        suppressed_penalty,
        flood_penalty,
        dev_penalty,
        tier,
        # Within a tier and never across one (R50.6): what the project declared
        # internet-facing or sensitive comes first.
        0 if finding.declaration else 1,
        -epss,
        severity_index,
        finding.path,
        finding.rule,
    )


def apply(findings: list[Finding],
          project: dict[str, object] | None = None) -> list[Finding]:
    """Sort worst-first and stamp each Finding with its position. With the project
    file, a Finding under a path it declares says so and ranks first in its tier."""
    known = declarations(project)
    if known:
        findings = [replace(f, declaration=declared(f, known)) for f in findings]
    flooded = frozenset(g.id for g in _grouping.describe(findings) if g.machine_written)
    ordered = sorted(findings, key=lambda f: sort_key(f, flooded))
    return [replace(f, rank=i + 1) for i, f in enumerate(ordered)]
