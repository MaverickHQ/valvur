"""Profiles — how much scanning, and whether the network is allowed.

`quick` is the offline guarantee (N2.1) and the pre-commit-speed path. `standard` is
the default. `deep` is opt-in and slow. The Scanner sets follow design.md section 2.
"""

from __future__ import annotations

QUICK = "quick"
STANDARD = "standard"
DEEP = "deep"

# Scanner names per Profile. Names not yet implemented are simply absent from the
# adapter registry and are skipped — the matrix is declared up front so that adding
# a Scanner is a one-line change here rather than a hunt through the orchestrator.
SCANNERS: dict[str, tuple[str, ...]] = {
    # ai-artifact belongs in quick: it is pure static file inspection, needs no
    # network, and is the check nothing else ships. Omitting it from the fast path
    # would mean the differentiator only runs when someone opts into a slower scan.
    QUICK: ("gitleaks", "opengrep", "trivy", "licence-file", "ai-artifact"),
    STANDARD: (
        "gitleaks", "opengrep", "trivy", "osv-scanner", "checkov", "syft",
        "licence-file", "ai-artifact", "dependency-reality",
    ),
    DEEP: (
        "gitleaks", "opengrep", "trivy", "osv-scanner", "checkov", "syft",
        "licence-file", "ai-artifact", "dependency-reality",
    ),
}

# Only `quick` is required to be fully offline.
ALLOWS_NETWORK: dict[str, bool] = {QUICK: False, STANDARD: True, DEEP: True}


def scanners_for(profile: str) -> tuple[str, ...]:
    if profile not in SCANNERS:
        raise ValueError(f"Unknown profile {profile!r}. Choose one of: {', '.join(SCANNERS)}")
    return SCANNERS[profile]


def select(adapters, profile: str):
    """Filter a registry down to the Scanners this Profile runs."""
    wanted = scanners_for(profile)
    return [a for a in adapters if a.name in wanted]


def not_run(profile: str) -> tuple[str, ...]:
    """Scanners a fuller profile would have run. Coverage narrows on the offline
    profile, and a bare "clean" from it is a claim we have not earned: measured on a
    real TypeScript project, quick reported 0 findings while standard found 24 CVEs
    in the same lockfile in the same minute. Quick must stay offline (N2.1), so the
    honest fix is to say what it did not look at, not to widen it."""
    if profile not in SCANNERS:
        # An unrecorded profile is not evidence of a gap. Writing the artifacts must
        # never fail over provenance we simply do not have.
        return ()
    ran = set(SCANNERS[profile])
    return tuple(s for s in SCANNERS[DEEP] if s not in ran)


# What each Scanner is the only source of, in the reader's terms rather than ours.
# Naming the tool alone misleads: quick does not run osv-scanner, but Trivy covers
# dependency CVEs, so "osv-scanner not run" reads as "dependencies unchecked".
_ADDS: dict[str, str] = {
    "checkov": "infrastructure misconfiguration",
    "syft": "the SBOM and dependency licences",
    "dependency-reality": "hallucinated and typosquatted packages",
    "osv-scanner": "a second dependency-advisory source",
}


def gaps_in_prose(profile: str) -> str:
    """The coverage a profile lacks, described by what is missing rather than by
    which binary did not run."""
    missing = [_ADDS[s] for s in not_run(profile) if s in _ADDS]
    if not missing:
        return "nothing else"
    if len(missing) == 1:
        return missing[0]
    return ", ".join(missing[:-1]) + f" or {missing[-1]}"
