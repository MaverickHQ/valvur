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
    QUICK: ("gitleaks", "opengrep", "trivy", "licence-file"),
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
