"""Profiles — what runs, and whether the network is allowed at all.

Two profiles, split on the only line that matters to this product: whether anything
leaves the machine. `offline` runs every Scanner that works under `--network=none`,
which is all of them bar one. `full` adds osv-scanner, and lets the
dependency-reality Check ask a registry for the one thing its local index cannot
answer — a package's age (ADR-0018).

The earlier `quick`/`standard`/`deep` split was drawn along speed while being
described as a network boundary, and `deep` was byte-identical to `standard`. See
ADR-0016. Old names still resolve so existing agent configuration keeps working.
"""

from __future__ import annotations

OFFLINE = "offline"
FULL = "full"

# Scanner names per Profile. Names not yet implemented are simply absent from the
# adapter registry and are skipped — the matrix is declared up front so that adding
# a Scanner is a one-line change here rather than a hunt through the orchestrator.
SCANNERS: dict[str, tuple[str, ...]] = {
    # Everything here runs under --network=none. Verified, not assumed: checkov with
    # --skip-download and syft cataloguing local files both complete with no socket.
    OFFLINE: (
        "gitleaks", "opengrep", "trivy", "checkov", "syft",
        "licence-file", "ai-artifact",
        # Existence is answered from the package-name index in the host cache
        # (ADR-0018), so the hallucination check runs with no socket at all.
        "dependency-reality",
    ),
    FULL: (
        "gitleaks", "opengrep", "trivy", "checkov", "syft",
        "licence-file", "ai-artifact", "dependency-reality",
        # The only Scanner that genuinely needs a socket: osv-scanner queries
        # api.osv.dev with the names and versions in your lockfiles, never source.
        "osv-scanner",
    ),
}

ALLOWS_NETWORK: dict[str, bool] = {OFFLINE: False, FULL: True}

#: Scanners that run on BOTH Profiles and do less without a network — the network
#: half of what they cover, in the reader's terms. dependency-reality checks existence
#: and near-misses from local data and asks a registry only for first-publish age.
NEEDS_NETWORK_FOR: dict[str, str] = {
    "dependency-reality": (
        "package age (newly-registered names), or whether JVM and Go dependencies exist"
    ),
}

DEFAULT = OFFLINE
"""Offline by default. The target market cannot send code or dependency manifests
anywhere, and the dependency-reality Check does transmit package names — so reaching
the network is something a developer opts into, never something they get by typing
`valvur scan`."""

# The 0.1.0rc1 names. Kept resolving so an agent config written against the rc does
# not break; `deep` was identical to `standard`, so both land on `full`.
ALIASES: dict[str, str] = {"quick": OFFLINE, "standard": FULL, "deep": FULL}


def resolve(profile: str) -> str:
    """Canonical Profile name, accepting the retired ones."""
    name = (profile or "").strip().lower()
    return ALIASES.get(name, name)


def scanners_for(profile: str) -> tuple[str, ...]:
    name = resolve(profile)
    if name not in SCANNERS:
        raise ValueError(f"Unknown profile {profile!r}. Choose one of: {', '.join(SCANNERS)}")
    return SCANNERS[name]


def select(adapters, profile: str):
    """Filter a registry down to the Scanners this Profile runs, each told what the
    Profile permits. This is the only place a network is granted to an adapter."""
    wanted = scanners_for(profile)
    network = ALLOWS_NETWORK[resolve(profile)]
    return [a.for_profile(network=network) for a in adapters if a.name in wanted]


def not_run(profile: str) -> tuple[str, ...]:
    """Scanners the fuller Profile would have run.

    A bare "clean" from a narrower Profile is a claim we have not earned, so the
    Summary says what was not run. Measured on a real project: the offline Profile
    reported 0 findings while the networked one found 24 CVEs in the same lockfile —
    that turned out to be a missing Trivy flag rather than a Profile limit, but the
    lesson stands: state the gap rather than let the reader assume there is none.
    """
    name = resolve(profile)
    if name not in SCANNERS:
        # An unrecorded profile is not evidence of a gap. Writing the artifacts must
        # never fail over provenance we simply do not have.
        return ()
    ran = set(SCANNERS[name])
    return tuple(s for s in SCANNERS[FULL] if s not in ran)


# What each Scanner is the only source of, in the reader's terms rather than ours.
# Naming the tool alone misleads: the offline Profile does not run osv-scanner, but
# Trivy covers dependency CVEs, so "osv-scanner not run" reads as "dependencies
# unchecked" — the opposite of true.
_ADDS: dict[str, str] = {
    "checkov": "infrastructure misconfiguration",
    "syft": "the SBOM and dependency licences",
    "osv-scanner": "a second dependency-advisory source",
}


def gaps_in_prose(profile: str) -> str:
    """The coverage a Profile lacks, described by what is missing rather than by
    which binary did not run — including what a Scanner that DID run could not do
    without a network."""
    missing = [_ADDS[s] for s in not_run(profile) if s in _ADDS]
    name = resolve(profile)
    if name in SCANNERS and not ALLOWS_NETWORK[name]:
        missing += [NEEDS_NETWORK_FOR[s] for s in SCANNERS[name] if s in NEEDS_NETWORK_FOR]
    if not missing:
        return "nothing else"
    if len(missing) == 1:
        return missing[0]
    return ", ".join(missing[:-1]) + f" or {missing[-1]}"
