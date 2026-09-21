"""One authority on what leaves the machine (N2.1, ADR-0010, task 26.2.2).

The decision is the Profile's: `offline` sends nothing, `full` may reach a fixed
list of hosts. Until this module the decision lived in `profiles.ALLOWS_NETWORK`
and was restated in six places — the runner's flag builder, Gitleaks' own
hard-coded flag, the two probes that start the image to read a file, `doctor`'s
host list, and the sentence `run.json` discloses — and 23.5.4 found the sentence
had lagged the truth by three registries for a week. Now everything reads from
here: whether a Profile has a network, the container flags that enforce it, the
hosts it may reach, and the sentence that names them. `scripts/verify-offline.py`
checks the same object, so the claim it verifies and the code it verifies against
cannot drift apart.

The moat (CLAUDE.md §3) has two halves and this module states both: the Scanners'
containers get `--network=none` unless the Profile says otherwise, and the host
shim's one reason to reach out — EPSS on `full` — is gated by the same boolean.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import profiles as _profiles

# ------------------------------------------------------------------- settings

#: Set inside a container launched WITH a network, and only then (ADR-0018). The
#: dependency-reality Check asks a registry only when it sees this, and it is set
#: in exactly the case `--network=none` is omitted — one decision, read by the
#: Check and enforced by the kernel.
NETWORK_ENV = "VALVUR_NETWORK"
#: The runtime network a NETWORKED container joins — the update, and `full`'s
#: Scanners. Unset, the runtime's default bridge. An air-gapped site whose mirror
#: registry lives on a user-defined network (or an `--internal` one, which is how
#: 22.B.3 proves the air gap structurally) names it here. Never applied to a
#: container launched without a network: `--network=none` is not negotiable.
CONTAINER_NETWORK_ENV = "VALVUR_CONTAINER_NETWORK"
#: Air-gapped operation (F10.5). Enterprises mirror Trivy's DB into an internal OCI
#: registry rather than granting egress to ghcr.io. ADR-0012 already made this
#: reachable by keeping the DB out of the image, so mirroring needs no special
#: build. Handed into every networked container so Trivy's fetch sees it.
DB_REPOSITORY_ENV = "VALVUR_DB_REPOSITORY"
#: Where Trivy fetches its database from when no mirror is named — the first of
#: its own two defaults (`trivy image --help`, 0.74: this, then ghcr.io), and what
#: a first scan sizes its "fetching" line from (24.1). Both answered 118.5MB in
#: under a second, anonymously, measured 2026-09-13.
DEFAULT_DB_REPOSITORY = "mirror.gcr.io/aquasec/trivy-db:2"
#: A mirror that speaks plain HTTP, or HTTPS with a certificate the container does
#: not trust. Measured 2026-09-12 (22.B.3): against an internal `registry:2` the
#: documented VALVUR_DB_REPOSITORY alone fails with "server gave HTTP response to
#: HTTPS client", because Trivy (go-containerregistry underneath) assumes TLS for
#: any host that is not localhost or a private-range IP literal. Trivy's own
#: `--insecure` is the switch; this is how it is reached from a shim with no flags.
DB_INSECURE_ENV = "VALVUR_DB_INSECURE"


def db_repository() -> str | None:
    return os.environ.get(DB_REPOSITORY_ENV) or None


# ------------------------------------------------------------- what full reaches

#: Every host `full` may reach, from the host process and from the container, and
#: how the disclosure sentence names each. The five registries the
#: dependency-reality Check asks for first-publish age, api.npmjs.org for npm
#: adoption (23.5.4), Maven Central and the Go proxy for existence (22.A.4), OSV
#: for the second advisory source, FIRST for EPSS. A host added here without a
#: spoken name fails a test; a spoken name absent from the sentence fails another.
SPOKEN_AS: dict[str, str] = {
    "pypi.org": "PyPI",
    "registry.npmjs.org": "the npm registry",
    "api.npmjs.org": "api.npmjs.org",
    "rubygems.org": "RubyGems",
    "repo.packagist.org": "Packagist",
    "crates.io": "crates.io",
    "repo1.maven.org": "Maven Central",
    "proxy.golang.org": "proxy.golang.org",
    "api.osv.dev": "api.osv.dev",
    "api.first.org": "FIRST",
}
FULL_HOSTS: tuple[str, ...] = tuple(SPOKEN_AS)

# Enumerated exactly, and kept exact. This sentence IS the non-exfiltration claim
# (§3), so a registry added without amending it would make the claim false —
# which is worse than never having made it. npm joined PyPI in task 19.D.1;
# RubyGems, Packagist and crates.io in 23.2.2-3, disclosed only from 23.5.4.
_WHAT_LEAVES_ON_FULL = (
    "dependency names, by the dependency-reality check: for Python, npm, Ruby, PHP "
    "and Rust only those the local index says exist (to PyPI, the npm registry, "
    "RubyGems, Packagist and crates.io, for their first-publish dates), and of those "
    "the npm names first published under 90 days ago (to api.npmjs.org, for "
    "last-month download counts); for JVM and Go every declared coordinate (to Maven "
    "Central and proxy.golang.org, for existence). Also the dependency names and "
    "versions in your lockfiles (to api.osv.dev, by osv-scanner) and the CVE "
    "identifiers found in this workspace (to FIRST, for EPSS scores). Never source "
    "code, and never a name the index already settled as absent."
)


def disclosure(*, used: bool) -> str:
    """`run.json`'s `what_left_the_machine`: the one sentence, or the one word."""
    return _WHAT_LEAVES_ON_FULL if used else "nothing"


# ------------------------------------------------------------------ the answer


@dataclass(frozen=True)
class Egress:
    """What one Profile permits, answered every way a caller needs it."""

    network: bool

    def container_flags(self) -> list[str]:
        """The runtime flags that enforce the decision. Without a network: no
        interface at all (N2.1). With one: the container is told (NETWORK_ENV),
        handed the database mirror if one is named, and joined to the named
        network if there is one."""
        if not self.network:
            return ["--network=none"]
        flags = ["--env", f"{NETWORK_ENV}=1"]
        mirror = db_repository()
        if mirror:
            flags += ["--env", f"{DB_REPOSITORY_ENV}={mirror}"]
        joined = os.environ.get(CONTAINER_NETWORK_ENV)
        if joined:
            flags.append(f"--network={joined}")
        return flags

    def hosts(self) -> tuple[str, ...]:
        """What this Profile may reach: nothing, or exactly the list above."""
        return FULL_HOSTS if self.network else ()


#: A container launched with no interface, whatever the Profile: the probes that
#: start the image to read a file, and nothing else.
NONE = Egress(network=False)


def for_profile(profile: str) -> Egress:
    """The one decision, from the Profile table, as an Egress."""
    return Egress(network=_profiles.ALLOWS_NETWORK[_profiles.resolve(profile)])
