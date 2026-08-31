# ADR-0016 — Two Profiles, split on the network boundary

**Status:** accepted · **Date:** 2026-08-31 · **Supersedes:** the `quick` /
`standard` / `deep` Profile set introduced in Phase 2.

## Context

The Profile set had three problems, all found while scanning a real project.

**`deep` was byte-identical to `standard`.** Same nine Scanners, same network
setting. A user choosing it got exactly `standard` while believing they had asked
for more. That is the same class of dishonesty this product criticises elsewhere.

**The split was drawn along speed while being described as a network boundary.**
`quick` omitted Checkov and Syft. Neither needs a network: Checkov runs with
`--skip-download` and Syft catalogues local files. Measured under `--network=none`,
both complete — Syft in 1.8s, Checkov in 13.7s. So the offline Profile was giving up
infrastructure-misconfiguration and SBOM coverage to save time, while its name and
its role in the moat were about exfiltration.

**The narrow Profile was returning false negatives.** On a real Electron app `quick`
reported 0 dependency CVEs where `standard` found 24. That turned out to be a
missing Trivy flag rather than a Profile limit (Trivy excludes dev dependencies by
default), but it exposed the real risk: an offline Profile that misses things makes
"no network required" worth nothing, because the honest answer becomes "run the
networked one anyway".

## Decision

Two Profiles, split on the only line this product is built around — whether anything
leaves the machine.

- **`offline`** (default): every Scanner that completes under `--network=none` —
  Gitleaks, Opengrep, Trivy, Checkov, Syft, licence-file, ai-artifact.
- **`full`**: adds the two that genuinely need a socket — `osv-scanner`
  (api.osv.dev) and the dependency-reality Check (public registries). Both send
  package **names**, never source.

`offline` is the default. The target market cannot send code or dependency
manifests anywhere, and the dependency-reality Check does transmit package names, so
reaching the network is something a developer opts into rather than something they
acquire by typing `valvur scan`.

The retired names still resolve — `quick` → `offline`, `standard` → `full`,
`deep` → `full` — so an agent configuration written against `0.1.0rc1` keeps
working. They are not advertised in `--help` or the MCP schema.

## Consequences

- The offline Profile costs ~21s rather than ~7s on a mid-size repository, almost
  entirely Checkov. It now covers everything the networked Profile does except a
  second advisory source and the slopsquat Check.
- The moat claim gets sharper: the default Profile is the provable one, and
  `--network=none` covers the default path rather than an opt-in fast path.
- N2.1 now constrains `offline`. The requirement ID is unchanged; only the Profile
  it names has been renamed.
- Resolution happens once at `scan()`'s entry. Every downstream lookup is a
  `dict.get` with a default, so an unresolved `"standard"` would have landed on
  `ALLOWS_NETWORK`'s `False` and silently disabled the network — a test covers this.

## Alternatives rejected

**Keep three Profiles, move only Syft into `quick`.** Cheapest change, and `quick`
would have stayed fast. Rejected because it leaves `deep` as a duplicate and leaves
the naming describing speed while the product's axis is network.

**Drop the offline Profile entirely and ship one networked scan.** Proposed on the
grounds that an offline Profile returning false negatives is worse than none. This
was a fair reading of the evidence at the time, but the evidence was a bug: with the
Trivy flag corrected, the offline Profile finds every dependency CVE the networked
one finds. Dropping it would have traded away the moat (§3) to work around a
one-line defect.

**Make `full` the default.** Rejected: it would send package names to public
registries for anyone who types `valvur scan`, which contradicts §3 and the
procurement conversation the product is built for.
