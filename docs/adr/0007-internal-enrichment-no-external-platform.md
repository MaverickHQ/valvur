# Enrichment is internal, with no external prerequisites

**Requirements:** F6.8 (the `EnrichmentProvider` interface with no platform behind it), F6.2 (KEV shipped in the image), F6.3 and F6.4 (EPSS when permitted, KEV alone when not), F1.7 (no account or key).

> **Note (2026-08-31):** the Profile named here has been renamed. `quick` is now
> `offline` and is the default; `standard` and `deep` are now the single `full`
> Profile. See [ADR-0016](0016-two-profiles-split-on-the-network-boundary.md).


Exploit Signals come from a ~200-line internal module behind an `EnrichmentProvider`
interface: a CISA KEV snapshot bundled in the image, plus FIRST EPSS fetched on
demand for only the CVEs a Scan Run actually found. valvur depends on no external
platform.

## Considered Options

A sibling project, VulnGraph, is spec-complete but unbuilt: Postgres and Neo4j
ingesting five CVE sources into a system of record. An earlier proposal had valvur
consume a data artifact published by it. **Rejected because it made a tool we want now
hostage to a platform that does not exist.**

## Consequences

The scale difference makes this obvious in hindsight: valvur asks two closed questions
about the few dozen CVEs in one Workspace; VulnGraph answers open questions across
363,000. What looked like a shared component is a lookup table on one side and a
database on the other.

Offline, Enrichment degrades to KEV-only, which is the highest-signal source anyway
and preserves the `quick` Profile's offline guarantee. Enrichment age appears in
Provenance and is warned about when stale, because a confident answer from a
six-month-old snapshot is worse than no answer.

If VulnGraph is ever built it registers as an alternative Provider behind the same
interface — an enhancement, never a prerequisite. The dependency arrow points one way
only.
