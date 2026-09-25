# Non-exfiltration is a hard constraint, not a policy

**Requirements:** N2.1 (no network connection on the offline Profile, verified by a test that fails if one is made), F6.10 (what a lookup transmitted, recorded, with an opt-out), P5 (a documented command a reviewer can run to verify it).

> **Note (2026-08-31):** the Profile named here has been renamed. `quick` is now
> `offline` and is the default; `standard` and `deep` are now the single `full`
> Profile. See [ADR-0016](0016-two-profiles-split-on-the-network-boundary.md).


valvur must never transmit Workspace contents anywhere, and a reviewer must be able
to verify that unaided. The `quick` Profile runs with no network interface at all;
the Workspace is always mounted read-only; there is no account, API key or telemetry.

## Consequences

This is the product. Every serious competitor processes code or its metadata on their
own servers — a compliance wall for finance, defence, healthcare and government, and
an outright bar in jurisdictions whose residency rules the vendor's regions do not
satisfy. Competitors cannot copy this posture without breaking their own business
model, which is what makes it defensible when the feature list is not.

It must be testable, not merely asserted. A regression test runs a full `quick`
Profile with networking disabled and fails if anything attempts a socket. The
documented verification command in the README is the same property a user can run
themselves.

Any proposal that improves results by sending data somewhere is this constraint being
traded away, however useful it seems, and must be refused or escalated to the owner
explicitly. ADR-0008 exists to stop it happening indirectly through a dependency.

Scan Runs on AWS use the identical image with no AWS-specific code path, so the
guarantee does not weaken when the execution location changes.

## Amendment (2026-09-25, task 28.0.4): a first run's fetches are disclosed

The claim this ADR makes is about what leaves the machine, and a first run on
`offline` reaches out three times before any Scanner runs — the image from GHCR,
the database from `mirror.gcr.io`, the index from GHCR (24.1, 23.2.4). Nothing of
the workspace goes with those requests, so `what_left_the_machine: nothing` was
true; but `run.json` also said `network.used: false` and listed no fetch, so the
record of a first run could not be told from a steady-state one, and a reviewer
holding `run.json` to `unshare -rn` would have found a disagreement the file did
not explain. `network.fetched` now lists each fetch — what, source, size, seconds,
and the index's signature verdict — and is an empty list on every run that fetched
nothing. The proof `scripts/verify-offline.py` runs is unchanged: it was never a
first run's proof, and the file now says which kind of run it is.
