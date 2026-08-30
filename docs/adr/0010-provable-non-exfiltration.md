# Non-exfiltration is a hard constraint, not a policy

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
