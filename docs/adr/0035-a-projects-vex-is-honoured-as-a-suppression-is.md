# ADR-0035 — A project's own VEX statements are honoured as a Suppression is

**Status:** proposed 2026-11-21, for the owner's checkpoint B; from D82m in
[the signal-and-adoption design](../../.kiro/specs/signal-and-adoption/design.md).
Requirements F8.1, F8.3 and F8.7.

## Context

A maintainer who has assessed an advisory records that in VEX, the format their consumers'
tools read. valvur makes them record it again as a Suppression. OpenVEX is the open format,
and it has no expiry field. A Suppression must have one (F8.3), and valvur never writes one
(F8.7): an agent told to clear Findings must not have a cheaper way than fixing them
(`CLAUDE.md` §4).

## Decision

1. **A VEX document is read only when `.security-scan.toml` names it,** in a `[[vex]]` entry
   with a `path` and an `expires` date. valvur does not search the tree for VEX.
2. **The entry is the acceptance, and it expires.** Past its date the document's statements
   are no longer honoured, and it is reported as an expired Suppression is, which fails the
   gate at every threshold.
3. **What is honoured:** a statement of `not_affected` or `fixed`, for the Finding's
   vulnerability and its package at its version, with the justification or impact statement
   OpenVEX requires. Only dependency vulnerability Findings.
4. **How it shows:** under *Suppressed*, with the statement's justification, the document's
   author and its timestamp. Never hidden.
5. **A statement that matches nothing is reported at `low`,** and does not fail the gate at
   every threshold as a stale Suppression does. A VEX document is written for a product's
   consumers and names versions the tree no longer holds. This narrows the approved
   requirement, which says *as an unused Suppression is*.
6. **valvur writes no VEX statement about a Workspace,** and prints none. The skill's rule on
   Suppressions names `[[vex]]`.

## Consequences

- One assessment, recorded once, in the format a consumer reads.
- The human step is the same as a Suppression's: an edit to `.security-scan.toml`, reviewed.
- A VEX document changed after its entry was written is honoured as changed, until the
  entry expires. A reviewer of the document's diff is the control, as for any Suppression.

## Rejected

- **Reading any `*.openvex.json` in the tree.** No decision is recorded and nothing expires.
- **An expiry counted from the statement's timestamp.** It sets a policy the project did not
  choose, and a document re-dated by a tool would never lapse.
- **Generating VEX from Suppressions.** It would be valvur asserting `not_affected`, which
  it has not analysed.
