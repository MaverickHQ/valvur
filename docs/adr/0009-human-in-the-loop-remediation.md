# The developer chooses which fixes to apply and when to rescan

**Requirements:** F9.2 (no MCP tool modifies the Workspace's source), F9.4 (no watchers, no save hooks, no automatic rescan), F9.5 and F9.6 (a vanished Finding is not a fix; a Suppression needs a human).

valvur proposes; it never remediates. There is no `scan_and_fix` tool, no file
watcher, no on-save hook, and no autonomous scan-fix-rescan loop. Rescanning is
always an explicit call.

## Consequences

This is a safety property, not a UX preference. An agent instructed to drive Findings
to zero has a cheaper path via deleting code or writing Suppressions than via correct
fixes. "The Finding disappeared" and "the vulnerability is fixed" are different
claims, and only a human can tell them apart — swapping a hash function satisfies the
Scanner and breaks every stored credential.

`REMEDIATION.md` is therefore written as a proposal, with each Remediation Item
independently applicable, because developers cherry-pick. Partial application is the
expected path, not an edge case: a Scan Run reports which proposed items were
addressed, which were skipped, and what is new.

ADR-0001's read-only mount makes this structural rather than merely intended. The
upstream AWS sample ships the opposite — a hook firing on every file save that
instructs an agent to remediate. Both of its hook files are deliberately dropped.
