# ADR-0025 — Fresh data without a terminal

**Status:** accepted 2026-09-27 by the owner, with the first-principles review (E7), and
approved under `CLAUDE.md` §10; written by task R0.5. Implemented by R6.6. Amends task
14.2 and F10.8.

## Context

The vulnerability database is stale after 7 days (`DB_STALE_AFTER_DAYS`), the Name Index
after 30. A stale database makes any nil result `inconclusive` (F7.16, F7.17). A scan
fetched **absent** data since 24.1, and never **stale** data, by 14.2's rule; and none of
the MCP tools could refresh anything. So an agent-only user who scanned a clean project a
week after installing got *inconclusive* and could not fix it without a terminal (the review's
N3). 14.2's reasons were a download the user did not ask for, and the two
Profiles scanning different data; the first is answered by announcing and recording the
fetch, the second by fetching the same data on both.

## Decision

1. **A scan refreshes stale data as it fetches absent data**: the vulnerability
   database, the Name Index and, if adopted (ADR-0023), OSV's offline database. Each
   fetch is announced on every progress surface and recorded in `run.json` under
   `network.fetched`. Data comes in; nothing of the Workspace leaves (N2.1, ADR-0010).
2. **`fetch = "never"`**, as a setting or `VALVUR_FETCH=never`, turns every fetch off
   for air-gapped use; a stale result is then `inconclusive` with the reason, as now.
3. **An `update` MCP tool** fetches on request and says what it fetched (F10.8).

## Rejected

- **Raise the staleness thresholds.** Hides the risk the threshold exists to state.
- **Keep refreshing manual.** The agent path has no terminal; the seven-day trap stays.
- **Refresh in the background.** A watcher, which F9.4 forbids.
