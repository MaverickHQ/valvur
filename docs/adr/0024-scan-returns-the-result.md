# ADR-0024 — `scan` returns the result

**Status:** accepted 2026-09-27 by the owner, with the first-principles review (E5),
written by task R0.5. **Confirmed by R6.1's measurement on 2026-09-28**; implemented by
R6.2 and R6.3.

## Context

`scan` started a job and returned at once, and the agent polled `scan_status`, because
*many MCP clients time out at 30-60 [seconds]* (`mcp/jobs.py`). For the two clients this
product targets that is not the case. Claude Code gives a stdio tool call a 30-minute
idle window that progress notifications keep open, a wall-clock default of about 28
hours, and moves a call still running after two minutes to a background task
(code.claude.com/docs/en/mcp). Kiro enforces a startup timeout and, per its issue
tracker, no per-call timeout. Polling cost the second gate's agent pass 16 turns and
$1.08: one `scan`, six `scan_status`, five shell calls it wrote to wait (F9.1). The
status reply grew field by field, and its fields came to disagree with its text (C4, C7;
F9.10). Claude Code hands the model only `structuredContent` when a reply has both forms
(29.2.4).

## Decision

1. **`scan` blocks and returns the result** within its budget, 300 s by default, sending
   progress notifications. Past the budget it returns a partial result naming each cut.
2. **A second `scan` on a workspace whose scan is running attaches** and returns the same
   generation, so a client with a short timeout still works. `scan_status` remains as an
   alias that attaches.
3. **Reply schema 2 is structured first** (F9.8 to F9.10): state, verdict, reason,
   complete, scope, counts, groups, what did not run, `next`, `error.kind`, and a
   `report` field holding the Markdown summary, so the text reaches the model too. It
   stays under Claude Code's 25,000-token limit. The text form is rendered from the
   fields.

**Fallback:** if R6.1 finds that Claude Code loses a backgrounded call's result, keep
start-and-poll, with the schema-2 reply.

## Rejected

- **Keep start-and-poll.** Its premise does not hold for the primary clients, and it
  costs turns and money on every scan.
- **MCP Tasks.** Accepted into the specification, not yet implemented by Claude Code.

## Measured (R6.1, 2026-09-28)

`scripts/spikes/r6_1_background.py`: a stdio MCP server with one tool that runs for a
given time, sends a progress notification every ten seconds, and returns a number the
model could not guess. Claude Code 2.1.283, headless (`claude -p`, `--strict-mcp-config`),
asked for the number:

| call | wall | the number reached the model | turns | cost |
|---|---|---|---|---|
| 5 s | 28.9 s | yes | 3 | $0.69 |
| 150 s | 186.9 s | yes | 3 | $0.26 |

The 150-second call came back as its own tool result, the text the server sent, in the
same three turns as the five-second one: nothing was lost and nothing had to poll. The
interactive client's move to the background at two minutes is documented behaviour
that an unattended run cannot drive. For a client that does move the call, or times it
out, decision 2 is the answer: the second `scan` attaches and returns the same
generation. **The fallback does not apply.**
