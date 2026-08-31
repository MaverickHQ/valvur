# Usability gate

The protocol for tasks **1.12** (Phase 1) and **10.8** (Phase 10).

## Why this exists

Phase 1 was ordered as a walking skeleton specifically so the install and first-run
experience could be tested on day two rather than month two. This is that test. It is
the only task in the plan that cannot be run by the person who built the thing —
the author always knows the answers, and unconsciously fills the gaps a newcomer
falls into.

**Run it once per gate, with a different person each time.** First-run impressions do
not reset; you cannot re-use a participant.

## Who to ask

A developer who has **never seen valvur** and has not discussed it with you. They do
not need security expertise — arguably better if they lack it, since a stated goal is
that `SUMMARY.md` is comprehensible to someone who has never used a scanner.

## The rules

0. **Have them take the MCP path first.** Since ADR-0015 that is the primary
   interface: paste the config into Kiro or Claude Code, restart, ask the agent to
   scan. The CLI is the second way in and should be tried second, if at all. Watching
   someone use the path we have deprioritised would answer the wrong question.
1. Give them **only the repository URL**. No verbal setup, no "you'll want to…".
2. **Say nothing while they work.** Not a hint, not a nudge. The silence is the
   experiment. If they get stuck for more than two minutes, that is a finding — write
   down where, and only then help.
3. Ask them to **narrate what they are thinking**, especially when something surprises
   them or does not match what they expected.
4. **Time it.** Start when they open the README, stop when they have read a real
   finding from a real scan of a real repository.
5. Have them scan **a project of their own**, not our fixture. Our fixture is designed
   to produce findings; their repo is the honest case.

## What to record

Write these down as they happen — reconstructed notes lose the detail that matters.

| Record | Why it matters |
|---|---|
| Time to first useful result | Target is under five minutes (P1) |
| Every command they had to guess at | Documentation gap |
| Every error message they hit | Feeds task 10.5 — each must name the exact next command |
| Anything they expected that did not happen | A model mismatch, the most valuable kind of finding |
| Anything they read twice | Ambiguous wording |
| Where they stopped to ask a question | Where the docs stop working |
| Whether they understood the findings **without help** | Feeds task 10.4.12 |
| Whether the agent surfaced anything when the server failed | Agents commonly swallow stderr, so a dead server can look like an idle one |
| Whether they knew the results were gitignored | F7.2 is a promise; do they perceive it? |

## Two questions at the end

- "What did you think this tool did, before you ran it? And after?"
- "If this were your project, what would you have wanted the README to say first?"

## What happens to the notes

They become the task list for **Phase 10 — First-run experience**. Do not fix anything
during the session, and do not fix anything immediately after: the value is the whole
list, prioritised together. A confusion you patch in isolation usually hides a
structural problem the full list would have revealed.

## Recording the result

Append findings here under a dated heading, then tick the corresponding task in
`.kiro/specs/valvur/tasks.md`.

---

## Gate 1 — Phase 1 (task 1.12)

- **Date:**
- **Participant:**
- **Time to first useful result:**
- **Findings:**

## Gate 2 — Phase 10 (task 10.8)

- **Date:**
- **Participant:**
- **Time to first useful result:**
- **Findings:**
