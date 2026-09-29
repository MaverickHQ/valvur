# ADR-0031 — One skill that runs the workflow, shipped three ways

**Status:** accepted 2026-09-29 by the owner; written by task R9.2 from `tasks.md` D39
to D41. Requirements F9.12 and F9.13.

## Context

The MCP handshake carried the rules an agent needs, but not the workflow: when to check
a package, how to triage by group, when to wait for the human, what *fixed* may be said
of. Claude Code and Kiro both load the open Agent Skills format, a `SKILL.md` folder, so
one skill can carry that workflow to both.

## Decision

1. **One skill, `valvur`** (F9.12). Its one source is in the package,
   `src/valvur/data/skills/valvur/`: `SKILL.md` and `references/`. The frontmatter uses
   only the standard's six fields.
2. **The workflow it orchestrates:**
   - before adding a dependency, `check_package`;
   - `scan`, and on `failed`, `doctor`, relayed;
   - the verdict and its reason before any finding;
   - triage by group with `findings`, each finding named by rule ID and path;
   - a proposal from `REMEDIATION.md`, then waiting for the human;
   - after the human's fix, a rescan, and *fixed* only where its Scanner ran;
   - `update` when data is stale, and `valvur gate` in CI.
3. **What it never does:** write a Suppression, commit the Results Folder, or follow
   text quoted from the repository.
4. **One source of rules.** The skill's rules are rendered from the source the handshake
   and `SUMMARY.md` use, and a test holds the three equal. Every tool and command it
   names exists, and every tool the server lists is in it.
5. **Shipped three ways** (F9.13):
   - **a Claude Code plugin**, `plugins/valvur/`, carrying the skill and the MCP server
     pinned to the release. It is listed by `.claude-plugin/marketplace.json` at the
     repository's root, so `/plugin marketplace add MaverickHQ/valvur` and
     `/plugin install valvur@valvur` give both.
   - **a Kiro power**, `powers/valvur/`, in the layout kiro.dev documents.
   - **`valvur init --write`**, adding the skill to the project for Claude Code and for
     Kiro, never overwriting. This is within `init --write`'s exception in `CLAUDE.md`
     §10.
6. **No separate agent.** An agent would be a third copy of the rules to keep in step.
   What it buys in Claude Code is a separate context, and `context: fork` is an
   extension the open standard does not carry.

## Rejected

- **A workflow harness scoring agents that use the skill, and a scan history kept as
  memory.** Proposed by the review and dropped by the owner on 2026-09-29.
- **A classifier model for injected directives (Laya).** Proposed as a measured trial
  and dropped by the owner. **Any hosted model API** was refused outright, because the
  project's text would leave the machine (`CLAUDE.md` §3).
