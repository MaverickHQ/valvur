# ADR-0036 — Ranking reads what the project declares, and one dependency Finding lists its lockfiles

**Status:** proposed 2026-11-21, for the owner's checkpoint B; from D82n in
[the signal-and-adoption design](../../.kiro/specs/signal-and-adoption/design.md).
Requirements F6.5, F7.14 and F5.3.

## Context

valvur ranks by Finding Class, then by exploitation evidence. It knows nothing of which part
of a project faces the internet or holds sensitive data, and it does not analyse
reachability (`CLAUDE.md` §2). The project's developers know, and have nowhere to say it.

Separately, an advisory found through three lockfiles is one Finding by its Fingerprint, and
`findings.merge` keeps the first path and drops the other two.

## Decision

1. **`.security-scan.toml` takes `[[context]]` entries:** a `path`, and `exposure =
   "internet"` or `data = "sensitive"`.
2. **A Finding under a declared path ranks before one that is not, within the same tier.**
   It never crosses a tier: evidence of exploitation still outranks a declaration.
3. **Every raised Finding says which declaration raised it,** and every output calls it a
   declaration. No output calls it analysis, exposure analysis or reachability.
4. **A project with no declaration ranks exactly as today.**
5. **A dependency Finding carries `paths`,** every lockfile it was found through, sorted.
   `path` stays the first. The Fingerprint does not change: it never held the path.

## Consequences

- The top of `REMEDIATION.md` can follow the project's own view of its risk.
- A declaration is unchecked. One that names every path changes nothing, and one that is
  wrong misorders within a tier and removes no Finding and changes no verdict.
- A fix can be checked against every lockfile that needs it.

## Rejected

- **Inferring exposure from the code** (routes, listeners, Dockerfile ports). That is a claim
  of analysis valvur cannot support.
- **A declaration that changes severity or the verdict.** It would be a way to lower a
  Finding without a Suppression's reason and expiry.
- **One Finding per lockfile.** It changes identity, and so `fp_version`, which invalidates
  every Suppression everywhere (`CLAUDE.md` §8).
