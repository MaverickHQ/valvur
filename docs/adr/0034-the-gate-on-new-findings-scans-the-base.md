# ADR-0034 — The gate on new Findings scans the base ref itself

**Status:** accepted 2026-11-22 by the owner, at checkpoint B, as proposed on
2026-11-21; from D82k and D82l in
[the signal-and-adoption design](../../.kiro/specs/signal-and-adoption/design.md).
Requirements F5.3 and N2.5. Amends ADR-0021.

## Context

`valvur gate` fails on every active Finding at or above a threshold. A project with a
backlog cannot switch it on without first clearing the backlog, so it does not switch it on.

Most tools solve this with a committed baseline file. ADR-0011 keeps scan output out of git
on every branch, and a file an agent can edit is a way to make a Finding old. valvur's own
`new` Status compares with the last Scan Run on the same machine, which in CI is nothing.

ADR-0021 makes the File Set the git view of the working tree. valvur scans no other tree.

## Decision

1. **`valvur gate --new-since <ref>` fails only on active Findings that the named ref does
   not have.** The ref is a commit of the same repository.
2. **The gate scans the ref itself,** with the image, the Profile and the data the working
   tree's Scan Run recorded, into the cache and never into the Workspace. A base result is
   reused only when the commit, the image, the Profile and every dataset are the same.
3. **A commit's tree is read with git's plumbing** (`ls-tree`, `cat-file --batch`), which
   writes nothing to the repository. Its File Set is the tree, less that commit's own
   excludes. `valvur scan --ref <ref> --out <dir>` exposes the same scan.
4. **A Finding is already there by its Fingerprint alone,** in any state in the base.
5. **The gate never falls back to gating on nothing.** A ref that cannot be read, a base
   scan that is incomplete, or two Scan Runs that differ in image, Profile or data fail it,
   with the reason.
6. **Everything else about the gate stands,** and a gate without the option behaves as today.

## Consequences

- A team can adopt the gate on the day it adopts valvur, and the output says each run how
  many Findings were not gated on.
- A pull request costs a second scan, less what ADR-0030 reuses and the base result's own
  reuse while the base branch has not moved.
- A renamed file, or a static-analysis match whose text changed, has a new Fingerprint and
  counts as new. That errs toward failing.
- CI needs the base commit present, so a shallow checkout fails the gate with a line that
  says how to fetch it.

## Rejected

- **A committed baseline file.** ADR-0011, and it can be edited.
- **`state.json`'s Status as the base.** It holds nothing on a fresh runner.
- **`git worktree add` or `git archive`.** The first writes under `.git`; the second drops
  what `export-ignore` names, without saying so.
- **A baseline kept by a service.** `CLAUDE.md` §3: no account, and results never leave the
  machine.
