# ADR-0021 — The File Set is the git view

**Status:** accepted 2026-09-27 by the owner, with the first-principles review
(`docs/REVIEW-2026-09-27.md`, E2, E3 and 11.5), written by task R0.5. Implemented by
R3.2 and R3.7. Supersedes the `honour_gitignore` opt-in (29.0.1) and the built-in
`VENDORED` skip list.

## Context

A Scan Run read the working tree as mounted, minus a built-in list of dependency and
build directory names at any depth, minus `[scan] exclude`, which each Scanner received
in its own flag dialect. Three failures came from that shape, each measured:

- The first gate's tree held 312 tracked files and 107,544 on disk. It failed at the
  300 s budget, and reached a first finding after thirty minutes and a read of the
  source (F1.1, F7.7).
- One exclude meant two things. `exclude = ["archive"]` hid the top-level `archive/`
  from Gitleaks, Trivy and Syft, and **every** directory named `archive` from Opengrep,
  Checkov and OSV-Scanner; a flow planted in `src/archive/` went unreported (the review's N1).
- The built-in list skipped first-party code. `mypkg/build/steps.py` was read by no
  Scanner and the report said *2 active* without naming the directory (the review's N2).

Git already knows what the project is: `git ls-files -co --exclude-standard` listed the
312 files in 0.03 s. And the README claimed secrets *including git history*, which no
scan ever read: Gitleaks ran in `dir` mode and the image has no `git` (ADR-0005 keeps it
out; C10).

## Decision

1. **The File Set is the git view**: tracked files, and untracked files git does not
   ignore. An agent's uncommitted files are the code this tool exists to check.
2. **Always included, even when ignored:** `.env*` files and every agent-configuration
   file the AI Artifact Check reads. A secret in an ignored `.env` stays reported at
   medium, as `gitcontext` already ranks it; an ignored `.mcp.json` is still what the
   developer's agent obeys (F3.6).
3. **An exclude is a root-relative path prefix**, applied once, to the File Set.
   `archive` removes `archive/` and nothing else.
4. **A directory that is not a repository is walked**, skipping only VCS metadata and
   dependency caches, each skip named in the report. Past 20,000 files that walk refuses
   before any container starts, naming the largest directories and the exclude line. A
   git view over 20,000 files proceeds with the same names as a warning: tracked source
   is the user's code, not a data directory.
5. **The report states the scope**: the count, the bytes and the sha256 of the list, in
   `run.json` and `SUMMARY.md` (F7.7, F7.12).
6. **History is scanned for secrets** in a repository: the host writes `git log -p --all`
   with commit markers into the Snapshot (ADR-0022), bounded at 5,000 commits or 200 MB,
   whichever comes first, and says when the bound was hit. `[scan] history = false`
   turns it off. Measured: this repository's 357 commits make 10.9 MB in 1.2 s.
7. **`scope = "tree"`** walks the working tree instead, for a user who wants it.

`CLAUDE.md` §7 says exclusion is never a built-in default, because a project's tests
must never be silently skipped. The git view excludes nothing the project tracks, tests
included; it leaves out what the project itself told git is not source.

## Rejected

- **Keep the working tree and fix the exclude dialects.** The per-tool flags were
  written on 2026-08-31, called by nothing until 2026-09-26, and still disagreed after
  that. Six translations of one intent will drift again.
- **Tracked files only.** An agent's new, uncommitted files would go unscanned.
- **Honour `.gitignore` with no always-included files.** Ignored agent configuration
  and `.env` files are exactly where the owner's manual audit found issues.
- **`git` in the image for history.** GPL-2.0; ADR-0005.
