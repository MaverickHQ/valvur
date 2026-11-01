# ADR-0030 — Reuse a dependency Scanner's result when nothing it reads has changed

**Status:** accepted 2026-09-29 by the owner, with the review of that day; written by
task R9.2 from `tasks.md` D32. Requirement N1.5. Amended 2026-11-01: the key names the
image.

## Context

Every scan ran every Scanner. OSV-Scanner loads npm's whole offline database, about
10 s, even when no lockfile changed since the last scan. That load is most of an npm
repository's warm scan.

## Decision

1. **Kept:** Trivy's and OSV-Scanner's raw output, in the host cache.
2. **The key:**
   - the Scanner and its version;
   - the Profile;
   - the sha256 of every lockfile and manifest it reads;
   - the built time of the database it reads.
3. **Reused** when the key matches, and only for these two, whose inputs are exactly
   those files and that data. A Scanner that reads the source tree is never reused.
4. **Provenance:** `run.json` names each reused result and the run it came from.
5. **Opt-out:** `--fresh` on the CLI and `fresh: true` on the `scan` tool run everything.
6. **Where it lives:** the host cache, under its lock, pruned by `update --prune` and
   cleared by `--clear`. Nothing is written in the Workspace but the Results Folder.

## Fallback

If a warm rescan of acceptance repository 8 is not at least 30% faster, reuse ships off
by default, and the measurement is recorded.

## Rejected

- **Reusing source Scanners by file hash.** Their findings depend on the whole tree, and
  a stale finding reported as current is a false claim.
- **Incremental scanning of changed files only.** It breaks the one-generation Results
  Folder and the meaning of *fixed* (F5.6).

## Amendment, 2026-11-01: the key names the image

D81w builds Trivy, OSV-Scanner and Syft from their release's source, with the modules the
image gate names raised. Since then one Scanner version is two binaries, and in a user's
host cache an OSV-Scanner 2.7.0 result made by 1.6.0's image, which carried upstream's
binary, would have been reused by 1.6.1's, which builds its own. Their reports were
measured byte-identical, so no answer was wrong; a raise that changed one would have been.

The key's first item is now **the Scanner, its version and the image that ran it**: the
digest of the image's inputs, `image_built_from` in `run.json`. Those inputs include the
Dockerfile, which names each Scanner's version, checksum and raises. The cost is one
fresh run of the two Scanners after each upgrade of valvur, since the digest also covers
valvur's own code. An image that predates the digest keys as unknown, as before.
