# ADR-0022 — One Scan Container per Profile boundary, fed a Snapshot

**Status:** accepted 2026-09-27 by the owner, with the first-principles review (E1, E2,
E6), written by task R0.5. Implemented by R3.1 to R3.9. Amends ADR-0001's
implementation and keeps its principle; makes ADR-0017 moot for the Workspace.
Protocol 2 (`docs/PROTOCOL.md`).

## Context

Every Scanner ran in its own container, started by a host thread pool, each walking a
bind mount of the live working tree. Stopping a scan meant reconciling futures still
queued, `docker run` clients still blocked and containers the daemon owns. The code
grew a cancel flag, a per-runner registry, a process-wide registry, a budget path that
cancels futures, a cancel path that did not, a timeout path that kills by name and
polls, and a server-exit sweep (16.2, 23.3.3, 26.0.2, 27.1.1, 29.0.2). The second gate
found the gap between two of them: Scanners launched after `scan_cancel`, and
`CANCELLED` was reported with a container still up (C1; F1.11).

On Docker Desktop the mount was the cost: listing 109,521 files took 1.6 s on the host
and 16.6 s through the bind mount, once per Scanner. A 4 GB VM holds two 2 GiB
containers, so the fleet ran two at a time and queued the rest (29.1.3). Measured on
this Mac on the same 312 files: valvur's fleet 20.3 s; the same six invocations in
parallel inside one container 7.4 s and 8.3 s.

## Decision

1. **One Scan Container per Profile boundary.** `offline` runs one container with no
   network interface (F1.2, N2.1). `full` adds one more, with a network, for only the
   Scanners that need it: OSV-Scanner and the dependency-reality Check's registry
   questions. `egress.py` stays the only authority on who gets a network (ADR-0010).
2. **An in-image engine**, `python -m valvur.engine`, runs the Scanners as child
   processes in parallel, each in its own process group with its own timeout (F2.6,
   F2.7). It streams progress as JSON lines and leaves each report and a manifest of
   outcomes for the host. valvur's Python already ships in the image for the Checks
   (ADR-0013).
3. **The source arrives as a Snapshot**: the File Set (ADR-0021), streamed as a tar on
   stdin into a tmpfs of up to 512 MB, or into a per-scan volume beyond that, removed
   afterwards. The source tree is never mounted: a copy cannot modify the original,
   which is stronger than a read-only mount (F1.1, moat item 2). The engine reports the
   count it received, and a mismatch with the manifest refuses the scan.
4. **One deadline and one kill.** The engine stops what runs at the budget and writes a
   partial manifest naming each cut; the host kills the container if the engine does not
   return within a grace period. `scan_cancel` sends one kill and reports `CANCELLED`
   only once the runtime confirms the container is gone (F1.11).
5. **Nothing outlives its owner.** Containers carry `valvur.generation` and `valvur.pid`
   labels; orphans of dead owners are removed at every scan start and by `doctor`. The
   MCP server exits on stdin EOF and on parent death (F1.12).
6. **One memory ceiling per container**: 3 GiB, or 75% of the runtime's memory if that is
   less.
7. **Protocol 2.** The shim refuses a major-1 image with the fix named (F1.9).

## Consequences

- The SELinux relabel question (ADR-0017, F1.6) no longer arises for the Workspace: only
  valvur's own cache mounts need a label.
- Podman's shared-path problem on macOS and the unreadable-workspace probe container go
  away with the mount.
- The per-Scanner width, the name registries, the exclude dialects and the probe are
  deleted (R3.9).

## Rejected

- **Keep one container per Scanner and fix C1.** C1 was the gap between two stop paths;
  the next gap would be another pair.
- **Native binaries on the host.** Loses the kernel-enforced offline proof and the
  structural read-only guarantee on macOS.
- **One container reading a bind mount.** Keeps the 16.6 s walk per Scanner on Docker
  Desktop.
- **Always a volume.** Leaves the project's secrets on the VM's disk if a scan dies
  before cleanup; a tmpfs does not.
