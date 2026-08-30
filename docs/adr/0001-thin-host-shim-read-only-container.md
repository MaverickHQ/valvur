# Thin host shim with a read-only container engine

The MCP server is a small host-side shim installed via `uvx`/`pipx`; every Scanner
lives in one OCI image. The shim mounts the Workspace read-only, mounts a scratch
directory read-write, invokes the image, and then writes the Results Folder itself
as the developer's own user.

## Considered Options

**Fat container** — MCP server inside the image, Workspace mounted read-write.
One artifact, but container-written files land with broken ownership on every
runtime differently: root-owned under rootful Docker, subuid-mapped under rootless
Podman, and unreadable without `:z` labelling under SELinux. That is a
compatibility matrix for the least interesting part of the product.

**Host install** — everything on the host via pip and `curl | sh`. No container
runtime needed, but it reproduces the dependency management problem that makes the
upstream AWS sample painful to install, and the workspace jail has to be built out
of validation code.

## Consequences

The mount *is* the workspace jail. A scan of `~/.ssh` is not a bug we must
remember to block; it is a path that does not exist inside the container. The
upstream AWS sample attempted this jail in code and left a hole — its
`_save_scan_output()` resolves a path, checks only that it exists, and writes there.

Because the Workspace is read-only, valvur **cannot** modify the code it scans even
if a future bug tried to. This is what makes ADR-0009 a structural guarantee rather
than a policy.

The cost is two artifacts to version together. The shim must refuse an image whose
major version it does not recognise.
