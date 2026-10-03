<!-- generated: mcp-tools -->

# valvur's MCP tools

Rendered from the server's own list of tools; a test holds this file to it.
Each tool takes only the fields listed: any other is refused, not ignored.

## `scan`

Run a security scan of a project and return the result, with progress on the way; calling it while a scan runs here attaches to that scan. Writes results into .security-scan/ and never modifies your source.

It changes this machine as its description says, and never the source.

- `workspace` (string): Absolute path to the project to scan. Defaults to the current directory.
- `profile` (string, one of `offline`, `full`): offline (the default) runs every Scanner with no network access. full asks the network what local data cannot answer: OSV.dev in place of the offline database, the registries for each package's age and adoption and whether JVM and Go dependencies exist. They receive package names and versions, never source.
- `budget_s` (integer): Seconds the Scanners may take together (default 300). Past it, nothing new starts, what is running is stopped, and the result is reported incomplete with the cut Scanners named. 0 for none.
- `fresh` (boolean): Run every Scanner. By default Trivy's and OSV-Scanner's last result is reused when no dependency file and none of their data has changed since; a fresh result replaces it.

## `findings`

The last scan's findings, worst first and bounded: filter by `group`, `rule`, `path` or `status`, or give a `fingerprint` for that finding in full, with its evidence, exploitation, dependency path and the Scanners that reported it.

It changes nothing.

- `workspace` (string): Absolute path to the project to scan. Defaults to the current directory.
- `fingerprint` (string): One finding, in full.
- `group` (string): A group's id, from `groups` in a scan's reply or `findings.json`.
- `rule` (string)
- `path` (string): A path prefix, on whole segments.
- `status` (string, one of `new`, `persisting`, `regressed`)
- `limit` (integer): Default 20, max 100; a larger one is clamped, and said so.
- `include_suppressed` (boolean)
- `inventory` (boolean): Also list the sinks named for review (code execution, queries built from a value), which are not findings by themselves.

## `scan_status`

What the last scan actually did: which scanners ran, which failed, and whether the result is complete.

It changes nothing.

- `workspace` (string): Absolute path to the project to scan. Defaults to the current directory.

## `scan_cancel`

Stop a running scan: its containers are killed, nothing is written, and the previous results (if any) stand. What Ctrl-C does on the command line.

It changes this machine as its description says, and never the source.

- `workspace` (string): Absolute path to the project to scan. Defaults to the current directory.

## `update`

Fetch what a scan reads, now: the image if absent, the vulnerability database, the CISA KEV catalog and the package-name index, into this machine's cache; progress on the way, and the answer is what was fetched. Public data comes in; nothing of any workspace leaves.

It changes this machine as its description says, and never the source.

- `if_stale` (boolean): Only what is out of date.

## `doctor`

Check that this machine can scan, before scanning: the container runtime, the image, the vulnerability database, the package-name index, SELinux, TLS trust, and which MCP client configuration names valvur. One line per check with the fix on any that would fail a scan. Changes nothing but the containers of scans whose process ended, which it removes.

It changes this machine as its description says, and never the source.

- `workspace` (string): Absolute path to the project to scan. Defaults to the current directory.
- `network` (boolean): Also probe, with one bounded TCP connect per host, whether the registries a first run and the full profile need are reachable from here. Off by default: without it doctor opens no socket.

## `check_package`

Before adding a dependency: whether each package exists on its registry, is one edit from a far more popular one, was published as malicious, or is exposed to dependency confusion by this project's registry configuration. Answered from this machine's cache; no registry is asked, because asking about a hallucinated name tells whoever watches what to register. Never add a flagged package, or a replacement for it, without asking the human.

It changes nothing.

- `workspace` (string): Absolute path to the project to scan. Defaults to the current directory.
- `packages` (array, required): Up to 50, each {ecosystem, name, version?}.
  - `ecosystem` (string, required): npm, pip, cargo, gem or composer; go and maven answer unknown
  - `name` (string, required)
  - `version` (string): The version to be installed, when known: some are malicious only at one version.

<!-- /generated -->
