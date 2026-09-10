# ADR-0017 — SELinux relabelling of the source tree is opt-in

**Status:** accepted · **Date:** 2026-09-10 · **Closes:** F1.6, open and unimplemented
since Phase 8.

## Context

F1.6 says valvur applies the appropriate mount label where the host requires one. It
was never implemented, and on 2026-09-05 a note recorded that the defect could not be
reproduced through Podman's Fedora VM on macOS, guessing that virtiofs was hiding it.

**It reproduces immediately on a native filesystem inside that same VM.** Measured
2026-09-10 on Fedora CoreOS 44 — `targeted` policy enforcing, `container-selinux`
2.250, workspace on xfs on a block device — with both rootful and rootless Podman:

| Mount | Plain | With `:z` |
|---|---|---|
| Workspace under `$HOME` (`user_home_t` / `admin_home_t`), `:ro` | **denied** | reads |
| valvur's scratch directory, `:rw` | **denied** | writes |
| The Trivy database cache, `:rw` | **denied** | writes |

So valvur was unusable on RHEL — the **primary target market** (§5: regulated
industries, where Podman on RHEL is the default). *Could not reproduce* was not *does
not happen*.

One thing saved it from being worse than unusable. The readability probe runs
`ls -A /workspace | wc -l`, which returns `0` under denial while the host has entries,
so `WorkspaceUnreadable` is raised. **valvur never reports a false clean on an
enforcing host** — verified verbatim there. That is what makes this a usability defect
rather than a safety one, and what made an opt-in defensible at all.

## Decision

**valvur relabels its own directories unconditionally on an enforcing host, and never
relabels the scanned tree unless explicitly asked.**

- The scratch mount and the Trivy cache get `:z` whenever
  `/sys/fs/selinux/enforce` reads `1`. They are a temporary directory we created and a
  cache we own. Nothing about them belongs to the developer, and without the label the
  container cannot write its results at all.
- The Workspace gets `,z` only when `VALVUR_SELINUX_RELABEL=1` is set. Otherwise the
  scan refuses, and the message names SELinux, the environment variable, the manual
  `chcon`, and the undo.

`permissive` counts as not-enforcing: it logs the denial and allows the access, so
relabelling would be a write to someone's tree in exchange for nothing.

**An environment variable, not a CLI flag.** MCP is the primary interface (ADR-0015)
and has no command line; a flag would have fixed this for the second-choice path only.

## Rejected alternatives

**`:Z` — impossible here, not merely undesirable.** It stamps a private MCS category on
the tree. Measured: after a `:Z` mount, a second container is denied. valvur launches
its Scanners *concurrently against one mount*, so `:Z` would break the fleet from the
second Scanner onward. This is the one option that reading the documentation would not
have eliminated.

**Always `:z` on an enforcing host.** The strongest rejected option, and the one that
would make valvur work out of the box on its primary target platform. Rejected because
`:z` rewrites the SELinux context of every file in the scanned tree and the change
outlives the scan. §10 prohibits any feature that writes to the scanned source tree
without explicit owner approval, and moat item 2 is that the scanner *cannot modify the
code it scans*. A tool whose first promise is that it will not touch your code should
not quietly rewrite its labels — least of all in the defence and government
environments this is aimed at, where an unexplained relabel is itself an incident.

**The accepted cost is real and should not be minimised: a first run on RHEL fails.**
That is a bad first impression on the market that matters most, traded for a promise
that stays literally true. If that trade proves wrong in front of real users, this ADR
is the thing to revisit — not the promise.

**Cutting or narrowing F1.6.** The branch for *the defect does not reproduce on a
native host*. It reproduces, so this was never the applicable option.

**Excluding SELinux hosts from the supported set.** Would mean abandoning the primary
target market to avoid one environment variable.

## Consequences

- valvur works on SELinux-enforcing hosts, after one deliberate action by the developer.
- The remediation text carries a measurement most documentation gets wrong:
  **`restorecon -R` does not undo `:z`.** `container_file_t` is listed in the policy's
  `customizable_types`, and restorecon skips those unless forced. The first draft of
  this message shipped `restorecon -R` and was corrected to `restorecon -R -F` only
  because it was run on the host. A remediation instruction that silently does nothing
  is worse than none — the reader believes they have undone it.
- **F1.1 survives the relabel**, measured: a `,z` mount is still read-only, and a write
  to `/workspace` is refused. Relabelling grants the container the right to *read*, not
  to write.
- On any host without SELinux the emitted command line is byte-identical to before.
