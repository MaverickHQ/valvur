"""SELinux on the host: whether it is enforcing, whether the developer asked for
the source tree to be relabelled, and what to tell them when a mount is denied
(F1.6, ADR-0017, task 20.2). Split out of `runner.py` by 26.2.1: a host concern
the runner reads, not a container one it owns.
"""

from __future__ import annotations

import os as _os
from pathlib import Path

#: Opt-in, and an environment variable rather than a CLI flag: MCP is the primary
#: interface (ADR-0015) and has no command line, so a flag would fix this for the
#: second-choice path only.
RELABEL_ENV = "VALVUR_SELINUX_RELABEL"
#: Named so a test can point it somewhere real. Patching `Path.read_text` wholesale
#: could not tell "enforcing" from "SELinux is absent" — both end up False — so the
#: test proved only one of the two directions it claimed to.
SELINUX_ENFORCE = Path("/sys/fs/selinux/enforce")


def selinux_enforcing() -> bool:
    """Whether the HOST kernel is enforcing SELinux.

    The host, not the container, because the mount sources are host paths and it is
    the host's labels that decide whether the container may read them.

    `permissive` returns False deliberately: it logs the denial and allows the access,
    so relabelling would be a write to someone's tree in exchange for nothing.
    """
    try:
        return SELINUX_ENFORCE.read_text().strip() == "1"
    except OSError:
        return False          # not Linux, or SELinux absent


def _relabel_workspace() -> bool:
    """Whether the developer has asked us to relabel their source tree.

    **Off by default, and that is a deliberate cost.** `:z` rewrites the SELinux
    context of every file in the Workspace to `container_file_t`, which persists after
    the scan. CLAUDE.md section 10 prohibits any feature that writes to the scanned
    source tree without explicit owner approval, and a security tool whose first
    promise is that it cannot touch your code should not quietly rewrite its labels.

    valvur's OWN directories — the scratch mount and the database cache — are
    relabelled unconditionally on an enforcing host. They are a temporary directory we
    created and a cache we own; nothing about them is the developer's, and without the
    label the container cannot write its results at all.
    """
    return _os.environ.get(RELABEL_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _selinux_hint(workspace) -> str:
    """What to do about it, in the reader's terms.

    Every claim here was measured on Fedora CoreOS 44, xfs, SELinux enforcing, both
    rootful and rootless Podman (task 20.1).
    """
    return "\n".join([
        "SELinux is enforcing on this host, and the container may not read the "
        "workspace.",
        "  A directory under $HOME is labelled user_home_t or admin_home_t, which a",
        "  container process is not permitted to read.",
        "",
        "  valvur does not relabel your source tree unless you ask it to: that is a "
        "write",
        "  to the code it is scanning. Choose one:",
        "",
        f"    {RELABEL_ENV}=1 valvur scan {workspace}",
        "      Adds :z to the mount. The tree is relabelled container_file_t; the "
        "label",
        "      persists after the scan, and is shared, so other containers can read "
        "it too.",
        "",
        f"    chcon -R -t container_file_t {workspace}",
        "      The same change, made by you, once.",
        f"      Undo with: restorecon -R -F {workspace}",
        "      The -F is required. container_file_t is a customizable type, and",
        "      restorecon skips those unless forced - measured, plain restorecon -R",
        "      leaves the relabelled tree exactly as it was.",
        "",
        "  :Z is deliberately not offered. It stamps a private MCS category, and "
        "valvur",
        "  runs its Scanners concurrently against one mount - measured, the second",
        "  container is denied.",
    ])
