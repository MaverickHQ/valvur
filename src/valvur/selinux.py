"""SELinux on the host: whether it is enforcing, whether the developer asked for
the source tree to be relabelled, and what to tell them when a mount is denied
(F1.6, ADR-0017, task 20.2). Split out of `runner.py` by 26.2.1: a host concern
the runner reads, not a container one it owns.
"""

from __future__ import annotations

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


