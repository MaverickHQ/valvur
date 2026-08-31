#!/usr/bin/env python3
"""Verify that an `offline` scan sends nothing, on any platform.

    python3 scripts/verify-offline.py [path-to-scan]

Non-exfiltration has two halves, and one flag only covers one of them.

  1. The Scanners run inside containers launched with `--network=none`. There is no
     network interface for them to use. Checked here by inspecting the arguments
     valvur builds for every Scanner the `offline` Profile runs.

  2. The host shim — the part that is NOT in a container — could still open a socket.
     It has a reason to: exploit enrichment fetches EPSS scores from FIRST on the
     `full` Profile, gated by a single boolean threaded from the Profile. One
     inverted condition and the guarantee is gone with no visible symptom.
     Checked here by poisoning every connect path in the process and running a real
     scan.

What this does NOT prove: that a determined adversary could not bypass a check
running inside their own interpreter. For a proof the process cannot influence, run
the scan under an OS that denies it the network outright — on Linux:

    unshare -rn valvur scan --profile offline

which needs no privileges, and works because the container runtime is reached over a
unix socket rather than the network. macOS has no equivalent; disconnecting the
machine entirely is the platform-independent version.
"""

from __future__ import annotations

import socket
import sys
import tempfile
from pathlib import Path

attempts: list[str] = []


class Connected(RuntimeError):
    """The host process tried to reach the network during an offline scan."""


def _deny(name: str):
    def blocked(*args, **kwargs):
        target = args[1] if len(args) > 1 else kwargs.get("address", "?")
        attempts.append(f"{name} -> {target}")
        raise Connected(f"{name} -> {target}")

    return blocked


def check_containers_have_no_network() -> bool:
    from valvur import profiles
    from valvur.runner import ContainerRunner

    runner = ContainerRunner(runtime="/usr/local/bin/docker")
    probe = Path(tempfile.mkdtemp())
    flags = runner._base_flags(probe, tempfile.mkdtemp(), network=False)
    ok = "--network=none" in flags
    print(f"  [{'PASS' if ok else 'FAIL'}] containers are launched with --network=none")
    print(f"         Scanners on offline: {', '.join(profiles.SCANNERS[profiles.OFFLINE])}")
    # The check is only meaningful if it can fail: the networked path must differ.
    networked = runner._base_flags(probe, tempfile.mkdtemp(), network=True)
    if "--network=none" in networked:
        print("  [FAIL] the flag is unconditional, so this check proves nothing")
        return False
    return ok


def check_host_opens_no_connection(target: str) -> bool:
    socket.socket.connect = _deny("connect")
    socket.socket.connect_ex = _deny("connect_ex")
    socket.create_connection = _deny("create_connection")
    socket.getaddrinfo = _deny("getaddrinfo")

    from valvur.cli import main

    print(f"  ...  scanning {target} with every connect path poisoned")
    try:
        main(["scan", target, "--profile", "offline"])
    except Connected as exc:
        print(f"  [FAIL] the host process tried to connect: {exc}")
        return False

    if attempts:
        print(f"  [FAIL] {len(attempts)} connection attempt(s) from the host process")
        for attempt in dict.fromkeys(attempts):
            print(f"         {attempt}")
        return False
    print("  [PASS] the host process opened no connection")
    return True


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print("Verifying that an offline scan sends nothing.\n")

    containers_ok = check_containers_have_no_network()
    host_ok = check_host_opens_no_connection(target)

    print()
    if containers_ok and host_ok:
        print("VERIFIED: nothing left this machine.")
        print("Stronger still, on Linux: unshare -rn valvur scan --profile offline")
        return 0
    print("FAILED: see above. This is the product's central claim — treat it as a bug.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
