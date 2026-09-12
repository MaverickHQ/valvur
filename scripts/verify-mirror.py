#!/usr/bin/env python3
"""Prove an air-gapped configuration reaches only its mirrors.

    VALVUR_DB_REPOSITORY=mirror.internal:5000/trivy-db \\
    VALVUR_NAME_INDEX_URL=http://mirror.internal:8080 \\
    python3 scripts/verify-mirror.py [path-to-scan]

Runs `valvur update` and then an `offline` scan with every connect path in this
process poisoned — except to the hosts named in the mirror settings, and loopback.
Any other destination is refused the way an air gap would refuse it, recorded, and
fails the verdict at the end. That covers the host half of the claim (22.B.3): the
shim fetches the package-name index and CISA KEV itself, from VALVUR_NAME_INDEX_URL
and VALVUR_KEV_URL when set.

The container half is not this script's to prove. `valvur update` launches Trivy in
a container with a network, pointed at VALVUR_DB_REPOSITORY; whether THAT container
can reach the internet is a property of the network it joins. Put the mirror on a
network with no route out — Docker's `--internal`, named in VALVUR_CONTAINER_NETWORK
— and the gap is structural. The recipe that was measured is in docs/RELEASING.md.
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

attempts: list[str] = []
allowed: set[str] = {"127.0.0.1", "::1", "localhost"}


def _host_of(address) -> str:
    if isinstance(address, tuple):
        return str(address[0])
    return str(address)


def _deny(name: str, original, address_index: int):
    def guarded(*args, **kwargs):
        target = args[address_index] if len(args) > address_index else kwargs.get("address", "?")
        host = _host_of(target)
        if host in allowed:
            return original(*args, **kwargs)
        attempts.append(f"{name} -> {host}")
        # An OSError, not a private exception: valvur must see what a real air gap
        # shows it — a connection that fails — and handle it the way it would there.
        # The attempt is recorded either way, and judged at the end.
        raise ConnectionRefusedError(f"air gap: {name} -> {host}")

    return guarded


def _poison() -> None:
    # Method calls carry `self` first; the module-level functions do not.
    socket.socket.connect = _deny("connect", socket.socket.connect, 1)  # type: ignore[method-assign]
    socket.socket.connect_ex = _deny("connect_ex", socket.socket.connect_ex, 1)  # type: ignore[method-assign]
    socket.create_connection = _deny("create_connection", socket.create_connection, 0)
    socket.getaddrinfo = _deny("getaddrinfo", socket.getaddrinfo, 0)


def main() -> int:
    from valvur import cache
    from valvur.cli import main as valvur

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    mirrors = {
        name: os.environ.get(name, "") for name in ("VALVUR_NAME_INDEX_URL", "VALVUR_KEV_URL")
    }
    for url in filter(None, mirrors.values()):
        host = urlparse(url).hostname or ""
        allowed.add(host)
        try:
            allowed.update(info[4][0] for info in socket.getaddrinfo(host, None))
        except OSError:
            pass
    print("Verifying that an air-gapped configuration reaches only its mirrors.")
    print(f"  database mirror : {os.environ.get('VALVUR_DB_REPOSITORY') or '(none — direct)'}")
    print(f"  index mirror    : {mirrors['VALVUR_NAME_INDEX_URL'] or '(none — direct)'}")
    print(f"  KEV mirror      : {mirrors['VALVUR_KEV_URL'] or '(none — direct)'}")
    print(f"  cache           : {cache.root()}")
    print(f"  permitted hosts : {', '.join(sorted(allowed))}\n")

    _poison()

    print("  ...  valvur update, with every other connect path poisoned")
    code = valvur(["update"])
    if code != 0:
        print(f"  [FAIL] valvur update exited {code}")
        return 1
    if not cache.db_present() or not cache.name_index_present():
        print("  [FAIL] update exited 0 but the cache is incomplete")
        return 1
    print("  [PASS] update completed from the mirrors alone")

    print(f"  ...  offline scan of {target}, still poisoned")
    code = valvur(["scan", target, "--profile", "offline"])
    if code != 0:
        print(f"  [FAIL] valvur scan exited {code}")
        return 1
    import json

    run = json.loads((Path(target) / ".security-scan" / "run.json").read_text())
    if not run.get("complete"):
        print(f"  [FAIL] the scan was incomplete: {[s for s in run['scanners'] if not s['ok']]}")
        return 1
    print(f"  [PASS] offline scan complete: {run['findings']}")

    if attempts:
        print(f"\n  [FAIL] {len(attempts)} connection attempt(s) outside the mirrors:")
        for attempt in dict.fromkeys(attempts):
            print(f"         {attempt}")
        return 1
    print("\nVERIFIED: nothing reached beyond the mirrors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
