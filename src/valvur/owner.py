"""Who started a container, so nothing outlives its owner (R3.6; F1.11, F1.12).

Every container valvur starts carries three labels: the process that started it,
the host that process runs on, and the Scan Run's generation. A container whose
owner process has ended on this host is an orphan: a server killed with `kill -9`
leaves its fleet running with nobody to read the result, and the second gate's
next scan met them. Each scan start and `doctor` reap orphans; a server on its way
out kills its own by label.

The host label is what makes reaping safe on a runtime shared between machines: a
PID means nothing on another host, so a container from elsewhere is never judged.
A leaf module: it imports nothing from valvur, so every launcher can use it.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess

PID_LABEL = "valvur.pid"
HOST_LABEL = "valvur.host"
GENERATION_LABEL = "valvur.generation"


def labels(generation: str | None = None) -> list[str]:
    """The `--label` flags for a container this process starts."""
    return ["--label", f"{PID_LABEL}={os.getpid()}",
            "--label", f"{HOST_LABEL}={socket.gethostname()}",
            "--label", f"{GENERATION_LABEL}={generation or 'none'}"]


def alive(pid: int) -> bool:
    """Whether `pid` is a process on this host. One this process may not signal
    still exists, and counts."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _run(runtime: str, *args: str) -> str:
    try:
        return subprocess.run([runtime, *args], capture_output=True, text=True,  # noqa: S603
                              timeout=30, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _labelled(runtime: str, *filters: str) -> list[str]:
    selectors = [a for f in (PID_LABEL, *filters) for a in ("--filter", f"label={f}")]
    return _run(runtime, "ps", "-a", "-q", *selectors).split()


def orphans(runtime: str) -> list[str]:
    """The names of containers started on this host by a process that has ended."""
    ids = _labelled(runtime, f"{HOST_LABEL}={socket.gethostname()}")
    if not ids:
        return []
    try:
        inspected = json.loads(_run(runtime, "inspect", *ids) or "[]")
    except ValueError:
        return []
    found = []
    for container in inspected:
        raw = ((container.get("Config") or {}).get("Labels") or {}).get(PID_LABEL, "")
        if raw.isdigit() and not alive(int(raw)):
            found.append(str(container.get("Name", "")).lstrip("/"))
    return sorted(n for n in found if n)


def reap(runtime: str) -> list[str]:
    """Remove every orphan; return their names. Best effort: nothing here raises."""
    names = orphans(runtime)
    if names:
        _run(runtime, "rm", "-f", *names)
    return names


def kill_mine(runtime: str) -> int:
    """Kill every container this process started, by label, in one call. Returns
    how many were signalled."""
    ids = _labelled(runtime, f"{PID_LABEL}={os.getpid()}",
                    f"{HOST_LABEL}={socket.gethostname()}")
    if ids:
        with contextlib.suppress(Exception):
            _run(runtime, "kill", *ids)
    return len(ids)
