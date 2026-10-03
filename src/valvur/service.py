"""One scan service (D51): every surface runs a scan through `run_scan`.

The CLI's `scan` and the MCP tool both call it. It owns the runner, the locks, the
budget and the cancellation; a surface chooses the budget (none at a terminal, where
Ctrl-C is the person's, and F2.6's five minutes over MCP) and renders the result.
Until R23.4 the CLI called `api.scan` itself, MCP went through `operations`, the jobs
and a closure of its own, and one scan was summarised three times.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import api, profiles
from .api import ScanRun


class Cancellation:
    """A cancel that may arrive before the scan's runner exists (F1.11): held, and
    used the moment the runner is attached. `cancel` and `attach` share one lock,
    so whichever runs second sees the other: a cancel with no runner yet is
    remembered, and `attach` finds it and stops the runner itself (26.0.2)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runner: Any = None
        self.requested = False

    @property
    def runner(self) -> Any:
        """The scan's runner, once attached; None before."""
        return self._runner

    def attach(self, runner: Any) -> None:
        with self._lock:
            self._runner = runner
            pending = self.requested
        if pending:
            runner.kill()

    def cancel(self) -> int:
        """Stop the scan: the containers its runner had started, or, before it has
        one, the scan as soon as it does. Returns how many engines were stopped."""
        with self._lock:
            self.requested = True
            runner = self._runner
        return int(runner.kill()) if runner is not None else 0


def new_runner() -> Any:
    """The runtime a scan uses (R3.9): the Scan Container, or inside the image the
    engine as a process there (R8.1)."""
    from . import engine_host

    return engine_host.for_scan()


def run_scan(
    workspace: Path, *, profile: str = profiles.DEFAULT,
    on_progress: Callable[[str], None] | None = None, budget_s: float | None = None,
    fresh: bool = False, jobs: int | None = None, sbom: bool = False,
    out: Path | None = None, runner: Any = None, cancellation: Cancellation | None = None,
) -> ScanRun:
    """One Scan Run of `workspace`, its Results Folder written, and its record."""
    runner = runner if runner is not None else new_runner()
    if cancellation is not None:
        cancellation.attach(runner)
    return api.scan(workspace, runner=runner, profile=profile, on_progress=on_progress,
                    jobs=jobs, budget_s=budget_s, sbom=sbom, out=out, fresh=fresh)
