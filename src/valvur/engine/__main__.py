"""`python -m valvur.engine`: the Scan Container's entry point (ADR-0022)."""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

from . import RESULTS, RESULTS_ENV, WORKSPACE, WORKSPACE_ENV, run


def _terminated(signum, _frame):
    """A stop from the host (R3.5): unwind, so `run` stops every tool it started.
    Each tool has its own process group, which a kill of the engine's never reaches."""
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _terminated)
    sys.exit(run(sys.stdin.buffer, Path(os.environ.get(WORKSPACE_ENV, WORKSPACE)),
                 Path(os.environ.get(RESULTS_ENV, RESULTS))))
