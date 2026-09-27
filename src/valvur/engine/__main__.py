"""`python -m valvur.engine`: the Scan Container's entry point (ADR-0022)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import RESULTS, RESULTS_ENV, WORKSPACE, WORKSPACE_ENV, run

if __name__ == "__main__":
    sys.exit(run(sys.stdin.buffer, Path(os.environ.get(WORKSPACE_ENV, WORKSPACE)),
                 Path(os.environ.get(RESULTS_ENV, RESULTS))))
