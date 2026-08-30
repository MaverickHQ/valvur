"""What every Check provides.

A **Check** is detection valvur performs itself, as opposed to a **Scanner**, which is
a third-party tool we orchestrate (see CONTEXT.md). Checks run *inside the container*
exactly as Scanners do — see ADR-0013 for why that is not merely tidiness.

A Check emits JSON on stdout. The host-side adapter parses it, so Checks reuse the
fleet's failure isolation, Profile selection, concurrency and Provenance for free.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class Check(Protocol):
    name: str

    def run(self, workspace: Path) -> list[dict]:
        """Inspect the Workspace and return JSON-serialisable finding records.

        Returns plain dicts, not Findings: this runs in the container, and the host
        builds the Finding model so redaction and fingerprinting stay on one side of
        the boundary.
        """
        ...
