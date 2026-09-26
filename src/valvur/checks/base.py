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

from ..coverage import Coverage


@runtime_checkable
class Check(Protocol):
    name: str

    def run(self, workspace: Path, exclude: tuple[str, ...] = ()) -> list[dict]:
        """Inspect the Workspace and return JSON-serialisable finding records.
        `exclude` is what the scan skips before reading (29.0.1): the committed
        `[scan] exclude` prefixes, beside the vendored list every walk prunes.

        Returns plain dicts, not Findings: this runs in the container, and the host
        builds the Finding model so redaction and fingerprinting stay on one side of
        the boundary.
        """
        ...

    def coverage(self, workspace: Path, exclude: tuple[str, ...] = (),
                 *, network: bool = False) -> Coverage:
        """What this Check reads and what it deliberately does not (19.E.1) — the
        Check's own knowledge, declared by the Check (22.D.3).

        Runs on the HOST, unlike `run`: it is a static statement about files on
        disk and needs no container. Until 22.D.3 the adapter answered this on the
        Check's behalf, by testing the Check's name — the boundary ADR-0013 drew,
        crossed in the wrong direction. The default is empty, not "everything":
        a Check that has not declared its limits is recorded as having declared
        nothing, which is honest.
        """
        return Coverage()
