"""Per-Scanner outcomes — what actually ran, what failed, and why.

Without this a clean result is unfalsifiable: you cannot distinguish "no
vulnerabilities" from "every Scanner silently exited 1". For a tool whose output
gates a release, that distinction is the whole point (N3.1).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerRun:
    tool: str
    ok: bool
    version: str = ""
    reason: str = ""
    # A third state, distinct from both. A Scanner with nothing to analyse has not
    # failed, and the Scan Run is still complete — but it has not run either, and
    # letting that look identical to "ran and found nothing" is how a conditional
    # Scanner silently stops working.
    skipped: bool = False

    @property
    def failed(self) -> bool:
        return not self.ok
