"""One Scanner's run, as the record keeps it: whether it completed, why not, how
long, what was launched, and what the budget did to it. In `core` (D50), so every
layer that reads a run's Scanners reads this one shape; `provenance` writes it to
`run.json`.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The two things a budget does to a Scanner (`ScannerRun.budget`).
BUDGET_CUT = "cut"
BUDGET_NOT_STARTED = "not-started"


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
    #: Wall-clock seconds this Scanner took, container start to report read (23.3.2).
    #: The fleet runs concurrently, so a scan takes about as long as its slowest —
    #: which is how a user finds the Checkov cost, and how 23.4.2 is measured.
    duration_s: float = 0.0
    #: The command line the runner launched after the image name, from the
    #: Invocation (28.3.6): what produced the raw output, beside its version and
    #: duration. Empty when nothing was launched.
    argv: tuple[str, ...] = ()
    #: The Scan Run whose result this is, when it was reused rather than run (R14.3,
    #: D32): nothing it reads had changed since. Empty when it ran.
    reused_from: str = ""
    #: What the scan's budget did to it (R3.5, D53): `cut` while it ran, `not-started`
    #: before its turn, empty when the budget did nothing. A field, not the first
    #: words of `reason`, which is for a reader.
    budget: str = ""

    @property
    def failed(self) -> bool:
        return not self.ok
