"""The tools valvur exposes. Populated in sub-phase 9.1.

Every tool here is read-only with respect to the Workspace. There is no
`scan_and_fix`, no `apply`, no `write` and no `remediate`, and a test asserts their
absence — ADR-0009 is a safety property, so adding one should fail the build rather
than merely fail review.
"""

from __future__ import annotations

from .server import Tool

# Names that must never appear here. Asserted by test, not by convention.
FORBIDDEN = ("scan_and_fix", "apply", "write", "remediate", "fix", "patch", "edit")


def registry() -> list[Tool]:
    return []
