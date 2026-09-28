"""Machine settings: what this machine decides, where the project's policy is
`.security-scan.toml` (D11).

`fetch` first (ADR-0025, R6.6): `never` turns every fetch a scan would make off,
for air-gapped use, absent data and stale data alike; anything else lets a scan
fetch what is absent and refresh what is stale, announced and recorded.
"""

from __future__ import annotations

import os

FETCH_ENV = "VALVUR_FETCH"
NEVER = "never"


def fetch() -> str:
    """`never`, or `auto`."""
    return NEVER if os.environ.get(FETCH_ENV, "").strip().lower() == NEVER else "auto"
