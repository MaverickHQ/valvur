"""Fuzz the readers of `.security-scan.toml` (R27.4, D63c).

The project's committed configuration: `[scan]` settings and its excludes, and the
suppressions. A file that does not parse, or parses to the wrong shapes, is a
problem the scan reports, never an exception.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from valvur import exclusions, suppressions

WORKSPACE = Path(tempfile.mkdtemp(prefix="valvur-fuzz-config-"))
SEEDS = [b'[scan]\nexclude = ["vendor", "tests/fixtures"]\n',
         b'[[suppress]]\nfingerprint = "0e2cb52a1e48b5c3e8507724afdc67b4"\nrule = "R"\n'
         b'path = "Dockerfile"\nexpires = 2027-08-31\nreason = "why"\n',
         b"[scan]\nfetch = \"never\"\nbudget = 120\n", b"not = [toml", b""]


def test_one_input(data: bytes) -> None:
    (WORKSPACE / ".security-scan.toml").write_bytes(data)
    exclusions.load_scan_settings(WORKSPACE)
    exclusions.load_configured(WORKSPACE)
    suppressions.load(WORKSPACE)


def main() -> None:
    """Run as a fuzzer: atheris only here, so the unit suite runs the seeds without it."""
    import atheris  # deferred: a dev dependency (the `fuzz` extra), never the shim's

    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
