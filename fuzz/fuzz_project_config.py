"""Fuzz the readers of `.security-scan.toml` (R27.4, D63c).

The project's committed configuration: `[scan]` settings and its excludes, and the
suppressions. A file that does not parse, or parses to the wrong shapes, is a
problem the scan reports, never an exception.
"""

from __future__ import annotations

import contextlib
import sys
import tempfile
from pathlib import Path

try:
    import atheris  # the `fuzz` extra; the unit suite runs the seeds without it
except ImportError:
    atheris = None

# Instrumented as imported: valvur, and the parsers whose branches shape its input.
# Instrumenting everything loaded took 10 s to start one input, and ClusterFuzzLite's
# 30 s reproduction dropped two real crashes (PR #196).
with (atheris.instrument_imports(include=["valvur", "tomllib", "json", "shlex"]) if atheris
      else contextlib.nullcontext()):
    from valvur import exclusions, suppressions

WORKSPACE = Path(tempfile.mkdtemp(prefix="valvur-fuzz-config-"))
SEEDS = [b'[scan]\nexclude = ["vendor", "tests/fixtures"]\n',
         b'[[suppress]]\nfingerprint = "0e2cb52a1e48b5c3e8507724afdc67b4"\nrule = "R"\n'
         b'path = "Dockerfile"\nexpires = 2027-08-31\nreason = "why"\n',
         b"[scan]\nfetch = \"never\"\nbudget = 120\n", b"not = [toml", b"",
         # Each crash found, fixed with a test in tests/test_fuzz_crashes.py.
         b"\xdc", b"[scan]\nexclude = 5", b"scan = 3", b"suppress = 3", b"suppress = [1, 'x']"]


def test_one_input(data: bytes) -> None:
    (WORKSPACE / ".security-scan.toml").write_bytes(data)
    exclusions.load_scan_settings(WORKSPACE)
    exclusions.load_configured(WORKSPACE)
    suppressions.load(WORKSPACE)


def main() -> None:
    """Run as a fuzzer, with atheris; the unit suite calls `test_one_input` alone."""
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
