"""Fuzz the readers of `findings.json` (R27.4, D63c): the gate and the `scan` reply.

The Results Folder is written by valvur, but it sits in the project, where anything
can change it before `valvur gate` or a client reads it. Unreadable results are a
verdict or a reply that says so, never an exception.
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
    import json

    from valvur import gate, reply
    from valvur.results import RESULTS_DIR

WORKSPACE = Path(tempfile.mkdtemp(prefix="valvur-fuzz-findings-"))
RESULTS = WORKSPACE / RESULTS_DIR
RESULTS.mkdir()
(RESULTS / "run.json").write_text(json.dumps(
    {"complete": True, "status": "findings", "scanners": [], "generation": "g"}))
SEEDS = [json.dumps({"schema": 2, "findings": [
             {"rule": "R", "path": "a.py", "line": 1, "severity": "high",
              "title": "t", "fingerprint": "f", "suppressed": False}]}).encode(),
         b'{"findings": []}', b"{",
         # Each crash found, fixed with a test in tests/test_fuzz_crashes.py.
         b"7", b"[]", b'{"findings": [1, "x", null]}', b'{"findings": {"a": 1}}',
         b'{"findings": [{"severity": 5, "rule": []}]}',
         b'{"findings": [{"rule": "R", "path": "a.py", "line": 1, "title": "t"}]}',
         b'{"findings": [{"rule": "R", "path": "a.py", "line": 1, "severity": "high", '
         b'"fingerprint": "f", "suppressed": false}]}']


def test_one_input(data: bytes) -> None:
    (RESULTS / "findings.json").write_bytes(data)
    gate.evaluate(WORKSPACE, fail_on="any")
    reply.text(reply.fields(WORKSPACE))


def main() -> None:
    """Run as a fuzzer, with atheris; the unit suite calls `test_one_input` alone."""
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
