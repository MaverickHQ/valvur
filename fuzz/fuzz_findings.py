"""Fuzz the readers of `findings.json` (R27.4, D63c): the gate and the `scan` reply.

The Results Folder is written by valvur, but it sits in the project, where anything
can change it before `valvur gate` or a client reads it. Unreadable results are a
verdict or a reply that says so, never an exception.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

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
         b'{"findings": []}', b"{"]


def test_one_input(data: bytes) -> None:
    (RESULTS / "findings.json").write_bytes(data)
    gate.evaluate(WORKSPACE, fail_on="any")
    reply.text(reply.fields(WORKSPACE))


def main() -> None:
    """Run as a fuzzer: atheris only here, so the unit suite runs the seeds without it."""
    import atheris  # deferred: a dev dependency (the `fuzz` extra), never the shim's

    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
