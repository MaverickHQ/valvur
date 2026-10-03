"""26.3.2 — the fleet's outcome is a type, not a 4-tuple.

`_run_one` and `_outcome` returned `(ScannerRun, findings, artifact, raw)` and
`_scan_locked` indexed it by position in eleven places — including the budget-cut
rewrite that rebuilt one with `dataclasses.replace(outcome[0], …), *outcome[1:]`.
26.0.1 had just added a fifth thing (the unreadable report's raw text) to that
tuple and 26.2.1 moved the callers; one `ScannerOutcome` with four named fields,
after both.
"""

from __future__ import annotations

import re
from pathlib import Path

from valvur import fleet
from valvur.fleet import ScannerOutcome
from valvur.invocation import ScannerOutput
from valvur.scanner_run import ScannerRun


class _Adapter:
    kind = "scanner"
    name = "probe"
    artifact = "probe.json"

    def __init__(self, output: ScannerOutput, findings=()):
        self._output = output
        self._findings = list(findings)

    def applies_to(self, workspace, context=None):
        return True, ""

    def run(self, runner, workspace):
        return self._output

    def parse(self, output):
        return list(self._findings)


def test_a_run_is_a_scanner_outcome_with_named_fields(tmp_path):
    output = ScannerOutput("probe", "1", '{"x": 1}', "", 0)
    outcome = fleet.outcome(_Adapter(output), output).timed(0.0)

    assert isinstance(outcome, ScannerOutcome)
    assert isinstance(outcome.scanner, ScannerRun) and outcome.scanner.ok
    assert outcome.findings == []
    assert outcome.artifact == ("probe.json", '{"x": 1}')
    assert outcome.raw == '{"x": 1}'
    assert outcome.scanner.duration_s >= 0


def test_a_failure_keeps_the_raw_text_and_no_artifact(tmp_path):
    outcome = fleet.outcome(_Adapter(ScannerOutput("probe", "1", "", "boom", 1)),
                           ScannerOutput("probe", "1", "", "boom", 1))

    assert not outcome.scanner.ok and "boom" in outcome.scanner.reason
    assert outcome.findings == [] and outcome.artifact is None and outcome.raw == ""


class _Unreadable(_Adapter):
    def parse(self, output):
        raise ValueError("cut mid-write")


def test_the_budget_cut_rewrites_the_scanner_and_keeps_the_rest(tmp_path):
    """What `dataclasses.replace(outcome[0], …), *outcome[1:]` did, by name. The
    outcome cut here is a failed one that still carries its raw text — a report
    the adapter could not read (26.0.1) — so a cut that rebuilt the outcome from
    the ScannerRun alone would be seen to drop it."""
    output = ScannerOutput("probe", "1", '{"Results": [{"Vuln', "", 0)
    outcome = fleet.outcome(_Unreadable(output), output)
    assert not outcome.scanner.ok and outcome.raw == '{"Results": [{"Vuln'

    cut = outcome.cut("cut by the 20s budget after 20s")

    assert cut.scanner.reason.startswith("cut by the 20s budget")
    assert cut.scanner.ok is outcome.scanner.ok
    assert cut.raw == '{"Results": [{"Vuln', "the cut dropped the raw text"
    assert (cut.findings, cut.artifact) == (outcome.findings, outcome.artifact)


def test_the_fleet_reads_names_not_positions():
    """Eleven positional reads became none, wherever the fleet's code now lives."""
    source = "".join(Path(f"src/valvur/{name}.py").read_text()
                     for name in ("api", "fleet", "assembly"))

    positional = re.findall(r"\b(?:outcome|o)\[[0-3]\]|\*outcome\[1:\]", source)
    assert positional == [], f"the fleet still indexes an outcome by position: {positional}"
