"""R10.1: a failed Scanner with nothing found reads `inconclusive` (D30, F7.19).

Until R10 such a run read `clean` beside `complete: false`: the gate failed it and
every surface said *incomplete*, but the one word an agent switches on said the code
was clean when part of it was never looked at. The three Statuses are unchanged; a
false `clean` is removed.
"""

from __future__ import annotations

import json

from conftest import CrashingAdapter

from valvur import scan
from valvur.adapters import GitleaksAdapter


def _plain(tmp_path):
    """A workspace nothing casts doubt on: one source file, no manifest."""
    (tmp_path / "app.py").write_text("print('hello')\n")
    return tmp_path


def test_nothing_found_while_a_scanner_failed_is_inconclusive_naming_it(
    tmp_path, runner_finding_nothing
):
    workspace = _plain(tmp_path)
    clean = scan(workspace, runner=runner_finding_nothing, adapters=[GitleaksAdapter()])
    assert clean.status == "clean"

    run = scan(workspace, runner=runner_finding_nothing,
               adapters=[GitleaksAdapter(), CrashingAdapter()])

    assert run.status == "inconclusive"
    assert "exploding-scanner" in run.status_reason


def test_run_json_the_summary_the_reply_and_the_gate_agree(tmp_path, runner_finding_nothing):
    from valvur import gate, reply

    workspace = _plain(tmp_path)
    scan(workspace, runner=runner_finding_nothing,
         adapters=[GitleaksAdapter(), CrashingAdapter()])
    results = workspace / ".security-scan"

    run_json = json.loads((results / "run.json").read_text())
    summary = (results / "SUMMARY.md").read_text()
    fields = reply.fields(workspace)
    verdict = gate.evaluate(workspace, fail_on="critical", no_inconclusive=True)

    assert run_json["status"] == "inconclusive" and run_json["complete"] is False
    assert "exploding-scanner" in run_json["status_reason"]
    assert "**Status:** inconclusive" in summary
    assert (fields["verdict"], fields["reason"]) == ("inconclusive", run_json["status_reason"])
    assert any(line.startswith("inconclusive: ") for line in verdict.failures)


def test_with_a_finding_the_run_still_reads_findings_and_incomplete(
    tmp_path, runner_finding_one_secret
):
    workspace = _plain(tmp_path)

    run = scan(workspace, runner=runner_finding_one_secret,
               adapters=[GitleaksAdapter(), CrashingAdapter()])

    assert run.status == "findings"
    assert json.loads((workspace / ".security-scan" / "run.json").read_text())[
        "complete"] is False
