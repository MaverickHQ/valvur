"""29.0.3 — a budget cut is its own message, and the failure record diagnoses
(the gate's B1, B6, B7; F2.6, F2.7, F9.9).

Measured at the first gate: the 300 s default budget killed every Scanner, and
the failure read *"ScannerFailed: Every scanner failed. Refusing to report a
scan."* followed by *"Run `doctor` … it names what this machine is missing"* —
and `doctor` said *ready*. Nothing named the budget, the levers, or the cause;
each Scanner's record was its 1,500-character command line.
"""

from __future__ import annotations

import json
import time

import pytest
from test_budget import _Adapter, _Runner, _scan

from valvur import api

LEVERS = ("[scan] exclude", "budget_s", "--budget", "VALVUR_JOBS", "--jobs")


def test_a_budget_that_cuts_everything_is_its_own_refusal_with_the_levers(workspace):
    with pytest.raises(api.BudgetExhausted) as caught:
        _scan(workspace, _Runner(), [_Adapter("slow", 5.0), _Adapter("slower", 5.0)],
              budget_s=0.3)

    text = str(caught.value)
    assert text.startswith("the 0.3s budget ran out before any Scanner finished")
    assert "slow" in text and "slower" in text and "none finished" in text
    for lever in LEVERS:
        assert lever in text, lever
    assert "doctor" not in text and "Every scanner failed" not in text
    assert api.BudgetExhausted.doctor_may_help is False
    assert api.ScannerFailed.doctor_may_help is True, "a precondition failure keeps its advice"


def test_a_partial_cut_names_the_levers_where_the_cut_is_reported(workspace):
    _scan(workspace, _Runner(), [_Adapter("ok", 0.05), _Adapter("slow", 5.0)], budget_s=0.3)

    summary = (workspace / ".security-scan" / "SUMMARY.md").read_text()
    assert "**slow** — cut by the 0.3s budget after" in summary
    assert "The 0.3s budget cut slow." in summary
    for lever in LEVERS:
        assert lever in summary, lever
    run = json.loads((workspace / ".security-scan" / "run.json").read_text())
    reasons = {s["tool"]: s["reason"] for s in run["scanners"]}
    # The cut is the cause; the exit code the kill produced is not repeated
    # inside it as if the runtime had done it.
    assert reasons["slow"].startswith("cut by the 0.3s budget after ")
    assert "137" not in reasons["slow"] and "killed" not in reasons["slow"]


def test_the_failed_reply_names_doctor_only_for_a_precondition(tmp_path, monkeypatch):
    from valvur.mcp import jobs
    from valvur.operations import scan_status, scan_status_reply

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)

    def cut(workspace, profile, progress):
        raise api.BudgetExhausted("the 300s budget ran out before any Scanner finished: "
                                  "8 cut; none finished. To finish: …")

    jobs.start(tmp_path, "offline", cut)
    time.sleep(0.2)
    text, fields = scan_status_reply({"workspace": str(tmp_path)})
    jobs.reset()
    assert text.startswith("FAILED after") and "budget ran out" in text
    assert "doctor" not in text, "doctor says ready; the message must not send the agent there"
    assert fields["job"]["doctor_may_help"] is False

    def missing(workspace, profile, progress):
        raise RuntimeError("No container runtime found.")

    jobs.start(tmp_path, "offline", missing)
    time.sleep(0.2)
    status = scan_status({"workspace": str(tmp_path)})
    jobs.reset()
    assert "`doctor`" in status and "valvur doctor" in status


def test_the_record_names_a_runtime_kill_and_keeps_the_argv_out_of_it():
    from valvur.adapters import GitleaksAdapter
    from valvur.api import _outcome
    from valvur.invocation import ScannerOutput

    argv = tuple(f"--flag-{i}" for i in range(60))
    killed = _outcome(GitleaksAdapter(),
                      ScannerOutput("gitleaks", "8.30.1", "", "", 137, argv=argv)).scanner
    assert killed.reason.startswith("exit 137: killed by the runtime")
    assert "memory ceiling" in killed.reason and "2g" in killed.reason
    assert "--flag-" not in killed.reason and killed.argv == argv

    said = _outcome(GitleaksAdapter(),
                    ScannerOutput("gitleaks", "8.30.1", "", "Killed", 137, argv=argv)).scanner
    assert said.reason.endswith("— last stderr: Killed")

    other = _outcome(GitleaksAdapter(),
                     ScannerOutput("gitleaks", "8.30.1", "", "boom", 1, argv=argv)).scanner
    assert other.reason == "exited 1 with no report: boom"


def test_the_levers_are_one_sentence_in_one_place():
    """README prose, the refusal and SUMMARY.md name the same three levers; the
    sentence lives in one module so they cannot drift."""
    from valvur import levers

    for lever in LEVERS:
        assert lever in levers.LEVERS, lever
    from pathlib import Path

    readme = Path(__file__).resolve().parent.parent.joinpath("README.md").read_text()
    for lever in LEVERS:
        assert lever in readme, f"the README does not name {lever}"
