"""Task 29.2.4 — every reply's advice is a field, because Claude Code drops the text.

Measured in 29.2.3's transcripts: when a reply carries `structuredContent`, Claude
Code 2.1.283 hands the model the JSON and not the text block. `DONE` lost nothing
(its dict carries `next`); `RUNNING` lost its one instruction — *call again; do not
report a result yet* — and the model built its own wait; `FAILED`, `CANCELLING` and
`CANCELLED` lost every sentence after the state. So each sentence the text says
after the state is a field now, and the budget cut's cause and levers sit beside
`job.error` rather than only inside it. The text is unchanged.
"""

from __future__ import annotations

import threading
import time

import pytest

from valvur import api
from valvur.levers import LEVERS
from valvur.mcp import jobs
from valvur.operations import scan_status_reply


@pytest.fixture(autouse=True)
def _quick(monkeypatch):
    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    yield
    jobs.reset()


def _settle(job, seconds: float = 2.0) -> None:
    assert job.wait(seconds), "the job never settled"


# ------------------------------------------------------------------ each state


def test_running_carries_the_instruction_the_text_gives(tmp_path):
    release = threading.Event()

    def work(workspace, profile, progress):
        progress("fleet: 2 Scanners, 2 at a time")
        progress("gitleaks: started")
        progress("gitleaks: ok (0.1s)")
        progress("trivy: started")
        release.wait(5)
        return ""

    job = jobs.start(tmp_path, "offline", work)
    time.sleep(0.2)
    text, fields = scan_status_reply({"workspace": str(tmp_path)})
    release.set()
    _settle(job)

    assert text.startswith("RUNNING")
    assert "This call waited 0s for it. Call again; do not report a result yet." in text
    job_fields = fields["job"]
    assert job_fields["next"] == [
        "Call `scan_status` again; it waits up to 0.1 s and returns the moment the scan "
        "finishes; do not report a result yet."
    ]
    assert job_fields["waited_s"] == 0.1
    # A Scanner that announced its start is a *finished* one, not a completion of
    # an unannounced stage; the text's "Completed so far" is the latter (29.0.4).
    assert job_fields["finished"] == 1
    assert job_fields["finished_scanners"] == ["gitleaks: ok (0.1s)"]
    assert job_fields["completed"] == []
    assert job_fields["now"] is None
    assert job_fields["running"] == {"trivy": pytest.approx(0.2, abs=0.5)}


def test_failed_carries_the_doctor_sentence_only_when_doctor_may_help(tmp_path):
    def missing(workspace, profile, progress):
        raise RuntimeError("No container runtime found.")

    _settle(jobs.start(tmp_path, "offline", missing))
    text, fields = scan_status_reply({"workspace": str(tmp_path)})
    assert text.startswith("FAILED")
    assert fields["job"]["next"] == [
        "Run `doctor` (the tool; `valvur doctor` on a shell) before scanning again: it "
        "names what this machine is missing and the fix.",
        "No result to report.",
    ]
    assert "budget" not in fields["job"]


def test_a_budget_cut_is_fields_beside_the_error(tmp_path):
    from valvur import levers
    from valvur.provenance import ScannerRun

    scanners = [ScannerRun("checkov", ok=False, reason="cut by the 30s budget", duration_s=30.2),
                ScannerRun("trivy", ok=False, reason="not started: the 30s budget was spent")]
    fields_in = levers.budget_fields(scanners, 30.0, files=327, largest=[("docs", 108)])

    def cut(workspace, profile, progress):
        raise api.BudgetExhausted(
            levers.budget_exhausted_message(scanners, 30.0, files=327, largest=[("docs", 108)]),
            fields_in)

    _settle(jobs.start(tmp_path, "offline", cut))
    text, fields = scan_status_reply({"workspace": str(tmp_path)})
    assert "budget ran out" in text and "doctor" not in text
    job = fields["job"]
    assert job["doctor_may_help"] is False
    assert job["next"] == ["No result to report."]
    assert job["budget"] == {
        "seconds": 30.0, "cut": {"checkov": 30.2}, "not_started": ["trivy"],
        "files": 327, "largest": [["docs", 108]], "levers": LEVERS,
    }
    assert LEVERS in job["error"], "the text still carries the levers; the field is beside it"


def test_a_budget_error_without_fields_is_the_old_shape(tmp_path):
    """`BudgetExhausted` built from a message alone — every test before 29.2.4 —
    reports no `budget` field rather than a broken one."""

    def cut(workspace, profile, progress):
        raise api.BudgetExhausted("the 300s budget ran out before any Scanner finished")

    _settle(jobs.start(tmp_path, "offline", cut))
    _text, fields = scan_status_reply({"workspace": str(tmp_path)})
    assert "budget" not in fields["job"] and fields["job"]["next"] == ["No result to report."]


def test_cancelling_and_cancelled_carry_their_sentences(tmp_path):
    release = threading.Event()

    def work(workspace, profile, progress):
        release.wait(5)
        raise RuntimeError("every Scanner failed")   # what killing them looks like

    job = jobs.start(tmp_path, "offline", work)
    time.sleep(0.1)
    jobs.cancel(tmp_path)                             # no canceller attached: stays CANCELLING
    text, fields = scan_status_reply({"workspace": str(tmp_path)})
    assert text.startswith("CANCELLING")
    assert fields["job"]["next"] == ["Call again; no result will follow."]

    release.set()
    _settle(job)
    text, fields = scan_status_reply({"workspace": str(tmp_path)})
    assert text.startswith("CANCELLED")
    assert fields["job"]["next"] == [
        "No result: a cancelled scan writes nothing, and the previous results, if any, "
        "stand. Call `scan` to start again."
    ]


# --------------------------------------------------------- the property, held


def test_every_sentence_after_the_state_is_in_the_structured_reply(tmp_path):
    """Whatever the text says after its first line, the structured reply carries —
    verbatim, or for RUNNING's wait line as `next` and `waited_s`. What 29.2.4 is
    held by, over every branch of `scan_status_reply` that answers for a job."""
    release = threading.Event()

    def running(workspace, profile, progress):
        progress("fleet: 1 Scanners, 1 at a time")
        progress("gitleaks: started")
        release.wait(5)
        return ""

    def failed(workspace, profile, progress):
        raise RuntimeError("No container runtime found.")

    def cancelled(workspace, profile, progress):
        release.wait(5)
        raise RuntimeError("stopped")

    seen: dict[str, tuple[str, dict]] = {}
    job = jobs.start(tmp_path, "offline", running)
    time.sleep(0.15)
    seen["RUNNING"] = scan_status_reply({"workspace": str(tmp_path)})
    release.set()
    _settle(job)
    jobs.reset()
    release.clear()

    _settle(jobs.start(tmp_path, "offline", failed))
    seen["FAILED"] = scan_status_reply({"workspace": str(tmp_path)})
    jobs.reset()

    job = jobs.start(tmp_path, "offline", cancelled)
    time.sleep(0.1)
    jobs.cancel(tmp_path)
    seen["CANCELLING"] = scan_status_reply({"workspace": str(tmp_path)})
    release.set()
    _settle(job)
    seen["CANCELLED"] = scan_status_reply({"workspace": str(tmp_path)})

    for state, (text, fields) in seen.items():
        assert text.startswith(state), (state, text)
        job_fields = fields["job"]
        for line in text.splitlines()[1:]:
            if not line.strip():
                continue
            if line.startswith("This call waited"):
                assert any("do not report a result yet" in n for n in job_fields["next"])
                assert job_fields["waited_s"] == jobs.STATUS_WAIT_SECONDS
            elif line.startswith("Now: ") and " running — " in line:
                # "<tool> <s>s running — k of N finished: <names>" is three fields.
                assert job_fields["running"] and job_fields["fleet"] is not None
                assert f"{job_fields['finished']} of {job_fields['fleet']} finished" in line
                for name in job_fields["finished_scanners"]:
                    assert name in line
            elif line.startswith("Now: "):
                assert job_fields["now"] == line[len("Now: "):].rstrip(".")
            elif line.startswith("Completed so far: "):
                rest = line[len("Completed so far: "):]
                assert rest == (", ".join(job_fields["completed"]) or "starting")
            elif line.startswith("Workspace: "):
                assert line in job_fields["workspace"]
            else:
                assert line in job_fields["next"], (state, line)
