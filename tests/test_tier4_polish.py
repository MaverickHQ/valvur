"""26.4.1 and 26.4.2 — the polish the second review's Tier 4 named.

26.4.1: `Job.state` was five string literals compared in six places across
`jobs.py` and `operations.py`, and 26.0.2 added comparisons. A `State` enum that
serialises the same, and a transition table the code cannot leave.

26.4.2: 26.0.3 put a `generation` in every JSON artifact; an agent that reads
`SUMMARY.md` and then `findings.json` — the contract's reading order — still could
not tell whether they were the same run. Now `SUMMARY.md`'s machine block,
`scan_status`'s DONE line and `valvur gate` name it too.
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

import pytest

from valvur import api
from valvur.mcp import jobs
from valvur.mcp.jobs import State

# ------------------------------------------------------------------ 26.4.1


def test_the_states_are_an_enum_that_serialises_as_the_old_words():
    assert [s.value for s in State] == ["running", "cancelling", "done", "failed", "cancelled"]
    assert State.DONE == "done" and f"{State.CANCELLED}" == "cancelled"
    assert jobs.ACTIVE == (State.RUNNING, State.CANCELLING)


def test_a_new_job_is_running_and_settles_through_the_table(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    let_go = threading.Event()
    job = jobs.start(tmp_path, "offline", lambda w, p, progress: let_go.wait(5) and "fine")
    assert job.state is State.RUNNING
    let_go.set()
    job.wait(2)
    assert job.state is State.DONE and job.summary == "fine"


@pytest.mark.parametrize("frm, to", [
    (State.DONE, State.RUNNING), (State.FAILED, State.CANCELLING),
    (State.CANCELLED, State.DONE), (State.RUNNING, State.CANCELLED),
    (State.CANCELLING, State.FAILED),
])
def test_a_transition_the_table_does_not_list_is_refused(tmp_path, frm, to):
    """The docstring's diagram is the only one the code can make: a settled job
    never runs again, and a job is never CANCELLED without having been told to
    stop first (CANCELLING), nor FAILED once it was."""
    job = jobs.Job(workspace=tmp_path, profile="offline", started=time.monotonic(), state=frm)

    with pytest.raises(jobs.IllegalTransition, match=f"{frm.value} → {to.value}"):
        job.transition(to)
    assert job.state is frm


def test_every_state_change_in_the_code_goes_through_the_table():
    """No bare `job.state = …` outside `Job.transition` — the table is the API."""
    source = Path("src/valvur/mcp/jobs.py").read_text()
    assignments = [line.strip() for line in source.splitlines()
                   if re.search(r"\bstate\s*=\s*State\.", line) and "self._state =" not in line
                   and "state: State" not in line]
    assert assignments == [], f"a state is assigned outside the table: {assignments}"
    operations = Path("src/valvur/operations.py").read_text()
    assert not re.search(r"\.state\s*=\s*", operations)
    assert not re.search(r'state\s*(==|!=|in)\s*\(?"', operations), \
        "operations.py compares a state to a literal"


def test_a_cancel_that_arrives_too_late_settles_done_not_cancelled(tmp_path, monkeypatch):
    """CANCELLING → DONE is in the table on purpose (26.0.2): a cancel that lands
    during the final write is too late, the result was written, and DONE is the
    truth."""
    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    let_go = threading.Event()

    def work(workspace, profile, progress):
        jobs.current(workspace).canceller = lambda: 0
        let_go.wait(5)
        return "written before the cancel could stop it"

    job = jobs.start(tmp_path, "offline", work)
    time.sleep(0.02)
    jobs.cancel(tmp_path)
    let_go.set()
    job.wait(2)

    assert job.state is State.DONE


# ------------------------------------------------------------------ 26.4.2


def _scan(workspace, runner):
    from valvur.adapters import GitleaksAdapter

    return api.scan(workspace, runner=runner, adapters=[GitleaksAdapter()])


def test_summary_md_names_the_generation_in_its_machine_block(workspace, runner_finding_nothing):
    run = _scan(workspace, runner_finding_nothing)
    summary = (workspace / ".security-scan" / "SUMMARY.md").read_text()

    machine_block = summary.split("**Active findings:**")[0]
    assert run.generation in machine_block
    assert f"generation `{run.generation}`" in machine_block
    findings = json.loads((workspace / ".security-scan" / "findings.json").read_text())
    assert findings["generation"] == run.generation


def test_the_done_line_names_the_generation(tmp_path, monkeypatch, runner_finding_nothing):
    from valvur import operations

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "app.py").write_text("x = 1\n")
    run = _scan(workspace, runner_finding_nothing)
    jobs.start(workspace, "offline", lambda w, p, progress: "done")
    jobs.current(workspace).wait(2)

    status = operations.scan_status({"workspace": str(workspace)})

    first = status.splitlines()[0]
    assert first.startswith("DONE in ") and run.generation in first, first


def test_the_gate_names_the_generation_it_judged(workspace, runner_finding_nothing):
    from valvur import gate

    run = _scan(workspace, runner_finding_nothing)

    verdict = gate.evaluate(workspace)

    assert run.generation in verdict.summary
    assert f"generation {run.generation}" in gate.render(verdict)
