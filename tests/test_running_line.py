"""29.0.4 — what is running has a line (the gate's B5; F9.9).

Measured at the first gate: sixteen consecutive `scan_status` polls over 290 s
answered *Completed so far: image pulled (17s), database fetched (21s), index
fetched (7s)* and nothing else, because no Scanner finished before the budget
cut them all — nothing an agent could use to tell a running scan from a hung
one. The fleet now announces its size and each Scanner's start, the job
timestamps every message, and the RUNNING reply says what is running and for
how long, and what has finished.
"""

from __future__ import annotations

import re
import time

from test_budget import _Adapter, _Runner, _scan

from valvur import api


def test_the_fleet_announces_its_size_and_each_start(workspace):
    _, said = _scan(workspace, _Runner(), [_Adapter("fast", 0.05), _Adapter("quick", 0.05)])

    assert said[0] == "fleet: 2 Scanners, 2 at a time"
    for tool in ("fast", "quick"):
        assert said.index(f"{tool}: started") < next(
            i for i, m in enumerate(said) if m.startswith(f"{tool}: ok"))


def test_the_running_line_names_what_runs_and_what_finished(workspace, monkeypatch):
    from valvur.mcp import jobs
    from valvur.operations import scan_status_reply

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    runner = _Runner()

    def work(ws, profile, progress):
        return api.scan(ws, runner=runner, adapters=[_Adapter("fast", 0.05), _Adapter("slow", 5.0)],
                        on_progress=progress)

    job = jobs.start(workspace, "offline", work)
    time.sleep(0.5)
    try:
        text, fields = scan_status_reply({"workspace": str(workspace)})
    finally:
        runner.stopped.set()
        job.settled.wait(timeout=10)
        jobs.reset()

    assert text.startswith("RUNNING — offline scan")
    assert re.search(r"Now: slow \ds running — 1 of 2 finished: fast: ok \(", text), text
    assert "Completed so far: starting" in text, "fetch completions keep their own line"
    assert set(fields["job"]["running"]) == {"slow"} and fields["job"]["fleet"] == 2
    assert fields["job"]["finished"] == 1
    assert isinstance(fields["job"]["running"]["slow"], float)


def test_a_fetch_in_progress_still_has_its_own_line_and_a_job_timestamps_messages(tmp_path,
                                                                                   monkeypatch):
    from valvur.mcp import jobs

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    job = jobs.Job(workspace=tmp_path, profile="offline", started=time.monotonic())
    job.note("image pulled (17s)")
    job.note(f"{api.FETCH_STARTED}the vulnerability database (118MB) — the first run only")
    assert len(job.progress) == len(job.progress_at) == 2
    assert job.progress_at[0] <= job.progress_at[1]
