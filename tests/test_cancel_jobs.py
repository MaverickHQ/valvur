"""Task 23.3.3 — `scan_cancel` over MCP, and `--jobs N` on the CLI.

Interruption is its own outcome (F1.11, 16.2): the containers stop, no Results
Folder is written, and the run is not reported as failed. Ctrl-C gave the CLI that;
an agent had no equivalent, and a scan it started outlived its interest. `--jobs`
is for the machine that cannot start eight containers at once — Docker Desktop's
default memory, measured — and it is honoured by the fleet's executor, not by hope.
"""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

import pytest
from conftest import LegacyDispatch

from valvur import api
from valvur.adapters import GitleaksAdapter
from valvur.runner import ContainerRunner, ScannerOutput

# ------------------------------------------------------------ the runner's kill


def test_a_runner_kills_only_its_own_containers_and_remembers_it_was_cancelled(monkeypatch):
    """`kill_running` stops everything this PROCESS started — right for Ctrl-C,
    wrong for an MCP server scanning two workspaces at once. A runner kills what it
    launched, and nothing else."""
    import valvur.runner as runner_module

    killed: list[str] = []

    def fake_run(cmd, **kwargs):
        if cmd[1] == "kill":
            killed.extend(cmd[2:])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    mine = ContainerRunner(image="x/y:1", runtime="/usr/local/bin/docker")
    with runner_module._live_lock:
        runner_module._live_containers.update({"valvur-mine1", "valvur-mine2", "valvur-other"})
    mine._mine.update({"valvur-mine1", "valvur-mine2", "valvur-finished"})
    try:
        stopped = mine.kill()
    finally:
        with runner_module._live_lock:
            runner_module._live_containers.clear()

    assert stopped == 2
    assert sorted(killed) == ["valvur-mine1", "valvur-mine2"]
    assert mine.cancelled is True


def test_a_launch_is_tracked_on_the_runner_as_well_as_the_process(monkeypatch):
    import valvur.runner as runner_module

    seen: list[str] = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd[cmd.index("--name") + 1])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = ContainerRunner(image="x/y:1", runtime="/usr/local/bin/docker")

    runner._launch(["/usr/local/bin/docker", "run", "--name", "valvur-abc", "x/y:1"])

    assert seen == ["valvur-abc"]
    assert runner._mine == {"valvur-abc"}
    with runner_module._live_lock:
        assert "valvur-abc" not in runner_module._live_containers   # released after exit


# ---------------------------------------------------- a cancelled scan writes nothing


class _Runner(LegacyDispatch):
    """A fake that can be cancelled the way the real one is: `kill()` sets the
    flag, and the Scanners that were running come back with no report."""

    image = "x/y:1"
    runtime = "/usr/local/bin/docker"

    def __init__(self, *, cancel_during: str | None = None):
        self.cancelled = False
        self.cancel_during = cancel_during
        self.calls: list[str] = []

    def kill(self) -> int:
        self.cancelled = True
        return 1

    def _scanner(self, tool: str, version: str, payload: str) -> ScannerOutput:
        self.calls.append(tool)
        if self.cancel_during == tool:
            self.kill()
            return ScannerOutput(tool, version, "", "killed", 137)
        return ScannerOutput(tool, version, payload, "", 0)

    def run_gitleaks(self, workspace):
        return self._scanner("gitleaks", "8.30.1", "[]")

    def run_trivy(self, workspace):
        return self._scanner("trivy", "0.74.0", '{"Results": []}')


def test_a_cancelled_scan_stops_writes_nothing_and_is_not_a_failure(tmp_path, monkeypatch):
    """F1.11 over MCP: the same three properties Ctrl-C gives the CLI."""
    from valvur import cache
    from valvur.adapters import TrivyAdapter

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    # Trivy's adapter refuses without its database before any container starts
    # (26.2.1 moved that check from the runner, which the fake bypassed).
    monkeypatch.setattr(cache, "db_present", lambda: True)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('hi')\n")

    with pytest.raises(api.ScanCancelled) as caught:
        api.scan(workspace, runner=_Runner(cancel_during="gitleaks"),
                 adapters=[GitleaksAdapter(), TrivyAdapter()])

    assert not issubclass(api.ScanCancelled, api.ScannerFailed)
    assert "cancelled: 1 of 2 Scanner(s) had finished" in str(caught.value)
    results = workspace / ".security-scan"
    assert not (results / "run.json").exists()
    assert not (results / "SUMMARY.md").exists()
    assert not (results / "state.json").exists()
    assert sorted(p.name for p in results.iterdir()) == [".gitignore", ".lock"]


def test_a_cancel_that_lands_before_the_fleet_starts_no_scanner(tmp_path, monkeypatch):
    """A kill before the scan begins: the flag is checked before the fetches and
    before the fleet (26.0.2 moved the first check ahead of the fetches), so
    nothing is pulled and eight containers are not started only to be killed."""
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    runner = _Runner()
    runner.cancelled = True

    with pytest.raises(api.ScanCancelled, match="before it began"):
        api.scan(workspace, runner=runner, adapters=[GitleaksAdapter()])

    assert runner.calls == []


def test_a_cancel_that_lands_after_the_fleet_still_writes_nothing(tmp_path, monkeypatch):
    """The flag is checked after the fleet too: a kill that arrives between the last
    Scanner finishing and the write must not produce a Results Folder from a run the
    developer said to stop."""
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    runner = _Runner()
    real = api._pipeline.run

    def cancel_then_run(findings, ctx):
        runner.kill()
        return real(findings, ctx)

    monkeypatch.setattr(api._pipeline, "run", cancel_then_run)

    with pytest.raises(api.ScanCancelled):
        api.scan(workspace, runner=runner, adapters=[GitleaksAdapter()])

    assert not (workspace / ".security-scan" / "run.json").exists()


def test_a_runner_without_the_flag_is_never_cancelled(tmp_path, monkeypatch):
    from conftest import FakeRunner

    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    workspace = tmp_path / "ws"
    workspace.mkdir()

    run = api.scan(workspace, runner=FakeRunner(), adapters=[GitleaksAdapter()])

    assert not run.failures


# ------------------------------------------------------------------ the job


@pytest.fixture(autouse=True)
def _clean_jobs():
    from valvur.mcp import jobs

    jobs.reset()
    yield
    jobs.reset()


def test_cancelling_a_running_job_stops_it_and_status_says_cancelled(tmp_path, monkeypatch):
    from valvur.mcp import jobs
    from valvur.operations import cancel_scan, scan_status

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    stopped: list[str] = []
    let_go = threading.Event()

    def work(workspace, profile, progress):
        job = jobs.current(workspace)
        job.canceller = lambda: stopped.append("killed") or 3
        progress("gitleaks: ok (0.4s)")
        let_go.wait(timeout=5)
        raise api.ScanCancelled("cancelled: 1 of 8 Scanner(s) had finished")

    jobs.start(tmp_path, "offline", work)
    time.sleep(0.05)

    reply = cancel_scan({"workspace": str(tmp_path)})
    let_go.set()
    time.sleep(0.2)
    status = scan_status({"workspace": str(tmp_path)})

    assert stopped == ["killed"]
    assert reply.startswith("Cancelling the offline scan of ")
    assert "stopped 3 container(s)" in reply
    assert "No results are written for a cancelled scan" in reply
    assert status.startswith("CANCELLED after ")
    assert "1 of 8 Scanner(s) had finished" in status
    assert "No result" in status and "`scan`" in status
    assert "FAILED" not in status


def test_cancelling_when_nothing_runs_says_so(tmp_path):
    from valvur.operations import cancel_scan

    assert cancel_scan({"workspace": str(tmp_path)}) == f"No scan is running in {tmp_path}."


def test_a_cancel_request_that_arrives_after_the_work_finished_is_reported_as_done(
    tmp_path, monkeypatch
):
    """Cancel is a request: if the scan completed before the containers could be
    stopped, the result stands and the status says DONE, not CANCELLED."""
    from valvur.mcp import jobs
    from valvur.operations import cancel_scan

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    jobs.start(tmp_path, "offline", lambda workspace, profile, progress: "done")
    time.sleep(0.2)

    reply = cancel_scan({"workspace": str(tmp_path)})

    assert reply == f"No scan is running in {tmp_path}."
    assert jobs.current(tmp_path).state == "done"


def test_a_cancelling_job_is_shown_as_such_while_containers_stop(tmp_path, monkeypatch):
    from valvur.mcp import jobs
    from valvur.operations import cancel_scan, scan_status

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    let_go = threading.Event()

    def work(workspace, profile, progress):
        jobs.current(workspace).canceller = lambda: 0
        let_go.wait(timeout=5)
        raise RuntimeError("Every scanner failed. Refusing to report a scan.")

    jobs.start(tmp_path, "offline", work)
    time.sleep(0.05)
    cancel_scan({"workspace": str(tmp_path)})

    asked = time.monotonic()
    during = scan_status({"workspace": str(tmp_path)})
    waited = time.monotonic() - asked
    let_go.set()
    time.sleep(0.2)
    after = scan_status({"workspace": str(tmp_path)})

    assert during.startswith("CANCELLING — ")
    # Polled like a running job: a poll that returned instantly would cost the
    # agent a turn per millisecond of the fleet stopping (10.2.5).
    assert waited >= 0.09, waited
    # Whatever the fleet raised on its way down, a job the agent cancelled is
    # cancelled, not failed: "every scanner failed" is what killing them looks like.
    assert after.startswith("CANCELLED after ")


def test_a_cancel_that_lands_before_the_runner_is_attached_is_honoured_when_it_is(
    tmp_path, monkeypatch
):
    """26.0.2 (a). `jobs.cancel` calls the canceller if one is attached; the work
    attaches it only once `ContainerRunner()` exists. Measured 2026-09-20: a cancel
    in that window returned `stopped=0`, the runner was never told, the scan ran
    to completion and the job settled `done` — a cancel confirmed and dropped.
    Now attaching a canceller to a job already `cancelling` calls it at once."""
    from valvur.mcp import jobs

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    runner_exists = threading.Event()
    killed: list[int] = []

    class Runner:
        cancelled = False

        def kill(self):
            self.cancelled = True
            killed.append(1)
            return 0

    def work(workspace, profile, progress):
        runner_exists.wait(timeout=5)          # the fetches, before any runner
        runner = Runner()
        jobs.current(workspace).canceller = runner.kill
        if runner.cancelled:                    # what api.scan's boundary check does
            raise api.ScanCancelled("cancelled before the Scanners started")
        return "scan finished normally"

    job = jobs.start(tmp_path, "offline", work)
    time.sleep(0.02)
    cancelled, stopped = jobs.cancel(tmp_path)
    runner_exists.set()
    job.wait(2)

    assert cancelled is job and stopped == 0
    assert killed == [1], "the runner was never told to stop"
    assert job.state == "cancelled", job.state
    assert job.summary == ""


def test_a_second_scan_while_the_first_is_still_stopping_is_refused_and_the_first_kept(
    tmp_path, monkeypatch
):
    """26.0.2 (b). `jobs.start` refused only `running`; a job in `cancelling` was
    replaced in the registry, so its CANCELLED was never reported and the second
    scan failed on the workspace lock with a message about a scan the agent
    thought it had stopped."""
    from valvur.mcp import jobs
    from valvur.operations import cancel_scan, scan_status, start_scan

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    let_go = threading.Event()

    def work(workspace, profile, progress):
        jobs.current(workspace).canceller = lambda: 2
        let_go.wait(timeout=5)
        raise api.ScanCancelled("cancelled: 1 of 8 Scanner(s) had finished")

    first = jobs.start(tmp_path, "offline", work)
    time.sleep(0.05)
    cancel_scan({"workspace": str(tmp_path)})

    reply = start_scan({"workspace": str(tmp_path), "profile": "offline"})
    assert jobs.start(tmp_path, "offline", work) is first
    assert jobs.current(tmp_path) is first
    assert "still stopping" in reply and "CANCELLED" in reply, reply

    let_go.set()
    first.wait(2)
    assert scan_status({"workspace": str(tmp_path)}).startswith("CANCELLED after ")


def test_a_cancel_before_any_container_says_the_scan_stops_at_its_next_step(tmp_path, monkeypatch):
    """The reply is true either way: containers stopped, or none had started and
    the scan stops at its next boundary."""
    from valvur.mcp import jobs
    from valvur.operations import cancel_scan

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    let_go = threading.Event()
    jobs.start(tmp_path, "offline", lambda w, p, progress: let_go.wait(5))
    time.sleep(0.02)

    reply = cancel_scan({"workspace": str(tmp_path)})
    let_go.set()

    assert "no container had started" in reply and "next step" in reply, reply


def test_the_scan_job_registers_its_own_runner_as_the_canceller(tmp_path, monkeypatch):
    """`_run_scan` is where the runner exists; a cancel stops THAT fleet."""
    from valvur import api as api_module
    from valvur import operations
    from valvur import runner as runner_module
    from valvur.mcp import jobs

    class Runner:
        def kill(self):
            return 0

    seen: dict = {}
    monkeypatch.setattr(runner_module, "ContainerRunner", Runner)

    def fake_scan(workspace, *, runner, profile, on_progress, jobs=None, budget_s=None):
        seen["canceller"] = jobs_module_current(workspace).canceller
        seen["runner"] = runner
        return api_module.ScanRun(findings=[], profile=profile)

    jobs_module_current = jobs.current
    monkeypatch.setattr(api_module, "scan", fake_scan)
    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)

    jobs.start(tmp_path, "offline", operations._run_scan)
    jobs.current(tmp_path).wait(2)

    assert seen["canceller"].__func__ is Runner.kill
    assert seen["canceller"].__self__ is seen["runner"]


def test_the_tool_is_registered_as_acting_and_shared_with_the_operation():
    """A cancel kills containers and moves a job's state, so it is not read-only
    (27.1.2) — and it writes nothing, of ours or the user's, so it is not
    destructive either (F1.11)."""
    from valvur.mcp.tools import registry
    from valvur.operations import cancel_scan

    [tool] = [t for t in registry() if t.name == "scan_cancel"]

    assert tool.handler is cancel_scan
    assert tool.describe()["annotations"] == {"readOnlyHint": False, "destructiveHint": False}
    assert "workspace" in tool.schema["properties"]


# ------------------------------------------------------------------ --jobs


class _Counting:
    """An adapter that records how many of its kind were running at once."""

    artifact = None
    in_flight = 0
    peak = 0
    lock = threading.Lock()

    def __init__(self, name: str):
        self.name = name

    def applies_to(self, workspace):
        return True, ""

    def run(self, runner, workspace):
        with _Counting.lock:
            _Counting.in_flight += 1
            _Counting.peak = max(_Counting.peak, _Counting.in_flight)
        time.sleep(0.15)
        with _Counting.lock:
            _Counting.in_flight -= 1
        return ScannerOutput(self.name, "1", "[]", "", 0)

    def parse(self, output):
        return []


@pytest.fixture
def counting():
    _Counting.in_flight = 0
    _Counting.peak = 0
    return [_Counting("a"), _Counting("b"), _Counting("c"), _Counting("d")]


def _scan(tmp_path, monkeypatch, adapters, **kwargs):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    workspace = tmp_path / "ws"
    workspace.mkdir(exist_ok=True)
    api.scan(workspace, runner=object(), adapters=adapters, **kwargs)
    return _Counting.peak


def test_jobs_bounds_how_many_scanners_run_at_once(tmp_path, monkeypatch, counting):
    assert _scan(tmp_path, monkeypatch, counting, jobs=1) == 1


def test_the_default_is_the_whole_fleet_at_once(tmp_path, monkeypatch, counting):
    monkeypatch.delenv("VALVUR_JOBS", raising=False)

    assert _scan(tmp_path, monkeypatch, counting) == 4


def test_the_environment_sets_the_default_for_every_surface(tmp_path, monkeypatch, counting):
    """The MCP server takes no flags; `VALVUR_JOBS` in its configuration is how a
    laptop with a small Docker Desktop memory limit says two at a time."""
    monkeypatch.setenv("VALVUR_JOBS", "2")

    assert _scan(tmp_path, monkeypatch, counting) == 2


def test_an_explicit_jobs_beats_the_environment(tmp_path, monkeypatch, counting):
    monkeypatch.setenv("VALVUR_JOBS", "1")

    assert _scan(tmp_path, monkeypatch, counting, jobs=3) == 3


def test_a_nonsense_environment_value_is_ignored_not_fatal(tmp_path, monkeypatch, counting):
    monkeypatch.setenv("VALVUR_JOBS", "many")

    assert _scan(tmp_path, monkeypatch, counting) == 4


def test_the_cli_takes_jobs_and_refuses_zero(monkeypatch, tmp_path, capsys):
    from conftest import FakeRunner

    from valvur import cli

    seen: dict = {}

    def fake_scan(workspace, *, runner, profile, on_progress, jobs=None, budget_s=None):
        seen["jobs"] = jobs
        return api.ScanRun(findings=[], profile=profile)

    monkeypatch.setattr(cli, "scan", fake_scan)
    (tmp_path / "ws").mkdir()

    assert cli.main(["scan", str(tmp_path / "ws"), "--jobs", "2"], runner=FakeRunner()) == 0
    assert seen["jobs"] == 2

    with pytest.raises(SystemExit) as stop:
        cli.main(["scan", str(tmp_path / "ws"), "--jobs", "0"], runner=FakeRunner())
    assert stop.value.code == 2
    assert "--jobs" in capsys.readouterr().err


def test_the_platform_docs_say_why_jobs_exists():
    text = Path("README.md").read_text()

    assert "--jobs" in text and "VALVUR_JOBS" in text
    assert "Docker Desktop" in text.split("--jobs")[0][-1500:] or \
        "Docker Desktop" in text.split("--jobs")[1][:1500]
