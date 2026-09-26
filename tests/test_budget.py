"""Task 23.3.7 — a scan budget.

Each Scanner has a 600s timeout and the run had none: an agent session with a
runaway Checkov waited ten minutes for one Scanner. Past the budget no new Scanner
starts, the running ones are stopped, and the run is reported incomplete with the
ones it cut named — on every surface a failed Scanner already reaches.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

from valvur import api
from valvur.runner import ScannerOutput


class _Adapter:
    """A Scanner that takes `seconds`, unless the runner stops it first."""

    artifact = None

    def __init__(self, name: str, seconds: float):
        self.name = name
        self.seconds = seconds

    def applies_to(self, workspace):
        return True, ""

    def run(self, runner, workspace):
        if runner.stopped.wait(timeout=self.seconds):
            return ScannerOutput(self.name, "1", "", "killed", 137)
        return ScannerOutput(self.name, "1", "[]", "", 0)

    def parse(self, output):
        return []


class _Runner:
    """Stops its fleet the way the real one does — every running Scanner comes
    back with exit 137 and no report — and remembers being asked."""

    image = "x/y:1"
    runtime = "/usr/local/bin/docker"

    def __init__(self):
        self.stopped = threading.Event()
        self.stops = 0
        self.cancelled = False

    def stop_containers(self) -> int:
        self.stops += 1
        self.stopped.set()
        return 2


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def _scan(workspace, runner, adapters, **kwargs):
    said: list[str] = []
    run = api.scan(workspace, runner=runner, adapters=adapters, on_progress=said.append,
                   **kwargs)
    return run, said


# ------------------------------------------------------------- the cut itself


def test_past_the_budget_running_scanners_are_stopped_and_queued_ones_never_start(workspace):
    runner = _Runner()
    # Two workers: `fast` finishes and `slow2` takes its place, so at the cut both
    # slow ones are running and `queued` has not started.
    adapters = [_Adapter("fast", 0.05), _Adapter("slow", 5.0), _Adapter("slow2", 5.0),
                _Adapter("queued", 0.05)]

    started = time.monotonic()
    run, said = _scan(workspace, runner, adapters, budget_s=0.4, jobs=2)
    elapsed = time.monotonic() - started

    assert elapsed < 3, "the budget did not stop the slow Scanners"
    assert runner.stops == 1
    by_tool = {s.tool: s for s in run.scanners}
    assert by_tool["fast"].ok
    for tool in ("slow", "slow2"):
        assert not by_tool[tool].ok
        assert by_tool[tool].reason.startswith("cut by the 0.4s budget after ")
        # The cut is the cause (29.0.3): the exit code the kill produced is not
        # repeated inside it as if the runtime had done it.
        assert "137" not in by_tool[tool].reason
    assert not by_tool["queued"].ok
    assert by_tool["queued"].reason == "not started: the 0.4s budget was spent before its turn"
    assert [f.tool for f in run.failures] == ["slow", "slow2", "queued"]
    assert run.budget_s == 0.4 and sorted(run.budget_cut) == ["queued", "slow", "slow2"]
    assert any(line.startswith("budget spent after ") and "stopping slow, slow2" in line
               and "not starting queued" in line for line in said), said


def test_a_run_within_its_budget_is_untouched(workspace):
    runner = _Runner()

    run, said = _scan(workspace, runner, [_Adapter("a", 0.05), _Adapter("b", 0.05)],
                      budget_s=5.0)

    assert not run.failures
    assert runner.stops == 0
    assert run.budget_s == 5.0 and run.budget_cut == []
    assert not any("budget" in line for line in said)


def test_no_budget_means_no_cut_however_long(workspace):
    runner = _Runner()

    run, _ = _scan(workspace, runner, [_Adapter("a", 0.05), _Adapter("b", 0.6)])

    assert not run.failures
    assert run.budget_s is None


def test_the_cut_is_reported_incomplete_on_every_surface(workspace):
    """The same paths a crashed Scanner takes: run.json, SUMMARY.md's failures
    section, and scan_status through both — with the budget named."""
    from valvur.operations import scan_status

    runner = _Runner()
    _scan(workspace, runner, [_Adapter("ok", 0.05), _Adapter("slow", 5.0)], budget_s=0.3)

    run = json.loads((workspace / ".security-scan" / "run.json").read_text())
    assert run["complete"] is False
    assert run["budget"] == {"seconds": 0.3, "cut": ["slow"]}
    summary = (workspace / ".security-scan" / "SUMMARY.md").read_text()
    assert "## ⚠ Scanners that did not complete" in summary
    assert "**slow** — cut by the 0.3s budget" in summary
    status = scan_status({"workspace": str(workspace)})
    assert "slow: FAILED — cut by the 0.3s budget" in status
    assert "This scan was INCOMPLETE" in status


def test_a_runner_that_cannot_stop_containers_still_cuts_what_has_not_started(workspace):
    """The suite's fakes have no `stop_containers`; the running Scanner is waited
    for and the queued one is still refused, so the budget bounds new work even
    where it cannot interrupt old."""
    class Bare:
        pass

    class Plain(_Adapter):
        def run(self, runner, workspace):
            time.sleep(self.seconds)
            return ScannerOutput(self.name, "1", "[]", "", 0)

    run, _ = _scan(workspace, Bare(), [Plain("slow", 0.5), Plain("queued", 0.05)],
                   budget_s=0.2, jobs=1)

    by_tool = {s.tool: s for s in run.scanners}
    assert by_tool["slow"].ok, "it finished; nothing could stop it, and its result is real"
    assert by_tool["queued"].reason.startswith("not started: the 0.2s budget")


def test_a_scanner_that_finishes_anyway_after_the_cut_is_a_result_not_a_casualty(workspace):
    """Between the budget expiring and the kill landing, a Scanner can complete on
    its own. Its report is real and it is not named as cut."""
    class Finisher(_Adapter):
        def run(self, runner, workspace):
            time.sleep(self.seconds)          # ignores the stop, finishes cleanly
            return ScannerOutput(self.name, "1", "[]", "", 0)

    runner = _Runner()

    run, _ = _scan(workspace, runner, [Finisher("finisher", 0.4)], budget_s=0.15)

    assert runner.stops == 1
    [scanner] = run.scanners
    assert scanner.ok and scanner.reason == ""
    assert run.budget_cut == [] and not run.failures


def test_a_budget_cut_is_not_a_cancel(workspace):
    """Cancelling writes nothing (F1.11); a cut writes an incomplete result — the
    Scanners that finished are a result, and the ones that did not are named."""
    runner = _Runner()

    run, _ = _scan(workspace, runner, [_Adapter("ok", 0.05), _Adapter("slow", 5.0)],
                   budget_s=0.3)

    assert runner.cancelled is False
    assert (workspace / ".security-scan" / "run.json").exists()
    assert [s.tool for s in run.scanners if s.ok] == ["ok"]


def test_a_budget_must_be_positive(workspace):
    with pytest.raises(ValueError, match="budget"):
        api.scan(workspace, runner=_Runner(), adapters=[_Adapter("a", 0.05)], budget_s=0)


# ------------------------------------------------------------- the two surfaces


def test_mcp_scans_default_to_f2_6s_five_minutes_and_a_client_may_change_it(tmp_path, monkeypatch):
    from valvur import api as api_module
    from valvur import operations
    from valvur import runner as runner_module
    from valvur.mcp import jobs

    seen: list = []

    class Runner:
        def kill(self):
            return 0

    monkeypatch.setattr(runner_module, "ContainerRunner", Runner)

    def fake_scan(workspace, *, runner, profile, on_progress, budget_s=None, **kw):
        seen.append(budget_s)
        return api_module.ScanRun(findings=[], profile=profile)

    monkeypatch.setattr(api_module, "scan", fake_scan)
    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)

    jobs.start(tmp_path, "offline", operations._run_scan)
    jobs.current(tmp_path).wait(2)
    jobs.reset()
    jobs.start(tmp_path, "offline", operations._scan_with_budget(90))
    jobs.current(tmp_path).wait(2)
    jobs.reset()
    jobs.start(tmp_path, "offline", operations._scan_with_budget(0))
    jobs.current(tmp_path).wait(2)
    jobs.reset()

    assert seen == [300.0, 90.0, None]
    assert operations.MCP_BUDGET_S == 300


def test_the_scan_tool_accepts_a_budget(tmp_path, monkeypatch):
    from valvur.mcp import jobs
    from valvur.mcp.tools import registry
    from valvur.operations import start_scan

    [tool] = [t for t in registry() if t.name == "scan"]
    assert tool.schema["properties"]["budget_s"]["type"] == "integer"

    started: list = []
    monkeypatch.setattr(jobs, "start", lambda workspace, profile, run: started.append(run))
    start_scan({"workspace": str(tmp_path), "budget_s": 45})
    start_scan({"workspace": str(tmp_path)})

    assert started[0].budget_s == 45.0
    assert started[1].budget_s == 300.0


def test_the_cli_has_no_budget_unless_asked(monkeypatch, tmp_path, capsys):
    from conftest import FakeRunner

    from valvur import cli

    seen: list = []

    def fake_scan(workspace, *, runner, profile, on_progress, jobs=None, budget_s=None):
        seen.append(budget_s)
        return api.ScanRun(findings=[], profile=profile)

    monkeypatch.setattr(cli, "scan", fake_scan)
    (tmp_path / "ws").mkdir()

    assert cli.main(["scan", str(tmp_path / "ws")], runner=FakeRunner()) == 0
    assert cli.main(["scan", str(tmp_path / "ws"), "--budget", "120"], runner=FakeRunner()) == 0
    with pytest.raises(SystemExit):
        cli.main(["scan", str(tmp_path / "ws"), "--budget", "0"], runner=FakeRunner())

    assert seen == [None, 120.0]
    assert "--budget" in capsys.readouterr().err


def test_the_real_runner_can_stop_its_fleet_without_cancelling(monkeypatch):
    import subprocess

    import valvur.runner as runner_module
    from valvur.runner import ContainerRunner

    killed: list[str] = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: killed.extend(cmd[2:]) or
                        subprocess.CompletedProcess(cmd, 0, "", ""))
    runner = ContainerRunner(image="x/y:1", runtime="/usr/local/bin/docker")
    runner._mine.add("valvur-a")
    with runner_module._live_lock:
        runner_module._live_containers.add("valvur-a")
    try:
        stopped = runner.stop_containers()
    finally:
        with runner_module._live_lock:
            runner_module._live_containers.discard("valvur-a")

    assert stopped == 1 and killed == ["valvur-a"]
    assert runner.cancelled is False
