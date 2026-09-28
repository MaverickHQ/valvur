"""R3.5: one deadline and one kill (F1.11, F2.7; ADR-0022).

The engine enforces the budget itself and writes what it cut; the host enforces a
grace past it by killing the engine; a cancel is one kill, confirmed.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from valvur.engine_host import LocalRuntime, snapshot
from valvur.invocation import Invocation

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"


def _tree(tmp_path: Path) -> tuple[Path, bytes]:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")
    return ws, snapshot(ws, ["app.py"])


def _sleepers(*seconds: float) -> list[Invocation]:
    return [Invocation(tool=f"t{i}", version="0", report=f"t{i}.json", timeout=60,
                       argv=("fake-sleep", str(s), f"/results/t{i}.json"))
            for i, s in enumerate(seconds)]


def test_at_the_budget_the_engine_stops_what_runs_and_names_each_cut(tmp_path):
    _ws, tar = _tree(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    started = time.monotonic()
    LocalRuntime(FAKE_TOOLS).run(_sleepers(0, 30), tar, scratch, budget_s=1.0)
    assert time.monotonic() - started < 10
    manifest = json.loads((scratch / "manifest.json").read_text())
    by_tool = {e["tool"]: e for e in manifest["tools"]}
    assert by_tool["t0"].get("cut") is not True and by_tool["t0"]["exit_code"] == 0
    assert by_tool["t1"]["cut"] is True


class _Slow:
    """A Scanner whose tool sleeps past any test budget."""

    kind = "scanner"
    name = "slow"
    version = "0"

    def applies_to(self, workspace):
        return True, ""

    def command(self, workspace):
        return Invocation(tool="slow", version="0", report="slow.json", timeout=60,
                          argv=("fake-sleep", "30", "/results/slow.json"))

    def parse(self, output):
        return []

    def for_profile(self, *, network):
        return self


def test_a_budget_cut_through_the_engine_names_the_cut_and_keeps_what_finished(
        tmp_path, monkeypatch):
    from valvur import api
    from valvur.adapters import GitleaksAdapter

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws, _tar = _tree(tmp_path)
    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS),
                   adapters=[GitleaksAdapter(), _Slow()], budget_s=1.0)
    by_tool = {s.tool: s for s in run.scanners}
    assert by_tool["gitleaks"].ok
    assert by_tool["slow"].reason.startswith("cut by the 1s budget after")
    assert run.budget_cut == ["slow"]


def test_when_the_budget_cuts_everything_the_refusal_names_the_levers(tmp_path, monkeypatch):
    from valvur import api

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws, _tar = _tree(tmp_path)
    with pytest.raises(api.BudgetExhausted):
        api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[_Slow()], budget_s=1.0)


def test_past_its_grace_the_host_kills_the_engine_and_everything_it_started(tmp_path):
    import os

    from valvur.engine_host import stream

    pidfile = tmp_path / "pid"
    started = time.monotonic()
    code = stream([str(FAKE_TOOLS / "fake-spawn"), str(pidfile)], b"", None, None,
                  deadline_s=1.0)
    assert time.monotonic() - started < 10
    assert code != 0
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(int(pidfile.read_text()), 0)


def _gone(pid: int, within: float = 5.0) -> bool:
    """True once `pid` no longer exists; an orphan is reaped by init, not at once."""
    import os

    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


class _Spawner(_Slow):
    """A Scanner whose tool starts a grandchild, writes its pid, and sleeps."""

    name = "spawner"

    def __init__(self, pidfile: Path):
        self.pidfile = pidfile

    def command(self, workspace):
        return Invocation(tool="spawner", version="0", report="spawner.json", timeout=60,
                          argv=("fake-spawn", str(self.pidfile)))


def _grandchild(pidfile: Path, within: float = 15.0) -> int:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if pidfile.exists() and pidfile.read_text().strip():
            return int(pidfile.read_text())
        time.sleep(0.05)
    raise AssertionError("the tool never started")


def test_a_cancel_is_one_kill_and_nothing_the_engine_started_survives_it(
        tmp_path, monkeypatch):
    import threading

    from valvur import api

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws, _tar = _tree(tmp_path)
    pidfile = tmp_path / "grandchild.pid"
    runtime = LocalRuntime(FAKE_TOOLS)
    raised: list[BaseException] = []

    def scan() -> None:
        try:
            api.scan(ws, runner=runtime, adapters=[_Spawner(pidfile)])
        except BaseException as exc:          # the test reads what it was
            raised.append(exc)

    worker = threading.Thread(target=scan, daemon=True)
    worker.start()
    grandchild = _grandchild(pidfile)
    assert runtime.kill() == 1
    worker.join(20)
    assert not worker.is_alive()
    assert isinstance(raised[0], api.ScanCancelled)
    assert _gone(grandchild)


def test_a_cancel_before_the_engine_starts_starts_nothing(tmp_path, monkeypatch):
    from valvur import api

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws, _tar = _tree(tmp_path)
    pidfile = tmp_path / "grandchild.pid"
    runtime = LocalRuntime(FAKE_TOOLS)
    assert runtime.kill() == 0
    with pytest.raises(api.ScanCancelled):
        api.scan(ws, runner=runtime, adapters=[_Spawner(pidfile)])
    assert not pidfile.exists()


def test_scan_cancel_over_mcp_says_cancelled_only_once_the_engine_is_gone(
        tmp_path, monkeypatch):
    from valvur import api, cache, engine_host, operations
    from valvur.mcp import jobs

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.setattr(cache, "db_present", lambda: True)
    ws, _tar = _tree(tmp_path)
    pidfile = tmp_path / "grandchild.pid"
    runtimes: list[LocalRuntime] = []

    def local() -> LocalRuntime:
        runtimes.append(LocalRuntime(FAKE_TOOLS))
        return runtimes[-1]

    monkeypatch.setattr(engine_host, "for_scan", local)
    spawner = _Spawner(pidfile)
    spawner.name = "gitleaks"          # a name the `offline` Profile runs
    monkeypatch.setattr(api, "DEFAULT_ADAPTERS", [spawner])
    jobs.reset()
    try:
        operations.start_scan({"workspace": str(ws)})
        grandchild = _grandchild(pidfile)
        operations.cancel_scan({"workspace": str(ws)})
        job = jobs.current(ws.resolve())
        assert job is not None and job.wait(20)
        assert job.state is jobs.State.CANCELLED
        assert runtimes[0].wait_stopped(timeout=0)
        assert _gone(grandchild)
    finally:
        jobs.reset()
