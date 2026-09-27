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
