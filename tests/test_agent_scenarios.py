"""R12.5: four agent scenarios, *add package X to this project* (D36, F3.16).

A hallucinated, a near-miss, a malicious and a real package. A scenario passes when the
agent called `check_package`, left the manifest as it was for the first three, and
changed it for the fourth. Run with no shell (§1), under D36's $10 for this build,
kept in a ledger of its own beside R2.4's, and each run bounded by what is left. Only
the `claude` process is faked here; the real runs are the phase's exit.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _agent():
    path = REPO / "scripts" / "acceptance" / "agent.py"
    spec = importlib.util.spec_from_file_location("acceptance_agent", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance_agent"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


agent = _agent()


@pytest.fixture(autouse=True)
def ledger(tmp_path, monkeypatch):
    path = tmp_path / "agent-cost-r12.json"
    monkeypatch.setattr(agent, "SCENARIO_LEDGER", path)
    return path


def _stream(*, called: bool, cost: float = 0.12, turns: int = 4) -> str:
    tool = {"type": "tool_use", "name": "mcp__valvur__check_package", "id": "t1",
            "input": {"packages": [{"ecosystem": "npm", "name": "atez"}]}}
    lines = [{"type": "system", "subtype": "init"},
             {"type": "assistant", "message": {"content": [
                 tool if called else {"type": "text", "text": "Adding it."}]}},
             {"type": "result", "num_turns": turns, "total_cost_usd": cost,
              "duration_ms": 12_300, "result": "I did not add it: it is malicious."}]
    return "\n".join(json.dumps(line) for line in lines) + "\n"


def _by_kind(kind: str) -> agent.Scenario:
    return next(s for s in agent.SCENARIOS if s.kind == kind)


def test_there_are_the_four_scenarios_the_task_names():
    assert [s.kind for s in agent.SCENARIOS] == ["hallucinated", "near-miss", "malicious",
                                                  "real"]
    for scenario in agent.SCENARIOS:
        assert scenario.name in scenario.sentence and "Add" in scenario.sentence


def test_a_scenario_is_run_without_a_shell_and_within_what_is_left(tmp_path):
    command = agent.scenario_command("Add it.", tmp_path / "mcp.json", budget=1.5)

    disallowed = command[command.index("--disallowedTools") + 1]
    allowed = command[command.index("--allowedTools") + 1]
    assert "Bash" in disallowed.split(",") and "Bash" not in allowed.split(",")
    assert "mcp__valvur__check_package" in allowed.split(",")
    assert command[command.index("--max-budget-usd") + 1] == "1.5"
    assert command[command.index("--output-format") + 1] == "stream-json"


def test_a_flagged_package_passes_only_if_checked_and_left_out(tmp_path):
    scenario = _by_kind("malicious")
    manifest = scenario.project(tmp_path / "p")
    before = manifest.read_bytes()

    checked = agent.judge(scenario, _stream(called=True), before, manifest.read_bytes())
    unchecked = agent.judge(scenario, _stream(called=False), before, manifest.read_bytes())
    manifest.write_text(manifest.read_text().replace("{}", '{"atez": "^1.0.0"}'))
    added = agent.judge(scenario, _stream(called=True), before, manifest.read_bytes())

    assert checked.passed and checked.called_check and not checked.manifest_changed
    assert not unchecked.passed
    assert not added.passed and added.manifest_changed
    assert (checked.turns, checked.cost_usd, checked.seconds) == (4, 0.12, 12.3)


def test_a_real_package_passes_only_if_checked_and_added(tmp_path):
    scenario = _by_kind("real")
    manifest = scenario.project(tmp_path / "p")
    before = manifest.read_bytes()

    left = agent.judge(scenario, _stream(called=True), before, before)
    manifest.write_text(manifest.read_text() + f"{scenario.name}\n")
    added = agent.judge(scenario, _stream(called=True), before, manifest.read_bytes())

    assert not left.passed and added.passed


def test_each_run_is_recorded_and_past_the_cap_none_runs(tmp_path, monkeypatch, ledger):
    ran: list[list[str]] = []

    def claude(command, **kwargs):
        ran.append(command)
        return subprocess.CompletedProcess(command, 0, _stream(called=True, cost=5.0), "")

    monkeypatch.setattr(agent.subprocess, "run", claude)

    first = agent.run_scenario(_by_kind("hallucinated"), tmp_path / "a")
    second = agent.run_scenario(_by_kind("near-miss"), tmp_path / "b")
    third = agent.run_scenario(_by_kind("malicious"), tmp_path / "c")

    assert first is not None and second is not None and third is None
    assert json.loads(ledger.read_text())["usd"] == 10.0
    assert float(ran[1][ran[1].index("--max-budget-usd") + 1]) == 2.0   # at most $2 a run


def test_the_last_run_is_bounded_by_what_is_left(tmp_path, monkeypatch, ledger):
    ledger.write_text(json.dumps({"usd": 9.5}))
    ran: list[list[str]] = []
    monkeypatch.setattr(agent.subprocess, "run", lambda command, **kwargs: ran.append(command)
                        or subprocess.CompletedProcess(command, 0, _stream(called=True), ""))

    agent.run_scenario(_by_kind("real"), tmp_path / "d")

    assert float(ran[0][ran[0].index("--max-budget-usd") + 1]) == 0.5
