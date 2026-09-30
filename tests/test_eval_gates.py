"""R9.3: the Score's gates (ADR-0026, D21).

Pass or fail, beside the tracks: offline, honesty, freshness, ranking and speed.
Each is judged from the phase that builds what it checks and recorded before, so
R9's baseline records a stale KEV without failing a phase that cannot fix it yet.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "eval.py"


def _harness():
    spec = importlib.util.spec_from_file_location("valvur_eval", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["valvur_eval"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _track(**overrides) -> dict:
    return {"score": 50.0, "complete": True, "status": "findings",
            "what_left_the_machine": "nothing", "safe_flagged_high": [],
            "seconds": 5.0, **overrides}


FRESH = {"database_age_days": 1.0, "name_index_age_days": 1.0, "kev_age_days": 1.0}
CLOSED_R9_TO_R11 = "\n".join(f"- [x] **R{p}.1** **t**" for p in (9, 10, 11)) + \
    "\n- [ ] **R14.1** **t**\n"


def test_each_gate_passes_on_a_clean_offline_fresh_honest_run():
    gates = _harness().judge_gates(
        {"secrets": _track()}, FRESH, ranking_first=True, tasks_text=CLOSED_R9_TO_R11)

    assert {name: (g["judged"], g["ok"]) for name, g in gates.items()} == {
        "offline": (True, True), "honesty": (True, True), "freshness": (True, True),
        "ranking": (True, True), "speed": (False, True)}


def test_each_gate_names_what_failed():
    gates = _harness().judge_gates(
        {"secrets": _track(what_left_the_machine="lockfile names to osv.dev"),
         "dependencies": _track(status="clean", complete=False,
                                safe_flagged_high=["deps/pip/requests-2.20.0"])},
        {**FRESH, "kev_age_days": 33.0}, ranking_first=False, tasks_text=CLOSED_R9_TO_R11)

    assert not gates["offline"]["ok"] and "secrets" in gates["offline"]["reason"]
    assert not gates["honesty"]["ok"]
    assert "clean while incomplete: dependencies" in gates["honesty"]["reason"]
    assert "deps/pip/requests-2.20.0" in gates["honesty"]["reason"]
    assert not gates["freshness"]["ok"] and "kev 33.0 days" in gates["freshness"]["reason"]
    assert not gates["ranking"]["ok"]


def test_a_gate_is_recorded_not_judged_until_its_phase_closes():
    gates = _harness().judge_gates(
        {"secrets": _track()}, {**FRESH, "kev_age_days": 33.0}, ranking_first=True,
        tasks_text="- [x] **R9.1** **t**\n- [ ] **R10.1** **t**\n- [ ] **R11.1** **t**\n")

    assert gates["offline"]["judged"] is True
    assert (gates["freshness"]["judged"], gates["freshness"]["ok"]) == (False, False)
    assert gates["freshness"]["from"] == "R11"


def test_a_run_without_the_dependencies_track_does_not_judge_ranking():
    """`--tracks real-code-precision` scans no ranking fixture. The gate records
    that it was not measured, and is not judged: failing it would fail every partial
    run once R11 closed, for a fixture nobody asked it to scan."""
    gates = _harness().judge_gates(
        {"real-code-precision": _track()}, FRESH, ranking_first=None,
        tasks_text=CLOSED_R9_TO_R11)

    assert gates["ranking"]["judged"] is False
    assert gates["ranking"]["reason"] == "the ranking fixture was not scanned"
    assert gates["offline"]["judged"] is True


def test_the_speed_gate_is_the_median_warm_scan_within_110_percent_of_the_baseline():
    """R14.5, D21: judged from R14 when an acceptance report is given; without one
    the speed is not measured, and not judged."""
    harness = _harness()
    closed = CLOSED_R9_TO_R11.replace("- [ ] **R14.1**", "- [x] **R14.1**")
    baseline = {"speed": {"linux": 5.0, "mac": 6.0}}

    def gate(median, platform):
        speed = harness.speed_of({"median_rescan_s": median,
                                  "platform": {"platform": platform}}, baseline)
        return harness.judge_gates({"secrets": _track()}, FRESH, ranking_first=True,
                                   tasks_text=closed, speed=speed)["speed"]

    fast, slow = gate(5.4, "Linux 6.8 x86_64"), gate(7.0, "Darwin 25.6.0 arm64")
    unmeasured = harness.judge_gates({"secrets": _track()}, FRESH, ranking_first=True,
                                     tasks_text=closed)["speed"]

    assert (fast["judged"], fast["ok"]) == (True, True)
    assert (slow["judged"], slow["ok"]) == (True, False)
    assert "7.0 s against 6.0 s" in slow["reason"]
    assert unmeasured["judged"] is False
