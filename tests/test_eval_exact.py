"""R45.6: the Score compared exactly, for a release no one reads first (Requirement 21.3).

The ratchet lets a track fall up to 2 points, and lets it rise freely: a change is expected
to move the Score, and the owner reads by how much. An image patch that releases itself
must not move it at all, in either direction, since a Score that moved means valvur reports
something else. `scripts/eval.py --compare … --exact` fails on any difference.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "eval"))
_spec = importlib.util.spec_from_file_location("valvur_eval", REPO / "scripts" / "eval.py")
evaluate = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules["valvur_eval"] = evaluate
_spec.loader.exec_module(evaluate)  # type: ignore[union-attr]

BASELINE = {"tracks": {"secrets": 100.0, "sast-python": 40.9, "real-code-precision": 2.3}}


def _result(**scores: float) -> dict:
    tracks = {**BASELINE["tracks"], **{name.replace("_", "-"): score
                                       for name, score in scores.items()}}
    return {"tracks": {name: {"score": score} for name, score in tracks.items()}, "gates": {}}


def test_every_track_at_its_baseline_passes_exactly():
    assert evaluate.compare(_result(), BASELINE, exact=True) == []


def test_a_track_above_its_baseline_fails_exactly_and_passes_the_ratchet():
    result = _result(sast_python=41.0)

    assert evaluate.compare(result, BASELINE) == []
    assert evaluate.compare(result, BASELINE, exact=True) == [
        "sast-python: 41.0, not its baseline of 40.9 exactly"]


def test_a_track_below_by_less_than_the_ratchets_tolerance_fails_exactly():
    result = _result(sast_python=40.8)

    assert evaluate.compare(result, BASELINE) == []
    assert evaluate.compare(result, BASELINE, exact=True) == [
        "sast-python: 40.8, not its baseline of 40.9 exactly"]


def test_a_track_that_was_not_measured_fails_exactly():
    result = _result()
    del result["tracks"]["real-code-precision"]

    assert evaluate.compare(result, BASELINE) == []
    assert evaluate.compare(result, BASELINE, exact=True) == [
        "real-code-precision: not measured, and its baseline is 2.3"]


def test_the_flag_is_on_the_command_line_and_needs_a_baseline(capsys):
    assert evaluate.main(["--exact"]) == 2
    assert "--exact needs --compare" in capsys.readouterr().err
