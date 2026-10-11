"""R29.6 (D65a) and R41.3 (D80b): re-basings, never recorded as a fall or a rise.

The baseline is a ratchet: a track is only ever raised. When the corpus widened from 13
projects to 48, track 8 measured a different thing, so its baseline is re-recorded at
what the wider corpus measures, on both lanes, with the old number and the new beside
the reason. A re-basing is the one way a baseline goes down, and it says so. A track
added re-bases the Score the same way: its mean before beside its mean after.
"""

from __future__ import annotations

import json
from pathlib import Path

BASELINE = Path(__file__).resolve().parent / "eval" / "baseline.json"


def _baseline() -> dict:
    return json.loads(BASELINE.read_text())


def test_track_8_is_rebased_on_the_wider_corpus_with_both_numbers_on_both_lanes():
    baseline = _baseline()
    entry = next((e for e in baseline.get("rebased", []) if e["at"] == "R29.6"), None)

    assert entry, "no re-basing recorded for R29.6"
    assert entry["corpus"] == [13, 48] and entry["why"]
    assert entry["tracks"] == {"real-code-precision": {"linux": [5.9, 2.3], "mac": [5.9, 2.3]}}
    assert baseline["tracks"]["real-code-precision"] == 2.3
    assert baseline["mac"]["tracks"]["real-code-precision"] == 2.3


def test_each_lanes_score_is_the_mean_of_its_tracks():
    baseline = _baseline()
    for lane in (baseline, baseline["mac"]):
        tracks = lane["tracks"].values()
        assert lane["score"] == round(sum(tracks) / len(tracks), 1)


def test_track_9_is_added_and_the_score_re_based_with_both_numbers_on_both_lanes():
    """R41.3 (D80b): a ninth track changes what the Score is a mean of, so the Score is
    re-based, not raised: its value over eight tracks beside its value over nine, on
    each lane, and track 9 recorded as new."""
    baseline = _baseline()
    entry = next((e for e in baseline.get("rebased", []) if e["at"] == "R41.3"), None)

    assert entry, "no re-basing recorded for R41.3"
    assert entry["why"]
    for lane, tracks in (("linux", baseline["tracks"]), ("mac", baseline["mac"]["tracks"])):
        before, after = entry["tracks"]["llm-output"][lane]
        assert before is None and after == tracks["llm-output"], lane
        assert entry["score"][lane][0] == 73.4, lane
    assert entry["score"]["linux"][1] == baseline["score"]
    assert entry["score"]["mac"][1] == baseline["mac"]["score"]
