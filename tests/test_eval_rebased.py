"""R29.6 (D65a): track 8 re-based on the wider corpus, never recorded as a fall.

The baseline is a ratchet: a track is only ever raised. When the corpus widened from 13
projects to 48, track 8 measured a different thing, so its baseline is re-recorded at
what the wider corpus measures, on both lanes, with the old number and the new beside
the reason. A re-basing is the one way a baseline goes down, and it says so.
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
