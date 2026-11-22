"""R48.2: the real-code track says which rule, and which Scanner, each number is (D82a).

The eighth track gave one number for 171 Findings. The bar of R49 is set rule by rule, so
the track's report gains `by_rule`, for each rule with a judged Finding, and `by_scanner`,
for every Scanner that found anything on the corpus. The track's own score does not move:
it judges what it judged. The scan is faked, as `tests/test_eval_run.py` fakes it.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from test_eval_run import _harness, _results


def _finding(fingerprint: str, rule: str, scanner: str, **more) -> dict:
    return {"fingerprint": fingerprint, "rule": rule, "path": f"{fingerprint}.py",
            "sources": [scanner], "suppressed": None, "status": "new", **more}


FOUND = {
    "flask": [_finding("f1", "valvur.python.weak-hash", "opengrep"),
              _finding("f2", "private-key", "gitleaks"),
              _finding("f3", "jwt", "gitleaks"),
              _finding("f4", "CVE-2026-0001", "trivy"),
              _finding("f5", "CKV_GHA_7", "checkov"),
              _finding("f6", "valvur.python.weak-hash", "opengrep", inventory=True)],
    "django": [_finding("d1", "valvur.python.weak-hash", "opengrep"),
               _finding("d2", "valvur.python.sql-injection", "opengrep"),
               _finding("d3", "CVE-2026-0002", "osv-scanner")],
    "sanic": [], "litestar": [], "undici": [],
}
VERDICTS = {("flask", "f1"): "fp", ("flask", "f2"): "fp", ("flask", "f3"): "tp",
            ("django", "d1"): "fp", ("django", "d2"): "tp"}


def _track(tmp_path: Path, *, jobs: int = 1, scan=None, found: dict | None = None) -> dict:
    harness, found = _harness(), FOUND if found is None else found
    checkouts = tmp_path / "checkouts"
    for name in found:
        (checkouts / name).mkdir(parents=True, exist_ok=True)
    labels = tmp_path / "labels.toml"
    labels.write_text("".join(
        f'[[label]]\nrepo = "{repo}"\nfingerprint = "{fp}"\nrule = "r"\nverdict = "{verdict}"\n'
        f'reason = "read"\n' for (repo, fp), verdict in VERDICTS.items()))
    hygiene = tmp_path / "hygiene.toml"
    hygiene.write_text('[[label]]\nrepo = "flask"\nfingerprint = "f5"\nrule = "CKV_GHA_7"\n'
                       'verdict = "tp"\nreason = "read"\n')
    result = harness.run(
        ["real-code-precision"], tmp_path / "work", image="valvur:dev",
        scan=scan or (lambda root: _results(root, found[root.name])),
        image_id=lambda image: "sha256:abc", corpus=[{"name": name} for name in found],
        checkouts=checkouts, labels=labels, hygiene=hygiene, jobs=jobs)
    return result["tracks"]["real-code-precision"]


def test_the_tracks_own_numbers_are_what_they_were(tmp_path):
    """By hand: 2 true and 3 false of the judged, so 100 * (2 + 1) / (2 + 3 + 1)."""
    track = _track(tmp_path)

    assert (track["score"], track["tp"], track["fp"]) == (50.0, 2, 3)
    assert track["others"] == {"checkov": 1, "osv-scanner": 1, "trivy": 1}


def test_each_judged_rule_has_its_scanner_and_its_counts(tmp_path):
    assert _track(tmp_path)["by_rule"] == [
        {"scanner": "gitleaks", "rule": "jwt", "tp": 1, "fp": 0},
        {"scanner": "gitleaks", "rule": "private-key", "tp": 0, "fp": 1},
        {"scanner": "opengrep", "rule": "valvur.python.sql-injection", "tp": 1, "fp": 0},
        {"scanner": "opengrep", "rule": "valvur.python.weak-hash", "tp": 0, "fp": 2}]


def test_each_scanner_has_its_findings_and_how_many_were_judged(tmp_path):
    assert _track(tmp_path)["by_scanner"] == {
        "checkov": {"findings": 1, "judged": 1, "tp": 1, "fp": 0},
        "gitleaks": {"findings": 2, "judged": 2, "tp": 1, "fp": 1},
        "opengrep": {"findings": 3, "judged": 3, "tp": 1, "fp": 2},
        "osv-scanner": {"findings": 1, "judged": 0, "tp": 0, "fp": 0},
        "trivy": {"findings": 1, "judged": 0, "tp": 0, "fp": 0}}


def test_a_baseline_written_before_these_keys_still_compares(tmp_path):
    harness = _harness()
    track = _track(tmp_path)

    assert harness.compare({"tracks": {"real-code-precision": track}, "gates": {}},
                           {"tracks": {"real-code-precision": 50.0}}) == []


def test_four_jobs_scan_four_at_a_time_and_give_the_same_report(tmp_path):
    at_once, most, lock = [0], [0], threading.Lock()

    def scan(root: Path) -> None:
        with lock:
            at_once[0] += 1
            most[0] = max(most[0], at_once[0])
        time.sleep(0.05)
        _results(root, FOUND[root.name])
        with lock:
            at_once[0] -= 1

    four = _track(tmp_path / "four", jobs=4, scan=scan)
    seen = most[0]
    most[0] = 0
    one = _track(tmp_path / "one", jobs=1, scan=scan)

    assert 1 < seen <= 4 and most[0] == 1
    assert {k: v for k, v in four.items() if k != "seconds"} == {
        k: v for k, v in one.items() if k != "seconds"}


def test_a_project_whose_scan_fails_under_four_jobs_is_named_and_the_track_is_incomplete(
        tmp_path):
    def scan(root: Path) -> None:
        if root.name == "sanic":
            raise RuntimeError("the container was killed")
        if root.name != "undici":
            _results(root, FOUND[root.name])

    track = _track(tmp_path, jobs=4, scan=scan)

    assert track["complete"] is False
    assert track["incomplete"] == ["sanic", "undici"]
    assert (track["tp"], track["fp"]) == (2, 3)
    assert _track(tmp_path / "again", jobs=1, scan=scan)["incomplete"] == ["sanic", "undici"]
