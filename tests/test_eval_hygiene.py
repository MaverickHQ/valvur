"""R48.3: Checkov's and zizmor's Findings on the corpus, in a table of their own (D82a, D82b).

The eighth track judges valvur's rules, the vendored ones and Gitleaks. Checkov and zizmor
gave 776 Findings on the corpus that nobody had judged. They are not pooled into the track:
most say a fact about a file, true by reading it, and would carry the number past its target
with nothing changed in valvur. They get a table, `hygiene`, by rule, with labels in
`tests/eval/labels/hygiene.toml`. A rule with more than 25 Findings is judged on the 25 with
the lowest Fingerprints, and says it was sampled.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_eval_by_rule import _finding
from test_eval_run import _harness, _results


def _labels(path: Path, verdicts: dict[tuple[str, str], str], **changed: str) -> Path:
    path.write_text("".join(
        f'[[label]]\nrepo = "{repo}"\nfingerprint = "{fp}"\nrule = "r"\nverdict = "{verdict}"\n'
        f'reason = "read"\n' + (f'changed = "{changed[fp]}"\n' if fp in changed else "")
        for (repo, fp), verdict in verdicts.items()))
    return path


def _track(tmp_path: Path, found: dict[str, list[dict]], hygiene: dict[tuple[str, str], str],
           corpus: dict[tuple[str, str], str] | None = None) -> tuple[object, dict]:
    harness = _harness()
    checkouts = tmp_path / "checkouts"
    for name in found:
        (checkouts / name).mkdir(parents=True, exist_ok=True)
    result = harness.run(
        ["real-code-precision"], tmp_path / "work", image="valvur:dev",
        scan=lambda root: _results(root, found[root.name]),
        image_id=lambda image: "sha256:abc", corpus=[{"name": name} for name in found],
        checkouts=checkouts, labels=_labels(tmp_path / "corpus.toml", corpus or {}),
        hygiene=_labels(tmp_path / "hygiene.toml", hygiene))
    return harness, result


def test_a_labelled_checkov_finding_is_counted_under_hygiene_and_the_track_does_not_move(tmp_path):
    found = {"flask": [_finding("c1", "CKV_DOCKER_2", "checkov"),
                       _finding("c2", "CKV_DOCKER_2", "checkov"),
                       _finding("z1", "unpinned-uses", "zizmor"),
                       _finding("g1", "private-key", "gitleaks")]}

    hygiene = {("flask", "c1"): "tp", ("flask", "c2"): "fp", ("flask", "z1"): "tp"}

    _, result = _track(tmp_path, found, hygiene, {("flask", "g1"): "fp"})

    track = result["tracks"]["real-code-precision"]
    assert track["hygiene"] == [
        {"scanner": "checkov", "rule": "CKV_DOCKER_2", "findings": 2, "judged": 2, "tp": 1,
         "fp": 1, "sampled": False},
        {"scanner": "zizmor", "rule": "unpinned-uses", "findings": 1, "judged": 1, "tp": 1,
         "fp": 0, "sampled": False}]
    assert (track["score"], track["tp"], track["fp"]) == (50.0, 0, 1)
    assert track["unlabelled"] == [] and track["hygiene_unlabelled"] == []


def test_of_a_rules_26_findings_the_25_lowest_fingerprints_are_judged(tmp_path):
    prints = [f"{n:02d}" for n in range(26)]
    found = {"flask": [_finding(fp, "unpinned-uses", "zizmor") for fp in reversed(prints[:13])],
             "django": [_finding(fp, "unpinned-uses", "zizmor") for fp in prints[13:]]}
    labels = {("flask" if n < 13 else "django", fp): "tp" for n, fp in enumerate(prints[:25])}

    harness, result = _track(tmp_path, found, labels)

    track = result["tracks"]["real-code-precision"]
    assert track["hygiene"] == [{"scanner": "zizmor", "rule": "unpinned-uses", "findings": 26,
                                 "judged": 25, "tp": 25, "fp": 0, "sampled": True}]
    assert track["hygiene_unlabelled"] == [], "the 26th needs no label"
    assert harness.compare(result, {"tracks": {}}) == []


def test_a_dependency_scanners_finding_is_never_looked_up(tmp_path):
    found = {"flask": [_finding("t1", "CVE-2026-0001", "trivy"),
                       _finding("o1", "CVE-2026-0002", "osv-scanner")]}

    _, result = _track(tmp_path, found, {("flask", "t1"): "fp"}, {("flask", "o1"): "fp"})

    track = result["tracks"]["real-code-precision"]
    assert track["hygiene"] == [] and (track["tp"], track["fp"]) == (0, 0)
    assert track["by_scanner"]["trivy"] == {"findings": 1, "judged": 0, "tp": 0, "fp": 0}


def test_a_judged_finding_with_no_label_fails_the_comparison_naming_it(tmp_path):
    found = {"flask": [_finding("c1", "CKV_DOCKER_2", "checkov")]}

    harness, result = _track(tmp_path, found, {})

    assert result["tracks"]["real-code-precision"]["hygiene_unlabelled"] == [
        "flask: CKV_DOCKER_2 at c1.py (c1)"]
    assert harness.compare(result, {"tracks": {}}) == [
        "real-code-precision: 1 Checkov or zizmor finding(s) with no label: "
        "flask: CKV_DOCKER_2 at c1.py (c1)"]


def test_the_baseline_records_each_labels_verdict(tmp_path):
    found = {"flask": [_finding("c1", "CKV_DOCKER_2", "checkov"),
                       _finding("g1", "private-key", "gitleaks")]}
    harness, result = _track(tmp_path, found, {("flask", "c1"): "tp"}, {("flask", "g1"): "fp"})
    baseline = tmp_path / "baseline.json"

    harness.update_baseline(result, baseline, labels=tmp_path / "corpus.toml",
                            hygiene=tmp_path / "hygiene.toml")

    assert json.loads(baseline.read_text())["labels"] == {
        "corpus": {"flask g1": "fp"}, "hygiene": {"flask c1": "tp"}}


@pytest.mark.parametrize("changed, expected", [
    ({}, ["flask c1: fp, where the baseline records tp, with no `changed` reason"]),
    ({"c1": "2026-11-22: the file was read again, and the port is not exposed"}, []),
])
def test_a_verdict_that_differs_from_the_baselines_needs_a_reason(tmp_path, changed, expected):
    harness = _harness()
    path = _labels(tmp_path / "hygiene.toml", {("flask", "c1"): "fp", ("flask", "new"): "tp"},
                   **changed)

    assert harness.precision.label_changes(path, {"flask c1": "tp", "flask gone": "fp"}) == expected


def test_the_committed_labels_agree_with_the_committed_baseline():
    """The guard itself: a label bent to meet a target shows here, with no git history."""
    harness = _harness()
    repo = Path(harness.__file__).resolve().parent.parent
    recorded = json.loads((repo / "tests" / "eval" / "baseline.json").read_text()).get("labels")

    assert recorded is not None, "the baseline records no labels yet"
    for name in ("corpus", "hygiene"):
        path = repo / "tests" / "eval" / "labels" / f"{name}.toml"
        assert harness.precision.label_changes(path, recorded[name]) == [], name
        assert recorded[name], f"the baseline records no {name} label"


def test_the_guard_is_red_when_a_committed_label_is_bent(tmp_path):
    """Seen red against a hand-made break: one committed verdict turned, with no reason."""
    harness = _harness()
    repo = Path(harness.__file__).resolve().parent.parent
    recorded = json.loads((repo / "tests" / "eval" / "baseline.json").read_text())["labels"]
    text = (repo / "tests" / "eval" / "labels" / "hygiene.toml").read_text()
    bent = tmp_path / "hygiene.toml"
    bent.write_text(text.replace('verdict = "fp"', 'verdict = "tp"', 1))

    changes = harness.precision.label_changes(bent, recorded["hygiene"])

    assert len(changes) == 1 and "tp, where the baseline records fp" in changes[0]
