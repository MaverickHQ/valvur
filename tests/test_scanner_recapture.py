"""R47.3 (D81v): a Scanner's golden, recaptured twice from the new binary, and judged (N3.9).

R47.1 measured each recapture twice on one image and one day's data. Opengrep, zizmor and
OSV-Scanner gave the same bytes; Trivy and Syft differed only in their run's identity, and
Checkov only in the order of its failed checks. So a recapture is judged after those fields
alone are blanked, and anything else that differs is refused: a golden nobody can reproduce
is no golden. The container runtime is faked, as every unit test fakes it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _script():
    sys.path.insert(0, str(REPO / "scripts"))
    path = REPO / "scripts" / "scanner_upgrade.py"
    spec = importlib.util.spec_from_file_location("scanner_upgrade", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


class Runtime:
    """A Scan Container that writes each capture's report in turn."""

    def __init__(self, *reports: str):
        self.reports = list(reports)
        self.plans = []

    def run(self, plan, tar, scratch, **_):
        [invocation] = plan
        self.plans.append((invocation, len(tar)))
        name = invocation.report or f"{invocation.tool}.stdout"
        (scratch / name).write_text(self.reports.pop(0))
        return 0


def _trivy(report_id: str, created: str, vulnerability: str = "CVE-2026-0001") -> str:
    return json.dumps({"SchemaVersion": 2, "ReportID": report_id, "CreatedAt": created,
                       "Results": [{"Target": "requirements.txt",
                                    "Vulnerabilities": [{"VulnerabilityID": vulnerability}]}]})


def _root(tmp_path: Path) -> Path:
    golden = tmp_path / "tests" / "fixtures" / "golden"
    golden.mkdir(parents=True)
    (golden / "trivy-0.75.0.json").write_text("{}")
    (golden / "zizmor-1.30.1.json").write_text("[]")
    return tmp_path


def test_two_captures_that_differ_only_in_the_run_s_identity_are_one_golden(tmp_path):
    root = _root(tmp_path)
    first = _trivy("01a1-one", "2026-10-25T18:14:33Z")
    runtime = Runtime(first, _trivy("01a1-two", "2026-10-25T18:14:34Z"))

    written = _script().recapture(root, "trivy", "0.76.0", runtime=runtime)

    assert written == "tests/fixtures/golden/trivy-0.76.0.json"
    assert (root / written).read_text() == first             # the capture, as Trivy wrote it
    assert not (root / "tests/fixtures/golden/trivy-0.75.0.json").exists()
    assert (root / "tests/fixtures/golden/zizmor-1.30.1.json").exists()
    # Trivy's recipe: the two lockfiles of broken-repo its golden was taken from, offline.
    invocation, _ = runtime.plans[0]
    assert len(runtime.plans) == 2 and invocation.tool == "trivy"
    assert invocation.network is False


def test_a_recapture_that_differs_in_what_a_parser_reads_is_refused(tmp_path):
    root = _root(tmp_path)
    upgrade = _script()
    runtime = Runtime(_trivy("a", "t1"), _trivy("b", "t2", vulnerability="CVE-2026-0002"))

    with pytest.raises(upgrade.LeftForOwner, match=r"not deterministic.*broken-repo"):
        upgrade.recapture(root, "trivy", "0.76.0", runtime=runtime)

    assert not (root / "tests/fixtures/golden/trivy-0.76.0.json").exists()
    assert (root / "tests/fixtures/golden/trivy-0.75.0.json").exists()


def test_checkov_s_order_alone_is_not_a_difference_and_zizmor_s_stdout_is_its_report(tmp_path):
    root = _root(tmp_path)
    upgrade = _script()
    a, b = ({"check_id": "CKV_AWS_19"}, {"check_id": "CKV_AWS_57"})
    block = lambda *checks: [{"check_type": "terraform",                    # noqa: E731
                              "results": {"failed_checks": list(checks)}}]
    runtime = Runtime(json.dumps(block(a, b)), json.dumps(block(b, a)))
    assert upgrade.recapture(root, "checkov", "3.3.29", runtime=runtime) == \
        "tests/fixtures/golden/checkov-3.3.29.json"

    zizmor = Runtime("[]\n", "[]\n")
    assert upgrade.recapture(root, "zizmor", "1.31.1", runtime=zizmor) == \
        "tests/fixtures/golden/zizmor-1.31.1.json"
    assert zizmor.plans[0][0].report is None
    assert not (root / "tests/fixtures/golden/zizmor-1.30.1.json").exists()


def _eval_writing(tracks: dict[str, float], calls: list):
    """`scripts/eval.py`, which scans every track in the image, stood in for by what it
    writes: `score.json` under `--out`."""
    def run(argv, **_):
        calls.append(argv)
        out = Path(argv[argv.index("--out") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "score.json").write_text(json.dumps(
            {"score": round(sum(tracks.values()) / len(tracks), 1),
             "tracks": {name: {"score": value} for name, value in tracks.items()}}))
        return type("Done", (), {"returncode": 0})()
    return run


def test_the_score_is_run_against_the_baseline_and_each_track_s_delta_is_in_the_body(tmp_path):
    upgrade = _script()
    baseline = json.loads((REPO / "tests" / "eval" / "baseline.json").read_text())["tracks"]
    now = {**baseline, "sast-js": baseline["sast-js"] + 1.5,
           "infrastructure": baseline["infrastructure"] - 2.5}
    calls: list = []

    deltas = upgrade.score(REPO, tmp_path / "eval", run=_eval_writing(now, calls))

    [argv] = calls
    assert argv[argv.index("--compare") + 1].endswith("tests/eval/baseline.json")
    assert set(deltas) == set(baseline)
    assert deltas["sast-js"] == (baseline["sast-js"], baseline["sast-js"] + 1.5, 1.5)
    assert deltas["secrets"][2] == 0.0

    body = upgrade.body({"scanner": "trivy", "from": "0.75.0", "to": "0.76.0"}, deltas=deltas)
    assert "Trivy 0.75.0 → 0.76.0" in body
    assert "| sast-js | 55.0 | 56.5 | +1.5 |" in body
    assert "| infrastructure | 95.0 | 92.5 | -2.5 |" in body
    # More than 2 points under its baseline stops the move, and the body says which.
    assert "more than 2 points under its baseline: infrastructure" in body
