"""R9.3: `scripts/eval.py` scans each track and writes the Score (ADR-0026, N4.1, N4.4).

The container is faked by a scan function that writes a Results Folder, as
`scripts/acceptance.py`'s tests fake it; everything else is the real harness.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "eval.py"


def _harness():
    spec = importlib.util.spec_from_file_location("valvur_eval", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["valvur_eval"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _results(root: Path, findings: list[dict], *, complete: bool = True) -> None:
    folder = root / ".security-scan"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "findings.json").write_text(json.dumps({"findings": findings}))
    (folder / "run.json").write_text(json.dumps({
        "status": "findings" if findings else "clean", "complete": complete,
        # R11.6: every dataset's age in one block, which the gate reads.
        "data": {"database": {"age_days": 1.5, "basis": "built"},
                 "name_index": {"age_days": 2.4, "basis": "built"},
                 "malicious": {"age_days": 0.5, "basis": "built"},
                 "kev": {"age_days": 33.0, "basis": "released"},
                 "epss": {"age_days": 0.4, "basis": "scored"}, "osv": {}},
        "network": {"what_left_the_machine": "nothing"},
    }))


def _flag_the_config_files(root: Path) -> None:
    """Gitleaks finds every secret under `config/`, and nothing else."""
    findings = [{"path": p.relative_to(root).as_posix(), "rule": "generic-api-key",
                 "sources": ["gitleaks"], "suppressed": None, "status": "new"}
                for p in sorted((root / "config").glob("*.env"))]
    _results(root, findings)


def test_a_track_is_scanned_scored_and_recorded(tmp_path):
    harness = _harness()

    result = harness.run(["secrets"], tmp_path / "work", scan=_flag_the_config_files,
                         image="valvur:dev", image_id=lambda image: "sha256:abc")

    secrets = result["tracks"]["secrets"]
    # Every file-borne secret found, none from history, no placeholder flagged:
    # TPR 0.5, FPR 0 in each of ten categories.
    assert secrets["score"] == 50.0
    assert (secrets["vulnerable"], secrets["safe"]) == (20, 20)
    assert secrets["complete"] is True
    assert result["score"] == 50.0
    assert result["image"] == {"name": "valvur:dev", "id": "sha256:abc"}
    assert result["data"] == {"database_age_days": 1.5, "name_index_age_days": 2.4,
                              "malicious_age_days": 0.5, "kev_age_days": 33.0,
                              "epss_age_days": 0.4, "osv_age_days": None}
    assert result["duration_s"] >= 0


def test_the_result_and_its_scorecard_are_written(tmp_path):
    harness = _harness()
    result = harness.run(["secrets"], tmp_path / "work", scan=_flag_the_config_files,
                         image="valvur:dev", image_id=lambda image: "sha256:abc")

    written = harness.write(result, tmp_path / "out")

    assert json.loads(written["json"].read_text())["tracks"]["secrets"]["score"] == 50.0
    card = written["markdown"].read_text()
    assert "| secrets | 50.0 |" in card
    assert "**The Score: 50.0**" in card


def _result(**scores: float) -> dict:
    return {"tracks": {name.replace("_", "-"): {"score": value}
                       for name, value in scores.items()},
            "gates": {}, "image": {"name": "valvur:dev", "id": "sha256:abc"}}


def test_a_track_more_than_two_points_under_its_baseline_fails_the_comparison():
    harness = _harness()
    baseline = {"tracks": {"secrets": 90.0, "dependencies": 100.0}}

    assert harness.compare(_result(secrets=88.0, dependencies=100.0), baseline) == []
    assert harness.compare(_result(secrets=87.9, dependencies=100.0), baseline) == [
        "secrets: 87.9, more than 2 points under its baseline of 90.0"]


def test_a_baseline_is_raised_by_a_better_run_and_never_lowered(tmp_path):
    harness = _harness()
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"tracks": {"secrets": 90.0, "dependencies": 100.0}}))

    kept = harness.update_baseline(_result(secrets=95.0, dependencies=97.0), path)

    assert kept == ["dependencies: 97.0 is under the recorded 100.0; kept"]
    assert json.loads(path.read_text())["tracks"] == {"secrets": 95.0, "dependencies": 100.0}


def test_a_run_judges_its_gates_from_what_the_scans_wrote(tmp_path):
    harness = _harness()

    def scan(root: Path) -> None:
        findings = [{"path": "examples/aws.env.example", "rule": "aws-access-token",
                     "sources": ["gitleaks"], "severity": "critical", "suppressed": None,
                     "status": "new"}] if (root / "examples").exists() else [
            {"path": "deps/ranking/pom.xml", "rule": "CVE-2021-44228", "rank": 1,
             "severity": "critical", "suppressed": None, "status": "new",
             "exploit": {"cve": "CVE-2021-44228", "kev": True}},
            {"path": "deps/ranking/pom.xml", "rule": "CVE-2019-14379", "rank": 2,
             "severity": "critical", "suppressed": None, "status": "new",
             "exploit": {"cve": "CVE-2019-14379", "kev": False}}]
        _results(root, findings)

    result = harness.run(["secrets", "dependencies"], tmp_path / "work", scan=scan,
                         image="valvur:dev", image_id=lambda image: "sha256:abc")

    assert result["tracks"]["secrets"]["safe_flagged_high"] == ["examples/aws.env.example"]
    assert result["gates"]["ranking"]["ok"] is True
    assert result["gates"]["offline"]["ok"] is True
    assert "examples/aws.env.example" in result["gates"]["honesty"]["reason"]


def test_a_case_whose_premise_broke_is_recorded_and_not_scored(tmp_path):
    harness = _harness()
    index = tmp_path / "names"
    index.mkdir()
    # Only PyPI is indexed here: every other ecosystem's case cannot be checked.
    (index / "pypi.txt").write_text("\n".join(sorted({"flask", "humanize", "requests"})) + "\n")

    result = harness.run(["package-reality"], tmp_path / "work",
                         scan=lambda root: _results(root, []), image="valvur:dev",
                         image_id=lambda image: "sha256:abc", index_dir=index)

    track = result["tracks"]["package-reality"]
    assert "package-reality-pkg/pip/real-1" not in track["invalid"]
    assert track["invalid"]["package-reality-pkg/npm/real-1"] == \
        "no npm index to check 'express' against"
    # PyPI's ten cases, and npm's two malicious names, which no premise constrains.
    assert (track["vulnerable"], track["safe"]) == (8, 4)


def test_the_benchmark_track_is_scored_as_the_owasp_scorecard_scores(tmp_path):
    harness = _harness()
    benchmark = tmp_path / "BenchmarkPython"
    benchmark.mkdir()
    (benchmark / "expectedresults-0.1.csv").write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00100,sqli,true,89\n"
        "BenchmarkTest00101,sqli,false,89\n")

    def scan(root: Path) -> None:
        _results(root, [{"path": "testcode/BenchmarkTest00100.py",
                         "rule": "valvur.python.string-built-sql", "suppressed": None,
                         "status": "new", "sources": ["opengrep"]}])

    result = harness.run(["sast-python"], tmp_path / "work", scan=scan, image="valvur:dev",
                         image_id=lambda image: "sha256:abc", benchmark=benchmark,
                         verify=lambda checkout: None)

    track = result["tracks"]["sast-python"]
    # pathtraver: TPR 0; sqli: TPR 1, FPR 0. The scorecard's mean: 50.
    assert track["score"] == 50.0
    assert (track["vulnerable"], track["safe"]) == (2, 1)


def test_real_code_precision_is_scored_and_unlabelled_findings_fail_the_comparison(tmp_path):
    harness = _harness()
    checkouts = tmp_path / "checkouts"
    (checkouts / "flask").mkdir(parents=True)
    labels = tmp_path / "labels.toml"
    labels.write_text('[[label]]\nrepo = "flask"\nfingerprint = "a1"\nrule = "r"\n'
                      'verdict = "tp"\nreason = "a real shell injection"\n')

    def scan(root: Path) -> None:
        _results(root, [
            {"fingerprint": "a1", "rule": "valvur.python.subprocess-shell-true",
             "path": "a.py", "sources": ["opengrep"], "suppressed": None, "status": "new"},
            {"fingerprint": "b2", "rule": "valvur.python.weak-hash", "path": "b.py",
             "sources": ["opengrep"], "suppressed": None, "status": "new"}])

    result = harness.run(["real-code-precision"], tmp_path / "work", scan=scan,
                         image="valvur:dev", image_id=lambda image: "sha256:abc",
                         corpus=[{"name": "flask"}], checkouts=checkouts, labels=labels)

    track = result["tracks"]["real-code-precision"]
    assert (track["score"], track["tp"], track["fp"]) == (100.0, 1, 0)
    assert track["unlabelled"] == ["flask: valvur.python.weak-hash at b.py (b2)"]
    assert harness.compare(result, {"tracks": {"real-code-precision": 100.0}}) == [
        "real-code-precision: 1 finding(s) with no label: "
        "flask: valvur.python.weak-hash at b.py (b2)"]


def test_the_agent_track_holds_the_real_files_on_every_lane(tmp_path):
    """The first Linux run built the agent-configuration track before anything had
    fetched awesome-cursorrules, and held ten safe cases fewer than the Mac's: the
    same score, by luck. The track now fetches what it reads."""
    harness = _harness()
    fetched: list[str] = []
    checkout = tmp_path / "awesome-cursorrules"

    def fetch() -> Path:
        fetched.append("awesome-cursorrules")
        (checkout / "rules").mkdir(parents=True, exist_ok=True)
        for n in range(3):
            (checkout / "rules" / f"r{n}.mdc").write_text("Prefer small functions.\n")
        return checkout

    result = harness.run(["agent-configuration"], tmp_path / "work",
                         scan=lambda root: _results(root, []), image="valvur:dev",
                         image_id=lambda image: "sha256:abc", cursorrules=fetch)

    assert fetched == ["awesome-cursorrules"]
    assert result["tracks"]["agent-configuration"]["safe"] == 23 + 3
