"""R2.2: the harness judges a scan against its repository's `expected.toml`.

Tested on fixture results folders: what a scan wrote, not how it ran.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "acceptance.py"

TASKS = """\
- [x] **R3.1** **Tracer bullet.**
- [ ] **R3.2** **The File Set**
"""


def _module():
    spec = importlib.util.spec_from_file_location("acceptance", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _results(tmp_path: Path, findings: list[dict], complete: bool = True) -> Path:
    folder = tmp_path / ".security-scan"
    folder.mkdir(parents=True)
    (folder / "findings.json").write_text(json.dumps({"findings": findings}))
    (folder / "run.json").write_text(json.dumps({"complete": complete, "status": "findings"}))
    return folder


def _finding(rule: str, path: str, severity: str = "low") -> dict:
    return {"rule": rule, "path": path, "severity": severity, "suppressed": False}


EXPECTED = {"run": {"complete": True},
            "must": [{"rule": "subprocess-shell-true", "path": "src/app.py"}]}


def test_a_missing_expected_finding_fails(tmp_path):
    verdict = _module().judge(_results(tmp_path, []), EXPECTED, TASKS)
    assert verdict.ok is False
    assert verdict.missing == ["subprocess-shell-true at src/app.py"]


def test_an_unexpected_finding_is_listed_and_fails_only_at_high_or_critical(tmp_path):
    harness = _module()
    low = [_finding("subprocess-shell-true", "src/app.py"), _finding("weak-hash", "b.py")]
    verdict = harness.judge(_results(tmp_path / "low", low), EXPECTED, TASKS)
    assert verdict.ok is True
    assert verdict.unexpected == ["weak-hash at b.py (low)"]

    high = [*low, _finding("aws-access-token", "c.py", "critical")]
    verdict = harness.judge(_results(tmp_path / "high", high), EXPECTED, TASKS)
    assert verdict.ok is False
    assert "aws-access-token at c.py (critical)" in verdict.unexpected


def test_a_repository_that_allows_other_findings_is_judged_on_its_musts(tmp_path):
    expected = {**EXPECTED, "run": {"complete": True, "unexpected": "allowed"}}
    findings = [_finding("subprocess-shell-true", "src/app.py"),
                _finding("CVE-2024-1", "requirements.txt", "critical")]
    assert _module().judge(_results(tmp_path, findings), expected, TASKS).ok is True


def test_an_until_expectation_is_pending_until_its_task_is_ticked(tmp_path):
    harness = _module()
    expected = {"run": {"complete": True},
                "must": [{"rule": "subprocess-shell-true", "path": "mypkg/build/steps.py",
                          "until": "R3.2"}]}
    verdict = harness.judge(_results(tmp_path / "a", []), expected, TASKS)
    assert (verdict.ok, verdict.pending) == (True, ["subprocess-shell-true at "
                                                    "mypkg/build/steps.py (until R3.2)"])
    ticked = TASKS.replace("- [ ] **R3.2**", "- [x] **R3.2**")
    verdict = harness.judge(_results(tmp_path / "b", []), expected, ticked)
    assert verdict.ok is False and verdict.missing


def test_a_forbidden_path_and_an_incomplete_run_fail(tmp_path):
    harness = _module()
    expected = {"run": {"complete": True}, "must_not": [{"path_prefix": "archive/"}]}
    found = [_finding("subprocess-shell-true", "archive/app.py")]
    verdict = harness.judge(_results(tmp_path / "a", found), expected, TASKS)
    assert verdict.ok is False and verdict.forbidden == ["archive/app.py"]
    verdict = harness.judge(_results(tmp_path / "b", [], complete=False), expected, TASKS)
    assert verdict.ok is False and verdict.incomplete is True


def _write_repo(root: Path, expected_toml: str) -> Path:
    root.mkdir(parents=True)
    (root / "expected.toml").write_text(expected_toml)
    return root


def test_running_a_repository_measures_time_and_containers_and_judges_it(tmp_path):
    harness = _module()
    root = _write_repo(tmp_path / "4-nested-names", '[run]\ncomplete = true\n'
                       '[[must]]\nrule = "subprocess-shell-true"\npath = "src/app.py"\n')

    def fake_scan(workspace: Path) -> None:
        _results(workspace, [_finding("valvur.python.subprocess-shell-true", "src/app.py",
                                      "high")])

    result = harness.run_repo(root, scan=fake_scan, containers=lambda: 0, tasks_text=TASKS,
                              platform={"platform": "Linux", "swap_gb": 0})
    assert result.name == "4-nested-names"
    assert result.verdict.ok is True
    assert result.seconds >= 0 and result.containers_after == 0


def test_a_container_left_behind_fails_the_repository(tmp_path):
    harness = _module()
    root = _write_repo(tmp_path / "1-gate", "[run]\ncomplete = true\n")
    result = harness.run_repo(root, scan=lambda ws: _results(ws, []), containers=lambda: 2,
                              tasks_text=TASKS, platform={"platform": "Linux", "swap_gb": 0})
    assert result.ok is False and result.containers_after == 2


def test_the_report_has_a_row_per_repository_and_the_platform(tmp_path):
    harness = _module()
    passing = harness.RepoResult("2-lockfiles", harness.Verdict(), 12.3, 0)
    failing = harness.RepoResult("3-history-secret",
                                 harness.Verdict(ok=False, missing=["aws-access-token at x"]),
                                 4.0, 0)
    table = harness.render_markdown([passing, failing], {"platform": "macOS 26.6.2",
                                                         "swap_gb": 11.9})
    assert "| 2-lockfiles | pass | 12.3 | none | 0 | 0 | 0 | 0 |" in table
    assert "| 3-history-secret | FAIL | 4.0 | none | 0 | 1 | 0 | 0 |" in table
    assert "macOS 26.6.2" in table
    assert harness.to_json([passing, failing], {})["repositories"][1]["missing"] == [
        "aws-access-token at x"]


def test_only_directories_with_expectations_are_repositories(tmp_path):
    harness = _module()
    for name in ("1-gate-shaped", "4-nested-names"):
        _write_repo(tmp_path / name, "[run]\ncomplete = true\n")
    (tmp_path / "probe-workspace").mkdir()          # left by a probe run
    (tmp_path / ".terraform-aws-vpc-clone").mkdir()
    assert list(harness.discover(tmp_path)) == ["1-gate-shaped", "4-nested-names"]
    assert list(harness.discover(tmp_path, only="4")) == ["4-nested-names"]


def test_a_mac_time_target_is_judged_only_on_a_mac_with_little_swap(tmp_path):
    harness = _module()
    expected = {"run": {"complete": True},
                "timing": {"mac_warm_seconds": 30, "until": "R3.2"}}
    quiet_mac = {"platform": "Darwin 25.6.0 arm64", "swap_gb": 1.0}
    open_task = harness.judge_time(165.2, expected, TASKS, quiet_mac)
    assert open_task == ("pending", "165.2 s against 30 s on the Mac (until R3.2)")
    ticked = TASKS.replace("- [ ] **R3.2**", "- [x] **R3.2**")
    assert harness.judge_time(165.2, expected, ticked, quiet_mac)[0] == "fail"
    assert harness.judge_time(12.0, expected, ticked, quiet_mac)[0] == "pass"
    swapping = {"platform": "Darwin 25.6.0 arm64", "swap_gb": 10.2}
    assert harness.judge_time(165.2, expected, ticked, swapping)[0] == "recorded"
    linux = {"platform": "Linux 6.8 x86_64", "swap_gb": 0.0}
    assert harness.judge_time(165.2, expected, ticked, linux)[0] == "recorded"


def test_the_probe_workspace_is_absolute_because_the_server_refuses_a_relative_one(
        tmp_path, monkeypatch):
    path = REPO / "scripts" / "acceptance" / "probes.py"
    spec = importlib.util.spec_from_file_location("acceptance_probes", path)
    probes = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance_probes"] = probes
    spec.loader.exec_module(probes)  # type: ignore[union-attr]
    monkeypatch.chdir(tmp_path)
    root = probes.workspace(Path("relative-out"), data_files=2)
    assert root.is_absolute()


def test_the_uploaded_artifact_is_the_report_and_not_the_probe_workspace():
    """The first green Linux run uploaded 117 MB, 30,013 files: the probe workspace
    sits under `--out`, and the step uploaded the whole directory."""
    text = (REPO / ".github" / "workflows" / "acceptance.yml").read_text()
    step = text.split("actions/upload-artifact", 1)[1].split("- name:", 1)[0]
    assert "acceptance-report/report.json" in step
    assert "acceptance-report/report.md" in step
    assert "path: acceptance-report/\n" not in step
