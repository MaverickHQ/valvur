"""R26.3: the tag's run trusts CI's verdict on the same commit (D62b).

`1.4.0`'s `verify` spent 10 of its 14 minutes rebuilding the image and rerunning
`verify.sh` and the e2e suite on a commit whose required checks had just passed them
(R26.1). `scripts/ci_verdict.py` reads those checks back from the API instead: every
one passed, or the job fails naming each that did not. A check it cannot judge (no
completed run, skipped, or an API that does not answer) makes the verdict
*unreadable*, and the job reruns the suites as before and says so. The network is
faked here, as every test fakes it.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SHA = "4d18abd50cbd84437ada6991bfa22620c6d4a22d"


def _script():
    spec = importlib.util.spec_from_file_location("ci_verdict",
                                                  REPO / "scripts" / "ci_verdict.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["ci_verdict"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _run(name: str, conclusion: str | None = "success", *, at: str = "2026-10-04T09:00:00Z",
         status: str = "completed") -> dict:
    return {"name": name, "status": status, "conclusion": conclusion,
            "completed_at": at if status == "completed" else None,
            "app": {"slug": "github-actions"}}


def _all_passed() -> list[dict]:
    return [_run(name) for name in _script().REQUIRED]


def _verdict(runs: list[dict], tmp_path, capsys, monkeypatch) -> tuple[int, str, str]:
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    code = _script().main([SHA], fetch=lambda sha: runs)
    return code, output.read_text() if output.exists() else "", capsys.readouterr().out


def test_every_required_check_passed_is_a_pass(tmp_path, capsys, monkeypatch):
    code, output, out = _verdict([*_all_passed(), _run("an optional one", "failure")],
                                 tmp_path, capsys, monkeypatch)

    assert code == 0
    assert "verdict=passed" in output.splitlines()
    assert f"all 8 required checks passed on {SHA[:12]}" in out


def test_a_required_check_that_failed_fails_the_job_naming_each(tmp_path, capsys, monkeypatch):
    runs = _all_passed()
    runs[0] = _run(runs[0]["name"], "failure")
    runs[2] = _run(runs[2]["name"], "cancelled")

    code, output, out = _verdict(runs, tmp_path, capsys, monkeypatch)

    assert code == 1
    assert "verdict=failed" in output.splitlines()
    assert f"::error::{runs[0]['name']}: failure" in out.splitlines()
    assert f"::error::{runs[2]['name']}: cancelled" in out.splitlines()


def test_the_newest_completed_run_of_a_check_decides(tmp_path, capsys, monkeypatch):
    """A check runs twice on a landed commit, for the pull request and for the push
    to `main`, and a re-run adds a third; the newest says what the commit is now."""
    name = _script().REQUIRED[0]
    rerun = [_run(name, "failure", at="2026-10-04T08:00:00Z"),
             _run(name, "success", at="2026-10-04T08:30:00Z")]
    code, _, _ = _verdict(_all_passed()[1:] + rerun, tmp_path, capsys, monkeypatch)
    assert code == 0

    later_failure = [_run(name, "success", at="2026-10-04T08:00:00Z"),
                     _run(name, "failure", at="2026-10-04T08:30:00Z")]
    code, _, _ = _verdict(_all_passed()[1:] + later_failure, tmp_path, capsys, monkeypatch)
    assert code == 1
