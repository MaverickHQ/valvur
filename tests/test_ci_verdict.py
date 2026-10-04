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


def _unreadable(runs, tmp_path, capsys, monkeypatch, **kwargs) -> str:
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    fetch = kwargs.pop("fetch", lambda sha: runs)
    assert _script().main([SHA, "--wait", "0"], fetch=fetch, **kwargs) == 0
    assert "verdict=unreadable" in output.read_text().splitlines()
    return capsys.readouterr().out


def test_a_check_with_no_completed_run_or_skipped_is_unreadable_and_says_so(
        tmp_path, capsys, monkeypatch):
    """D62's fallback: a check skipped by a path filter, or never run here, says
    nothing about this commit, so the job reruns the suites itself."""
    runs = _all_passed()
    missing, skipped = runs.pop(0)["name"], runs[0]["name"]
    runs[0] = _run(skipped, "skipped")

    out = _unreadable(runs, tmp_path, capsys, monkeypatch)

    assert f"::warning::{missing}: missing" in out.splitlines()
    assert f"::warning::{skipped}: skipped" in out.splitlines()
    assert "CI's verdict cannot be read; rerunning verify.sh and the e2e suite" in out


def test_an_api_that_does_not_answer_is_unreadable(tmp_path, capsys, monkeypatch):
    def refused(sha):
        raise OSError("HTTP Error 403: Forbidden")

    out = _unreadable([], tmp_path, capsys, monkeypatch, fetch=refused)

    assert "::warning::the check runs could not be read: HTTP Error 403: Forbidden" in out


def test_it_waits_for_a_run_in_progress_and_then_judges_it(tmp_path, capsys, monkeypatch):
    """The push to `main` runs the checks again; a tag pushed straight after the
    landing finds them running."""
    name = _script().REQUIRED[0]
    pending = [*_all_passed()[1:], _run(name, None, status="in_progress")]
    answers = iter([pending, _all_passed()])
    slept = []
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))

    code = _script().main([SHA, "--wait", "60"], fetch=lambda sha: next(answers),
                          sleep=slept.append)

    assert code == 0 and slept == [30]
    assert "verdict=passed" in (tmp_path / "output").read_text()


def test_a_failure_outweighs_what_cannot_be_read(tmp_path, capsys, monkeypatch):
    runs = _all_passed()
    runs[0] = _run(runs[0]["name"], "failure")
    runs[1] = _run(runs[1]["name"], "skipped")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))

    assert _script().main([SHA, "--wait", "0"], fetch=lambda sha: runs) == 1


def _verify_steps() -> list[str]:
    release = (REPO / ".github" / "workflows" / "release.yml").read_text()
    verify = release.split("\n  verify:", 1)[1].split("\n  build:", 1)[0]
    return verify.split("\n      - ")[1:]


def _step(steps: list[str], needle: str) -> tuple[int, str]:
    [found] = [(i, s) for i, s in enumerate(steps) if needle in s]
    return found


def test_verify_reads_the_verdict_and_reruns_the_suites_only_when_it_cannot():
    release = (REPO / ".github" / "workflows" / "release.yml").read_text()
    verify = release.split("\n  verify:", 1)[1].split("\n  build:", 1)[0]
    steps = _verify_steps()

    assert "checks: read" in verify and "checks: write" not in verify
    at, verdict = _step(steps, "scripts/ci_verdict.py")
    assert "id: ci" in verdict and '"$GITHUB_SHA"' in verdict
    assert "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}" in verdict
    for needle in ("./scripts/verify.sh", "uv run pytest -q"):
        i, step = _step(steps, needle)
        assert "if: steps.ci.outputs.verdict == 'unreadable'" in step, needle
        assert i > at, f"{needle} runs before the verdict is read"


def test_verify_still_checks_the_tag_and_still_runs_the_score_and_the_gate():
    """What no required check measures stays, unconditionally: the tag against the
    tree, its signature and `main`, the self-scan on today's data, and the Score."""
    steps = _verify_steps()
    _, version = _step(steps, "does not match pyproject.toml version")
    _, signed = _step(steps, " tag -v ")
    _, gate = _step(steps, "valvur gate . --fail-on any --no-inconclusive")
    _, score = _step(steps, "python scripts/eval.py")

    assert "merge-base --is-ancestor" in signed
    assert "if: env.REHEARSAL != 'true'" in signed
    for step in (version, gate, score):
        assert "\n        if:" not in step, step.splitlines()[0]
