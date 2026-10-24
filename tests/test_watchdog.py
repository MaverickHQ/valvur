"""R42.5 (D81s): no scheduled workflow fails, or stops, in silence (N3.8).

`refresh.yml` failed on 2026-10-12 and 2026-10-19 and filed no issue: its checkout ran
only on a month's first Monday, so its own `file-issue` step could not be found. The
watchdog reads every workflow with a `schedule:` and its last scheduled runs on `main`,
and keeps one issue per workflow: opened on a failure or an overdue run, commented on
after, closed by a pass. Tested against GitHub's API on loopback (`tests/fake_github.py`).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from fake_github import FakeGitHub

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "watchdog.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "watchdog"

NIGHTLY = """\
name: nightly
on:
  schedule:
    - cron: "37 3 * * *"     # daily, 03:37 UTC
  workflow_dispatch:
jobs: {}
"""

ON_PUSH = """\
name: ci
on:
  push:
    branches: [main]
jobs: {}
"""


def _script():
    spec = importlib.util.spec_from_file_location("watchdog", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["watchdog"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _run(number: int, started: str, conclusion: str | None, *, event: str = "schedule") -> dict:
    return {"id": number, "event": event, "head_branch": "main",
            "status": "completed" if conclusion else "in_progress", "conclusion": conclusion,
            "created_at": started, "run_started_at": started,
            "html_url": f"https://github.com/MaverickHQ/valvur/actions/runs/{number}"}


@pytest.fixture
def workflows(tmp_path: Path) -> Path:
    directory = tmp_path / "workflows"
    directory.mkdir()
    (directory / "nightly.yml").write_text(NIGHTLY)
    (directory / "ci.yml").write_text(ON_PUSH)
    return directory


def _watch(github: FakeGitHub, workflows: Path, now: str, *extra: str) -> int:
    return _script().main(["--repo", github.repo, "--api", github.url, "--now", now,
                           "--workflows", str(workflows), *extra])


def test_a_failed_scheduled_run_with_no_open_issue_opens_one(workflows, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "t0ken")
    with FakeGitHub() as github:
        github.runs["nightly.yml"] = [_run(2, "2026-10-24T08:22:37Z", "failure"),
                                      _run(1, "2026-10-23T08:01:02Z", "success")]

        assert _watch(github, workflows, "2026-10-24T09:00:00Z") == 0

    assert [i["title"] for i in github.issues] == ["watchdog: nightly.yml"]
    body = github.issues[0]["body"]
    assert "actions/runs/2" in body and "2026-10-24" in body and "failure" in body
    assert github.authorizations and all(a == "Bearer t0ken" for a in github.authorizations)


def test_a_failure_with_its_issue_open_comments_and_never_opens_a_second(workflows):
    with FakeGitHub() as github:
        github.issue("watchdog: nightly.yml")
        github.runs["nightly.yml"] = [_run(3, "2026-10-24T08:22:37Z", "timed_out")]

        assert _watch(github, workflows, "2026-10-24T09:00:00Z") == 0

    assert len(github.issues) == 1
    comments = github.issues[0]["comments"]
    assert len(comments) == 1 and "actions/runs/3" in comments[0]


def test_no_scheduled_run_within_the_gap_and_the_margin_is_overdue(workflows):
    """A daily cron's gap is 24 hours, and D81s's margin 18: overdue after 42."""
    with FakeGitHub() as github:
        github.runs["nightly.yml"] = [_run(4, "2026-10-22T08:00:00Z", "success")]

        assert _watch(github, workflows, "2026-10-24T01:59:00Z") == 0
        assert github.issues == []
        assert _watch(github, workflows, "2026-10-24T02:01:00Z") == 0

    assert [i["title"] for i in github.issues] == ["watchdog: nightly.yml"]
    assert "overdue" in github.issues[0]["body"]


def test_a_workflow_that_has_never_run_on_its_schedule_is_overdue(workflows):
    with FakeGitHub() as github:
        github.runs["nightly.yml"] = [_run(5, "2026-10-24T08:00:00Z", "success",
                                           event="workflow_dispatch")]

        assert _watch(github, workflows, "2026-10-24T09:00:00Z") == 0

    assert "overdue" in github.issues[0]["body"]


def test_a_pass_closes_the_open_issue_naming_the_run(workflows):
    with FakeGitHub() as github:
        github.issue("watchdog: nightly.yml")
        github.issue("watchdog: other.yml")
        github.runs["nightly.yml"] = [_run(6, "2026-10-24T08:22:37Z", None),
                                      _run(5, "2026-10-23T08:22:37Z", "success")]

        assert _watch(github, workflows, "2026-10-24T09:00:00Z") == 0

    nightly, other = github.issues
    assert nightly["state"] == "closed" and "actions/runs/5" in nightly["comments"][0]
    assert other["state"] == "open"


def test_a_pass_with_no_issue_open_files_nothing(workflows):
    with FakeGitHub() as github:
        github.runs["nightly.yml"] = [_run(5, "2026-10-23T08:22:37Z", "success")]

        assert _watch(github, workflows, "2026-10-24T09:00:00Z") == 0

    assert github.writes == []


def test_a_workflow_without_a_schedule_is_never_read(workflows):
    with FakeGitHub() as github:
        github.runs["nightly.yml"] = [_run(5, "2026-10-23T08:22:37Z", "success")]

        _watch(github, workflows, "2026-10-24T09:00:00Z")

    assert any("/nightly.yml/" in r for r in github.reads)
    assert not any("ci.yml" in r for r in github.reads)


def test_a_dry_run_lists_what_it_would_file_and_files_nothing(workflows, capsys):
    with FakeGitHub() as github:
        github.runs["nightly.yml"] = [_run(2, "2026-10-24T08:22:37Z", "failure")]

        assert _watch(github, workflows, "2026-10-24T09:00:00Z", "--dry-run") == 0

    assert github.writes == []
    assert "would open: watchdog: nightly.yml" in capsys.readouterr().out


def test_an_api_that_cannot_be_read_fails_the_run(workflows):
    with FakeGitHub(repo="someone/else") as github:
        assert _script().main(["--repo", "MaverickHQ/valvur", "--api", github.url,
                               "--now", "2026-10-24T09:00:00Z",
                               "--workflows", str(workflows)]) == 2


@pytest.mark.parametrize(("crons", "hours"), [
    (["37 3 * * *"], 24), (["23 5 * * 1"], 168), (["41 */6 * * *"], 6),
    (["0 1 * * 1", "0 1 * * 4"], 96), (["29 3 * * 1-5"], 72),
])
def test_the_longest_gap_between_two_cron_times(crons, hours):
    assert _script().longest_gap_hours(crons) == hours


def test_every_scheduled_workflow_in_the_repository_is_read_with_its_crons():
    schedules = _script().schedules(REPO / ".github" / "workflows")

    assert schedules["acceptance.yml"] == ["37 3 * * *"]
    assert schedules["refresh.yml"] == ["23 5 * * 1"]
    assert "ci.yml" not in schedules and len(schedules) >= 9


@pytest.mark.parametrize(("now", "run"), [
    ("2026-10-12T15:00:00Z", 38254221059), ("2026-10-19T12:00:00Z", 39240320485)])
def test_the_incident_replayed_refresh_s_silent_failures_are_filed(tmp_path, now, run):
    """`refresh.yml`'s scheduled runs as the Actions API answered on 2026-10-24: each
    failure, seen the day it happened, opens the issue nobody filed."""
    recorded = json.loads((FIXTURES / "refresh-runs-2026-10-24.json").read_text())
    directory = tmp_path / "workflows"
    directory.mkdir()
    (directory / "refresh.yml").write_text(
        (REPO / ".github" / "workflows" / "refresh.yml").read_text())
    with FakeGitHub() as github:
        github.runs["refresh.yml"] = [r for r in recorded["workflow_runs"]
                                      if r["created_at"] <= now]

        assert _watch(github, directory, now) == 0

    assert [i["title"] for i in github.issues] == ["watchdog: refresh.yml"]
    assert f"actions/runs/{run}" in github.issues[0]["body"]


def test_only_one_workflow_is_judged_when_named_so_the_nightly_can_watch_the_watchdog(
        workflows):
    (workflows / "watchdog.yml").write_text(NIGHTLY.replace("37 3", "47 6"))
    with FakeGitHub() as github:
        github.runs["nightly.yml"] = [_run(2, "2026-10-24T08:22:37Z", "failure")]
        github.runs["watchdog.yml"] = [_run(7, "2026-10-24T08:00:00Z", "startup_failure")]

        assert _watch(github, workflows, "2026-10-24T09:00:00Z", "--only", "watchdog.yml") == 0

    assert [i["title"] for i in github.issues] == ["watchdog: watchdog.yml"]
    assert not any("nightly.yml" in r for r in github.reads)


def test_a_workflow_the_api_does_not_know_yet_has_no_runs(workflows):
    """A workflow file the Actions API answers 404 for has never run: overdue, not an
    unreadable API."""
    with FakeGitHub() as github:
        assert _watch(github, workflows, "2026-10-24T09:00:00Z") == 0

    assert "overdue" in github.issues[0]["body"]
