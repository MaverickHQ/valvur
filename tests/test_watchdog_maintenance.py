"""R46.3: the weekly maintenance session is watched (Requirement 24, D81z).

The watchdog watches the workflows. Nothing watched the scheduled agent session, which can
stop without failing. Its week leaves one of two marks: a pull request titled
`chore: maintenance, …`, or a comment naming the week on the issue *maintenance: the weekly
record*. After Thursday 12:00 UTC, a week with neither keeps one issue,
`watchdog: weekly maintenance, <week>`, closed when either appears.

The repository is public. A comment by anyone, or a pull request from a fork under the
routine's title, would otherwise silence the watchdog, so only the owner's marks count.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from fake_github import FakeGitHub

REPO = Path(__file__).resolve().parent.parent
RECORD = "maintenance: the weekly record"
ISSUE = "watchdog: weekly maintenance, 2026-W47"
FRIDAY, WEDNESDAY = "2026-11-20T06:47:00Z", "2026-11-18T06:47:00Z"   # of ISO week 47


def _script():
    spec = importlib.util.spec_from_file_location("watchdog", REPO / "scripts" / "watchdog.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["watchdog"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


@pytest.fixture
def github(tmp_path):
    with FakeGitHub() as fake:
        fake.workflows = tmp_path / "workflows"
        fake.workflows.mkdir()
        yield fake


def _watch(github: FakeGitHub, now: str, *extra: str) -> int:
    return _script().main(["--repo", github.repo, "--api", github.url, "--now", now,
                           "--workflows", str(github.workflows), "--maintenance", *extra])


def _pull(created: str, *, title: str = "chore: maintenance, 2026-11-19",
          repo: str = "MaverickHQ/valvur", association: str = "OWNER") -> dict:
    return {"number": 900, "title": title, "created_at": created,
            "author_association": association, "head": {"repo": {"full_name": repo}}}


def _record(github: FakeGitHub, *comments: dict, association: str = "OWNER") -> dict:
    return github.issue(RECORD, author_association=association, comments=list(comments))


def _comment(body: str, created: str = "2026-11-19T06:40:00Z", association: str = "OWNER") -> dict:
    return {"body": body, "created_at": created, "author_association": association}


def _opened(github: FakeGitHub) -> list[str]:
    return [body["title"] for method, path, body in github.writes
            if method == "POST" and path.endswith("/issues")]


def test_after_thursday_noon_a_week_with_neither_mark_gets_one_issue(github):
    assert _watch(github, FRIDAY) == 0

    assert _opened(github) == [ISSUE]
    assert "2026-W47" in github.issues[-1]["body"] and RECORD in github.issues[-1]["body"]


def test_a_week_with_a_maintenance_pull_request_gets_none(github):
    github.pulls = [_pull("2026-11-19T06:20:00Z")]

    _watch(github, FRIDAY)

    assert _opened(github) == []


def test_a_week_with_a_record_of_nothing_to_fix_gets_none(github):
    _record(github, _comment("2026-W47: nothing to fix"))

    _watch(github, FRIDAY)

    assert _opened(github) == []


def test_a_week_still_in_progress_gets_none_and_the_week_before_is_the_one_judged(github):
    github.pulls = [_pull("2026-11-12T06:20:00Z", title="chore: maintenance, 2026-11-12")]

    _watch(github, WEDNESDAY)

    assert _opened(github) == []


def test_the_issue_is_closed_when_either_mark_appears(github):
    issue = github.issue(ISSUE)
    _record(github, _comment("2026-W47: nothing to fix", "2026-11-21T09:00:00Z"))

    _watch(github, "2026-11-21T06:47:00Z")

    assert issue["state"] == "closed"
    assert any("2026-W47" in comment for comment in issue["comments"])


def test_a_second_run_in_the_same_state_opens_no_second_issue_and_says_nothing(github):
    _watch(github, FRIDAY)
    writes = len(github.writes)

    _watch(github, "2026-11-21T06:47:00Z")

    assert _opened(github) == [ISSUE] and len(github.writes) == writes


@pytest.mark.parametrize("mark", [
    pytest.param(lambda g: _record(g, _comment("2026-W47: nothing to fix", association="NONE")),
                 id="a-strangers-comment"),
    pytest.param(lambda g: _record(g, _comment("2026-W47: nothing to fix"), association="NONE"),
                 id="a-strangers-record-issue"),
    pytest.param(lambda g: g.pulls.append(_pull("2026-11-19T06:20:00Z", repo="a-stranger/valvur",
                                                association="NONE")), id="a-fork"),
    pytest.param(lambda g: g.pulls.append(_pull("2026-11-19T06:20:00Z", association="NONE")),
                 id="not-the-owners"),
    pytest.param(lambda g: _record(g, _comment("2026-W46: nothing to fix")),
                 id="another-weeks-record"),
    pytest.param(lambda g: g.pulls.append(_pull("2026-11-12T06:20:00Z")), id="last-weeks-pull"),
])
def test_a_mark_that_is_not_the_owners_or_not_this_weeks_does_not_count(github, mark):
    mark(github)

    _watch(github, FRIDAY)

    assert _opened(github) == [ISSUE]


def test_a_dry_run_says_what_it_would_file_and_files_nothing(github, capsys):
    _watch(github, FRIDAY, "--dry-run")

    assert github.writes == []
    assert f"would open: {ISSUE}" in capsys.readouterr().out
