"""R52.5: the Health record, one issue a daily workflow rewrites (D82r, Requirement 14.4).

An adopter asks whether the project is looked after, and the answers were spread over
workflow runs: the Score by track, what the nightly found in the published image, how much
of a week's change the tests notice, and how long a vulnerability takes to heal.
`scripts/health.py` reads each from recorded runs, through GitHub's API, and writes them
into one issue, *valvur health*. It commits nothing, so it needs no identity that can push.

Every number comes from a recorded run. One that cannot be read today keeps its last value
and the day it was read, and says so: a record that goes quiet when its source fails would
read as health.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from fake_github import FakeGitHub

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "health.py"
NOW = "2026-11-23T07:00:00Z"
SCORE = {"score": 76.8, "tracks": {"sast-python": {"score": 39.0}, "secrets": {"score": 100.0},
                                   "llm-output": {"score": 79.0}}}
CLEAN = {"blocking": [], "accepted": [], "unfixed": [{"id": "CVE-2024-23342"}], "refused": []}
BLOCKED = {"blocking": [{"id": "CVE-1"}, {"id": "CVE-2"}], "accepted": [],
           "unfixed": [{"id": "CVE-2024-23342"}], "refused": []}


def _script():
    spec = importlib.util.spec_from_file_location("health", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["health"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


@pytest.fixture
def github():
    with FakeGitHub() as fake:
        fake.artifact("eval-report", {"score.json": SCORE}, created="2026-11-16T05:10:00Z")
        fake.artifact("eval-report", {"score.json": {"score": 1.0, "tracks": {}}},
                      created="2026-11-22T05:10:00Z", branch="build/a-branch")
        fake.artifact("image-gate-published", {"image-gate.json": BLOCKED},
                      created="2026-11-21T04:00:00Z")
        fake.artifact("image-gate-published", {"image-gate.json": CLEAN},
                      created="2026-11-22T04:00:00Z")
        fake.artifact("mutation-report", {"mutation.json": {"score": 83.8, "caught": 31,
                                                            "survived": 6}},
                      created="2026-11-18T06:00:00Z")
        fake.releases[fake.repo] = []
        yield fake


def _run(github: FakeGitHub, *, now: str = NOW, extra: tuple[str, ...] = ()) -> int:
    return _script().main(["--repo", github.repo, "--api", github.url, "--now", now, *extra])


def _record(github: FakeGitHub) -> str:
    [issue] = [i for i in github.issues if i["title"] == "valvur health"
               and (i.get("user") or {}).get("login") == "github-actions[bot]"]
    return issue["body"]


def test_the_issue_gives_the_score_by_track_from_the_recorded_run_on_main(github):
    assert _run(github) == 0

    body = _record(github)
    assert "**The Score: 76.8**, measured on 2026-11-16" in body
    assert "| sast-python | 39.0 |" in body and "| secrets | 100.0 |" in body
    assert "| 1.0 |" not in body, "a branch's run is not the project's Score"


def test_it_gives_the_published_images_verdict_by_day(github):
    assert _run(github) == 0

    body = _record(github)
    assert "| 2026-11-22 | 0 | 1 | 0 |" in body
    assert "| 2026-11-21 | 2 | 1 | 0 |" in body
    assert body.index("| 2026-11-22 |") < body.index("| 2026-11-21 |"), "newest first"


def test_it_gives_the_mutation_score(github):
    assert _run(github) == 0

    assert ("**The mutation score: 83.8**, measured on 2026-11-18: of the week's code "
            "hunks, 31 reverted were noticed by a test and 6 were not") in _record(github)


def test_a_number_that_cannot_be_read_keeps_its_last_value_and_date_and_says_so(github):
    assert _run(github) == 0
    github.broken.add("eval-report")
    github.artifacts[:] = [a for a in github.artifacts if a["name"] != "mutation-report"]

    assert _run(github, now="2026-11-24T07:00:00Z") == 0

    body = _record(github)
    assert "**The Score: 76.8**, measured on 2026-11-16" in body
    assert "could not be read on 2026-11-24" in body and "| sast-python | 39.0 |" in body
    assert "**The mutation score: 83.8**, measured on 2026-11-18" in body
    assert body.count("could not be read on 2026-11-24") == 2
    assert "| 2026-11-21 | 2 | 1 | 0 |" in body, "a day already read is kept"


def test_a_number_never_read_is_said_to_be_absent_not_left_out():
    with FakeGitHub() as empty:
        assert _run(empty) == 0

        body = _record(empty)
    assert "**The Score:** no recorded run on `main` could be read" in body
    assert "**The mutation score:** no recorded run could be read" in body
    assert "no verdict could be read" in body


def test_time_to_heal_is_given_against_its_target(github):
    """`heal_report.py` exists on this branch, so the line is its own summary. With no
    heal in the month, it says none, and the baseline it is measured against."""
    assert _run(github) == 0

    body = _record(github)
    assert "## Time to heal" in body
    assert "2026-11: 0 advisories healed" in body and "48 hours" in body
    assert "136.5 hours" in body


def test_a_second_run_rewrites_the_one_issue_and_opens_no_other(github):
    assert _run(github) == 0
    github.artifact("image-gate-published", {"image-gate.json": CLEAN},
                    created="2026-11-23T04:00:00Z")

    assert _run(github, now="2026-11-24T07:00:00Z") == 0

    assert [i["title"] for i in github.issues] == ["valvur health"]
    assert [w[0] for w in github.writes] == ["POST", "PATCH"]
    body = _record(github)
    assert "| 2026-11-23 | 0 | 1 | 0 |" in body and "| 2026-11-21 | 2 | 1 | 0 |" in body
    assert "Written on 2026-11-24" in body


def test_an_issue_of_the_same_title_by_someone_else_is_neither_read_nor_written(github):
    """The repository is public, and the record reads its own last values back: a
    stranger's issue of that title must not be able to write them."""
    planted = {"score": {"date": "2026-01-01", "score": 99.9, "tracks": {"planted": 99.9}}}
    theirs = github.issue("valvur health", user={"login": "someone-else"},
                          body=f"<!-- valvur-health-state\n{json.dumps(planted)}\n-->")
    github.broken.add("eval-report")

    assert _run(github) == 0

    assert theirs["body"].startswith("<!-- valvur-health-state"), "theirs is untouched"
    assert "99.9" not in _record(github) and "planted" not in _record(github)
    assert not any(w[0] == "PATCH" and w[1].endswith(f"/issues/{theirs['number']}")
                   for w in github.writes)


def test_the_record_holds_what_it_read_where_the_next_run_finds_it(github):
    assert _run(github) == 0

    state = _script().state_of(_record(github))
    assert state["score"] == {"date": "2026-11-16", "score": 76.8,
                              "tracks": {"llm-output": 79.0, "sast-python": 39.0,
                                         "secrets": 100.0}}
    assert sorted(state["image"]) == ["2026-11-21", "2026-11-22"]


def test_a_token_is_sent_to_the_api_and_never_to_the_storage(github, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "a-token-for-the-test")

    assert _run(github) == 0

    assert github.storage_authorizations and not any(github.storage_authorizations)
    assert set(github.authorizations) == {"Bearer a-token-for-the-test"}


def test_a_dry_run_prints_the_record_and_writes_nothing(github, capsys):
    assert _run(github, extra=("--dry-run",)) == 0

    assert github.writes == []
    assert "**The Score: 76.8**" in capsys.readouterr().out


def test_an_image_day_older_than_thirty_is_dropped_from_the_record(github):
    assert _run(github) == 0

    assert _run(github, now="2026-12-22T07:00:00Z") == 0

    body = _record(github)
    assert "| 2026-11-22 |" in body and "| 2026-11-21 |" not in body


# ------------------------------------------------------------------ the workflow, the link

WORKFLOW = REPO / ".github" / "workflows" / "health.yml"
LINK = ("https://github.com/MaverickHQ/valvur/issues?q=is%3Aissue+is%3Aopen+in%3Atitle+"
        "%22valvur+health%22+author%3Aapp%2Fgithub-actions")


def _code() -> str:
    return "\n".join(line for line in WORKFLOW.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))


def test_the_workflow_runs_daily_and_on_dispatch_and_at_no_other_time():
    import re

    triggers = _code().split("\non:\n", 1)[1].split("\n\n", 1)[0]

    assert re.fullmatch(r'  schedule:\n    - cron: "\d+ \d+ \* \* \*".*\n  workflow_dispatch:.*',
                        triggers, re.S), triggers
    assert "pull_request" not in triggers and "push" not in triggers


def test_it_may_read_runs_and_write_issues_and_nothing_more():
    """Amended by R52.1: a download needs `actions: read`, beside `issues: write`."""
    import re

    code = _code()

    assert "\npermissions: {}\n" in code
    grants = re.findall(r"^    permissions:\n((?:      .+\n)+)", code, re.M)
    assert len(grants) == code.count("\n    runs-on:") == 1
    assert sorted(line.split("#")[0].strip() for line in grants[0].splitlines()) == [
        "actions: read", "issues: write"]
    assert "contents: write" not in code and "secrets." not in code
    assert "persist-credentials: false" in code


def test_every_action_it_uses_is_pinned_by_commit():
    import re

    uses = re.findall(r"uses:\s*(\S+)", _code())

    assert uses and all(one.startswith("./.github/actions/")
                        or re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", one) for one in uses), uses


def test_it_runs_the_script_with_arguments_the_script_takes():
    import re

    run = _code().split("python3 scripts/health.py", 1)[1].split("\n\n", 1)[0]
    script = SCRIPT.read_text(encoding="utf-8")

    passed = set(re.findall(r"(?<![\w-])(--[a-z][\w-]*)", run))
    assert "--repo" in passed and all(f'"{flag}"' in script for flag in passed)
    assert "GH_TOKEN: ${{ github.token }}" in _code()


def test_the_watchdog_reads_its_schedule():
    import importlib.util

    spec = importlib.util.spec_from_file_location("watchdog", REPO / "scripts" / "watchdog.py")
    watchdog = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["watchdog"] = watchdog
    spec.loader.exec_module(watchdog)  # type: ignore[union-attr]

    crons = watchdog.schedules(REPO / ".github" / "workflows")

    assert len(crons["health.yml"]) == 1


def test_the_readme_links_to_the_record():
    readme = (REPO / "README.md").read_text(encoding="utf-8")

    assert f"]({LINK})" in readme
    assert "author%3Aapp%2Fgithub-actions" in LINK, "the link finds the workflow's own issue"
