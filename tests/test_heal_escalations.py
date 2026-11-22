"""R44.5: what the heal cannot do reaches the owner once (Requirement 11, D81m).

`scripts/heal.py escalations` turns a plan and the run's Findings into the issues to open,
to comment on and to close: one per `heal: <reason>: <subject>`. It reads the open issues
as `gh issue list --json number,title,body,author,comments` gives them and writes nothing:
the workflow's `escalate` job applies what it prints.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HEAL = REPO / "scripts" / "heal.py"
DESIGN = REPO / ".kiro" / "specs" / "self-healing-supply-chain" / "design.md"
NOW = "2026-10-21T06:41:00Z"
RUN = "https://github.com/MaverickHQ/valvur/actions/runs/2"
BOT = {"is_bot": True, "login": "app/github-actions"}


def _plan(*escalations: dict, findings: tuple[dict, ...] = ()) -> dict:
    return {"schema": 1, "made": NOW, "lock": "requirements-checkov.txt",
            "findings": list(findings), "pins": [], "escalations": list(escalations)}


def _escalations(tmp_path: Path, plan: dict, *, issues: tuple[dict, ...] = (),
                 observed: tuple[dict, ...] = ()) -> list[dict]:
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    (tmp_path / "issues.json").write_text(json.dumps(list(issues)))
    (tmp_path / "findings.json").write_text(json.dumps({"schema": 1, "findings": list(observed)}))
    run = subprocess.run(
        [sys.executable, str(HEAL), "escalations", "--plan", str(tmp_path / "plan.json"),
         "--observed", str(tmp_path / "findings.json"), "--issues", str(tmp_path / "issues.json"),
         "--now", NOW, "--run", RUN], capture_output=True, text=True, check=False, cwd=tmp_path)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)["actions"]


def _issue(number: int, title: str, body: str = "", *, author: dict | None = None,
           comments: tuple[dict, ...] = ()) -> dict:
    return {"number": number, "title": title, "body": body, "author": author or BOT,
            "comments": list(comments)}


MAJOR = {"package": "beta", "reason": "major", "findings": ["fp-1"]}


def test_an_escalation_with_no_issue_opens_one_titled_from_reason_and_package(tmp_path):
    actions = _escalations(tmp_path, _plan(MAJOR))

    assert [(a["action"], a["title"]) for a in actions] == [("open", "heal: major: beta")]
    assert "new major version" in actions[0]["body"] and "beta" in actions[0]["failed"]


def test_the_reasons_are_the_designs_closed_list():
    sys.path.insert(0, str(HEAL.parent))
    import heal

    section = DESIGN.read_text().split("### 8. Escalations")[1].split("\n### ")[0]
    listed = re.findall(r"^\| `([a-z-]+)` \|", section, re.M)

    assert len(listed) == 12
    assert sorted(heal.REASONS) == sorted(listed)


def test_the_same_cause_at_the_next_run_opens_nothing_and_says_nothing_twice(tmp_path):
    opened = _escalations(tmp_path, _plan(MAJOR))[0]
    had = _issue(7, opened["title"], opened["failed"] + "\n\n" + opened["body"])

    assert _escalations(tmp_path, _plan(MAJOR), issues=(had,)) == []


def test_new_evidence_for_an_open_issue_is_a_comment_on_it(tmp_path):
    opened = _escalations(tmp_path, _plan(MAJOR))[0]
    had = _issue(7, opened["title"], opened["failed"] + "\n\n" + opened["body"])
    more = {**MAJOR, "findings": ["fp-1", "fp-2"]}

    actions = _escalations(tmp_path, _plan(more), issues=(had,))

    assert [(a["action"], a["number"], a["title"]) for a in actions] == [
        ("comment", 7, "heal: major: beta")]
    said = _issue(7, opened["title"], had["body"], comments=(
        {"author": {"login": "github-actions"}, "body": actions[0]["body"]},))
    assert _escalations(tmp_path, _plan(more), issues=(said,)) == []


def test_a_cause_that_has_gone_closes_its_issue_naming_the_run(tmp_path):
    had = _issue(7, "heal: major: beta", "…")

    actions = _escalations(tmp_path, _plan(), issues=(had,))

    assert [(a["action"], a["number"]) for a in actions] == [("close", 7)]
    assert RUN in actions[0]["comment"]


def test_issues_that_are_not_this_steps_to_close_are_left_alone(tmp_path):
    others = (
        _issue(1, "heal: policy-refused: #310", "…"),
        _issue(2, "heal: release-stopped: v1.6.3", "…"),
        _issue(3, "heal: major: beta", "…", author={"is_bot": False, "login": "a-stranger"}),
        _issue(4, "heal: no-such-reason: beta", "…"),
        _issue(5, "watchdog: heal.yml", "…"),
    )

    actions = _escalations(tmp_path, _plan(MAJOR), issues=others)

    assert [(a["action"], a["title"]) for a in actions] == [("open", "heal: major: beta")]
