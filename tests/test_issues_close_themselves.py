"""R28.3: a scheduled job's issue closes itself when the next run passes (D64b).

The issue-on-failure action opened one issue per failing workflow and commented on it
after that. Closing it was the owner's: #147 and #170 were closed by hand once their
cause had passed, and #181 stayed open after. Now each workflow that files an issue on
failure closes it, through the same action, when a later run of the same job passes.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ACTION = (REPO / ".github" / "actions" / "file-issue" / "action.yml").read_text()
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))


def _steps(text: str) -> list[str]:
    return re.split(r"\n\s+- (?=name:|uses:|if:|id:)", text)


def _issue_steps(text: str) -> list[dict[str, str]]:
    found = []
    for step in _steps(text):
        if "uses: ./.github/actions/file-issue" not in step:
            continue
        field = {key: value.strip().strip("'\"") for key, value in
                 re.findall(r"^\s*(if|title|passed):\s*(.+)$", step, re.M)}
        found.append(field)
    return found


def _mirrors(condition: str) -> set[str]:
    """The conditions under which a run passed, from the one under which it failed. In
    a job that runs after the jobs it needs, `failure()` is theirs, and a pass is said by
    their results, since `success()` there is ambiguous."""
    assert "failure()" in condition, condition
    return {condition.replace("failure()", "success()"),
            condition.replace("failure()", "!contains(needs.*.result, 'failure')")}


def test_the_action_closes_the_open_issue_of_its_title_when_told_the_run_passed():
    inputs = ACTION.split("\ninputs:", 1)[1].split("\nruns:", 1)[0]
    assert re.search(r"^  passed:\n(?:    .+\n)*?    default: ['\"]?false", inputs, re.M)
    run = ACTION.split("run: |", 1)[1]

    assert "gh issue close" in run
    # Only the issue of this exact title: the search is fuzzy, the close must not be.
    assert "select(.title == $ENV.TITLE)" in run


def test_the_failure_half_still_needs_what_failed_and_why():
    run = ACTION.split("run: |", 1)[1]

    assert re.search(r'\[ -z "\$FAILED" \] \|\| \[ -z "\$BODY" \]', run)


def test_every_workflow_that_files_an_issue_on_failure_closes_it_on_success():
    files = 0
    for workflow in WORKFLOWS:
        steps = _issue_steps(workflow.read_text())
        opened = [s for s in steps if s.get("passed", "false") != "true"]
        closed = {(s["title"], s["if"]) for s in steps if s.get("passed") == "true"}
        for step in opened:
            files += 1
            pairs = {(step["title"], c) for c in _mirrors(step["if"])}
            assert pairs & closed, f"{workflow.name}: nothing closes '{step['title']}'"
    assert files >= 9, "the scheduled workflows' issue steps were not found"
