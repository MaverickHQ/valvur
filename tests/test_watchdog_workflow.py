"""R42.5: `.github/workflows/watchdog.yml`'s shape (D81s, N3.8).

Daily, with a checkout that always runs, no write at the top level, and the job holding
`actions: read` and `issues: write` alone. Nothing is spliced into a shell command.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "watchdog.yml"


def _text() -> str:
    return WORKFLOW.read_text()


def test_it_runs_daily_at_06_47_and_on_a_dispatch_with_a_dry_run():
    text = _text()

    assert re.search(r'^  schedule:\n    - cron: "47 6 \* \* \*"', text, re.M)
    assert re.search(r"^  workflow_dispatch:\n    inputs:\n      dry_run:\n", text, re.M)
    assert "pull_request" not in text and "workflow_run" not in text


def test_the_job_holds_actions_read_and_issues_write_alone():
    text = _text()

    assert re.search(r"^permissions: \{\}$", text, re.M)
    jobs = re.findall(r"^    permissions:\n((?:      \S.*\n)+)", text, re.M)
    assert len(jobs) == 1
    granted = {line.split("#")[0].strip() for line in jobs[0].splitlines()}
    assert granted == {"actions: read", "issues: write"}


def test_its_checkout_always_runs_before_anything_from_the_tree():
    steps = re.split(r"^      - ", _text().split("\n    steps:\n", 1)[1], flags=re.M)
    first = next(step for step in steps if step.strip() and not step.lstrip().startswith("#"))

    assert first.startswith("uses: actions/checkout@")
    assert "if:" not in first
    assert "persist-credentials: false" in first


def test_actions_are_pinned_and_no_expression_is_inside_a_shell_command():
    text = _text()

    for uses in re.findall(r"uses: (\S+)", text):
        assert uses.startswith("./") or re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", uses)
    for block in re.findall(r"run: \|\n((?:          .*\n)+)", text):
        assert "${{" not in block, block
    assert "python3 scripts/watchdog.py" in text


def test_the_nightly_judges_the_watchdog_s_own_last_run():
    text = (REPO / ".github" / "workflows" / "acceptance.yml").read_text()
    job = text.split("\n  watchdog:\n", 1)[1]

    assert "python3 scripts/watchdog.py" in job and "--only watchdog.yml" in job
    granted = re.search(r"^    permissions:\n((?:      \S.*\n)+)", job, re.M)
    assert granted and {line.split("#")[0].strip() for line in granted.group(1).splitlines()} \
        == {"actions: read", "issues: write"}
    for block in re.findall(r"run: \|\n((?:          .*\n)+)", job):
        assert "${{" not in block, block
