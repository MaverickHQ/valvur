"""R28.5: the weekly maintenance routine's prompt and procedure (D64d).

A scheduled Claude Code cloud routine reads the week's failed scheduled runs, open
issues and stalled Dependabot pull requests, and fixes what it can on a branch, with a
pull request. `docs/MAINTENANCE.md` holds its prompt and procedure. Creating the
routine, and its monthly cap, are the owner's (§8). It never pushes to `main`, tags,
approves or merges, and this holds the document to that and to the workflows it names.
"""

from __future__ import annotations

import re
from pathlib import Path

from test_links import _markdown

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "docs" / "MAINTENANCE.md"
TEXT = DOC.read_text(encoding="utf-8")


def _prompt() -> str:
    section = TEXT.split("## The prompt", 1)[1].split("\n## ", 1)[0]
    return re.search(r"^```text\n(.*?)^```", section, re.S | re.M)[1]


def test_the_link_check_reads_it():
    assert DOC in _markdown()


def test_the_prompt_names_each_thing_it_reads():
    prompt = _prompt()

    for read in ("failed", "scheduled", "open issues", "Dependabot", "docs/MAINTENANCE.md"):
        assert read in prompt, read


def test_it_names_every_scheduled_workflow_and_no_other():
    scheduled = {p.name for p in (REPO / ".github" / "workflows").glob("*.yml")
                 if re.search(r"^  schedule:", p.read_text(), re.M)}
    named = set(re.findall(r"`([a-z-]+\.yml)`", TEXT.split("## The procedure", 1)[1]))

    assert scheduled and named == scheduled


def test_it_fixes_on_a_branch_with_a_pull_request_and_never_lands_anything():
    prompt = _prompt()

    assert "branch" in prompt and "pull request" in prompt
    for never in ("push to `main`", "tag", "approve", "merge", "enable auto-merge"):
        assert re.search(rf"[Nn]ever[^.]*{re.escape(never)}", prompt), never


def test_it_never_suppresses_a_finding_to_make_a_run_green():
    """CLAUDE.md §4: the finding disappeared is not the vulnerability is fixed."""
    prompt = _prompt()

    assert re.search(r"[Nn]ever[^.]*(suppress|skip|disable)", prompt)
