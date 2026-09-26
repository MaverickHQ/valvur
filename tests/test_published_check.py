"""29.3.1 — the README cannot be ahead of PyPI (the gate's B4).

The prep commit bumps the README's status line before the tag, and the brake
between validation and promotion can be held for days; at the first gate the
README on `main` said `0.4.0 — published and installable` while PyPI served
`0.3.0`. Two wordings now, and a daily check of whichever is written.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "published.yml"


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_the_check_runs_daily_and_by_hand_and_may_open_an_issue():
    text = _text()
    assert re.search(r"^\s+- cron: ", text, re.M), "no schedule"
    assert "workflow_dispatch:" in text
    assert "issues: write" in text and "if: failure()" in text
    assert "gh issue create" in text and "gh issue comment" in text


def test_the_check_reads_the_readme_and_asks_both_registries():
    text = _text()
    assert "README.md" in text and "Status: `" in text
    assert "published and installable" in text and "release in progress" in text
    assert "pypi.org/pypi/valvur/" in text
    assert "docker manifest inspect" in text and "ghcr.io/maverickhq/valvur:" in text
    # Both directions: a claim ahead of the registries, and a claim behind them.
    assert "is published; PyPI" in text
    assert "still says release in progress" in text


def test_every_action_is_pinned_by_commit():
    for step in _text().split("uses: ")[1:]:
        assert re.match(r"\S+@[0-9a-f]{40} # v", step), "an action pinned by tag"
