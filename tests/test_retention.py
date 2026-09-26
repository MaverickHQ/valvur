"""Package retention (28.3.1, D2): the workflow's shape.

The three policies the task names, held as text: the rehearsal image and the
daily index are pruned by count, newest first, so a multi-architecture image
keeps its untagged platform manifests; the published image is never named, so a
release and the manifests under its tag cannot be deleted by a schedule.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "retention.yml"


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _steps() -> list[str]:
    """Each `uses: actions/delete-package-versions` step's text, to its end."""
    return _text().split("uses: actions/delete-package-versions@")[1:]


def test_the_job_runs_on_a_schedule_and_by_hand():
    text = _text()
    assert re.search(r"^\s+- cron: ", text, re.M), "no schedule"
    assert "workflow_dispatch:" in text, "cannot be run by hand for the first measurement"
    assert "packages: write" in text


def test_every_delete_step_is_pinned_by_commit():
    for step in _steps():
        assert re.match(r"[0-9a-f]{40} # v\d", step), "delete-package-versions pinned by a tag"


def test_the_rehearsal_and_the_index_are_kept_by_count_and_the_image_is_never_named():
    steps = {}
    for step in _steps():
        named = re.search(r"package-name:\s*(\S+)", step)
        assert named, "a delete step names no package"
        steps[named.group(1)] = step

    assert set(steps) == {"valvur-rehearsal", "valvur-index"}, sorted(steps)
    for name, step in steps.items():
        assert "package-type: container" in step, name
        keep = re.search(r"min-versions-to-keep:\s*(\d+)", step)
        assert keep, f"{name} has no count to keep"
        # By count, never by tag: a tag-based prune deletes the untagged platform
        # manifests under a tag that stays.
        assert "delete-only-untagged-versions" not in step, name
        assert "ignore-versions" not in step, name
    def keeps(name: str) -> int:
        match = re.search(r"min-versions-to-keep:\s*(\d+)", steps[name])
        assert match, name
        return int(match.group(1))

    assert keeps("valvur-rehearsal") >= 25, "fewer than the last five rehearsals whole"
    assert keeps("valvur-index") >= 90, "fewer than the thirty dated tags the task asks for"
    assert "package-name: valvur\n" not in _text(), "the published image is pruned by schedule"
