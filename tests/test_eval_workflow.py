"""R9.6: the Score's Linux lane, `eval.yml`, held to the script it runs (ADR-0026).

A workflow that passes an argument the harness no longer takes fails only when it
runs, weekly; this test fails on the commit that breaks it.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = (REPO / ".github" / "workflows" / "eval.yml").read_text()
SCRIPT = (REPO / "scripts" / "eval.py").read_text()


def test_every_argument_the_workflow_passes_is_one_the_harness_takes():
    run = WORKFLOW.split("python scripts/eval.py", 1)[1].split("\n\n", 1)[0]
    passed = set(re.findall(r"(?<![\w-])(--[a-z][\w-]*)", run))

    assert passed, "the workflow no longer runs scripts/eval.py"
    for flag in passed:
        assert f'"{flag}"' in SCRIPT, f"eval.yml passes {flag}, which scripts/eval.py lacks"


def test_it_runs_weekly_on_dispatch_and_on_a_change_to_the_harness():
    assert re.search(r"^\s+- cron: ", WORKFLOW, re.M)
    assert "workflow_dispatch:" in WORKFLOW
    for path in ("scripts/eval.py", "scripts/eval/**", "tests/eval/**", "rules/**"):
        assert f'"{path}"' in WORKFLOW


def test_it_scans_with_the_image_built_from_the_tree_and_compares_when_it_can():
    assert "docker buildx bake dev" in WORKFLOW
    assert "VALVUR_IMAGE: valvur:dev" in WORKFLOW
    assert "--compare tests/eval/baseline.json" in WORKFLOW


def test_a_release_is_stopped_by_a_score_under_its_baseline():
    """N4.3: the detection a release ships is measured before it leaves. The Score
    runs in `verify`, before anything is pushed, against the committed baseline."""
    release = (REPO / ".github" / "workflows" / "release.yml").read_text()
    verify = release.split("\n  verify:", 1)[1].split("\n  build:", 1)[0]

    assert "python scripts/eval.py" in verify
    assert "--compare tests/eval/baseline.json" in verify
    assert "VALVUR_IMAGE: valvur:dev" in verify.split("python scripts/eval.py")[0].rsplit(
        "- name:", 1)[1]
