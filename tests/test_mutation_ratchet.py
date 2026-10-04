"""R29.5: the mutation score ratchets (D65d).

`mutation_check.py` reverts each hunk of a change and reports the ones no unit test
notices. It ran on pull requests only, non-required, so its score was read by nobody.
Now it runs weekly over the week's changes to `main`, and its score is a baseline that
may only rise: a week whose tests notice a smaller share of their own hunks fails.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = (REPO / ".github" / "workflows" / "mutation.yml").read_text()
BASELINE = REPO / "tests" / "eval" / "mutation-baseline.json"

_spec = importlib.util.spec_from_file_location("mutation_check",
                                               REPO / "scripts" / "mutation_check.py")
check = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("mutation_check", check)        # its dataclass looks itself up
_spec.loader.exec_module(check)


def _report(caught: int, survived: int, docs: int = 0):
    hunk = check.Hunk("src/valvur/x.py", "@@ -1 +1 @@")
    return ([(hunk, "caught")] * caught + [(hunk, "survived")] * survived
            + [(hunk, "no code change")] * docs)


def test_the_score_is_the_share_of_code_hunks_a_test_notices():
    assert check.score(_report(31, 6, docs=1)) == 83.8
    assert check.score(_report(0, 0, docs=2)) is None, "nothing to measure"


@pytest.mark.parametrize(("measured", "fails"), [(83.7, True), (83.8, False), (90.0, False),
                                                 (None, False)])
def test_a_fall_under_the_baseline_fails(measured, fails):
    assert check.falls(measured, {"score": 83.8}) is fails


@pytest.mark.parametrize(("measured", "kept"), [(90.0, 90.0), (80.0, 83.8), (None, 83.8)])
def test_the_baseline_only_rises(measured, kept):
    assert check.ratchet({"score": 83.8}, measured) == {"score": kept}


def test_the_recorded_baseline_is_r29_1_s_measurement_or_higher():
    recorded = json.loads(BASELINE.read_text())

    assert recorded["score"] >= 83.8


def test_main_compares_with_the_baseline_and_fails_on_a_fall(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"score": 90.0}))
    monkeypatch.setattr(check, "run", lambda repo, base, limit: _report(8, 2))
    monkeypatch.setattr(check, "_git", lambda *a, **k: "")

    assert check.main(["--base", "x", "--baseline", str(baseline)]) == 1
    assert "80.0" in capsys.readouterr().out
    assert json.loads(baseline.read_text()) == {"score": 90.0}, "never lowered"

    assert check.main(["--base", "x", "--baseline", str(baseline), "--update-baseline"]) == 1
    monkeypatch.setattr(check, "run", lambda repo, base, limit: _report(19, 1))
    assert check.main(["--base", "x", "--baseline", str(baseline), "--update-baseline"]) == 0
    assert json.loads(baseline.read_text()) == {"score": 95.0}


# ---------------------------------------------------------------- the workflow

def test_it_runs_weekly_over_the_week_s_changes_to_main_against_the_baseline():
    assert re.search(r"^\s+- cron: ", WORKFLOW, re.M) and "workflow_dispatch:" in WORKFLOW
    assert '--before="7 days ago"' in WORKFLOW
    assert "scripts/mutation_check.py" in WORKFLOW
    assert "--baseline tests/eval/mutation-baseline.json" in WORKFLOW


def test_its_failure_is_an_issue_and_its_pass_closes_it():
    assert "if: failure() && github.event_name == 'schedule'" in WORKFLOW
    assert "if: success() && github.event_name == 'schedule'" in WORKFLOW
    assert WORKFLOW.count("uses: ./.github/actions/file-issue") == 2


def test_it_reads_and_writes_nothing_but_issues():
    top = WORKFLOW.split("\npermissions:", 1)[1].split("\njobs:", 1)[0]
    assert top.strip() == "contents: read"
    assert "contents: write" not in WORKFLOW
    for uses in re.findall(r"uses:\s*(\S+)", WORKFLOW):
        assert uses.startswith("./") or re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", uses)
