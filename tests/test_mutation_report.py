"""R52.5: the weekly mutation run leaves its score where a script can read it.

R52.1 found the mutation score in no artifact: `mutation.yml` printed it, and a log is
nothing a script should parse. The check now writes what it measured as JSON when asked,
and the workflow uploads it as `mutation-report`, which the Health record reads.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = (REPO / ".github" / "workflows" / "mutation.yml").read_text(encoding="utf-8")


def _check():
    spec = importlib.util.spec_from_file_location("mutation_check",
                                                  REPO / "scripts" / "mutation_check.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["mutation_check"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_what_a_run_measured_is_its_score_and_the_counts_behind_it():
    check = _check()
    hunk = check.Hunk("src/valvur/x.py", "@@ -1 +1 @@")
    report = ([(hunk, "caught")] * 31 + [(hunk, "survived")] * 6
              + [(hunk, "no code change")] * 4 + [(hunk, "not applied")] * 2)

    assert check.measurement(report) == {"score": 83.8, "caught": 31, "survived": 6,
                                      "documentation_only": 4, "not_applied": 2}


def test_a_run_with_no_code_hunk_has_no_score_to_report():
    check = _check()
    hunk = check.Hunk("src/valvur/x.py", "@@ -1 +1 @@")

    assert check.measurement([(hunk, "no code change")])["score"] is None


def test_it_is_written_where_asked(tmp_path):
    check = _check()
    hunk = check.Hunk("src/valvur/x.py", "@@ -1 +1 @@")
    out = tmp_path / "mutation.json"

    check.write_measured(out, [(hunk, "caught"), (hunk, "survived")])

    assert json.loads(out.read_text()) == {"score": 50.0, "caught": 1, "survived": 1,
                                           "documentation_only": 0, "not_applied": 0}


def test_the_workflow_asks_for_it_and_uploads_it_whatever_the_score_did():
    run = WORKFLOW.split("scripts/mutation_check.py", 1)[1].split("\n\n", 1)[0]
    script = (REPO / "scripts" / "mutation_check.py").read_text(encoding="utf-8")

    assert "--out mutation.json" in run and '"--out"' in script
    upload = WORKFLOW.split("name: mutation-report", 1)[0].rsplit("- ", 1)[1]
    after = WORKFLOW.split("name: mutation-report", 1)[1].split("\n\n", 1)[0]
    assert "actions/upload-artifact@" in upload
    assert "if: always()" in upload, "a score that fell is the one most worth recording"
    assert "path: mutation.json" in after and "if-no-files-found: ignore" in after
    assert "retention-days: 90" in after
