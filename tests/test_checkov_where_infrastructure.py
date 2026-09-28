"""R4.3: Checkov only where there is infrastructure other than workflows (F2.1, F2.2).

R4.1 kept Checkov (KICS found 14 of its 22 distinct rules) and gave workflows to
zizmor. So a workflow no longer decides that Checkov runs, and where Checkov does run
it leaves workflows alone, or one write-all permission would be two Findings.
"""

from __future__ import annotations

from pathlib import Path


def test_where_checkov_runs_it_leaves_workflows_to_zizmor(tmp_path):
    from valvur.adapters import CheckovAdapter

    argv = CheckovAdapter().command(tmp_path).argv
    assert argv[argv.index("--skip-framework") + 1] == "github_actions"


def test_a_workflows_only_repository_skips_checkov_and_says_why(tmp_path):
    from conftest import FakeRunner

    from valvur import api, cache
    from valvur.adapters import CheckovAdapter, GitleaksAdapter

    (tmp_path / "cache").mkdir()
    ws = tmp_path / "ws"
    (ws / ".github" / "workflows").mkdir(parents=True)
    (ws / ".github" / "workflows" / "ci.yml").write_text("on: push\njobs: {}\n")
    (ws / "app.py").write_text("x = 1\n")
    import pytest

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(cache, "root", lambda: tmp_path / "cache")
        run = api.scan(ws, runner=FakeRunner(), adapters=[GitleaksAdapter(), CheckovAdapter()])
    [checkov] = [s for s in run.scanners if s.tool == "checkov"]
    assert checkov.skipped and checkov.ok
    assert "zizmor" in checkov.reason
    assert Path(ws / ".security-scan" / "run.json").exists()
