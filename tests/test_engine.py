"""R3.1 onwards: the in-image engine, tested without a container.

`LocalRuntime` runs `python -m valvur.engine` as a host process, with stand-in tools
from `tests/fixtures/fake-tools` first on its PATH: the container runtime is the one
boundary this suite fakes (tasks.md §3). The engine itself runs for real.
"""

from __future__ import annotations

import json
from pathlib import Path

from valvur.adapters import GitleaksAdapter
from valvur.engine_host import LocalRuntime, snapshot

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
KEY = "AKIA" + "QX3ZR5TW7YB2MN4P"          # assembled: push protection is on


def _workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{KEY}"\n')
    (ws / "README.md").write_text("# two files\n")
    return ws


def test_the_engine_unpacks_a_snapshot_and_leaves_a_report_and_a_manifest(tmp_path):
    ws = _workspace(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    tar = snapshot(ws, ["config.py", "README.md"])
    code = LocalRuntime(FAKE_TOOLS).run([GitleaksAdapter().command(ws)], tar, scratch)

    assert code == 0
    manifest = json.loads((scratch / "manifest.json").read_text())
    assert manifest["received"] == 2
    [entry] = manifest["tools"]
    assert (entry["tool"], entry["exit_code"], entry["timed_out"]) == ("gitleaks", 0, False)
    report = json.loads((scratch / "gitleaks.json").read_text())
    assert [item["File"] for item in report] == ["/workspace/config.py"]


def test_a_scan_through_the_engine_reports_the_planted_secret(tmp_path, monkeypatch):
    from valvur import api

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws = _workspace(tmp_path)
    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[GitleaksAdapter()])
    findings = json.loads((ws / ".security-scan" / "findings.json").read_text())["findings"]
    assert [(f["rule"], f["path"]) for f in findings] == [("aws-access-token", "config.py")]


def test_container_paths_map_whole_prefixes_only(tmp_path):
    from valvur.engine import _mapped

    workspace, results = tmp_path / "results-workspace", tmp_path / "results"
    assert _mapped("/workspace", workspace, results) == str(workspace)
    assert _mapped("--report-path=/results/g.json", workspace, results) == \
        f"--report-path={results}/g.json"
    assert _mapped("/workspaces-other", workspace, results) == "/workspaces-other"


import pytest  # noqa: E402


@pytest.mark.e2e
def test_a_real_scan_container_reports_the_planted_secret(mountable_tmp, monkeypatch):
    from valvur import api
    from valvur.engine_host import ContainerRuntime

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws = _workspace(mountable_tmp)
    api.scan(ws, runner=ContainerRuntime(), adapters=[GitleaksAdapter()])
    findings = json.loads((ws / ".security-scan" / "findings.json").read_text())["findings"]
    assert [(f["rule"], f["path"]) for f in findings] == [("aws-access-token", "config.py")]
