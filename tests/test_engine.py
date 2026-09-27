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


def _plan(*entries):
    from valvur.invocation import Invocation

    return [Invocation(tool=tool, version="0", argv=tuple(argv), report=report,
                       timeout=timeout) for tool, argv, report, timeout in entries]


def _run(tmp_path, plan, events=None):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    ws = _workspace(tmp_path)
    LocalRuntime(FAKE_TOOLS).run(plan, snapshot(ws, ["config.py"]), scratch,
                                 on_event=(events.append if events is not None else None))
    return scratch, json.loads((scratch / "manifest.json").read_text())


def test_the_tools_run_in_parallel(tmp_path):
    import time

    plan = _plan(("a", ["fake-sleep", "1", "/results/a.json"], "a.json", 30),
                 ("b", ["fake-sleep", "1", "/results/b.json"], "b.json", 30),
                 ("c", ["fake-sleep", "1", "/results/c.json"], "c.json", 30))
    started = time.monotonic()
    _scratch, manifest = _run(tmp_path, plan)
    assert time.monotonic() - started < 2.5, "three one-second tools ran one after another"
    assert sorted(e["tool"] for e in manifest["tools"]) == ["a", "b", "c"]


def test_a_tool_past_its_timeout_is_killed_with_its_whole_group(tmp_path):
    import os
    import time

    pidfile = tmp_path / "grandchild.pid"
    plan = _plan(("slow", ["fake-spawn", str(pidfile)], None, 1))
    started = time.monotonic()
    _scratch, manifest = _run(tmp_path, plan)
    [entry] = manifest["tools"]
    assert time.monotonic() - started < 10
    assert (entry["timed_out"], entry["exit_code"]) == (True, 124)
    assert not entry["stderr_tail"].startswith(("canning", "orkspace", "hile")), \
        "the excerpt starts mid-word"
    grandchild = int(pidfile.read_text())
    time.sleep(0.2)
    try:
        os.kill(grandchild, 0)
        alive = True
    except ProcessLookupError:
        alive = False
    assert not alive, "the timed-out tool's grandchild outlived it"
