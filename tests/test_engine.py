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


@pytest.mark.timing
def test_the_tools_run_in_parallel(tmp_path):
    import time

    plan = _plan(("a", ["fake-sleep", "1", "/results/a.json"], "a.json", 30),
                 ("b", ["fake-sleep", "1", "/results/b.json"], "b.json", 30),
                 ("c", ["fake-sleep", "1", "/results/c.json"], "c.json", 30))
    started = time.monotonic()
    _scratch, manifest = _run(tmp_path, plan)
    assert time.monotonic() - started < 2.5, "three one-second tools ran one after another"
    assert sorted(e["tool"] for e in manifest["tools"]) == ["a", "b", "c"]


@pytest.mark.timing
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


def test_a_crash_or_a_missing_tool_fails_alone(tmp_path):
    plan = _plan(("ok", ["fake-sleep", "0", "/results/ok.json"], "ok.json", 30),
                 ("crash", ["fake-crash"], None, 30),
                 ("missing", ["no-such-tool-anywhere"], None, 30))
    _scratch, manifest = _run(tmp_path, plan)
    by_tool = {e["tool"]: e for e in manifest["tools"]}
    assert by_tool["ok"]["exit_code"] == 0
    assert (by_tool["crash"]["exit_code"], by_tool["crash"]["stderr_tail"]) == (
        2, "fatal: the tool could not start")
    assert by_tool["missing"]["exit_code"] == 127


def test_an_unreadable_report_fails_its_scanner_and_the_others_stand(tmp_path, monkeypatch):
    from valvur import api
    from valvur.adapters import OpengrepAdapter

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws = _workspace(tmp_path)
    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS),
                   adapters=[GitleaksAdapter(), OpengrepAdapter()])
    by_tool = {s.tool: s for s in run.scanners}
    assert by_tool["gitleaks"].ok and not by_tool["opengrep"].ok
    assert by_tool["opengrep"].reason.startswith("report unreadable")
    assert [f.rule for f in run.findings] == ["aws-access-token"]


def test_progress_arrives_while_the_tools_run(tmp_path):
    import time

    arrivals: list[tuple[float, dict]] = []
    plan = _plan(("a", ["fake-sleep", "1", "/results/a.json"], "a.json", 30),
                 ("b", ["fake-sleep", "0", "/results/b.json"], "b.json", 30))
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    ws = _workspace(tmp_path)
    LocalRuntime(FAKE_TOOLS).run(plan, snapshot(ws, ["config.py"]), scratch,
                                 on_event=lambda e: arrivals.append((time.monotonic(), e)))
    finished = time.monotonic()
    kinds = [(e["event"], e.get("tool")) for _, e in arrivals]
    assert kinds[0] == ("received", None)
    for tool in ("a", "b"):
        assert kinds.index(("start", tool)) < kinds.index(("end", tool))
    first_start = next(at for at, e in arrivals if e["event"] == "start")
    assert finished - first_start > 0.5, "progress arrived only after the run"


def test_a_timed_out_scanner_says_so_with_an_excerpt_that_ends_on_a_word(tmp_path, monkeypatch):
    from valvur import api
    from valvur.adapters.base import ScannerAdapter
    from valvur.invocation import Invocation

    class Slow(ScannerAdapter):
        name = "slow"
        version = "0"

        def command(self, workspace):
            return Invocation(tool="slow", version="0",
                              argv=("fake-spawn", str(tmp_path / "pid")), timeout=1)

        def parse(self, output):
            return []

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws = _workspace(tmp_path)
    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[Slow(), GitleaksAdapter()])
    slow = next(s for s in run.scanners if s.tool == "slow")
    assert slow.reason.startswith("timed out after 1s and was stopped — last stderr: ")
    excerpt = slow.reason.split("last stderr: ", 1)[1]
    assert excerpt.endswith("…") and excerpt[-2].isalpha() and excerpt[-3:-1] != "wh", excerpt


def test_a_tool_killed_by_a_signal_is_recorded_as_the_shell_records_it(tmp_path):
    """The runtime's OOM killer sends SIGKILL; Python reports that as -9, and the
    host reads exit 137 as "killed by the runtime" (29.0.3). The engine records
    128 plus the signal, as a shell and `docker run` do."""
    import json

    from valvur.invocation import Invocation

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "a.py").write_text("x = 1\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    LocalRuntime(FAKE_TOOLS).run(
        [Invocation(tool="hog", version="0", report="hog.json", argv=("fake-killed",))],
        snapshot(ws, ["a.py"]), scratch)
    [entry] = json.loads((scratch / "manifest.json").read_text())["tools"]
    assert entry["exit_code"] == 137


def test_a_tools_files_are_in_its_working_directory(tmp_path):
    """What an Invocation carries in `files` is written where the tool starts, so
    a tool that reads its configuration from its working directory finds it:
    Opengrep's `.semgrepignore` (R3.9)."""
    from valvur.invocation import Invocation

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "a.py").write_text("x = 1\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    LocalRuntime(FAKE_TOOLS).run(
        [Invocation(tool="cat", version="0", report="cat.txt",
                    argv=("fake-cat-cwd", ".semgrepignore", "/results/cat.txt"),
                    files=((".semgrepignore", "# nothing\n"),))],
        snapshot(ws, ["a.py"]), scratch)
    assert (scratch / "cat.txt").read_text() == "# nothing\n"


def test_opengrep_is_told_to_ignore_nothing():
    """Opengrep, like Semgrep, skips `build/`, `dist/`, `vendor/`, `test/` and
    `tests/` when it finds no `.semgrepignore` — measured inside the image, a
    flaw in `mypkg/build/` and one in `tests/` were both unread. The File Set
    decides what is read (ADR-0021); an ignore file that ignores nothing turns
    the tool's own list off."""
    from valvur.adapters import OpengrepAdapter

    files = dict(OpengrepAdapter().command(Path("/nonexistent")).files)
    ignore = files[".semgrepignore"]
    assert [line for line in ignore.splitlines() if line and not line.startswith("#")] == []
