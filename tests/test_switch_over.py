"""R3.9: the Scan Container is the only engine (ADR-0022).

A scan through a runtime that runs the engine uses it with no flag; the CLI and
the MCP server build that runtime; the status lines keep the words `scan_status`
reads (29.0.4); a first run still fetches what is absent (24.1); and `--jobs`
still bounds how many tools run at once, now inside the one container.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from valvur.engine_host import LocalRuntime
from valvur.invocation import Invocation

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
KEY = "AKIAV7Q2XR4TVBN6WLKJ"


@pytest.fixture
def ws(tmp_path, monkeypatch) -> Path:
    from valvur import cache

    monkeypatch.delenv("VALVUR_ENGINE", raising=False)
    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "config.py").write_text(f"KEY = '{KEY}'\n")
    return root


def test_a_runtime_that_runs_the_engine_is_used_with_no_flag(ws):
    from valvur import api
    from valvur.adapters import GitleaksAdapter

    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[GitleaksAdapter()])
    assert [f.path for f in run.findings if f.rule == "aws-access-token"] == ["config.py"]


def test_the_status_lines_keep_the_words_scan_status_reads(ws):
    from valvur import api
    from valvur.adapters import GitleaksAdapter

    said: list[str] = []
    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[GitleaksAdapter()],
             on_progress=lambda event: said.append(str(event)))
    assert "fleet: 1 Scanners, 1 at a time" in said
    assert "gitleaks: started" in said
    assert any(line.startswith("gitleaks: ok (") and line.endswith("s)") for line in said)


def test_the_cli_and_the_mcp_server_scan_through_the_scan_container(ws, monkeypatch):
    from valvur import api, cli, engine_host
    from valvur.adapters import GitleaksAdapter
    from valvur.mcp import handlers, jobs

    built: list[LocalRuntime] = []

    def local() -> LocalRuntime:
        built.append(LocalRuntime(FAKE_TOOLS))
        return built[-1]

    monkeypatch.setattr(engine_host, "for_scan", local)
    monkeypatch.setattr(api, "DEFAULT_ADAPTERS", [GitleaksAdapter()])
    assert cli.main(["scan", str(ws)]) == 0
    assert len(built) == 1
    jobs.reset()
    try:
        jobs.start(ws.resolve(), "offline", handlers._work(None, fresh=False))
        job = jobs.current(ws.resolve())
        assert job is not None and job.wait(30)
        assert job.state is jobs.State.DONE, job.error
    finally:
        jobs.reset()
    assert len(built) == 2


def test_the_scan_container_runtime_performs_a_first_runs_fetches(monkeypatch):
    from valvur.engine_host import ContainerRuntime
    from valvur.runner import ContainerRunner

    asked: list[str] = []
    for name in ("image_present", "pull_size_mb", "pull_image", "db_size_mb", "update_db",
                 "verify_compatible", "build_provenance"):
        monkeypatch.setattr(ContainerRunner, name,
                            lambda self, *a, _n=name, **k: asked.append(_n) or _n)
    runtime = ContainerRuntime(image="valvur:dev", runtime="/usr/local/bin/docker")
    for name in ("image_present", "pull_size_mb", "pull_image", "db_size_mb", "update_db",
                 "verify_compatible", "build_provenance"):
        assert getattr(runtime, name)() == name
    assert len(asked) == 7


def _sleepers(n: int) -> list[Invocation]:
    return [Invocation(tool=f"t{i}", version="0", report=f"t{i}.json", timeout=60,
                       argv=("fake-sleep", "1", f"/results/t{i}.json")) for i in range(n)]


@pytest.mark.timing
def test_jobs_bounds_how_many_tools_the_engine_runs_at_once(tmp_path):
    from valvur.engine_host import snapshot

    ws = tmp_path / "w"
    ws.mkdir()
    (ws / "a.py").write_text("a = 1\n")
    timings = {}
    for jobs in (None, 1):
        scratch = tmp_path / f"scratch-{jobs}"
        scratch.mkdir()
        started = time.monotonic()
        LocalRuntime(FAKE_TOOLS).run(_sleepers(3), snapshot(ws, ["a.py"]), scratch, jobs=jobs)
        timings[jobs] = time.monotonic() - started
    assert timings[None] < 2.5 <= timings[1], timings


class _Quiet:
    """A Scanner whose tool writes no report and says why on stderr."""

    kind = "scanner"
    version = "0"

    def __init__(self, name: str, code: int, message: str, empty_when=()):
        self.name, self.code, self.message, self.empty_when = name, code, message, empty_when

    def applies_to(self, workspace, context=None):
        return True, ""

    def command(self, workspace):
        return Invocation(tool=self.name, version="0", report=f"{self.name}.json", timeout=60,
                          argv=("fake-quiet", str(self.code), self.message),
                          empty_when=self.empty_when)

    def parse(self, output):
        import json

        return json.loads(output.stdout or "[]") and []

    def for_profile(self, *, network):
        return self


def test_nothing_to_scan_is_an_empty_result_and_a_missing_report_is_a_failure(ws):
    from valvur import api
    from valvur.adapters import GitleaksAdapter
    from valvur.invocation import NOTHING_TO_SCAN

    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[
        GitleaksAdapter(),
        _Quiet("nothing", 128, "No package sources found, --help for usage",
               empty_when=NOTHING_TO_SCAN),
        _Quiet("silent", 0, "could not open the report for writing")])
    by_tool = {s.tool: s for s in run.scanners}
    assert by_tool["nothing"].ok, by_tool["nothing"]
    assert not by_tool["silent"].ok
    assert "produced no report" in by_tool["silent"].reason


def test_on_an_enforcing_host_the_scan_containers_own_mounts_are_labelled(tmp_path, monkeypatch):
    """F1.6 for the Scan Container: every mount valvur owns carries `:z`, or an
    enforcing host denies the plan, the reports and the cache. There is no source
    mount to label (ADR-0022)."""
    from valvur import cache, engine_host, runner
    from valvur.engine_host import ContainerRuntime

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    for enforcing in (True, False):
        monkeypatch.setattr(engine_host, "selinux_enforcing", lambda e=enforcing: e)
        monkeypatch.setattr(runner, "selinux_enforcing", lambda e=enforcing: e)
        argv = ContainerRuntime(image="x/y:1", runtime="/usr/bin/podman").command(tmp_path)
        mounts = [argv[i + 1] for i, flag in enumerate(argv) if flag == "-v"]
        assert mounts and all(m.endswith((":z", ",z")) is enforcing for m in mounts), mounts
