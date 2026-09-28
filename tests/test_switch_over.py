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
             on_progress=said.append)
    assert "fleet: 1 Scanners, 1 at a time" in said
    assert "gitleaks: started" in said
    assert any(line.startswith("gitleaks: ok (") and line.endswith("s)") for line in said)


def test_the_cli_and_the_mcp_server_scan_through_the_scan_container(ws, monkeypatch):
    from valvur import api, cli, engine_host, operations
    from valvur.adapters import GitleaksAdapter
    from valvur.mcp import jobs

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
        operations.start_scan({"workspace": str(ws)})
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
