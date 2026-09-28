"""R3.3: the Snapshot (ADR-0022): where it lands, that it arrived whole, and that
the source tree is never mounted."""

from __future__ import annotations

from valvur.engine_host import TMPFS_LIMIT, ContainerRuntime


def _mounts(command: list[str]) -> list[str]:
    return [command[i + 1] for i, arg in enumerate(command) if arg == "-v"]


def _tmpfs(command: list[str]) -> list[str]:
    return [command[i + 1] for i, arg in enumerate(command) if arg == "--tmpfs"]


def test_a_small_snapshot_lands_in_memory_and_a_large_one_in_a_per_scan_volume(tmp_path):
    runtime = ContainerRuntime(image="valvur:dev", runtime="/usr/local/bin/docker")
    small = runtime.command(tmp_path, snapshot_bytes=10 * 2**20, name="valvur-a")
    assert any(t.startswith("/workspace:") for t in _tmpfs(small))
    assert not any(m.endswith(":/workspace") for m in _mounts(small))

    large = runtime.command(tmp_path, snapshot_bytes=TMPFS_LIMIT + 1, name="valvur-b")
    assert not any(t.startswith("/workspace:") for t in _tmpfs(large))
    assert "valvur-b-snapshot:/workspace" in _mounts(large)


def test_the_container_mounts_only_valvurs_own_directories(tmp_path):
    from valvur import cache

    runtime = ContainerRuntime(image="valvur:dev", runtime="/usr/local/bin/docker")
    sources = {m.split(":", 1)[0] for m in _mounts(runtime.command(tmp_path, name="valvur-c"))}
    from valvur import osv_offline

    # OSV's offline database joined valvur's own mounts in R4.6.
    assert sources == {str(tmp_path), str(cache.trivy_db()), str(cache.name_index()),
                       str(osv_offline.directory())}


def test_a_snapshot_that_arrives_short_refuses_the_scan(tmp_path, monkeypatch):
    import json

    import pytest

    from valvur import api
    from valvur.adapters import GitleaksAdapter

    class ShortRuntime:
        engine = True

        def run(self, plan, tar, scratch, on_event=None, budget_s=None, jobs=None):
            (scratch / "gitleaks.json").write_text("[]")
            (scratch / "manifest.json").write_text(json.dumps({"received": 1, "tools": [
                {"tool": "gitleaks", "exit_code": 0, "seconds": 0.1, "timed_out": False,
                 "stderr_tail": ""}]}))
            return 0

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws = tmp_path / "ws"
    ws.mkdir()
    for name in ("a.py", "b.py"):
        (ws / name).write_text("x = 1\n")
    with pytest.raises(api.ScannerFailed) as refused:
        api.scan(ws, runner=ShortRuntime(), adapters=[GitleaksAdapter()])
    assert "received 1 of 2 files" in str(refused.value)


def _running_mounts(runtime, plan, tar, scratch):
    """Start the Scan Container in a thread and read its mounts while it runs."""
    import json
    import subprocess
    import threading
    import time

    before = set(subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True,
                                check=True).stdout.split())
    worker = threading.Thread(target=runtime.run, args=(plan, tar, scratch))
    worker.start()
    mounts = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and mounts is None:
        now = set(subprocess.run(["docker", "ps", "-q", "--filter", "name=valvur-"],
                                 capture_output=True, text=True, check=True).stdout.split())
        for container in now - before:
            out = subprocess.run(["docker", "inspect", "--format", "{{json .Mounts}}",
                                  container], capture_output=True, text=True, check=False)
            if out.returncode == 0:
                mounts = json.loads(out.stdout)
        time.sleep(0.1)
    worker.join(60)
    return mounts


import pytest  # noqa: E402


@pytest.mark.e2e
def test_a_running_scan_container_has_no_mount_of_the_source_tree(mountable_tmp, monkeypatch):
    import subprocess

    from valvur import engine_host
    from valvur.engine_host import snapshot
    from valvur.invocation import Invocation

    ws = mountable_tmp / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")
    plan = [Invocation(tool="probe", version="0", argv=("sleep", "3"))]
    for limit in (engine_host.TMPFS_LIMIT, 1):         # in memory, then a volume
        monkeypatch.setattr(engine_host, "TMPFS_LIMIT", limit)
        scratch = mountable_tmp / f"scratch-{limit}"
        scratch.mkdir()
        mounts = _running_mounts(ContainerRuntime(), plan, snapshot(ws, ["app.py"]), scratch)
        assert mounts is not None, "the container was never seen running"
        sources = {m.get("Source", "") for m in mounts}
        assert not any(str(ws) in s for s in sources), sources
        volumes = [m for m in mounts if m.get("Type") == "volume"]
        assert bool(volumes) is (limit == 1), mounts
    leftover = subprocess.run(["docker", "volume", "ls", "-q", "--filter", "name=-snapshot"],
                              capture_output=True, text=True, check=True).stdout.split()
    assert leftover == [], leftover
