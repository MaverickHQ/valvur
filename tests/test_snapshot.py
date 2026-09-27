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
    assert sources == {str(tmp_path), str(cache.trivy_db()), str(cache.name_index())}


def test_a_snapshot_that_arrives_short_refuses_the_scan(tmp_path, monkeypatch):
    import json

    import pytest

    from valvur import api
    from valvur.adapters import GitleaksAdapter

    class ShortRuntime:
        engine = True

        def run(self, plan, tar, scratch, on_event=None):
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
