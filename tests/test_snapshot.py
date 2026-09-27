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
