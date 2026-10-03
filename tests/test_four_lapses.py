"""The four lapses the review of 2026-10-03 found (§3.5, D54): invariants that were
comments, not types or tests, so nothing failed when ADR-0022 moved every tool into
one container.
"""

from __future__ import annotations

import dataclasses
import shutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"
#: The container's scratch mount, as the runtime is told it.
SCRATCH = "/tmp:"  # noqa: S108 — the container's mount, not a file on this host


# --------------------------------------------- (a) /tmp holds no executable

def test_no_tool_is_granted_an_executable_tmp(tmp_path):
    """`Invocation.allow_exec` said "granted per Scanner, never to the fleet", and
    the Scan Container gave it to every tool, because Opengrep unpacked itself
    there. Its core is unpacked at image build now, and `/tmp` is `noexec` for all."""
    from valvur.engine_host import ContainerRuntime
    from valvur.invocation import Invocation
    from valvur.runner import launch_flags

    assert "allow_exec" not in {f.name for f in dataclasses.fields(Invocation)}
    for argv in (ContainerRuntime(image="valvur:dev", runtime="docker").command(tmp_path),
                 launch_flags("docker", generation=None, name="n", scratch=tmp_path,
                              network=False)):
        scratch = [argv[i + 1] for i, a in enumerate(argv) if a == "--tmpfs"
                   and argv[i + 1].startswith(SCRATCH)]
        assert scratch == [f"{SCRATCH}rw,noexec,nosuid,size=512m"], argv


def test_opengrep_runs_from_the_tree_the_image_unpacked(tmp_path):
    from valvur.adapters.opengrep import UNPACKED, OpengrepAdapter

    invocation = OpengrepAdapter().command(tmp_path)

    assert ("XDG_CACHE_HOME", UNPACKED) in invocation.env
    dockerfile = (REPO / "Dockerfile").read_text()
    assert f"XDG_CACHE_HOME={UNPACKED} /usr/local/bin/opengrep --version" in dockerfile


@pytest.mark.e2e
def test_opengrep_completes_in_the_scan_container_with_tmp_noexec(mountable_tmp):
    from valvur import api
    from valvur.adapters import OpengrepAdapter
    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "ws"
    shutil.copytree(FIXTURES / "broken-repo", ws)
    run = api.scan(ws, runner=ContainerRuntime(), adapters=[OpengrepAdapter()])

    [opengrep] = run.scanners
    assert opengrep.ok, opengrep.reason
    assert any(f.sources == ("opengrep",) for f in run.findings)
