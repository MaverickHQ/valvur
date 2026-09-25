"""A ceiling on every container (task 28.0.3, F3).

Measured 2026-09-23: `_base_flags` gave every Scanner `--read-only`, a 512m tmpfs,
`--cap-drop=ALL`, `--network=none` and a non-root user — and no `--memory`, no
`--pids-limit`, no `--security-opt=no-new-privileges`. A hostile repository could
not reach the network or write the tree, and could take the host's memory and CPU:
a pathological pattern for Opengrep, a multi-gigabyte lockfile for Trivy. N1.4
*measured* 2 GB (528 MiB peak on CI); nothing enforced it; the budget bounded time
only. The ceiling is one authority in the runner, sized from N1.4's measurement,
and dropped — saying so — only where rootless Podman on cgroup v1 refuses it.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from valvur import runner as _runner
from valvur.runner import ContainerRunner

#: What every Scanner's container is held to. 2 GB is N1.4's number; swap equal
#: to memory means no swap, so a container past the ceiling is killed rather than
#: swapping the host; 512 PIDs is ten times the widest fleet member (Checkov's
#: worker pool); no-new-privileges closes setuid inside a `--cap-drop=ALL` box.
MEMORY = ("--memory=2g", "--memory-swap=2g")
ALWAYS = ("--pids-limit=512", "--security-opt=no-new-privileges")


def _launched(monkeypatch, runtime: str) -> list[list[str]]:
    launched: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: (
        launched.append(list(cmd)) or subprocess.CompletedProcess(cmd, 0, "", "")))
    return launched


def _flags(cmd: list[str], image: str) -> list[str]:
    return cmd[:cmd.index(image)]


def test_every_container_is_held_to_the_ceiling(monkeypatch, tmp_path):
    from valvur.adapters import DEFAULT_ADAPTERS

    launched = _launched(monkeypatch, "docker")
    runner = ContainerRunner(image="x/y:1", runtime="/usr/local/bin/docker")

    for adapter in DEFAULT_ADAPTERS:
        adapter.run(runner, tmp_path)

    assert launched, "no container was launched"
    for cmd in launched:
        flags = _flags(cmd, "x/y:1")
        for flag in MEMORY + ALWAYS:
            assert flag in flags, f"{cmd[cmd.index('x/y:1') + 1]}: missing {flag}"


def test_the_ceiling_is_one_authority():
    """The literals live in one tuple, so 2g is 2g everywhere and a change is one
    diff. (The way `egress.py` holds the network flag.)"""
    source = Path(_runner.__file__).read_text()

    assert source.count("--memory=") == 1 and source.count("--pids-limit=") == 1, \
        "the ceiling is written in more than one place"
    assert tuple(_runner.RESOURCE_LIMITS) == MEMORY + ALWAYS


def test_rootless_podman_on_cgroup_v1_keeps_what_it_can(monkeypatch, tmp_path):
    """Rootless Podman on a cgroup v1 host refuses `--memory` outright ("cgroup v1
    rootless: memory limit not supported") and the container never starts — which
    would turn a safety flag into a scan that cannot run. There the memory flags
    are dropped, the PID limit and no-new-privileges stay, and the run says why."""
    from valvur.adapters import GitleaksAdapter

    monkeypatch.setattr(_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(_runner, "_cgroup_v2", lambda: False)
    launched = _launched(monkeypatch, "podman")
    runner = ContainerRunner(image="x/y:1", runtime="/usr/bin/podman")

    GitleaksAdapter().run(runner, tmp_path)

    flags = _flags(launched[0], "x/y:1")
    assert not any(f.startswith("--memory") for f in flags), "podman v1 would refuse to start"
    for flag in ALWAYS:
        assert flag in flags
    assert _runner.memory_ceiling_note("/usr/bin/podman"), "the dropped ceiling is not said"


def test_docker_and_cgroup_v2_podman_get_the_whole_ceiling(monkeypatch, tmp_path):
    from valvur.adapters import GitleaksAdapter

    monkeypatch.setattr(_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(_runner, "_cgroup_v2", lambda: True)
    launched = _launched(monkeypatch, "podman")

    GitleaksAdapter().run(ContainerRunner(image="x/y:1", runtime="/usr/bin/podman"), tmp_path)

    flags = _flags(launched[0], "x/y:1")
    for flag in MEMORY + ALWAYS:
        assert flag in flags
    assert _runner.memory_ceiling_note("/usr/bin/podman") is None


def test_the_database_fetch_container_is_held_too(monkeypatch, tmp_path):
    """The one container with a network — Trivy's database fetch — is the one
    most worth bounding, and it goes through the same builder."""
    launched = _launched(monkeypatch, "docker")
    runner = ContainerRunner(image="x/y:1", runtime="/usr/local/bin/docker")
    monkeypatch.setattr("valvur.cache.db_present", lambda: False)

    import contextlib

    with contextlib.suppress(Exception):   # the fake run returns nothing Trivy would
        runner.update_db()

    assert launched, "the fetch launched nothing"
    for flag in MEMORY + ALWAYS:
        assert flag in _flags(launched[0], "x/y:1"), flag


@pytest.mark.e2e
def test_a_container_past_the_ceiling_is_killed_not_swapped():
    """Against the real image: three gigabytes asked for inside a two-gigabyte
    box is an exit 137 in seconds, reported as a failed Scanner — never the host
    swapping while the budget counts down."""
    from valvur.invocation import Invocation

    runner = ContainerRunner()
    workspace = Path(__file__).parent / "fixtures" / "clean-repo"
    hog = Invocation(
        tool="python", version="3.12",
        argv=("python", "-c", "b = bytearray(3 * 1024 ** 3); print(len(b))"),
        timeout=120,
    )

    started = time.monotonic()
    out = runner.run(hog, workspace)
    elapsed = time.monotonic() - started

    print(f"28.0.3: exit {out.exit_code} after {elapsed:.1f}s")
    assert out.exit_code == 137, f"exit {out.exit_code}: the ceiling did not hold\n{out.stderr}"
    assert elapsed < 60, f"{elapsed:.0f}s — that is the host swapping, not a kill"
