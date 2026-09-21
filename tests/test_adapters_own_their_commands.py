"""26.2.1 — the adapter owns its command; the runner runs containers.

Until this, `runner.py` carried a `run_<tool>` method per Scanner — the command
line, the report file, the timeout, the network and exec grants — and the adapter
for the same tool carried only the parser: one Scanner, two homes, no contract
between them. Now `ScannerAdapter.command(workspace)` returns an `Invocation`
and the runner has one `run(invocation, workspace)`.

The safety net is a snapshot per Scanner under `tests/fixtures/invocations/`,
captured from the runner BEFORE the move (the same trick 23.5.2 used for the MCP
schema): each adapter's Invocation must reproduce it, so the refactor is a diff
in review and a changed argv is a deliberate change to a fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import FIXTURES

from valvur import cache
from valvur.invocation import Invocation

SNAPSHOTS = FIXTURES / "invocations"


def _snapshot(tool: str) -> dict:
    return json.loads((SNAPSHOTS / f"{tool}.json").read_text())


def _assert_matches(invocation: Invocation, tool: str) -> None:
    expected = _snapshot(tool)
    assert list(invocation.argv) == expected["argv"], f"{tool}'s argv changed"
    assert invocation.timeout == expected["timeout"]
    assert invocation.network is expected["network"]
    assert invocation.allow_exec is expected["allow_exec"]
    assert invocation.tool == tool if tool != "checks-batch" else invocation.tool == "checks"


# ---------------------------------------------------------------- PR 1: trivy, gitleaks


def test_trivy_reproduces_the_runners_argv(tmp_path, monkeypatch):
    from valvur.adapters import TrivyAdapter

    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.delenv("VALVUR_DB_REPOSITORY", raising=False)
    invocation = TrivyAdapter().command(tmp_path)

    _assert_matches(invocation, "trivy")
    assert invocation.report == "trivy.json"
    assert invocation.version == "0.74.0"


def test_trivy_refuses_before_launching_without_its_database(tmp_path, monkeypatch):
    """The host-side refusal that leads with the fix — the message a first-time
    user reads — moved from the runner to the adapter that knows what its tool
    needs. Verbatim: `test_first_run.py` quotes it."""
    from valvur.adapters import TrivyAdapter

    monkeypatch.setattr(cache, "db_present", lambda: False)

    with pytest.raises(RuntimeError, match="Fetch it once with:\n  valvur update"):
        TrivyAdapter().command(tmp_path)


def test_trivy_carries_the_mirror_flags_when_a_mirror_is_named(tmp_path, monkeypatch):
    from valvur.adapters import TrivyAdapter

    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.setenv("VALVUR_DB_REPOSITORY", "registry.internal/trivy-db:2")
    argv = TrivyAdapter().command(tmp_path).argv

    assert "--db-repository" in argv and "registry.internal/trivy-db:2" in argv


def test_the_database_fetch_is_trivys_command_too(monkeypatch):
    """`valvur update` fetches Trivy's database with Trivy; the runner runs it
    under the cache lock but no longer knows the command."""
    from valvur.adapters import trivy

    monkeypatch.delenv("VALVUR_DB_REPOSITORY", raising=False)
    _assert_matches(trivy.database_fetch(), "trivy-db")


def test_gitleaks_reproduces_the_runners_argv(tmp_path):
    from valvur.adapters import GitleaksAdapter

    invocation = GitleaksAdapter().command(tmp_path)

    _assert_matches(invocation, "gitleaks")
    assert invocation.report == "gitleaks.json"
    assert invocation.version == "8.30.1"


# ------------------------------------------------------------------ the runner's half


def test_the_runner_launches_an_invocation_as_base_flags_image_argv(tmp_path, monkeypatch):
    """The runner adds the container concerns — the mounts, the user, the
    read-only root, the network — and nothing tool-specific."""
    import subprocess

    from valvur.runner import ContainerRunner

    launched: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: (
        launched.append(list(cmd)) or subprocess.CompletedProcess(cmd, 0, "on stdout", "")))
    runner = ContainerRunner(image="x/y:1", runtime="/usr/local/bin/docker")
    invocation = Invocation(tool="probe", version="0", argv=("probe", "--flag"), report=None)

    output = runner.run(invocation, tmp_path)

    cmd = launched[0]
    image_at = cmd.index("x/y:1")
    assert cmd[image_at + 1:] == ["probe", "--flag"]
    assert cmd[0] == "/usr/local/bin/docker" and cmd[1] == "run"
    assert "--network=none" in cmd and "--read-only" in cmd and "--cap-drop=ALL" in cmd
    assert output.tool == "probe" and output.stdout == "on stdout" and output.exit_code == 0


def test_gitleaks_now_gets_the_same_container_as_every_other_scanner(tmp_path, monkeypatch):
    """Found by the move: `run_gitleaks` built its own flag list — no tmpfs, no
    cache mounts and, on an enforcing SELinux host, NO LABEL on its scratch mount,
    while every other Scanner's came from `_base_flags`. The snapshot records the
    old shape; this pins the new one. Unmeasured on an enforcing host (none is at
    hand); the flag diff is the evidence."""
    import subprocess

    from valvur.adapters import GitleaksAdapter
    from valvur.runner import ContainerRunner

    launched: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: (
        launched.append(list(cmd)) or subprocess.CompletedProcess(cmd, 0, "", "")))
    runner = ContainerRunner(image="x/y:1", runtime="/usr/local/bin/docker")

    GitleaksAdapter().run(runner, tmp_path)

    cmd = launched[0]
    flags = [f for f in cmd[:cmd.index("x/y:1")] if f.startswith("--") and f != "--name"]
    assert "--tmpfs" in flags, "gitleaks has no scratch tmpfs"
    assert any("/cache/trivy" in f for f in cmd), "gitleaks gets the standard mounts"
    assert _snapshot("gitleaks")["flags_shape"] != flags, "the old shape is deliberately gone"


def test_the_runner_names_no_tool(monkeypatch):
    """The target the task set: the container boundary knows containers. The
    database fetch is the one exception, and it is a call into Trivy's adapter,
    not a command line here."""
    import re

    source = Path("src/valvur/runner.py").read_text()
    # PR 1 of three: Trivy and Gitleaks. The tuple grows with each PR.
    for tool in ("gitleaks",):
        assert not re.search(rf'"{tool}"', source), f"runner.py still names {tool}"
    assert "def run_trivy" not in source and "def run_gitleaks" not in source
