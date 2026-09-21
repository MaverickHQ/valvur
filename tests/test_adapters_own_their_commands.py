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


# ------------------------------------------ PR 2: osv-scanner, checkov, syft, opengrep


@pytest.mark.parametrize("tool, adapter_name, report", [
    ("osv-scanner", "OsvAdapter", "osv.json"),
    ("checkov", "CheckovAdapter", "results_json.json"),
    ("syft", "SyftAdapter", "sbom.json"),
    ("opengrep", "OpengrepAdapter", "opengrep.json"),
])
def test_the_other_four_reproduce_the_runners_argv(tmp_path, tool, adapter_name, report):
    from valvur import adapters

    invocation = getattr(adapters, adapter_name)().command(tmp_path)

    _assert_matches(invocation, tool)
    assert invocation.report == report
    assert invocation.version == __import__("conftest").PINNED_VERSIONS[tool]
    # These four opt into the empty-result allowance the runner gave them; Trivy
    # and Gitleaks never had it and still do not.
    assert invocation.empty_when == __import__("valvur.invocation").invocation.NOTHING_TO_SCAN


def test_only_opengrep_is_granted_an_executable_scratch(tmp_path, monkeypatch):
    """Least privilege per Scanner: `exec` on /tmp is Opengrep's alone, because it
    unpacks and runs opengrep-core. A second adapter asking for it is a review
    question, not a default."""
    from valvur import adapters

    monkeypatch.setattr(cache, "db_present", lambda: True)
    granted = {
        a.name: a.command(tmp_path).allow_exec
        for a in adapters.DEFAULT_ADAPTERS if getattr(a, "kind", "") == "scanner"
    }

    assert granted == {"gitleaks": False, "trivy": False, "osv-scanner": False,
                       "opengrep": True, "checkov": False, "syft": False}


def test_only_osv_scanner_asks_for_a_network_among_the_scanners(tmp_path, monkeypatch):
    from valvur import adapters

    monkeypatch.setattr(cache, "db_present", lambda: True)
    networked = sorted(
        a.name for a in adapters.DEFAULT_ADAPTERS
        if getattr(a, "kind", "") == "scanner" and a.command(tmp_path).network
    )

    assert networked == ["osv-scanner"]


def test_syfts_command_carries_the_configured_exclusions(tmp_path):
    """The SBOM is a release artifact, so an exclusion has to reach it."""
    from valvur.adapters import SyftAdapter

    (tmp_path / ".security-scan.toml").write_text('[scan]\nexclude = ["tests/fixtures"]\n')
    argv = SyftAdapter().command(tmp_path).argv

    assert argv[-2:] == ("--exclude", "./tests/fixtures/**")


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
    # PR 2 of three: the six Scanners. The Checks follow in PR 3.
    for tool in ("gitleaks", "osv-scanner", "checkov", "syft", "opengrep"):
        assert not re.search(rf'"{tool}"', source), f"runner.py still names {tool}"
    for method in ("run_trivy", "run_gitleaks", "run_osv", "run_checkov", "run_syft",
                   "run_opengrep", "_capture"):
        assert f"def {method}" not in source, f"runner.py still has {method}"


# ------------------------------------------------------------------ PR 3: the Checks


def test_a_single_check_reproduces_the_runners_argv(tmp_path):
    from valvur.adapters import CheckAdapter

    _assert_matches(CheckAdapter("licence-file").command(tmp_path), "licence-file")
    granted = CheckAdapter("dependency-reality", uses_network=True, network=True)
    _assert_matches(granted.command(tmp_path), "dependency-reality")


def test_the_checks_batch_reproduces_the_runners_argv(tmp_path):
    from valvur.adapters.check import batch_command

    invocation, refused = batch_command(
        ["licence-file", "ai-artifact", "dependency-reality"], network=True)

    assert refused == {}
    _assert_matches(invocation, "checks-batch")


def test_dependency_reality_is_refused_before_launching_without_an_index_or_a_network(
    tmp_path, monkeypatch
):
    """The host-side refusal that leads with the fix, now the adapter's: single
    and batch alike, and the batch still launches for the others."""
    from valvur.adapters import CheckAdapter
    from valvur.adapters.check import batch_command

    monkeypatch.setattr(cache, "name_index_present", lambda: False)

    with pytest.raises(RuntimeError, match="valvur update"):
        CheckAdapter("dependency-reality", uses_network=True).command(tmp_path)
    invocation, refused = batch_command(["licence-file", "dependency-reality"], network=False)
    assert list(refused) == ["dependency-reality"]
    assert "valvur update" in refused["dependency-reality"].stderr
    assert invocation is not None and invocation.argv[-1] == "licence-file"
    # Granted a network, the registry can answer instead: no refusal.
    assert batch_command(["dependency-reality"], network=True)[1] == {}


def test_the_runner_names_no_tool_at_all():
    """The target the task set: the container boundary knows containers. Every
    Scanner's and every Check's name is gone from `runner.py`; the one call into
    an adapter is the database fetch, which is Trivy's by nature. The line count
    is measured in the task's STATUS note rather than pinned here — 860 to 517 —
    because a number about to move (26.2.2 takes the network settings out) is a
    test that fails for a reason nobody cares about."""
    source = Path("src/valvur/runner.py").read_text()
    for name in ("valvur.checks", "def run_check", "BatchUnsupported", "dependency-reality",
                 "licence-file", "ai-artifact", '"gitleaks"', '"osv-scanner"', '"checkov"',
                 '"syft"', '"opengrep"'):
        assert name not in source, f"runner.py still carries {name!r}"
