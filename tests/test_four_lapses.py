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
#: `cache.root` as written: the suite replaces it for every test (conftest), after
#: this module is imported.
_ROOT = __import__("valvur.cache", fromlist=["root"]).root
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


# ------------------------------------- (b) `full` in the image asks the registry

_PYPI_REQUESTS = "https://pypi.org/pypi/requests/json"


def _in_image_scan(tmp_path, monkeypatch, profile: str):
    """A scan as the image runs one in a pipeline step (R8.1): the engine as a
    process, dependency-reality as its own process beneath it, the registries a
    stand-in that records what the Check asked."""
    from conftest import write_name_index
    from fake_registry import FakePackageRegistry

    from valvur import api, cache
    from valvur.adapters.check import CheckAdapter
    from valvur.engine_host import ImageRuntime

    registry = FakePackageRegistry(tmp_path / "registry", {_PYPI_REQUESTS: {
        "info": {"name": "requests"},
        "releases": {"2.31.0": [{"upload_time_iso_8601": "2023-05-22T15:12:44Z"}]}}})
    registry.install(monkeypatch)
    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    # The job's cache, where the image keeps the index beside the database.
    write_name_index(tmp_path / "cache" / "names", pip=["requests"])
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "requirements.txt").write_text("requests==2.31.0\n")
    adapter = CheckAdapter("dependency-reality", uses_network=True)
    network = profile == "full"
    run = api.scan(ws, runner=ImageRuntime(), profile=profile,
                   adapters=[adapter.for_profile(network=network)])
    return run, registry.asked


def test_on_full_in_the_image_dependency_reality_asks_the_registry(tmp_path, monkeypatch):
    """D54(b): in the pipeline-step mode the runtime never set VALVUR_NETWORK, so
    on `full` the Check behaved as offline there and skipped the registry."""
    run, asked = _in_image_scan(tmp_path, monkeypatch, "full")

    assert _PYPI_REQUESTS in asked, asked
    [check] = run.scanners
    assert check.ok, check.reason


def test_on_offline_in_the_image_it_asks_nothing(tmp_path, monkeypatch):
    run, asked = _in_image_scan(tmp_path, monkeypatch, "offline")

    assert asked == []
    [check] = run.scanners
    assert check.ok, check.reason


# --------------------------------------------------- (c) the cache's precedence

def test_valvur_cache_wins_over_xdg_cache_home(tmp_path, monkeypatch):
    """`XDG_CACHE_HOME` overrode `VALVUR_CACHE` (the review's §3.5): the more
    specific setting should win, and now does; then the machine's `cache` setting;
    then XDG's, then `~/.cache`."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("VALVUR_CACHE", str(tmp_path / "valvur"))

    assert _ROOT() == tmp_path / "valvur" / "valvur"
    monkeypatch.delenv("VALVUR_CACHE")
    (tmp_path / "config" / "valvur").mkdir(parents=True)
    (tmp_path / "config" / "valvur" / "config.toml").write_text(
        f'cache = "{tmp_path / "configured"}"\n')
    assert _ROOT() == tmp_path / "configured" / "valvur"
    (tmp_path / "config" / "valvur" / "config.toml").unlink()
    assert _ROOT() == tmp_path / "xdg" / "valvur"


# ---------------------------------------------- (d) one Scanner list, two Profiles

def test_the_profiles_share_one_scanner_list_and_differ_in_the_network():
    """Both listed the same ten Scanners in two tuples (the review's §3.5), so
    selection filtered nothing; they differ in the grant alone."""
    from valvur import profiles

    assert profiles.SCANNERS[profiles.OFFLINE] is profiles.FLEET
    assert profiles.SCANNERS[profiles.FULL] is profiles.FLEET
    assert profiles.ALLOWS_NETWORK == {profiles.OFFLINE: False, profiles.FULL: True}


def test_run_json_keeps_scanners_not_run_for_its_schema(workspace, runner_finding_nothing):
    import json

    from valvur import api

    api.scan(workspace, runner=runner_finding_nothing)

    record = json.loads((workspace / ".security-scan" / "run.json").read_text())
    assert record["scanners_not_run"] == []


# --------------------------------------------- (e) dead code, duplicated constants

#: Two constants that hold the same word for different things: the malicious
#: list's directory beside the index, and its tag on the published artifact.
_SAME_WORD_TWO_MEANINGS = {"malicious"}


def _constants() -> dict[str, list[str]]:
    import ast

    held: dict[str, list[str]] = {}
    for path in sorted((REPO / "src" / "valvur").rglob("*.py")):
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id.isupper()
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                held.setdefault(node.value.value, []).append(
                    f"{path.relative_to(REPO)}:{node.targets[0].id}")
    return held


def test_each_constant_is_stated_once():
    """The Results Folder's name, the project file's, the image's digest path, the
    workspace's mount, the history pass's tool and the server's name were each a
    constant in two modules (the review's §3.5)."""
    twice = {value: where for value, where in _constants().items()
             if len(where) > 1 and value not in _SAME_WORD_TWO_MEANINGS}

    assert twice == {}


def test_every_settings_variable_is_named_by_the_settings_table():
    """`settings.ENVIRONMENT` names each machine setting's variable; a module that
    needs the name takes it from there rather than spelling it again."""
    from valvur import settings

    variables = set(settings.ENVIRONMENT.values())
    spelt = {value: where for value, where in _constants().items() if value in variables}

    assert spelt == {}


def test_the_dead_code_the_review_names_is_gone():
    from valvur import api, doctor, fingerprint, requirements, runner, summary

    for module, name in ((api, "JOBS_ENV"), (doctor, "LEVELS"), (doctor, "_default_fleet"),
                         (fingerprint, "for_dependency_reality"),
                         (requirements, "REQUIREMENTS_GLOB"), (runner, "ContainerStartFailed"),
                         (summary, "_counts_table")):
        assert not hasattr(module, name), f"{module.__name__}.{name}"
