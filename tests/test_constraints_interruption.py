"""Interruption is its own outcome (16.2): a stopped scan stops its containers,
every launch carries a name to kill it by, and a refusal is one line. Split from
`test_constraints.py` (28.4.3).
"""

from __future__ import annotations

import contextlib
import subprocess

import pytest

from valvur import profiles

# ------------------------------------------- interruption is its own outcome (16.2)

def test_interrupting_a_scan_stops_the_containers(monkeypatch):
    """F1.11, task 16.2. Measured before this existed: `docker run` does not stop its
    container on SIGINT, nor when the CLI is SIGKILLed — the daemon owns the
    lifecycle. The developer cancelled and the machine kept working, with the scratch
    mount holding raw output and live credentials (F5.7) alive for the duration.
    """
    import valvur.runner as runner_module

    killed: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        killed.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    # runner.py imports subprocess inside functions, so the global is the one that
    # matters — patching a module attribute would create one nothing reads.
    monkeypatch.setattr(subprocess, "run", fake_run)
    with runner_module._live_lock:
        runner_module._live_containers.update({"valvur-aaa", "valvur-bbb"})
    try:
        stopped = runner_module.kill_running("/usr/local/bin/docker")
    finally:
        with runner_module._live_lock:
            runner_module._live_containers.clear()

    assert stopped == 2
    assert all(c[1] == "kill" for c in killed), killed
    assert {name for c in killed for name in c[2:]} == {"valvur-aaa", "valvur-bbb"}


def test_every_container_launch_carries_a_name_to_kill_it_by(monkeypatch, tmp_path):
    """A container with no `--name` and no `--cidfile` cannot be stopped at all,
    which is the state valvur was in. Asserted over every Scanner rather than one,
    so a launch added without a handle fails the build."""
    from valvur import cache
    from valvur.adapters import DEFAULT_ADAPTERS
    from valvur.runner import ContainerRunner

    launched: list[list[str]] = []

    def capture(cmd, **kwargs):
        launched.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.setattr(subprocess, "run", capture)
    runner = ContainerRunner(runtime="/usr/local/bin/docker")

    for adapter in profiles.select(DEFAULT_ADAPTERS, profiles.FULL):
        with contextlib.suppress(Exception):
            adapter.run(runner, tmp_path)

    runs = [c for c in launched if isinstance(c, list) and "run" in c]
    assert runs, "no container was launched, so nothing was asserted"
    for cmd in runs:
        assert "--name" in cmd, f"launched with no handle to kill it by: {cmd[:6]}"


def test_a_launch_stops_being_tracked_once_it_finishes(monkeypatch, tmp_path):
    """Otherwise the registry grows for the life of the process and an interrupt
    tries to kill containers that exited long ago — noisy, and it hides the ones that
    are genuinely still running."""
    import valvur.runner as runner_module
    from valvur import cache
    from valvur.runner import ContainerRunner

    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "{}", ""),
    )
    from valvur.adapters import GitleaksAdapter

    GitleaksAdapter().run(ContainerRunner(runtime="/usr/local/bin/docker"), tmp_path)

    with runner_module._live_lock:
        assert runner_module._live_containers == set()


def test_without_an_index_the_runner_refuses_before_launching_and_names_the_fix(
    monkeypatch, tmp_path
):
    """The first-run experience. Measured 2026-09-12 with an empty cache: the Check
    failed inside the container and the reason reached `SUMMARY.md` as a traceback
    truncated at 200 characters, with `valvur update` cut off. Trivy already refuses
    host-side with the fix first — in the adapter since 26.2.1; the Check gets the
    same treatment."""
    from valvur import cache
    from valvur.runner import ContainerRunner

    launched: list[list[str]] = []
    monkeypatch.setattr(cache, "name_index_present", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: launched.append(cmd))
    runner = ContainerRunner(runtime="/usr/local/bin/docker")

    from valvur.adapters import CheckAdapter

    with pytest.raises(RuntimeError, match="valvur update"):
        CheckAdapter("dependency-reality", uses_network=True, network=False).run(runner, tmp_path)

    assert launched == [], "a container was launched with nothing to check against"
    # With a network the registry can answer instead, so no refusal.
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "[]", ""))
    CheckAdapter("dependency-reality", uses_network=True, network=True).run(runner, tmp_path)


def test_the_check_entry_point_turns_its_own_refusal_into_one_line(capsys, tmp_path):
    """In-container half of the same fix: a refusal is a sentence on stderr and a
    non-zero exit, not a traceback."""
    from valvur.checks.__main__ import main

    (tmp_path / "requirements.txt").write_text("nope-x\n")
    empty = tmp_path / "no-index"
    empty.mkdir()
    import os
    os.environ["VALVUR_NAME_INDEX"] = str(empty)
    try:
        code = main(["dependency-reality", str(tmp_path)])
    finally:
        del os.environ["VALVUR_NAME_INDEX"]

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("Run `valvur update`")
    assert "Traceback" not in captured.err
    assert captured.out == ""
