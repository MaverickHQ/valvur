"""Interruption is its own outcome (16.2): a stopped scan stops its containers,
every launch carries a name to kill it by, and a refusal is one line. Split from
`test_constraints.py` (28.4.3).
"""

from __future__ import annotations

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



# ------------------------------------------- restated for the Scan Container (R3.9)

def test_a_scan_container_is_found_by_its_owner_labels(monkeypatch, tmp_path):
    """The in-process registry of container names grew for the life of the
    process and died with it, so a server killed with SIGKILL left its fleet
    unfindable (R3.6). Since R3.9 there is no registry: every Scan Container
    carries its owner's PID and host, which outlive the process."""
    import os
    import socket

    from test_constraints_exfiltration import _launches

    from valvur import owner

    for argv, tools in _launches(profiles.FULL, tmp_path, monkeypatch):
        assert f"{owner.PID_LABEL}={os.getpid()}" in argv, tools
        assert f"{owner.HOST_LABEL}={socket.gethostname()}" in argv, tools


def test_every_container_launch_carries_a_name_to_kill_it_by(monkeypatch, tmp_path):
    """A container with no `--name` and no `--cidfile` cannot be stopped at all,
    which is the state valvur was in. Asserted over every Scan Container of a
    `full` scan, so a launch added without a handle fails the build."""
    from test_constraints_exfiltration import _launches

    launched = _launches(profiles.FULL, tmp_path, monkeypatch)
    assert launched, "no container was launched, so nothing was asserted"
    for argv, tools in launched:
        assert argv[argv.index("--name") + 1].startswith("valvur-"), tools


def test_without_an_index_the_runner_refuses_before_launching_and_names_the_fix(
    monkeypatch, tmp_path
):
    """The first-run experience. Measured 2026-09-12 with an empty cache: the Check
    failed inside the container and the reason reached `SUMMARY.md` as a traceback
    truncated at 200 characters, with `valvur update` cut off. The adapter refuses
    with the fix first, and the Check never enters the Scan Container's plan."""
    from test_constraints_exfiltration import _launches

    from valvur import cache
    from valvur.adapters import CheckAdapter

    monkeypatch.setattr(cache, "name_index_present", lambda: False)
    with pytest.raises(RuntimeError, match="valvur update"):
        CheckAdapter("dependency-reality", uses_network=True, network=False).command(tmp_path)

    launched = _launches(profiles.OFFLINE, tmp_path, monkeypatch, index=False)
    assert launched and all("dependency-reality" not in tools for _, tools in launched)
