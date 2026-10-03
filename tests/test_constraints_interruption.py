"""Interruption is its own outcome (16.2): a stopped scan stops its containers,
every launch carries a name to kill it by, and a refusal is one line. Split from
`test_constraints.py` (28.4.3).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from valvur import profiles
from valvur.invocation import Invocation

# ------------------------------------------- interruption is its own outcome (16.2)

def test_interrupting_a_scan_stops_the_containers(monkeypatch, tmp_path):
    """F1.11, task 16.2. Measured before this existed: `docker run` does not stop its
    container on SIGINT, nor when the CLI is SIGKILLed — the daemon owns the
    lifecycle. The developer cancelled and the machine kept working, with the scratch
    mount holding raw output and live credentials (F5.7) alive for the duration.
    Since R3.9 the CLI's handler kills this process's containers by label, and
    leaves another process's alone."""
    import json
    import os
    import signal
    import socket
    from pathlib import Path

    from valvur import cli, owner, service

    fake = Path(__file__).parent / "fixtures" / "fake-runtime" / "docker"
    state = tmp_path / "runtime.json"
    mine = {owner.PID_LABEL: str(os.getpid()), owner.HOST_LABEL: socket.gethostname()}
    other = {owner.PID_LABEL: "1", owner.HOST_LABEL: socket.gethostname()}
    state.write_text(json.dumps({"containers": [
        {"id": "a", "name": "valvur-aaa", "labels": mine},
        {"id": "b", "name": "valvur-bbb", "labels": mine},
        {"id": "c", "name": "valvur-ccc", "labels": other}]}))
    monkeypatch.setenv("FAKE_RUNTIME_STATE", str(state))

    class Runtime:
        runtime = str(fake)

    previous = signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)
    try:
        cancellation = service.Cancellation()
        cancellation.attach(Runtime())         # the scan's runner, as the service holds it
        cli._stop_on_interrupt(cancellation)
        with pytest.raises(SystemExit) as stopped:
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
    finally:
        signal.signal(signal.SIGINT, previous[0])
        signal.signal(signal.SIGTERM, previous[1])

    assert stopped.value.code == 130
    left = [c["name"] for c in json.loads(state.read_text())["containers"]]
    assert left == ["valvur-ccc"]


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


# ------------------------------ zero containers after any stop (R3.5, restated at R3.9)

def _valvur_containers() -> set[str]:
    import subprocess

    return set(subprocess.run(["docker", "ps", "-a", "--filter", "name=valvur-",
                               "--format", "{{.Names}}"],
                              capture_output=True, text=True, check=True).stdout.split())


class _InImageSleeper:
    """A Scanner whose tool, inside the image, sleeps past any test budget."""

    kind = "scanner"
    name = "sleeper"
    version = "0"

    def applies_to(self, workspace, context=None):
        return True, ""

    def parse(self, output):
        return []

    def for_profile(self, *, network):
        return self

    def command(self, workspace):
        return Invocation(tool="sleeper", version="0", timeout=120, argv=("sleep", "60"))


def _mountable_tree(root: Path) -> Path:
    ws = root / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")
    return ws


@pytest.mark.e2e
def test_after_a_budget_cut_no_container_is_left(mountable_tmp, monkeypatch):
    from valvur import api
    from valvur.engine_host import ContainerRuntime

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws = _mountable_tree(mountable_tmp)
    before = _valvur_containers()
    with pytest.raises(api.BudgetExhausted):
        api.scan(ws, runner=ContainerRuntime(), adapters=[_InImageSleeper()], budget_s=2.0)
    assert _valvur_containers() - before == set()


@pytest.mark.e2e
def test_after_the_grace_kill_no_container_is_left(mountable_tmp, monkeypatch):
    """An engine that does not honour its budget: the plan carries none, and the
    host's deadline is the budget plus a one-second grace."""
    from valvur import engine_host
    from valvur.engine_host import ContainerRuntime, snapshot

    ws = _mountable_tree(mountable_tmp)
    scratch = mountable_tmp / "scratch"
    scratch.mkdir()
    real = engine_host.write_plan
    monkeypatch.setattr(engine_host, "write_plan",
                        lambda scratch, plan, budget_s=None, jobs=None: real(scratch, plan, None))
    monkeypatch.setattr(engine_host, "GRACE_S", 1.0)
    before = _valvur_containers()
    started = time.monotonic()
    ContainerRuntime().run([_InImageSleeper().command(ws)], snapshot(ws, ["app.py"]),
                           scratch, budget_s=1.0)
    assert time.monotonic() - started < 30
    assert _valvur_containers() - before == set()


@pytest.mark.e2e
def test_after_a_cancel_no_container_is_left(mountable_tmp, monkeypatch):
    import threading

    from valvur import api
    from valvur.engine_host import ContainerRuntime

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws = _mountable_tree(mountable_tmp)
    runtime = ContainerRuntime()
    before = _valvur_containers()
    raised: list[BaseException] = []

    def scan() -> None:
        try:
            api.scan(ws, runner=runtime, adapters=[_InImageSleeper()])
        except BaseException as exc:          # the test reads what it was
            raised.append(exc)

    worker = threading.Thread(target=scan, daemon=True)
    worker.start()
    deadline = time.monotonic() + 60
    while not _valvur_containers() - before and time.monotonic() < deadline:
        time.sleep(0.2)
    assert _valvur_containers() - before, "the Scan Container was never seen"
    assert runtime.kill() == 1
    worker.join(60)
    assert not worker.is_alive()
    assert isinstance(raised[0], api.ScanCancelled)
    assert _valvur_containers() - before == set()
