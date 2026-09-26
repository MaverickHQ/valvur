"""29.0.2 — a Scanner past its timeout is stopped, not abandoned (F2.7, F2.5).

Its own file rather than the interruption constraint suite: that suite is the
release gate's, held to the forty-eight tests 28.4.4 split, and a timeout is
F2.7's case, not F1.11's.
"""

from __future__ import annotations

import subprocess

import pytest


def test_a_scanner_past_its_timeout_is_stopped_by_name_and_recorded(monkeypatch, tmp_path):
    """`subprocess.run(timeout=…)` kills the CLIENT, `docker run`; the container
    is the daemon's and runs on — measured at the first gate, 401 s past a 300 s
    timeout, and one at 92 % CPU 90 s after the server had exited. The runner
    now stops it by the name it gave it, waits until the runtime no longer lists
    it, and returns an output that says so, with the stderr read so far."""
    from valvur import runner as _runner
    from valvur.invocation import Invocation
    from valvur.runner import ContainerRunner

    killed: list[list[str]] = []
    waited: list[str] = []

    def expire(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 2, output=b"", stderr=b"partial stderr")

    monkeypatch.setattr(subprocess, "run", expire)
    monkeypatch.setattr(_runner, "_kill", lambda runtime, names: killed.append(names) or len(names))
    monkeypatch.setattr(_runner, "_wait_gone",
                        lambda runtime, name, timeout=15.0: waited.append(name) or True)
    runner = ContainerRunner(runtime="/usr/local/bin/docker")

    output = runner.run(Invocation(tool="probe", version="0", argv=("sleep", "600"), timeout=2),
                        tmp_path)

    assert output.stopped_after == 2 and output.exit_code == _runner.TIMED_OUT
    assert output.stderr == "partial stderr" and output.argv == ("sleep", "600")
    assert len(killed) == 1 and killed[0] == waited and waited[0].startswith("valvur-")
    assert waited[0] not in _runner._live_containers, "still tracked after it was stopped"


def test_the_record_says_timed_out_and_stopped_without_the_argv():
    """The reason a reader gets: the cause and the seconds, the stderr it had —
    not `Command '[docker run … 1,500 characters …]' timed out`, which is what
    `str(TimeoutExpired)` gave the record until now (the gate's B6)."""
    from valvur.adapters import GitleaksAdapter
    from valvur.api import _outcome
    from valvur.invocation import ScannerOutput

    long_argv = tuple(f"--flag-{i}" for i in range(60))
    output = ScannerOutput("gitleaks", "8.30.1", "", "partial stderr", 124,
                           argv=long_argv, stopped_after=300)

    run = _outcome(GitleaksAdapter(), output).scanner

    assert not run.ok
    assert run.reason == "timed out after 300s and was stopped — last stderr: partial stderr"
    assert "--flag-" not in run.reason and run.argv == long_argv

    bare = ScannerOutput("gitleaks", "8.30.1", "", "", 124, argv=long_argv, stopped_after=300)
    reason = _outcome(GitleaksAdapter(), bare).scanner.reason
    assert reason == "timed out after 300s and was stopped"


def test_the_cli_stops_on_sigterm_as_well_as_sigint(monkeypatch):
    """A cancelled CI job sends SIGTERM; until 29.0.2 only Ctrl-C stopped the fleet."""
    import signal

    from valvur import cli

    installed: list[int] = []
    monkeypatch.setattr(signal, "signal", lambda signum, handler: installed.append(signum))

    cli._stop_on_interrupt(runner=object())

    assert {signal.SIGINT, signal.SIGTERM} <= set(installed)


@pytest.mark.e2e
def test_a_scanner_past_its_timeout_leaves_no_container_behind(mountable_tmp):
    """The real thing: an Invocation of `sleep 600` under a two-second timeout,
    and two seconds later the runtime lists no container named for the run."""
    import time

    from valvur.invocation import Invocation
    from valvur.runner import ContainerRunner

    runner = ContainerRunner()
    started = time.monotonic()

    output = runner.run(Invocation(tool="probe", version="0", argv=("sleep", "600"), timeout=2),
                        mountable_tmp)

    elapsed = time.monotonic() - started
    assert output.stopped_after == 2, output
    time.sleep(2)
    listed = subprocess.run(
        [runner.runtime, "ps", "-a", "--filter", "name=valvur-", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=False, timeout=30).stdout.split()
    leaked = sorted(set(listed) & runner._mine)
    assert leaked == [], f"still running {elapsed:.0f}s in: {leaked}"
    assert elapsed < 60, f"stopping a timed-out Scanner took {elapsed:.0f}s"
