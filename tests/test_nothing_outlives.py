"""R3.6: nothing outlives its owner (F1.11, F1.12).

Every container valvur starts carries who started it: the process, the host and
the Scan Run's generation. A container whose owner process has ended on this host
is an orphan; each scan start and `doctor` remove them, and a server on its way
out kills its own by label. The runtime is faked by `fixtures/fake-runtime`,
which keeps its containers in a JSON file.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from valvur import owner

FAKE_RUNTIME = Path(__file__).parent / "fixtures" / "fake-runtime" / "docker"
SRC = Path(__file__).parent.parent / "src" / "valvur"


def _words(said: list[str]):
    """A progress callback keeping each event's words."""
    return lambda event: said.append(str(event))



def _dead_pid() -> int:
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    return process.pid


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    """The fake runtime and a way to read and seed its containers."""
    state = tmp_path / "runtime.json"
    state.write_text(json.dumps({"containers": [], "calls": []}))
    monkeypatch.setenv("FAKE_RUNTIME_STATE", str(state))

    class Fake:
        path = str(FAKE_RUNTIME)

        def seed(self, *containers: dict) -> None:
            data = json.loads(state.read_text())
            data["containers"] += list(containers)
            state.write_text(json.dumps(data))

        def names(self) -> list[str]:
            return sorted(c["name"] for c in json.loads(state.read_text())["containers"])

    return Fake()


def _container(name: str, pid: int | None, host: str | None = None) -> dict:
    labels = {}
    if pid is not None:
        labels = {owner.PID_LABEL: str(pid), owner.HOST_LABEL: host or socket.gethostname(),
                  owner.GENERATION_LABEL: "g"}
    return {"id": f"id-{name}", "name": name, "labels": labels}


# ------------------------------------------------------------------ the labels

def test_the_labels_name_the_process_the_host_and_the_generation():
    flags = owner.labels("gen-1")
    pairs = dict(flags[i + 1].split("=", 1) for i in range(0, len(flags), 2))
    assert set(flags[::2]) == {"--label"}
    assert pairs == {owner.PID_LABEL: str(os.getpid()),
                     owner.HOST_LABEL: socket.gethostname(),
                     owner.GENERATION_LABEL: "gen-1"}


def test_every_container_valvur_starts_is_labelled_with_its_owner():
    """A structural rule: each `run` a module builds carries `owner.labels`."""
    launches = 0
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(
                r'"run",\s*(?:"-i",\s*|\*\(\["-i"\] if interactive else \[\]\),\s*)?"--rm"',
                text):
            launches += 1
            window = text[match.start():match.start() + 400]
            assert "owner.labels(" in window, f"{path.name}: a container with no owner"
    # `runner.launch_flags`, which both launchers use since D52e, and the two probes.
    assert launches >= 3


def test_the_scan_container_and_the_fleet_carry_the_scan_runs_generation(
        tmp_path, monkeypatch):
    from valvur import cache
    from valvur.engine_host import ContainerRuntime
    from valvur.runner import ContainerRunner, launch_flags

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    for built in (ContainerRuntime(runtime="docker"), ContainerRunner(runtime="docker")):
        built.generation = "gen-7"
        argv = (built.command(tmp_path) if isinstance(built, ContainerRuntime)
                else launch_flags(built.runtime, generation=built.generation, name="n",
                                  scratch=tmp_path, network=False))
        assert f"{owner.GENERATION_LABEL}=gen-7" in argv
        assert f"{owner.PID_LABEL}={os.getpid()}" in argv


def test_a_scan_tells_its_runner_the_generation_it_will_write(tmp_path, monkeypatch):
    from valvur import api
    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import LocalRuntime

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")
    runtime = LocalRuntime(Path(__file__).parent / "fixtures" / "fake-tools")
    run = api.scan(ws, runner=runtime, adapters=[GitleaksAdapter()])
    assert runtime.generation == run.generation


# ------------------------------------------------------------------ the reaper

def test_the_reaper_removes_what_an_ended_process_left_and_nothing_else(runtime):
    dead = _dead_pid()
    runtime.seed(_container("valvur-orphan", dead),
                 _container("valvur-mine", os.getpid()),
                 _container("valvur-elsewhere", dead, host="another-machine"),
                 _container("someone-elses", None))
    assert owner.reap(runtime.path) == ["valvur-orphan"]
    assert runtime.names() == ["someone-elses", "valvur-elsewhere", "valvur-mine"]


def test_the_reaper_with_nothing_to_reap_says_so_and_costs_one_call(runtime):
    assert owner.reap(runtime.path) == []


def test_a_process_kills_its_own_containers_by_label(runtime):
    runtime.seed(_container("valvur-a", os.getpid()), _container("valvur-b", os.getpid()),
                 _container("valvur-other", _dead_pid()))
    assert owner.kill_mine(runtime.path) == 2
    assert runtime.names() == ["valvur-other"]


def test_each_scan_start_reaps_the_orphans_and_says_so(runtime, tmp_path, monkeypatch):
    from valvur import api
    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import LocalRuntime

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    runtime.seed(_container("valvur-orphan", _dead_pid()))
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")
    local = LocalRuntime(Path(__file__).parent / "fixtures" / "fake-tools")
    local.runtime = runtime.path                   # type: ignore[attr-defined]
    said: list[str] = []
    api.scan(ws, runner=local, adapters=[GitleaksAdapter()], on_progress=_words(said))
    assert runtime.names() == []
    assert any("valvur-orphan" in line and "ended" in line for line in said), said


def test_doctor_reaps_the_orphans_and_names_them(runtime, monkeypatch):
    from valvur import doctor

    runtime.seed(_container("valvur-orphan", _dead_pid()))
    check = doctor._check_orphans(runtime.path)
    assert check.name == "orphans"
    assert "valvur-orphan" in check.detail
    assert runtime.names() == []
    assert doctor._check_orphans(runtime.path).level == "ok"


# ------------------------------------------------------------------ the server

@pytest.mark.timing
def test_the_servers_shutdown_kills_its_containers_by_label_within_three_seconds(
        runtime, monkeypatch):
    from valvur.mcp import jobs, server

    monkeypatch.setenv("VALVUR_RUNTIME", runtime.path)
    runtime.seed(_container("valvur-a", os.getpid()), _container("valvur-b", os.getpid()))
    jobs.reset()
    started = time.monotonic()
    import io

    server.shutdown(out=io.StringIO())
    assert time.monotonic() - started < 3
    assert runtime.names() == []


def test_the_server_exits_when_its_parent_dies_though_stdin_stays_open(tmp_path):
    """The wrapper starts the server on a pipe this test keeps open, writes the
    server's pid, and is killed: no EOF arrives, so only `getppid` can tell."""
    read_end, write_end = os.pipe()
    pidfile = tmp_path / "server.pid"
    wrapper = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess, sys, time\n"
         "p = subprocess.Popen([sys.executable, '-m', 'valvur.mcp.server'],"
         f" stdin={read_end}, stderr=subprocess.DEVNULL)\n"
         f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
         "time.sleep(60)\n"],
        pass_fds=(read_end,))
    os.close(read_end)
    try:
        deadline = time.monotonic() + 20
        while not (pidfile.exists() and pidfile.read_text()) and time.monotonic() < deadline:
            time.sleep(0.05)
        server_pid = int(pidfile.read_text())
        time.sleep(1.5)                          # the server is up and polling
        wrapper.kill()
        wrapper.wait()
        deadline = time.monotonic() + 5
        gone = False
        while time.monotonic() < deadline and not gone:
            try:
                os.kill(server_pid, 0)
                time.sleep(0.1)
            except ProcessLookupError:
                gone = True
        assert gone, "the server outlived its parent"
    finally:
        os.close(write_end)


# ------------------------------------------------------------------ the lock

def test_the_workspace_lock_records_its_holder(tmp_path):
    from valvur import locking

    lock = tmp_path / ".lock"
    with locking.held(lock, exclusive=True, wait=False):
        assert lock.read_text().strip() == str(os.getpid())


def test_busy_names_a_running_holder(tmp_path):
    from valvur import locking

    lock = tmp_path / ".lock"
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys, time\n"
         f"sys.path.insert(0, {str(SRC.parent)!r})\n"
         "from pathlib import Path\n"
         "from valvur import locking\n"
         f"with locking.held(Path({str(lock)!r}), exclusive=True, wait=False):\n"
         "    print('held', flush=True)\n"
         "    time.sleep(30)\n"],
        stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "held"
        with pytest.raises(locking.Busy) as busy, \
                locking.held(lock, exclusive=True, wait=False, busy_message="busy."):
            pass
        assert f"process {holder.pid}" in str(busy.value)
        assert "is running" in str(busy.value)
    finally:
        holder.kill()
        holder.wait()


def test_the_holder_of_a_lock_is_read_back_with_whether_it_is_alive(tmp_path):
    from valvur import locking

    lock = tmp_path / ".lock"
    lock.write_text(f"{_dead_pid()}\n")
    pid, alive = locking.holder(lock)
    assert pid is not None and alive is False
    lock.write_text("")
    assert locking.holder(lock) == (None, False)


# ------------------------------------------------------------------ e2e

@pytest.mark.e2e
def test_after_kill_9_of_the_server_the_next_scan_reaps_the_orphans_and_runs(mountable_tmp):
    """The second gate's shape: a server killed mid-scan cannot clean up, so its
    fleet runs on with nobody to read it. The next scan finds them by label."""
    import shutil

    from valvur import api
    from valvur.engine_host import ContainerRuntime
    from valvur.runner import detect_runtime

    runtime = detect_runtime()
    workspace = mountable_tmp / "ws"
    shutil.copytree(Path(__file__).parent / "fixtures" / "broken-repo", workspace)
    data = workspace / "data"                  # enough to keep a Scanner busy
    data.mkdir()
    for i in range(5000):
        (data / f"row-{i}.py").write_text(f"value_{i} = {i}\n")

    def owned_by(pid: int) -> list[str]:
        return subprocess.run(
            [runtime, "ps", "-a", "-q", "--filter", f"label={owner.PID_LABEL}={pid}"],
            capture_output=True, text=True, check=False, timeout=30).stdout.split()

    server = subprocess.Popen(
        [sys.executable, "-c", "from valvur.mcp.server import main; raise SystemExit(main())"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, env={**os.environ, "PYTHONUNBUFFERED": "1"})
    try:
        assert server.stdin is not None and server.stdout is not None
        for message in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "scan", "arguments": {"workspace": str(workspace)}}},
        ):
            server.stdin.write(json.dumps(message) + "\n")
            server.stdin.flush()
        # `initialize` is answered; `scan` answers only when the scan does (R6.3).
        server.stdout.readline()
        deadline = time.monotonic() + 180
        # One Scan Container since R3.9: the first is the scan.
        while time.monotonic() < deadline and not owned_by(server.pid):
            time.sleep(0.2)
        server.kill()                                         # kill -9
        server.wait()
        left = owned_by(server.pid)
        assert left, "nothing outlived the server, so the test measures nothing"
    finally:
        server.kill()

    said: list[str] = []
    run = api.scan(workspace, runner=ContainerRuntime(), on_progress=_words(said))
    assert owned_by(server.pid) == []
    assert any("left by a scan whose process had ended" in line for line in said), said
    assert run.status in ("findings", "clean", "inconclusive")
