"""R6.10: the Kiro probe (D20).

A stdio client replaying Kiro's calls, from `tests/fixtures/mcp/kiro-sequence.json`:
initialize with roots, tools/list, calls with progress tokens, a ping while a scan
runs, and a cancellation. Every request but the cancelled one is answered, once;
the cancelled scan stops being waited for and is stopped by `scan_cancel`, which
leaves nothing behind. Replayed in-process here, and against the real server and
image in the e2e suite, which CI runs.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from valvur import events

SEQUENCE = Path(__file__).parent / "fixtures" / "mcp" / "kiro-sequence.json"


def _messages(workspace: Path) -> tuple[list[dict], dict]:
    spec = json.loads(SEQUENCE.read_text())
    text = json.dumps(spec["messages"]).replace("{workspace}", str(workspace))
    return json.loads(text), spec


def _judge(seen: list[dict], spec: dict) -> None:
    replies = [m for m in seen if "id" in m and "method" not in m]
    ids = [m["id"] for m in replies]
    assert sorted(ids) == sorted(spec["answered"]), ids
    assert len(ids) == len(set(ids)), "a request was answered twice"
    assert not [m for m in replies if "error" in m], "a JSON-RPC error reached Kiro"
    by_id = {m["id"]: m for m in replies}
    assert by_id[0]["result"]["serverInfo"]["name"] == "valvur"
    assert {"scan", "findings", "scan_cancel", "update"} <= {
        t["name"] for t in by_id[1]["result"]["tools"]}
    assert by_id[6]["result"]["structuredContent"]["state"] in ("cancelled", "none")


def test_kiros_sequence_in_process(tmp_path, monkeypatch):
    from conftest import McpSession

    from valvur.mcp import handlers, jobs

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 5.0)
    release = threading.Event()

    def held(budget_s, *, fresh=False):
        def run(workspace, profile, progress):
            # As a real runtime does: `scan_cancel` reaches the fleet through the
            # job's canceller, which is what ends the wait.
            jobs.current(workspace).canceller = lambda: release.set() or 1
            progress(events.fleet(1, 1))
            release.wait(10)
            raise RuntimeError("stopped")          # what a killed fleet raises
        return run

    monkeypatch.setattr(handlers, "_work", held)
    monkeypatch.setattr(handlers, "_roots", lambda: [tmp_path.resolve()])
    messages, spec = _messages(tmp_path)
    session = McpSession()
    try:
        for message in messages:
            if message.get("id") == 4:
                # Kiro pings while the scan runs: the scan has started by then.
                _until(lambda: (job := jobs.current(tmp_path.resolve())) is not None
                       and job.progress)
            session.send(message)
            if message.get("method") == "notifications/cancelled":
                continue
            if message.get("id") in spec["answered"]:
                session.reply(message["id"])
    finally:
        session.close()
        jobs.reset()

    _judge(session.seen, spec)


def _until(condition, seconds: float = 10) -> None:
    import time

    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "the scan never started"
        time.sleep(0.02)


@pytest.mark.e2e
def test_kiros_sequence_against_the_real_server(mountable_tmp):
    import sys

    _replay([sys.executable, "-c", "from valvur.mcp.server import main; raise SystemExit(main())"],
            mountable_tmp / "kiro")


def _replay(command: list[str], workspace: Path) -> None:
    """Kiro's sequence, against the server `command` starts, on a copy of a repository."""
    import shutil
    import subprocess
    import time

    shutil.copytree(Path(__file__).parent / "fixtures" / "broken-repo", workspace)
    messages, spec = _messages(workspace)
    server = subprocess.Popen(
        command,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    seen: list[dict] = []

    def read():
        for line in server.stdout:
            seen.append(json.loads(line))

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        for message in messages:
            if message.get("id") == 4:
                time.sleep(3)                       # the scan is running when Kiro pings
            server.stdin.write(json.dumps(message) + "\n")
            server.stdin.flush()
            if message.get("id") in (0, 1, 2):     # Kiro waits for these before going on
                deadline = time.monotonic() + 120
                while not any(m.get("id") == message["id"] for m in seen):
                    assert time.monotonic() < deadline, f"no reply to {message['id']}"
                    time.sleep(0.05)
        deadline = time.monotonic() + 180
        while not all(any(m.get("id") == i for m in seen) for i in spec["answered"]):
            assert time.monotonic() < deadline, [m.get("id") for m in seen]
            time.sleep(0.1)
        server.stdin.close()
        assert server.wait(timeout=60) == 0
    finally:
        if server.poll() is None:
            server.kill()
    reader.join(timeout=5)

    _judge(seen, spec)


REPO = Path(__file__).resolve().parent.parent


def _power_command() -> list[str]:
    """The Kiro power's server as Kiro starts it (R15.3), from its `mcp.json`:
    `uvx --from valvur==<version> valvur-mcp`, with the release swapped for this
    checkout, since the version being built is not published while it is built."""
    server = json.loads((REPO / "powers" / "valvur" / "mcp.json").read_text())
    server = server["mcpServers"]["valvur"]
    return [server["command"],
            *(str(REPO) if arg.startswith("valvur==") else arg for arg in server["args"])]


def test_the_powers_server_is_started_as_its_configuration_says():
    assert _power_command() == ["uvx", "--from", str(REPO), "valvur-mcp"]


@pytest.mark.e2e
def test_kiros_sequence_against_the_powers_server_configuration(mountable_tmp):
    """R15.3: the same replay, through the command the power gives Kiro."""
    _replay(_power_command(), mountable_tmp / "kiro-power")
