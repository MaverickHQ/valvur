"""Lifecycle probes (task R2.3): stop a scan four ways and look at what is left.

Each probe starts a real MCP server over stdio, starts a scan, waits until the fleet
has a container, stops the scan its own way, then asks the runtime which of the
scan's containers remain, and whether a fresh server can start the next scan.
`kill -9` of the server leaves containers, and R3.6's reaper removes them when the next
scan starts: the kill probe is judged on `left_at_next_start`.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

#: The task that makes a probe pass, while it is open (R2.3's exit names them). Empty
#: since R3.6 closed the last one, `kill`.
UNTIL: dict[str, str] = {}


@dataclass
class ProbeResult:
    kind: str
    #: The stopped scan's containers still listed after the probe's grace.
    containers_left: int
    next_scan_started: bool
    seconds: float
    until: str | None = None
    #: The stopped scan's containers still listed once the next scan has started:
    #: what a reaper (R3.6) must have removed.
    left_at_next_start: int = 0
    #: Whether a Scan Container was ever running: a probe that never saw one
    #: stopped nothing and measured an empty runtime (R3's first Mac run).
    scan_seen: bool = True

    @property
    def ok(self) -> bool:
        stopped_clean = self.kind == "kill" or self.containers_left == 0
        return (self.scan_seen and stopped_clean and self.left_at_next_start == 0
                and self.next_scan_started)


def _live() -> set[str]:
    out = subprocess.run(["docker", "ps", "--filter", "name=valvur-", "--format",
                          "{{.Names}}"], capture_output=True, text=True, check=False)
    return set(out.stdout.split())


class _Server:
    """A real `valvur-mcp`, spoken to as a client speaks to it."""

    def __init__(self) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-c", "from valvur.mcp.server import main; "
             "raise SystemExit(main())"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env={**os.environ, "PYTHONUNBUFFERED": "1"})
        self._id = 0
        self.request("initialize", {})

    def request(self, method: str, params: dict) -> dict:
        self._id += 1
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("the server's pipes are closed")
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self._id,
                                             "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        return json.loads(self.process.stdout.readline())

    def call(self, tool: str, arguments: dict) -> str:
        result = self.request("tools/call", {"name": tool, "arguments": arguments})["result"]
        return result["content"][0]["text"]

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=30)


def _scan_containers() -> set[str]:
    """Running Scan Containers: a scan's carry its generation (R3.6); the image
    probes before a scan carry `none`."""
    out = subprocess.run(["docker", "ps", "--filter", "name=valvur-", "--format",
                          '{{.Names}} {{.Label "valvur.generation"}}'],
                         capture_output=True, text=True, check=False)
    return {name for name, _, generation in (line.partition(" ")
                                             for line in out.stdout.splitlines())
            if generation and generation != "none"}


def _wait_for_fleet(before: set[str], seconds: float = 180) -> tuple[set[str], bool]:
    """Every container seen until a Scan Container is running, and whether one
    was. Since R3.9 a scan is one container, so the old wait for two outlasted it."""
    deadline = time.monotonic() + seconds
    seen: set[str] = set()
    while time.monotonic() < deadline:
        seen |= _live() - before
        if _scan_containers() - before:
            return seen | (_scan_containers() - before), True
        time.sleep(0.2)
    return seen, False


def _wait_state(server: _Server, workspace: Path, words: tuple[str, ...],
                seconds: float = 120) -> str:
    deadline = time.monotonic() + seconds
    text = ""
    while time.monotonic() < deadline:
        text = server.call("scan_status", {"workspace": str(workspace)})
        if text.startswith(words):
            return text
    return text


def _left_after(before: set[str], grace: float) -> int:
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not (_live() - before):
            return 0
        time.sleep(0.25)
    return len(_live() - before)


def _next_scan_starts(workspace: Path, stopped: set[str]) -> tuple[bool, int]:
    """Whether a fresh server can start a scan here, and how many of the stopped
    scan's containers are still listed once it has. It is then stopped cleanly."""
    server = _Server()
    try:
        reply = server.call("scan", {"workspace": str(workspace)})
        started = reply.startswith("Started")
        time.sleep(2.0)                           # past the scan's start, where a reaper runs
        orphans = len(_live() & stopped)
        server.call("scan_cancel", {"workspace": str(workspace)})
        _wait_state(server, workspace, ("CANCELLED", "DONE", "FAILED"), 60)
        return started, orphans
    finally:
        server.close()


def probe(kind: str, workspace: Path) -> ProbeResult:
    """Run one probe: `cancel`, `budget`, `stdin` or `kill`."""
    before = _live()
    started = time.monotonic()
    server = _Server()
    try:
        arguments = {"workspace": str(workspace)}
        if kind == "budget":
            arguments["budget_s"] = 3
        server.call("scan", arguments)
        fleet, scan_seen = _wait_for_fleet(before)
        if kind == "cancel":
            server.call("scan_cancel", {"workspace": str(workspace)})
            _wait_state(server, workspace, ("CANCELLED",))
            grace = 1.0
        elif kind == "budget":
            _wait_state(server, workspace, ("DONE", "FAILED"))
            grace = 1.0
        elif kind == "stdin":
            if server.process.stdin is not None:
                server.process.stdin.close()
            server.process.wait(timeout=60)
            grace = 3.0
        elif kind == "kill":
            os.kill(server.process.pid, signal.SIGKILL)
            server.process.wait(timeout=30)
            grace = 2.0
        else:
            raise ValueError(f"no probe named {kind!r}")
        left = _left_after(before, grace)
        stopped = fleet | (_live() - before)
    finally:
        server.close()
    next_started, orphans = _next_scan_starts(workspace, stopped)
    # What `kill -9` orphaned must not spoil the next probe: wait it out.
    _left_after(before, 300)
    return ProbeResult(kind, left, next_started, round(time.monotonic() - started, 1),
                       UNTIL.get(kind), orphans, scan_seen)


KINDS = ("cancel", "budget", "stdin", "kill")

BROKEN = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "broken-repo"


def workspace(dest: Path, data_files: int = 30_000) -> Path:
    """`broken-repo` plus enough files that the Scanners are still running when a
    probe stops them: on the bare fixture an orphan finished inside any grace."""
    import shutil

    # Absolute: the MCP server refuses a relative workspace (R1.2), which is how the
    # first Linux run's probes, given `--out acceptance-report`, never started a scan.
    root = (dest / "probe-workspace").resolve()
    if root.exists():
        shutil.rmtree(root)
    shutil.copytree(BROKEN, root)
    for i in range(data_files):
        path = root / "data" / f"{i // 1000:02}" / f"{i:05}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{i:032x}\n")
    # A repository, with the data tracked: past 20,000 files a folder walk refuses
    # before any container starts, and a git view proceeds (ADR-0021). R3's first
    # Mac run measured four probes of an empty runtime before this.
    git = ["git", "-C", str(root), "-c", "user.email=probe@example.com",
           "-c", "user.name=probe", "-c", "commit.gpgsign=false"]
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "probe workspace"]):
        subprocess.run([*git, *args], check=True, capture_output=True)  # noqa: S603
    return root
