"""The in-image engine (ADR-0022, task R3): one Scan Container runs every Scanner.

It reads a Snapshot of the File Set from stdin as a tar and unpacks it into the
workspace directory, reads the plan the host left in the results directory, runs
each Scanner, and writes a manifest of what happened beside the reports. Progress
goes to stderr as JSON lines. The host never mounts the source tree.

Paths default to the container's (`/workspace`, `/results`); `LocalRuntime` points
them elsewhere to run the same engine as a host process in tests.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import IO

WORKSPACE = "/workspace"
RESULTS = "/results"
WORKSPACE_ENV = "VALVUR_ENGINE_WORKSPACE"
RESULTS_ENV = "VALVUR_ENGINE_RESULTS"


def _event(record: dict) -> None:
    print(json.dumps(record), file=sys.stderr, flush=True)


def unpack(stream: IO[bytes], workspace: Path) -> int:
    """Extract the Snapshot into `workspace`; return how many files it held."""
    workspace.mkdir(parents=True, exist_ok=True)
    count = 0
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            if member.isfile():
                count += 1
            if hasattr(tarfile, "data_filter"):
                archive.extract(member, workspace, filter="data")
            else:                                   # Python before 3.11.4
                archive.extract(member, workspace)
    return count


def _mapped(argument: str, workspace: Path, results: Path) -> str:
    """The container paths in one argument, pointed at `workspace` and `results`:
    whole prefixes only, in one pass, at the start or after `=`. Two chained
    replaces corrupted a workspace whose own path contained `/results`."""
    import re

    where = {WORKSPACE: str(workspace), RESULTS: str(results)}
    return re.sub(r"(^|=)(/workspace|/results)(?=/|$)",
                  lambda m: m.group(1) + where[m.group(2)], argument)


#: `timeout(1)`'s convention for a tool the engine stopped at its timeout.
TIMED_OUT = 124
#: How much of a tool's stderr the manifest keeps.
STDERR_KEPT = 2000


def excerpt(text: str, limit: int) -> str:
    """The last `limit` characters, starting at a word boundary: the second gate
    read *… exclud (609.1s)*, a word cut in half and run into the duration."""
    if len(text) <= limit:
        return text.strip()
    tail = text[-limit:]
    cut = tail.find(" ")
    return (tail[cut + 1:] if 0 <= cut < limit // 2 else tail).strip()


class _Running:
    """One tool, started in its own session and so its own process group: a
    timeout kills the group, grandchildren included (R3.4)."""

    def __init__(self, tool: dict, workspace: Path, results: Path, scratch: Path):
        self.tool = tool
        self.name = tool["tool"]
        for name, text in tool.get("files", []):
            (results / name).write_text(text, encoding="utf-8")
        argv = [_mapped(a, workspace, results) for a in tool["argv"]]
        env = {**os.environ, **dict(tool.get("env", []))}
        self.stderr_path = scratch / f"{self.name}.stderr"
        stdout_path = results / f"{self.name}.stdout"
        self.started = time.monotonic()
        self.deadline = self.started + float(tool.get("timeout") or 600)
        with open(stdout_path, "wb") as out, open(self.stderr_path, "wb") as err:
            self.process = subprocess.Popen(  # noqa: S603 — the plan's own argv
                argv, stdout=out, stderr=err, env=env, cwd=scratch,
                start_new_session=True)
        self.timed_out = False
        _event({"event": "start", "tool": self.name})

    def poll(self, now: float) -> bool:
        """True once the tool has finished or been stopped."""
        import signal

        if self.process.poll() is not None:
            return True
        if now >= self.deadline:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()
            self.timed_out = True
            return True
        return False

    def entry(self) -> dict:
        seconds = round(time.monotonic() - self.started, 1)
        stderr = self.stderr_path.read_text(encoding="utf-8", errors="replace")
        code = TIMED_OUT if self.timed_out else self.process.returncode
        _event({"event": "end", "tool": self.name, "exit_code": code, "seconds": seconds,
                "timed_out": self.timed_out})
        return {"tool": self.name, "exit_code": code, "seconds": seconds,
                "timed_out": self.timed_out, "stderr_tail": excerpt(stderr, STDERR_KEPT)}


def run(stream: IO[bytes], workspace: Path, results: Path) -> int:
    import tempfile

    received = unpack(stream, workspace)
    _event({"event": "received", "files": received})
    plan = json.loads((results / "plan.json").read_text(encoding="utf-8"))
    entries = []
    with tempfile.TemporaryDirectory(prefix="valvur-engine-") as scratch_dir:
        running = [_Running(tool, workspace, results, Path(scratch_dir))
                   for tool in plan["tools"]]
        while running:
            now = time.monotonic()
            for tool in [t for t in running if t.poll(now)]:
                entries.append(tool.entry())
                running.remove(tool)
            time.sleep(0.05)
    (results / "manifest.json").write_text(
        json.dumps({"received": received, "tools": entries}), encoding="utf-8")
    return 0
