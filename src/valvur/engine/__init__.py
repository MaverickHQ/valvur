"""The in-image engine (ADR-0022, task R3): one Scan Container runs every Scanner.

It reads a Snapshot of the File Set from stdin as a tar and unpacks it into the
workspace directory, reads the plan the host left in the results directory, runs
each Scanner, and writes a manifest of what happened beside the reports. Progress
goes to stderr as JSON lines. The host never mounts the source tree.

Paths default to the container's (`/workspace`, `/results`, `/cache`); `LocalRuntime`
points them elsewhere to run the same engine as a process: in tests, and in the image
itself when it runs as a pipeline step with no runtime to start a container (R8.1).
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

from ..egress import NETWORK_ENV

WORKSPACE = "/workspace"
RESULTS = "/results"
CACHE = "/cache"
WORKSPACE_ENV = "VALVUR_ENGINE_WORKSPACE"
RESULTS_ENV = "VALVUR_ENGINE_RESULTS"
CACHE_ENV = "VALVUR_ENGINE_CACHE"


def _event(record: dict) -> None:
    print(json.dumps(record), file=sys.stderr, flush=True)


def unpack(stream: IO[bytes], workspace: Path) -> int:
    """Extract the Snapshot into `workspace`; return how many File Set entries it held:
    files and symbolic links alike, as the File Set counts them. A project that tracks
    a link was refused as a partial Snapshot until R29.2's corpus met one."""
    workspace.mkdir(parents=True, exist_ok=True)
    count = 0
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            if member.isfile() or member.issym():
                count += 1
            if hasattr(tarfile, "data_filter"):
                archive.extract(member, workspace, filter="data")
            else:                                   # Python before 3.11.4
                archive.extract(member, workspace)
    return count


def _mapped(argument: str, workspace: Path, results: Path, cache: Path | None = None) -> str:
    """The container paths in one argument, pointed at `workspace`, `results` and,
    when given, `cache`: whole prefixes only, in one pass, at the start, after `=`,
    or after a scheme such as Syft's `dir:`. Two chained replaces corrupted a
    workspace whose own path held `/results`."""
    import re

    where = {WORKSPACE: str(workspace), RESULTS: str(results)}
    if cache is not None:
        where[CACHE] = str(cache)
    return re.sub(rf"(^|=|^[a-z]+:)({'|'.join(map(re.escape, where))})(?=/|$)",
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

    def __init__(self, tool: dict, workspace: Path, results: Path, scratch: Path,
                 cache: Path | None = None):
        self.tool = tool
        self.name = tool["tool"]
        # Written where the tool starts, for a tool that reads its configuration
        # from its working directory: Opengrep's `.semgrepignore` (R3.9).
        for name, text in tool.get("files", []):
            (scratch / name).write_text(text, encoding="utf-8")
        argv = [_mapped(a, workspace, results, cache) for a in tool["argv"]]
        env = {**os.environ, **{name: _mapped(value, workspace, results, cache)
                                for name, value in tool.get("env", [])}}
        # The network grant is the plan's, per tool (D52c), in every runtime: told
        # to the tool it names and to no other, whatever this process inherited.
        env.pop(NETWORK_ENV, None)
        if tool.get("network"):
            env[NETWORK_ENV] = "1"
        self.stderr_path = scratch / f"{self.name}.stderr"
        stdout_path = results / f"{self.name}.stdout"
        self.started = time.monotonic()
        self.deadline = self.started + float(tool.get("timeout") or 600)
        self.timed_out = False
        #: Stopped by the scan's budget (R3.5), not by its own timeout.
        self.cut = False
        self.not_started: str | None = None
        self.process: subprocess.Popen | None = None
        with open(stdout_path, "wb") as out, open(self.stderr_path, "wb") as err:
            try:
                self.process = subprocess.Popen(  # noqa: S603 — the plan's own argv
                    argv, stdout=out, stderr=err, env=env, cwd=scratch,
                    start_new_session=True)
            except OSError as exc:
                # A missing or unrunnable tool fails alone (R3.4): recorded as the
                # shell records it, 127, and every other tool still runs.
                self.not_started = f"{argv[0]}: {exc.strerror or exc}"
        _event({"event": "start", "tool": self.name})

    def stop(self) -> None:
        """Kill the tool's whole process group and wait for it."""
        import signal

        if self.process is not None and self.process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()

    def poll(self, now: float) -> bool:
        """True once the tool has finished or been stopped."""
        if self.process is None or self.process.poll() is not None:
            return True
        if now >= self.deadline:
            self.stop()
            self.timed_out = True
            return True
        return False

    def entry(self) -> dict:
        seconds = round(time.monotonic() - self.started, 1)
        stderr = self.stderr_path.read_text(encoding="utf-8", errors="replace")
        if self.process is None:
            stderr, code = self.not_started or "", 127
        else:
            code = TIMED_OUT if self.timed_out else self.process.returncode
            if code < 0:
                # Killed by a signal: Python says -N, a shell and `docker run` say
                # 128 + N, and the host reads 137 as the runtime's kill (29.0.3).
                code = 128 - code
        _event({"event": "end", "tool": self.name, "exit_code": code, "seconds": seconds,
                "timed_out": self.timed_out})
        return {"tool": self.name, "exit_code": code, "seconds": seconds,
                "timed_out": self.timed_out, "cut": self.cut,
                "stderr_tail": excerpt(stderr, STDERR_KEPT)}


def run(stream: IO[bytes], workspace: Path, results: Path, cache: Path | None = None) -> int:
    import tempfile

    received = unpack(stream, workspace)
    _event({"event": "received", "files": received})
    plan = json.loads((results / "plan.json").read_text(encoding="utf-8"))
    entries = []
    running: list[_Running] = []
    pending = list(plan["tools"])
    #: How many tools run at once (`--jobs`); all of them unless the plan says.
    width = int(plan.get("jobs") or 0) or max(1, len(pending))
    with tempfile.TemporaryDirectory(prefix="valvur-engine-") as scratch_dir:
        try:
            budget = plan.get("budget_s")
            budget_deadline = time.monotonic() + float(budget) if budget else None
            while running or pending:
                while pending and len(running) < width:
                    running.append(_Running(pending.pop(0), workspace, results,
                                            Path(scratch_dir), cache))
                now = time.monotonic()
                if budget_deadline is not None and now >= budget_deadline:
                    # One deadline (R3.5): what is still running is stopped and named,
                    # and what never started is named as never started.
                    for tool in running:
                        tool.stop()
                        tool.cut = True
                        entries.append(tool.entry())
                    entries += [{"tool": t["tool"], "exit_code": TIMED_OUT, "seconds": 0.0,
                                 "timed_out": False, "cut": True, "not_started": True,
                                 "stderr_tail": ""} for t in pending]
                    running, pending = [], []
                    break
                for tool in [t for t in running if t.poll(now)]:
                    entries.append(tool.entry())
                    running.remove(tool)
                time.sleep(0.05)
        finally:
            # Stopped by the host (R3.5), or failing: nothing the engine started
            # outlives it, and no manifest claims a run that did not finish.
            for tool in running:
                tool.stop()
    (results / "manifest.json").write_text(
        json.dumps({"received": received, "tools": entries}), encoding="utf-8")
    return 0
