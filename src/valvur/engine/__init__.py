"""The in-image engine (ADR-0022, task R3): one Scan Container runs every Scanner.

It reads a Snapshot of the File Set from stdin as a tar and unpacks it into the
workspace directory, reads the plan the host left in the results directory, runs
each Scanner, and writes a manifest of what happened beside the reports. Progress
goes to stderr as JSON lines. The host never mounts the source tree.

Paths default to the container's (`/workspace`, `/results`); `LocalRuntime` points
them elsewhere to run the same engine as a host process in tests.
"""

from __future__ import annotations

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
    return (argument.replace(WORKSPACE, str(workspace))
            .replace(RESULTS, str(results)))


def run(stream: IO[bytes], workspace: Path, results: Path) -> int:
    received = unpack(stream, workspace)
    _event({"event": "received", "files": received})
    plan = json.loads((results / "plan.json").read_text(encoding="utf-8"))
    entries = []
    for tool in plan["tools"]:
        for name, text in tool.get("files", []):
            (results / name).write_text(text, encoding="utf-8")
        argv = [_mapped(a, workspace, results) for a in tool["argv"]]
        env = {**os.environ, **dict(tool.get("env", []))}
        _event({"event": "start", "tool": tool["tool"]})
        started = time.monotonic()
        proc = subprocess.run(argv, capture_output=True, text=True, env=env,  # noqa: S603
                              check=False)
        seconds = round(time.monotonic() - started, 1)
        if not tool.get("report"):
            (results / f"{tool['tool']}.stdout").write_text(proc.stdout, encoding="utf-8")
        entries.append({"tool": tool["tool"], "exit_code": proc.returncode,
                         "seconds": seconds, "timed_out": False,
                         "stderr_tail": proc.stderr[-2000:]})
        _event({"event": "end", "tool": tool["tool"], "exit_code": proc.returncode,
                "seconds": seconds})
    (results / "manifest.json").write_text(
        json.dumps({"received": received, "tools": entries}), encoding="utf-8")
    return 0
