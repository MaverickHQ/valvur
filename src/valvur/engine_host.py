"""The host's side of the Scan Container (ADR-0022, task R3).

The host builds a Snapshot of the File Set, writes the plan beside where the reports
will land, runs the in-image engine through a runtime, and reads the manifest back.
Two runtimes: the container one, and `LocalRuntime`, which runs the same engine as a
host process — the one boundary the tests fake (tasks.md §3).
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
from collections.abc import Callable, Iterable
from pathlib import Path

from .engine import RESULTS_ENV, WORKSPACE_ENV
from .invocation import Invocation


def snapshot(root: Path, files: Iterable[str]) -> bytes:
    """The File Set as a tar, each entry under its repo-relative path."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for rel in sorted(files):
            archive.add(root / rel, arcname=rel, recursive=False)
    return buffer.getvalue()


def plan_entry(invocation: Invocation) -> dict:
    return {"tool": invocation.tool, "version": invocation.version,
            "argv": list(invocation.argv), "report": invocation.report,
            "timeout": invocation.timeout, "env": [list(e) for e in invocation.env],
            "files": [list(f) for f in invocation.files],
            "empty_when": list(invocation.empty_when)}


def write_plan(scratch: Path, plan: list[Invocation]) -> None:
    (scratch / "plan.json").write_text(
        json.dumps({"tools": [plan_entry(i) for i in plan]}), encoding="utf-8")


class LocalRuntime:
    """Runs the engine as a host process, with `tools_dir` first on its PATH."""

    #: What `api` asks to choose the Scan Container's path (ADR-0022).
    engine = True

    def __init__(self, tools_dir: Path | None = None):
        self.tools_dir = tools_dir

    def run(self, plan: list[Invocation], tar: bytes, scratch: Path,
            on_event: Callable[[dict], None] | None = None) -> int:
        write_plan(scratch, plan)
        workspace = scratch.parent / f"{scratch.name}-workspace"
        env = {**os.environ, WORKSPACE_ENV: str(workspace), RESULTS_ENV: str(scratch)}
        if self.tools_dir is not None:
            env["PATH"] = f"{self.tools_dir}{os.pathsep}{env.get('PATH', '')}"
        proc = subprocess.run([sys.executable, "-m", "valvur.engine"],
                              input=tar, capture_output=True, env=env, check=False)
        for line in proc.stderr.decode("utf-8", "replace").splitlines():
            if on_event is not None and line.startswith("{"):
                on_event(json.loads(line))
        return proc.returncode
