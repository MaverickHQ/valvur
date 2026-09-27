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


def stream(command: list[str], tar: bytes, env: dict | None,
           on_event: Callable[[dict], None] | None) -> int:
    """Run the engine, feeding it the Snapshot and handing each progress line to
    `on_event` as it arrives, not after the run (R3.4): what a status line and an
    MCP progress notification are built from."""
    import threading

    process = subprocess.Popen(command, stdin=subprocess.PIPE,  # noqa: S603
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)

    def feed() -> None:
        try:
            if process.stdin is not None:
                process.stdin.write(tar)
                process.stdin.close()
        except BrokenPipeError:
            pass                      # the engine stopped reading: its exit code says why

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    if process.stderr is not None:
        for raw in process.stderr:
            line = raw.decode("utf-8", "replace").strip()
            if on_event is not None and line.startswith("{"):
                try:
                    on_event(json.loads(line))
                except ValueError:
                    pass
    writer.join()
    return process.wait()


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
        return stream([sys.executable, "-m", "valvur.engine"], tar, env, on_event)


#: Up to this size the Snapshot lands in a tmpfs, in memory and gone with the
#: container; beyond it, in a per-scan volume removed after the scan (ADR-0022).
TMPFS_LIMIT = 512 * 2**20


class ContainerRuntime:
    """One Scan Container (ADR-0022): the Snapshot on stdin, into an in-memory
    `/workspace`; the plan and the reports in a scratch directory mounted at
    `/results`; the source tree never mounted."""

    engine = True

    def __init__(self, image: str | None = None, runtime: str | None = None):
        from .runner import IMAGE

        self.image = image or IMAGE
        self._runtime = runtime

    @property
    def runtime(self) -> str:
        from .runner import detect_runtime

        if self._runtime is None:
            self._runtime = detect_runtime()
        return self._runtime

    def command(self, scratch: Path, *, network: bool = False, name: str | None = None,
                snapshot_bytes: int = 0) -> list[str]:
        import uuid

        from . import cache, egress
        from .runner import _resource_flags, _user_flags

        db, names = cache.trivy_db(), cache.name_index()
        db.mkdir(parents=True, exist_ok=True)
        names.mkdir(parents=True, exist_ok=True)
        name = name or f"valvur-{uuid.uuid4().hex[:16]}"
        if snapshot_bytes > TMPFS_LIMIT:
            # Past the tmpfs: a volume named for this scan, removed after it.
            landing = ["-v", f"{name}-snapshot:/workspace"]
        else:
            # In memory, gone with the container.
            landing = ["--tmpfs", "/workspace:rw,nosuid,size=512m,mode=1777"]
        return [
            self.runtime, "run", "-i", "--rm",
            "--name", name,
            *_user_flags(self.runtime),
            "--read-only", "--cap-drop=ALL", *_resource_flags(self.runtime),
            # Opengrep unpacks and runs opengrep-core from /tmp; R3.4 narrows this.
            "--tmpfs", "/tmp:rw,exec,nosuid,size=512m",   # noqa: S108 — the container's
            *landing,
            "-v", f"{scratch}:/results",
            "-v", f"{db}:/cache/trivy",
            "-v", f"{names}:/cache/names:ro",
            *egress.Egress(network=network).container_flags(),
            self.image, "python", "-m", "valvur.engine",
        ]

    def run(self, plan: list[Invocation], tar: bytes, scratch: Path,
            on_event: Callable[[dict], None] | None = None) -> int:
        import uuid

        write_plan(scratch, plan)
        network = any(i.network for i in plan)
        name = f"valvur-{uuid.uuid4().hex[:16]}"
        try:
            return stream(self.command(scratch, network=network, name=name,
                                       snapshot_bytes=len(tar)), tar, None, on_event)
        finally:
            if len(tar) > TMPFS_LIMIT:
                subprocess.run([self.runtime, "volume", "rm", "-f",  # noqa: S603
                                f"{name}-snapshot"], capture_output=True, check=False)
