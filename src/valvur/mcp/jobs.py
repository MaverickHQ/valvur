"""Background scan jobs, so a long scan never outlives a client's patience.

A `standard` scan takes ~20 seconds on a toy fixture and minutes on a real project;
many MCP clients time out at 30-60. A synchronous `scan` tool would work in
development and fail on exactly the repositories people care about.

So `scan` always starts a job and returns immediately, and the agent polls
`scan_status`. Always — not "when slow" — because a contract that changes shape
depending on project size is one an agent cannot reason about.

Threads, not processes: the work is a container invocation, so it is I/O-bound, and
the MCP server is a long-lived process spawned by the client.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Job:
    workspace: Path
    profile: str
    started: float
    state: str = "running"          # running | done | failed
    finished: float | None = None
    summary: str = ""
    error: str = ""
    progress: list[str] = field(default_factory=list)

    @property
    def elapsed(self) -> float:
        return (self.finished or time.monotonic()) - self.started


_jobs: dict[str, Job] = {}
_lock = threading.Lock()


def current(workspace: Path) -> Job | None:
    with _lock:
        return _jobs.get(str(workspace))


def start(workspace: Path, profile: str, run: Any) -> Job:
    """Begin a scan in the background. Refuses to start a second one concurrently."""
    key = str(workspace)
    with _lock:
        existing = _jobs.get(key)
        if existing and existing.state == "running":
            return existing
        job = Job(workspace=workspace, profile=profile, started=time.monotonic())
        _jobs[key] = job

    def work() -> None:
        try:
            job.summary = run(workspace, profile, job.progress.append)
            job.state = "done"
        except Exception as exc:
            # A failed scan is a reportable outcome, not a crashed server.
            job.state = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            job.finished = time.monotonic()

    threading.Thread(target=work, name=f"valvur-scan-{key}", daemon=True).start()
    return job


def reset() -> None:
    """Test seam. Never called in normal operation."""
    with _lock:
        _jobs.clear()
