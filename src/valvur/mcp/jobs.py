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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: How long `scan_status` waits for a running job before answering (task 10.2.5).
#:
#: Measured with a real agent: a 51-second scan cost **14 status polls in 20 turns**,
#: because each poll returned instantly and the agent — having read every file in
#: the repository while it waited — had nothing left to do but ask again. Each poll
#: is a full model turn; that run hit its turn limit before writing a report.
#:
#: Fifteen seconds sits well under the 30-60s at which the docstring above says
#: clients give up, and turns those 14 polls into 4. The job itself is unchanged:
#: `scan` still returns immediately, and the shape of the contract does not vary
#: with project size.
STATUS_WAIT_SECONDS = 15.0


@dataclass
class Job:
    workspace: Path
    profile: str
    started: float
    state: str = "running"          # running | cancelling | done | failed | cancelled
    finished: float | None = None
    summary: str = ""
    error: str = ""
    progress: list[str] = field(default_factory=list)
    settled: threading.Event = field(default_factory=threading.Event)
    #: What stops this job's containers, registered by the work once it has a
    #: runner (23.3.3). None until then: a cancel before that only sets the state.
    canceller: Callable[[], int] | None = None

    @property
    def elapsed(self) -> float:
        return (self.finished or time.monotonic()) - self.started

    def wait(self, seconds: float | None = None) -> bool:
        """Block until the job settles or the wait runs out. True when settled.

        The default is read at call time so a test can shorten it."""
        return self.settled.wait(timeout=STATUS_WAIT_SECONDS if seconds is None else seconds)


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
            if job.state == "cancelling":
                # Whatever the fleet raised on its way down — the scan's own
                # ScanCancelled, or "every Scanner failed", which is what killing
                # them looks like — a job the agent cancelled is cancelled (F1.11).
                job.state = "cancelled"
                job.error = str(exc)
            else:
                # A failed scan is a reportable outcome, not a crashed server.
                job.state = "failed"
                job.error = f"{type(exc).__name__}: {exc}"
        finally:
            job.finished = time.monotonic()
            job.settled.set()

    threading.Thread(target=work, name=f"valvur-scan-{key}", daemon=True).start()
    return job


def cancel(workspace: Path) -> tuple[Job | None, int]:
    """Ask a running job to stop: mark it, then kill its containers. Returns the
    job and how many containers were signalled; (None, 0) when nothing runs."""
    with _lock:
        job = _jobs.get(str(workspace))
        if job is None or job.state != "running":
            return None, 0
        job.state = "cancelling"
    stopped = job.canceller() if job.canceller is not None else 0
    return job, stopped


def reset() -> None:
    """Test seam. Never called in normal operation."""
    with _lock:
        _jobs.clear()
