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

import enum
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: How long `scan_status` waits for a running job before answering.
#:
#: Fifteen seconds from task 10.2.5, when clients were said to time out at 30 to
#: 60: a 51-second scan had cost 14 status polls in 20 turns, each returning
#: instantly. R6.1 measured Claude Code keeping a 150-second call's result, so
#: since R6.3 `scan_status` attaches for the MCP budget and a margin: in practice,
#: until the scan it names has finished.
STATUS_WAIT_SECONDS = 330.0


class State(enum.StrEnum):
    """A job's five states (26.4.1). A `StrEnum`, so every surface that printed
    the word still prints the word, and a test that compared `"done"` still can.

        RUNNING ──► CANCELLING ──► CANCELLED
           │             │
           ├──► DONE ◄───┘   (a cancel that landed during the write: too late,
           │                  the result was written, DONE is the truth — 26.0.2)
           └──► FAILED

    Every other move is refused by `Job.transition`.
    """

    RUNNING = "running"
    CANCELLING = "cancelling"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


#: The moves the diagram draws — the only ones the code makes.
TRANSITIONS: dict[State, frozenset[State]] = {
    State.RUNNING: frozenset({State.CANCELLING, State.DONE, State.FAILED}),
    State.CANCELLING: frozenset({State.CANCELLED, State.DONE}),
    State.DONE: frozenset(),
    State.FAILED: frozenset(),
    State.CANCELLED: frozenset(),
}


class IllegalTransition(RuntimeError):
    """A move the diagram does not draw."""


@dataclass
class Job:
    workspace: Path
    profile: str
    started: float
    state: State = State.RUNNING
    finished: float | None = None
    error: str = ""
    #: Whether `doctor` could name the cause of a failure (29.0.3, R1.5): only a
    #: precondition failure says yes — runtime, image, database, index, SELinux,
    #: TLS. Running, done, a budget cut, a busy workspace or a bug say no.
    doctor_may_help: bool = False
    #: What to do next when the failure knows better than `doctor` (R1.5): a busy
    #: workspace says to wait.
    next_moves: tuple[str, ...] = ()
    #: The failure as fields, when the exception carried any (29.2.4): the budget
    #: cut's seconds, what it cut, what never started, and the levers.
    failure: dict | None = None
    progress: list[str] = field(default_factory=list)
    #: When each progress message arrived (monotonic), beside it (29.0.4): what
    #: lets a status line say how long a Scanner has been running.
    progress_at: list[float] = field(default_factory=list)
    settled: threading.Event = field(default_factory=threading.Event)
    #: What stops this job's containers, registered by the work once it has a
    #: runner (23.3.3) — through the `canceller` property, never this field.
    _canceller: Callable[[], int] | None = field(default=None, repr=False)

    @property
    def canceller(self) -> Callable[[], int] | None:
        return self._canceller

    @canceller.setter
    def canceller(self, stop: Callable[[], int]) -> None:
        """Attach what stops this job — and if a cancel already landed, use it now.

        `cancel` and this setter share one lock, so whichever runs second sees the
        other's state: a cancel with no canceller yet marks the job, and the setter
        finds the mark and calls the canceller itself. Before 26.0.2 the cancel in
        that window returned `stopped=0`, the runner was never told, the scan ran to
        completion and the job settled `done` — measured, a cancel confirmed and
        dropped. The window is small (between `start` returning and the work's
        `ContainerRunner()`), which is why it was never seen by hand."""
        with _lock:
            self._canceller = stop
            pending = self.state is State.CANCELLING
        if pending:
            stop()

    def transition(self, to: State) -> None:
        """Move to `to`, or refuse: the table is the API, and no state is assigned
        anywhere else (a test says so)."""
        if to not in TRANSITIONS[self.state]:
            raise IllegalTransition(f"a job cannot go {self.state.value} → {to.value}")
        self.state = to

    @property
    def elapsed(self) -> float:
        return (self.finished or time.monotonic()) - self.started

    def note(self, message: str) -> None:
        """Record a progress message and when it arrived — the callback the scan
        is given (29.0.4)."""
        self.progress.append(message)
        self.progress_at.append(time.monotonic())

    def wait(self, seconds: float | None = None) -> bool:
        """Block until the job settles or the wait runs out. True when settled.

        The default is read at call time so a test can shorten it."""
        return self.settled.wait(timeout=STATUS_WAIT_SECONDS if seconds is None else seconds)


_jobs: dict[str, Job] = {}
_lock = threading.Lock()
#: Signalled when a job starts or an expected scan is settled, under `_lock`.
_changed = threading.Condition(_lock)
#: `scan` calls the server has read and whose jobs have not started yet (R23.4):
#: a `scan_cancel` that arrives in between is held for the scan about to start.
_expected = 0
#: How long a cancel waits for a scan the server has read and not yet started:
#: its call resolves the workspace first, which may ask the client for its roots.
EXPECTED_WAIT_S = 15.0


def _doctor_may_help(exc: BaseException) -> bool:
    """A precondition failure declares it (`doctor_may_help = True` on its class);
    a TLS or connection failure is one by nature (`doctor` checks trust). Anything
    else — a bug included — is not something `doctor` would name (R1.5)."""
    import ssl
    import urllib.error

    declared = getattr(exc, "doctor_may_help", None)
    if declared is not None:
        return bool(declared)
    return isinstance(exc, ssl.SSLError | urllib.error.URLError | ConnectionError)


def current(workspace: Path) -> Job | None:
    with _lock:
        return _jobs.get(str(workspace))


#: A job that has not settled: running, or told to stop and not yet stopped.
#: `start` refuses both — a `cancelling` job replaced in the registry (26.0.2)
#: could never report CANCELLED, and its successor failed on the workspace lock
#: with a message about a scan the agent believed it had stopped.
ACTIVE = (State.RUNNING, State.CANCELLING)


def start(workspace: Path, profile: str, run: Any) -> Job:
    """Begin a scan in the background. Refuses to start a second one while one is
    active — running, or still stopping."""
    key = str(workspace)
    with _lock:
        existing = _jobs.get(key)
        if existing and existing.state in ACTIVE:
            return existing
        job = Job(workspace=workspace, profile=profile, started=time.monotonic())
        _jobs[key] = job
        _changed.notify_all()

    def work() -> None:
        try:
            run(workspace, profile, job.note)
            with _lock:
                job.transition(State.DONE)
        except Exception as exc:
            with _lock:
                if job.state is State.CANCELLING:
                    # Whatever the fleet raised on its way down — the scan's own
                    # ScanCancelled, or "every Scanner failed", which is what
                    # killing them looks like — a job the agent cancelled is
                    # cancelled (F1.11).
                    job.transition(State.CANCELLED)
                    job.error = str(exc)
                else:
                    # A failed scan is a reportable outcome, not a crashed server.
                    job.transition(State.FAILED)
                    job.error = f"{type(exc).__name__}: {exc}"
                    job.doctor_may_help = _doctor_may_help(exc)
                    job.next_moves = tuple(getattr(exc, "next_moves", ()) or ())
                    job.failure = getattr(exc, "fields", None) or None
        finally:
            job.finished = time.monotonic()
            job.settled.set()

    threading.Thread(target=work, name=f"valvur-scan-{key}", daemon=True).start()
    return job


def cancel(workspace: Path) -> tuple[Job | None, int]:
    """Ask a running job to stop: mark it, then kill its containers. Returns the
    job and how many containers were signalled; (None, 0) when nothing runs.

    The mark and the read of the canceller happen under the lock the setter
    takes, so a canceller attached a moment later finds the mark (see
    `Job.canceller`). The kill itself runs outside the lock — it is I/O.

    While a scan the server has read has not started its job, a cancel waits for
    it, up to `EXPECTED_WAIT_S` (R23.4): sent just after `scan`, it used to find
    nothing, and the scan then ran (R6's backlog row)."""
    with _changed:
        deadline = time.monotonic() + EXPECTED_WAIT_S
        job = _jobs.get(str(workspace))
        while (job is None or job.state is not State.RUNNING) and _expected > 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            _changed.wait(remaining)
            job = _jobs.get(str(workspace))
        if job is None or job.state is not State.RUNNING:
            return None, 0
        job.transition(State.CANCELLING)
        stop = job._canceller
    stopped = stop() if stop is not None else 0
    return job, stopped


def active() -> list[Path]:
    """Every workspace with a job that has not settled, newest first — what the
    server's exit has to stop (27.1.1). A list, taken under the lock, so a job
    settling while the caller works through it changes nothing."""
    with _lock:
        return [Path(key) for key, job in reversed(_jobs.items()) if job.state in ACTIVE]


def expect() -> None:
    """A `scan` call has been read, and its job will follow: said by the server's
    reader, in the order the calls arrived, before the call's own thread runs."""
    global _expected
    with _lock:
        _expected += 1


def arrived() -> None:
    """The expected scan's job started, or its call was refused before it could."""
    global _expected
    with _lock:
        _expected = max(0, _expected - 1)
        _changed.notify_all()


def reset() -> None:
    """Test seam. Never called in normal operation."""
    global _expected
    with _lock:
        _jobs.clear()
        _expected = 0
