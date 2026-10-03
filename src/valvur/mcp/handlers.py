"""Each MCP tool's handler: what a call knows, passed to the operation it answers with.

The client's roots, the call's progress notifications, the scan's job and the tools
this server serves belong to the MCP server. Each handler takes them from the call
and passes them in, so `operations` and `reply` import nothing from `valvur.mcp`
(D51) and the CLI calls the same functions with none of them. A scan runs through
`service.run_scan`, as the CLI's does; the job wraps that call in its thread and
adds nothing else.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .. import operations, service
from . import jobs, protocol

#: The scan budget over MCP when the client names none (23.3.7): F2.6's five
#: minutes. The CLI has none unless `--budget` is given — a person at a terminal
#: can press Ctrl-C; an agent session with a runaway Scanner waited ten minutes.
MCP_BUDGET_S = 300.0


def _roots() -> list[Path] | None:
    """The roots of the client this call comes from; None outside a call, or when
    the client declared none (R6.4)."""
    call = protocol.current_call()
    return call.client.roots() if call is not None and call.client is not None else None


def _work(budget_s: float | None, *, fresh: bool):
    """What a `scan` call's job runs: one scan through the service, with MCP's
    budget unless the call named one (0 for none), and the job's cancel wired to
    the scan's own runner, so `scan_cancel` stops this fleet and no other."""
    budget = MCP_BUDGET_S if budget_s is None else budget_s

    def work(workspace: Path, profile: str, progress) -> None:
        cancellation = service.Cancellation()
        job = jobs.current(workspace)
        if job is not None:
            job.canceller = cancellation.cancel
        service.run_scan(workspace, profile=profile, on_progress=progress,
                         budget_s=float(budget) if budget else None, fresh=fresh,
                         cancellation=cancellation)

    work.budget_s = float(budget) if budget else None  # type: ignore[attr-defined]
    return work


def announce_scan() -> None:
    """Said by the server's reader as it reads a `scan` call: its job is coming, so
    a `scan_cancel` read after it waits for that job rather than finding none."""
    jobs.expect()


def scan_reply(args: dict) -> tuple[str, dict]:
    """`scan` (R6.3, ADR-0024): start the scan, or attach to the one already running
    here, and return its result in schema 2, sending each progress message as a
    notification on the way.

    R6.1 measured that Claude Code keeps a 150-second call's result, and start-and-
    poll cost the second gate's agent sixteen turns. A client that lets go of the
    call, by cancelling it or by closing stdin, stops the wait and not the scan: the
    next `scan` here attaches and returns the same generation, and `scan_cancel` is
    what stops one."""
    try:
        workspace = operations.resolve_workspace(args.get("workspace"), roots=_roots())
        profile = operations.checked_profile(args.get("profile"))
        budget_s = operations.checked_budget(args.get("budget_s"))
        job = jobs.start(workspace, profile, _work(budget_s, fresh=bool(args.get("fresh"))))
    finally:
        jobs.arrived()                 # the scan the server announced, started or refused
    _attach(job, None)
    return operations.status_of(workspace, job, waited_s=jobs.STATUS_WAIT_SECONDS)


def scan_status_reply(args: dict) -> tuple[str, dict]:
    """`scan_status` (R6.2, ADR-0024): schema 2. A running scan is attached to
    (R6.3): the call waits for its result, sending its progress, up to
    `jobs.STATUS_WAIT_SECONDS`, and never starts one. Returning instantly made an
    agent pay fourteen turns for one scan (task 10.2.5)."""
    workspace = operations.resolve_workspace(args.get("workspace"), roots=_roots())
    job = jobs.current(workspace)
    if job is not None and job.state in jobs.ACTIVE:
        _attach(job, jobs.STATUS_WAIT_SECONDS)
    return operations.status_of(workspace, job, waited_s=jobs.STATUS_WAIT_SECONDS)


def cancel_scan(args: dict) -> str:
    """Stop a running scan (23.3.3): the same outcome Ctrl-C gives the CLI (F1.11)
    — containers stopped, nothing written, not a failure."""
    workspace = operations.resolve_workspace(args.get("workspace"), roots=_roots())
    job, stopped = jobs.cancel(workspace)
    if job is None:
        return f"No scan is running in {workspace}."
    containers = (
        f"stopped {stopped} container(s)" if stopped
        else "no container had started; the scan stops at its next step"
    )
    return (
        f"Cancelling the {job.profile} scan of {workspace} after {job.elapsed:.0f}s — "
        f"{containers}.\n"
        "No results are written for a cancelled scan; the previous results, if any, "
        "stand. `scan_status` will read CANCELLED once the fleet has stopped; call "
        "`scan` to start again."
    )


def findings_reply(args: dict) -> tuple[str, dict]:
    """`findings`: the operation, with the client's roots."""
    return operations.findings_reply(args, roots=_roots())


def check_package_reply(args: dict) -> tuple[str, dict]:
    """`check_package`: the operation, with the client's roots."""
    return operations.check_package_reply(args, roots=_roots())


def doctor(args: dict) -> str:
    """`doctor`: the operation, with the client's roots and, since it answers inside
    the server, the tools this server serves (R6.9, R12.3)."""
    call = protocol.current_call()
    served = tuple(call.served) if call is not None else None
    return operations.doctor(args, roots=_roots(), served=served)


def update_reply(args: dict) -> tuple[str, dict]:
    """`update` (ADR-0025, R6.6; F10.8): the operation, each step sent as progress."""
    call = protocol.current_call()
    return operations.update_reply(args, progress=call.progress if call is not None else None)


def _attach(job: jobs.Job, seconds: float | None) -> None:
    """Wait for `job` to settle, for `seconds` at most (None: as long as it takes),
    sending each progress message as a notification to the call being answered,
    and stopping once the client lets go of the call (R6.3)."""
    call = protocol.current_call()
    deadline = None if seconds is None else time.monotonic() + seconds
    sent = 0
    while True:
        step = 0.25 if deadline is None else min(0.25, max(0.0, deadline - time.monotonic()))
        if job.settled.wait(timeout=step):
            break
        sent = _forward(job, call, sent)
        if call is not None and call.detached.is_set():
            break
        if deadline is not None and time.monotonic() >= deadline:
            break
    _forward(job, call, sent)


def _forward(job: jobs.Job, call: Any, sent: int) -> int:
    """Each progress message the job has said since `sent`, as a notification."""
    said = list(job.progress)
    if call is not None:
        for message in said[sent:]:
            call.progress(message)
    return len(said)


def scan_status(args: dict) -> str:
    """The text half of `scan_status_reply`, as a client that reads only text gets it."""
    return scan_status_reply(args)[0]
