"""One writer per Results Folder, one writer per database cache (task 16.3).

Two resources with different shapes, which is why the policies differ.

**The Workspace.** Only scans write it. Two concurrent scans do not corrupt anything
— measured 2026-09-05, four of them left every artifact valid and internally
consistent — but both read the same `state.json`, both write their own, and the last
one wins. The next run then computes its new/fixed/regressed diff against a view that
never happened. Silent, and the status diff is the one artifact a developer trusts to
say whether they made progress. A second scan therefore **fails fast**, which is what
`jobs.py` already does within a single process.

**The database cache.** Every scan reads it; only `valvur update` writes it. So the
right primitive is a shared/exclusive lock rather than mutual exclusion: any number of
scans may read at once, and an update waits for them and then excludes them. A scan
blocked behind a brief update **waits** rather than failing — erroring because
someone's pre-commit hook is refreshing would be worse than a three-second pause, and
Phase 14 is what put `--if-stale` in pre-commit hooks.

`fcntl.flock` rather than a PID file, because the kernel releases it when the process
dies: a crashed or killed scan leaves nothing to reap. POSIX-only, which task 13.3
made acceptable by scoping Windows to WSL2.
"""

from __future__ import annotations

import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class Busy(RuntimeError):
    """Someone else holds the lock, and we chose not to wait."""


@contextmanager
def held(path: Path, *, exclusive: bool = True, wait: bool = True,
         busy_message: str = "") -> Iterator[None]:
    """Hold a lock on `path` for the duration of the block.

    The lock file's *contents* are never read or written. Holding it is the whole
    signal, and an empty file cannot be misread as state.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
    mode = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
    if not wait:
        mode |= fcntl.LOCK_NB
    try:
        try:
            fcntl.flock(descriptor, mode)
        except OSError as exc:
            raise Busy(busy_message or f"another process holds {path}") from exc
        yield
    finally:
        # Closing releases the lock. Explicit unlock first so the intent is legible.
        with _ignore_os_error():
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextmanager
def _ignore_os_error() -> Iterator[None]:
    try:
        yield
    except OSError:
        pass


def workspace_lock(results_dir: Path) -> Path:
    """The lock lives inside the Results Folder, which is the one place valvur is
    allowed to write (N2.2) — so taking it creates that folder before a scan has
    produced anything.

    That must not leave git able to see it. `results.write()` writes the
    self-ignoring `.gitignore` at the end of a run, which is too late if the run is
    interrupted (task 16.2 makes interruption normal). So the folder ignores itself
    from the moment it exists, not from the moment it has contents — ADR-0011 is a
    guarantee about the folder, not about a successful scan.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    ignore = results_dir / ".gitignore"
    if not ignore.exists():
        ignore.write_text("*\n", encoding="utf-8")
    return results_dir / ".lock"


def cache_lock(cache_root: Path) -> Path:
    return cache_root / ".lock"
