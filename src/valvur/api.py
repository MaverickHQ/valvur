"""Public interface: scan a Workspace, get a ScanRun.

Orchestration only, in the order a scan happens: the locks, what a first run
fetches (`fetching`), the count, the fleet of Scanners (`fleet`), and the record
written from what they found (`assembly`). Everything tool-specific lives in
`adapters/`; the record itself is `scanrun.ScanRun` (R23.9).
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import TYPE_CHECKING

from . import events as _events
from . import hygiene as _hygiene
from . import osv_offline as _osv_offline
from . import profiles as _profiles
from . import results as _results
from . import scancontext as _scancontext
from . import settings as _settings
from .adapters.registry import DEFAULT_ADAPTERS
from .assembly import assemble
from .fetching import ensure_data, ensure_image
from .fleet import ScannerOutcome, engine_fleet, stop_if_cancelled
from .scanrun import BudgetExhausted, ScanCancelled, ScannerFailed, ScanRun

if TYPE_CHECKING:
    from .engine_host import Runtime

__all__ = ["DEFAULT_ADAPTERS", "BudgetExhausted", "ScanCancelled", "ScanRun",
           "ScannerFailed", "ScannerOutcome", "scan"]


def scan(
    workspace: Path, *, runner: Runtime, adapters=None, profile: str = _profiles.DEFAULT,
    on_progress=None, jobs: int | None = None, budget_s: float | None = None,
    sbom: bool = False, out: Path | None = None, fresh: bool = False,
) -> ScanRun:
    """One Scan Run of `workspace`. Its Results Folder is `.security-scan/` in the
    workspace, or in `out` when given (R8.1): a checkout mounted read-only into a
    pipeline step cannot hold it. With `sbom`, Syft writes the SBOM whatever the
    project file says (opt-in since 2026-09-28; D9). With `fresh`, every Scanner
    runs and none is reused; what ran is stored, so the next scan reuses the fresh
    answer rather than the one it replaced (R14.3, D32)."""
    if budget_s is not None and not budget_s > 0:
        raise ValueError(f"the budget must be a positive number of seconds; got {budget_s!r}")
    # Canonicalise once, at the door. Every downstream lookup is a dict.get with a
    # default, so a retired name like "standard" would quietly resolve to
    # ALLOWS_NETWORK's False and disable the network without saying so.
    profile = _profiles.resolve(profile)

    # One scan per Workspace, one writer per database (task 16.3). Taken in a fixed
    # order — Workspace, then cache — so two scans can never deadlock against each
    # other. The cache lock is SHARED: any number of scans may read the database at
    # once, and only a writer — `valvur update`, or a first run — excludes them.
    from . import cache as _cache_mod
    from . import locking as _locking

    out = Path(out) if out is not None else workspace
    with contextlib.ExitStack() as _locks:
        _locks.enter_context(_locking.held(
            _locking.workspace_lock(out / _results.RESULTS_DIR),
            exclusive=True, wait=False,
            busy_message=(
                f"a scan is already running in {workspace}. Wait for it, or scan a "
                "different workspace — two at once would each overwrite the other's "
                "state.json and silently spoil the next run's new/fixed diff."
            ),
        ))
        generation = _begin(runner, on_progress)
        # What a first run needs and does not have, in dependency order: the image
        # (10.2 claim 4 — `run` would pull it silently, and a first scan that shows
        # nothing for a minute looks hung, measured through Kiro in 22.G.1); then
        # the database, which Trivy fetches from inside that image; then the index
        # (24.1). Each is said on `on_progress`, and each happens here, before the
        # shared cache lock, because the two data fetches take it exclusively.
        stop_if_cancelled(runner, "before it began")
        fetched: list[dict] = []
        image = ensure_image(runner, on_progress)
        if image is not None:
            fetched.append(image)
        stop_if_cancelled(runner, "during the first run's fetches")
        if adapters is None:
            adapters = _profiles.select(DEFAULT_ADAPTERS, profile)
        if sbom:
            from .adapters.syft import SyftAdapter

            adapters = [SyftAdapter(enabled=True) if a.name == "syft" else a
                        for a in adapters]
        # What the scan reads of the project, read once and passed on (D52d).
        context = _scancontext.build(workspace)
        data, unfetched = ensure_data(runner, on_progress, workspace=workspace,
                                       adapters=adapters, context=context)
        fetched += data
        _locks.enter_context(_locking.held(
            _locking.cache_lock(_cache_mod.root()), exclusive=False, wait=True,
        ))
        return _scan_locked(
            workspace, runner=runner, adapters=adapters, profile=profile,
            on_progress=on_progress, unfetched=unfetched, fetched=fetched, jobs=jobs,
            budget_s=budget_s, generation=generation, out=out, fresh=fresh,
            context=context,
        )


def _begin(runner: Runtime, on_progress) -> str:
    """The Scan Run's generation, handed to the runner so every container it starts
    carries it (R3.6); and first, the containers an ended process left, removed.
    The second gate's next scan met the fleet a killed server had left running."""
    import uuid

    from . import owner

    generation = str(uuid.uuid4())
    runner.generation = generation
    runtime = runner.runtime
    if isinstance(runtime, str):
        reaped = owner.reap(runtime)
        if reaped and on_progress is not None:
            on_progress(_events.note(f"removed {len(reaped)} container(s) left by a scan "
                                     f"whose process had ended: {', '.join(reaped)}"))
    return generation


def _jobs_from_environment() -> int | None:
    raw = (_settings.get("jobs") or "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


def _scan_locked(workspace, *, runner, adapters, profile, on_progress,
                 unfetched: dict[str, str] | None = None, fetched: list[dict] | None = None,
                 jobs: int | None = None, budget_s: float | None = None,
                 generation: str | None = None, out: Path | None = None,
                 fresh: bool = False, context=None) -> ScanRun:
    """One Scan Run, under the Workspace lock: preflight, the fleet, then the
    assembly of the record — three functions since 28.4.2, one each."""
    shim_built_from, image_built_from = _preflight(runner, workspace)
    if adapters is None:
        adapters = _profiles.select(DEFAULT_ADAPTERS, profile)

    # The count (29.1.2), before a container starts: what the Scanners will read,
    # the largest directories, and — past the threshold — the one line that
    # would drop the largest, said before the budget is spent rather than after.
    from . import fileset as _fileset
    from .exclusions import LARGE_TREE

    # The File Set (ADR-0021), once: what the Snapshot holds, what every host-side
    # count reads, and what the record says was and was not read.
    if context is None:
        context = _scancontext.build(workspace)
    chosen = context.file_set
    files, largest = len(chosen.files), _fileset.largest(chosen.files)
    if on_progress is not None:
        on_progress(_events.workspace(files, largest))
        if chosen.warning:
            on_progress(_events.note(chosen.warning))
        elif files >= LARGE_TREE and largest and largest[0][0] != ".":
            # The sentence a first run needed before its budget was spent, not after.
            on_progress(_events.large_tree(*largest[0]))

    beside: dict = {}
    outcomes, cut = engine_fleet(adapters, runner, workspace, on_progress=on_progress,
                                 budget_s=budget_s, record=beside,
                                 jobs=jobs or _jobs_from_environment(), context=context,
                                 reuse=(profile, generation or ""), fresh=fresh)
    return assemble(
        outcomes, cut, declaring=DEFAULT_ADAPTERS, adapters=adapters, runner=runner,
        workspace=workspace, profile=profile,
        unfetched=unfetched, fetched=fetched, budget_s=budget_s,
        shim_built_from=shim_built_from, image_built_from=image_built_from,
        workspace_files=files, largest_dirs=largest, not_read=tuple(chosen.skipped),
        scope=chosen.manifest(workspace), ignored=frozenset(chosen.ignored),
        hygiene=_hygiene.assess(workspace, chosen.files), out=out,
        generation=generation, history=beside.get("history"), context=context,
        # OSV's offline databases this File Set needs, when OSV-Scanner reads them.
        osv_read=tuple(_osv_offline.needed(chosen.files))
        if any(a.name == "osv-scanner" and not a.network for a in adapters)
        else (),
    )


def _preflight(runner: Runtime, workspace) -> tuple[str | None, str | None]:
    """What has to be true before a container starts (F1.9, the mount, 23.4.4).
    Returns the tree the shim and the image were built from."""
    # Refuse a mismatched shim/image pair before doing any work (F1.9).
    runner.verify_compatible()
    # The tree, not the version (23.4.4): recorded now, judged in the report.
    return runner.build_provenance()
