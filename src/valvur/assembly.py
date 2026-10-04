"""The record of a scan, assembled from the fleet's outcomes: the named pipeline
over their Findings (22.D.1), the diff against the previous run (29.0.5), one
ScanRun, and the Results Folder written as one generation (26.0.3). Moved out of
`api`, the orchestrator, so each step is one function a reader can hold (R23.9).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import cache as _cache
from . import datasets as _datasets
from . import levers
from . import pipeline as _pipeline
from . import profiles as _profiles
from . import results as _results
from . import staleness as _staleness
from . import state as _state
from . import verdict as _verdict
from .fetching import say_why_unfetched
from .fleet import refuse_if_cancelled
from .scanrun import BudgetExhausted, ScannerFailed, ScanRun

if TYPE_CHECKING:
    from .engine_host import Runtime
    from .fleet import ScannerOutcome
    from .scancontext import ScanContext
    from .scanner_run import ScannerRun


def assemble(outcomes: list[ScannerOutcome | None], cut: list[str], *, declaring, adapters,
             runner: Runtime, workspace: Path, profile: str, unfetched, fetched,
             budget_s, shim_built_from, image_built_from,
             workspace_files: int = 0, largest_dirs=(), not_read=(), scope=None,
             generation: str | None = None, history: dict | None = None,
             ignored: frozenset[str] = frozenset(), hygiene: dict | None = None,
             osv_read: tuple[str, ...] = (), out: Path | None = None,
             context: ScanContext | None = None) -> ScanRun:
    """The fleet's outcomes through the named pipeline into one ScanRun, written as
    one generation. `declaring` is every adapter the Profiles know, each of which
    says what this Profile permits it, whether or not it ran."""
    completed = [o for o in outcomes if o is not None]
    # A cancel that landed during the fleet (F1.11): the Scanners it stopped came
    # back with no report, and the ones that finished are not a result either.
    refuse_if_cancelled(runner, sum(1 for o in completed if o.scanner.ok), len(adapters))
    scanners = say_why_unfetched([o.scanner for o in completed], unfetched or {})
    findings = [f for o in completed for f in o.findings]
    artifacts = [o.artifact for o in completed if o.artifact is not None]
    raw_outputs = [(o.scanner.tool, o.raw) for o in completed if o.raw]
    _refuse_total_failure(scanners, budget_s, files=workspace_files, largest=largest_dirs)

    # Everything after the fleet is the named pipeline (22.D.1): each stage says
    # why it sits where it does, and tests/test_pipeline.py pins the order.
    network = _profiles.ALLOWS_NETWORK.get(profile, False)
    results_dir = (out or workspace) / _results.RESULTS_DIR
    ctx = _pipeline.Context(
        workspace=workspace, profile=profile, network=network,
        # Every adapter, but each told what THIS Profile permits: dependency-reality's
        # contract says whether package age was checked, and that depends on the
        # network the Profile granted (ADR-0018), not on whether the adapter was run.
        declaring=[a.for_profile(network=network) for a in declaring],
        artifacts=artifacts, ignored=ignored, results=results_dir, scan=context,
    )
    # One value out, with every field a stage recorded (27.3.4).
    staged = _pipeline.run(findings, ctx)
    # And once more before anything is written: a kill that arrives between the
    # last Scanner and the write must not leave a Results Folder from a run the
    # developer said to stop.
    refuse_if_cancelled(runner, len(scanners), len(adapters))
    diff = _diff(staged, scanners, cut, results_dir)
    # This run's id when the orchestrator handed one to its containers (R3.6).
    named: dict[str, Any] = {"generation": generation} if generation else {}
    run = ScanRun(
        **named,
        history=history, findings=staged.findings, fixed=diff.fixed,
        not_rechecked=diff.not_rechecked, earlier=diff.earlier, scanners=scanners,
        network_used=network,
        fetched=list(fetched or []), profile=profile, budget_s=budget_s, budget_cut=cut,
        shim_built_from=shim_built_from, image_built_from=image_built_from,
        workspace_files=workspace_files, largest_dirs=tuple(largest_dirs),
        not_read=tuple(not_read), scope=scope, hygiene=hygiene,
        boundary=runner.boundary(), **_staged_fields(staged, osv_read),
    )
    _results_written(out or workspace, run, diff, artifacts, raw_outputs)
    return run


def _refuse_total_failure(scanners: list[ScannerRun], budget_s, *, files: int,
                          largest) -> None:
    """Total failure is a failed Scan Run (N3.2); partial failure is a reported one."""
    if not scanners or not all(s.failed for s in scanners):
        return
    if budget_s is not None and all(s.budget for s in scanners):
        # Not "every scanner failed": the budget ran out, which is what killing
        # them looks like from inside (29.0.3). The message names what ran, what
        # did not start, and the three levers.
        raise BudgetExhausted(
            levers.budget_exhausted_message(scanners, budget_s, files=files, largest=largest),
            levers.budget_fields(scanners, budget_s, files=files, largest=largest))
    detail = "; ".join(f"{s.tool}: {s.reason}" for s in scanners)
    raise ScannerFailed(f"Every scanner failed. Refusing to report a scan.\n{detail}")


def _staged_fields(staged: _pipeline.PipelineResult, osv_read: tuple[str, ...]) -> dict[str, Any]:
    """The ScanRun's fields the pipeline's stages and the datasets decide."""
    provider = staged.provider
    if provider is None:
        # Cannot happen while `enrich` is in the pipeline; said out loud rather than
        # left to an AttributeError.
        raise RuntimeError("the enrich stage did not run")
    return {
        "kev_age_days": provider.kev_age_days,
        "identity_reset": staged.identity_reset,
        "db_age_days": _datasets.DATABASE.age(),
        "db_overdue_days": _cache.db_overdue_days(),
        "name_index_age_days": _datasets.NAME_INDEX.age(),
        "kev_source": provider.kev_source,
        "kev_catalog": provider.kev_catalog,
        "epss_scored": provider.epss_scored,
        "epss_age_days": provider.epss_age_days,
        "data_ages": _staleness.data_ages(provider, osv=osv_read),
        "config_dropped": staged.config_dropped,
        "removed_by_class": staged.removed_by_class,
        "unpinned_dropped": staged.unpinned_dropped,
        "unpinned_files": staged.unpinned_files,
        "excluded_paths": staged.configured,
        "coverage": staged.coverage,
    }


@dataclass(frozen=True)
class _Diff:
    """This run against the previous one: what was fixed, what could not be
    re-checked, and the state the next run diffs against."""

    fixed: list[str]
    not_rechecked: list[tuple[str, str]]
    present_next: dict[str, str]
    still_fixed: set[str]
    sources_next: dict
    #: Each active Finding of the previous run, (state, rule, path), in its rank
    #: order (R21.4); None when the previous state did not name them.
    earlier: list[tuple[str, str, str]] | None
    #: This run's active Findings as the next run's table will name them.
    named_next: list[tuple[str, str, str]]


def _diff(staged: _pipeline.PipelineResult, scanners: list[ScannerRun], cut: list[str],
          results_dir: Path) -> _Diff:
    """A previous Finding absent now is fixed only if the Scanner that reported it
    ran this time (29.0.5). Cut, timed out or failed, it could not have looked,
    and the Finding is *not re-checked*: carried, counted, neither fixed nor
    persisting. Measured before this: a 30 s budget cut seven Scanners and the run
    said `fixed: 8`, then the next complete run would have said regressed. A
    skipped Scanner had nothing to analyse, which is an answer: its old Finding's
    file is gone, and gone is fixed."""
    current = {f.fingerprint: f.title for f in staged.findings}
    did_not_run = {r.tool for r in scanners if not r.ok and not r.skipped} | set(cut)
    previous_sources = _state.load_sources(results_dir)

    def not_run_for(fp: str) -> str | None:
        """The Scanners that would have re-checked `fp` and did not run, joined;
        "" when the state does not say which and something did not run; None
        when it was looked for."""
        sources = set(previous_sources.get(fp, ()))
        if not sources:
            return "" if did_not_run else None
        missing = sources & did_not_run
        return ", ".join(sorted(missing)) if missing else None

    gone = [fp for fp in staged.previous if fp not in current]
    # Name what was fixed, using the title remembered from the previous run.
    fixed = [staged.previous[fp] or fp for fp in gone if not_run_for(fp) is None]
    carried = {fp: staged.previous[fp] for fp in gone if not_run_for(fp) is not None}
    still_fixed = {fp for fp in staged.previously_fixed if fp not in current}
    still_fixed |= {fp for fp in gone if fp not in carried}
    # A carried Finding stays present, with the sources it had, so the next run
    # that looks for it says persisting or fixed rather than new or regressed.
    sources_next = {f.fingerprint: f.sources for f in staged.findings}
    sources_next.update({fp: previous_sources.get(fp, ()) for fp in carried})
    # The table a rescan opens with (R21.4): the previous run's active Findings,
    # named as its report named them, each fixed only where its Scanner looked.
    previous_named = _state.load_named(results_dir)
    earlier = None if previous_named is None else [
        ("open" if fp in current else "fixed" if not_run_for(fp) is None
         else "not re-checked", rule, path)
        for fp, rule, path in previous_named]
    ranked = sorted((f for f in staged.findings if _verdict.active(f)),
                    key=lambda f: f.rank or 10**9)
    named_next = [(f.fingerprint, f.rule, f.path) for f in ranked]
    # A carried Finding keeps its place in the next table, which will say what it is.
    named_next += [entry for entry in previous_named or () if entry[0] in carried]
    return _Diff(
        fixed=sorted(fixed),
        not_rechecked=sorted((title or fp, not_run_for(fp) or "")
                             for fp, title in carried.items()),
        present_next={**current, **carried}, still_fixed=still_fixed,
        sources_next=sources_next, earlier=earlier, named_next=named_next)


def _results_written(where: Path, run: ScanRun, diff: _Diff, artifacts, raw_outputs) -> None:
    _results.write(
        where, run, scanner_artifacts=artifacts, raw_outputs=raw_outputs,
        state=_state.render(diff.present_next, diff.still_fixed, sources=diff.sources_next,
                            generation=run.generation, named=diff.named_next),
    )
