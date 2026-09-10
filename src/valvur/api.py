"""Public interface: scan a Workspace, get a ScanRun.

Orchestration only. Everything tool-specific lives in `adapters/` — this module
sequences adapters, merges their Findings, diffs against the previous run, and
writes the Results Folder.
"""

from __future__ import annotations

import contextlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import cache as _cache
from . import coverage as _coverage
from . import enrichment as _enrichment
from . import exclusions as _exclusions
from . import gitcontext as _gitcontext
from . import licence_policy as _licence
from . import profiles as _profiles
from . import ranking as _ranking
from . import results
from . import results as _results
from . import state as _state
from . import suppressions as _suppressions
from .adapters import DEFAULT_ADAPTERS
from .findings import Finding, merge
from .provenance import ScannerRun


class ScannerFailed(RuntimeError):
    """A Scanner could not complete. Never downgraded to a clean result (F2.5)."""


@dataclass
class ScanRun:
    findings: list[Finding] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    scanners: list[ScannerRun] = field(default_factory=list)
    network_used: bool = False
    kev_age_days: float | None = None
    kev_source: str = ""
    # The database that decides whether findings EXIST, as opposed to KEV which only
    # decides how they rank. Until 2026-09-05 only the latter was instrumented.
    db_age_days: float | None = None
    db_overdue_days: float | None = None
    #: (old, new) when the Fingerprint algorithm changed and history was discarded.
    identity_reset: tuple[object, int] | None = None
    vendored_dropped: int = 0
    config_dropped: int = 0
    excluded_paths: list[str] = field(default_factory=list)
    profile: str = ""
    #: Per-adapter coverage contracts: what each reads and what it deliberately does
    #: not (task 19.E.1). Provenance, not findings — the gaps themselves arrive as
    #: Findings so they are ranked, fingerprinted and suppressible like anything else.
    coverage: dict = field(default_factory=dict)

    @property
    def failures(self) -> list[ScannerRun]:
        return [s for s in self.scanners if s.failed]

    @property
    def status(self) -> str:
        """`clean` must be explicit, so an agent can tell it from a run that never
        happened — and must not be claimed when we cannot support it.

        Three states, not two. Until 2026-09-05 a scan with a 400-day-old database
        and no findings reported `clean`, and the prose warning explaining why that
        meant nothing lived in `SUMMARY.md` — a file the results contract tells
        agents to read *bounded* while querying `findings.json` for detail. The one
        consumer most likely to act on the verdict was the one least likely to see
        the caveat.

        F7.16. `inconclusive` says the thing that is actually true: we looked, we found
        nothing, and our data was too old for that to be evidence.
        """
        if self.findings:
            return "findings"
        from . import cache as _cache

        age = self.db_age_days
        if age is not None and age > _cache.DB_STALE_AFTER_DAYS:
            return "inconclusive"
        return "clean"


def _run_one(adapter, runner, workspace) -> tuple:
    """Run one Scanner. One broken Scanner must never cost the others (F2.5)."""
    # Part of the ScannerAdapter protocol (task 17.3) rather than a `getattr` the
    # orchestrator hopes for. Every adapter inherits a default, so the call is
    # unconditional and an adapter that forgets the method is impossible.
    #
    # It does NOT make a MISSPELLED override a type error — mypy sees an extra
    # method and an inherited default, and is content. `test_applicability.py`
    # catches that; the type checker will not. Worth knowing rather than assuming.
    should_run, why = adapter.applies_to(workspace)
    if not should_run:
        # Not a failure: the Scan Run stays complete. Recorded so the reader can tell
        # "had nothing to look at" from "looked and found nothing".
        return ScannerRun(adapter.name, ok=True, skipped=True, reason=why), [], None, ""

    try:
        output = adapter.run(runner, workspace)
    except Exception as exc:
        return ScannerRun(adapter.name, ok=False, reason=str(exc)), [], None, ""

    if output.exit_code != 0 and not output.stdout.strip():
        return (
            ScannerRun(
                adapter.name,
                ok=False,
                version=output.version,
                reason=f"exited {output.exit_code} with no report: "
                f"{output.stderr.strip()[:200]}",
            ),
            [],
            None,
            output.stdout,
        )

    # An adapter may produce an artifact (an SBOM) instead of, or as well as, Findings.
    # Not on the protocol: see the note in adapters/base.py — a Protocol class
    # attribute's default is not inherited, only a method body is.
    artifact = getattr(adapter, "artifact", None)
    produced = (artifact, output.stdout) if artifact and output.stdout.strip() else None
    return (
        ScannerRun(adapter.name, ok=True, version=output.version),
        adapter.parse(output),
        produced,
        output.stdout,
    )


def scan(
    workspace: Path, *, runner, adapters=None, profile: str = _profiles.DEFAULT,
    on_progress=None,
) -> ScanRun:
    # Canonicalise once, at the door. Every downstream lookup is a dict.get with a
    # default, so a retired name like "standard" would quietly resolve to
    # ALLOWS_NETWORK's False and disable the network without saying so.
    profile = _profiles.resolve(profile)

    # One scan per Workspace, one writer per database (task 16.3). Taken in a fixed
    # order — Workspace, then cache — so two scans can never deadlock against each
    # other. The cache lock is SHARED: any number of scans may read the database at
    # once, and only `valvur update` excludes them.
    from . import cache as _cache_mod
    from . import locking as _locking

    with contextlib.ExitStack() as _locks:
        _locks.enter_context(_locking.held(
            _locking.workspace_lock(workspace / _results.RESULTS_DIR),
            exclusive=True, wait=False,
            busy_message=(
                f"a scan is already running in {workspace}. Wait for it, or scan a "
                "different workspace — two at once would each overwrite the other's "
                "state.json and silently spoil the next run's new/fixed diff."
            ),
        ))
        _locks.enter_context(_locking.held(
            _locking.cache_lock(_cache_mod.root()), exclusive=False, wait=True,
        ))
        return _scan_locked(
            workspace, runner=runner, adapters=adapters, profile=profile,
            on_progress=on_progress,
        )


def _scan_locked(workspace, *, runner, adapters, profile, on_progress) -> ScanRun:
    # Refuse a mismatched shim/image pair before doing any work (F1.9).
    verify = getattr(runner, "verify_compatible", None)
    if verify is not None:
        verify()

    # And confirm the container can actually see the source. An unreadable workspace
    # is indistinguishable from a clean one from inside a Scanner.
    readable = getattr(runner, "verify_workspace_readable", None)
    if readable is not None:
        readable(workspace)

    if adapters is None:
        adapters = _profiles.select(DEFAULT_ADAPTERS, profile)

    # Scanners are independent and I/O-bound — each is a container invocation — so
    # they run concurrently. Serially, six Scanners will not meet the 5-minute
    # standard budget (F2.6, N1.2). Results are collected back into declaration
    # order so a Scan Run is reproducible regardless of which finished first.
    outcomes: list[tuple | None] = [None] * len(adapters)

    with ThreadPoolExecutor(max_workers=max(1, len(adapters))) as pool:
        futures = {
            pool.submit(_run_one, adapter, runner, workspace): index
            for index, adapter in enumerate(adapters)
        }
        for future in as_completed(futures):
            outcome = future.result()
            outcomes[futures[future]] = outcome
            if on_progress is not None:
                status = 'ok' if outcome[0].ok else 'failed'
                on_progress(f"{outcome[0].tool}: {status}")

    completed = [o for o in outcomes if o is not None]
    scanners = [outcome[0] for outcome in completed]
    findings = [f for outcome in completed for f in outcome[1]]
    artifacts = [o[2] for o in completed if o[2] is not None]
    raw_outputs = [(o[0].tool, o[3]) for o in completed if o[3]]

    # Total failure is a failed Scan Run (N3.2). Partial failure is a reported one.
    if scanners and all(s.failed for s in scanners):
        detail = "; ".join(f"{s.tool}: {s.reason}" for s in scanners)
        raise ScannerFailed(f"Every scanner failed. Refusing to report a scan.\n{detail}")

    # Coverage gaps, from the whole registry rather than this Profile's selection
    # (task 19.E.1). Deliberately outside the Scanner fleet: a coverage limit is a
    # static fact about the Workspace, needs no container and no socket, and stays
    # true on every Profile. It used to live inside the dependency-reality Check,
    # which the default `offline` Profile does not run — so the one message saying
    # "this scan could not help you" was missing exactly where it mattered most.
    configured = tuple(_exclusions.load_configured(workspace))
    coverage_declared = _coverage.collect(DEFAULT_ADAPTERS, workspace, configured)
    for adapter in DEFAULT_ADAPTERS:
        findings += list(adapter.coverage(workspace, configured).gaps)

    # Dependency licence policy reads the SBOM the fleet just produced (F4.4-F4.6).
    sbom = next((body for name, body in artifacts if name == "sbom.cdx.json"), "")
    if sbom:
        findings += _licence.evaluate(_licence.project_licence(workspace), sbom)

    # Vendored and generated code is not the developer's to fix.
    findings, vendored_dropped = _exclusions.filter_findings(findings)

    # Paths this project chose not to scan, from its committed config. Never a
    # built-in default: silently skipping a project's tests would hide real code.
    findings, config_dropped = _exclusions.filter_configured(findings, configured)
    excluded_paths = list(configured)

    findings = merge(findings)

    # A secret git is not carrying is a local credential, not a leak.
    findings = _gitcontext.apply(workspace, findings)

    # Exploit intelligence: what the world reports, as opposed to what a Scanner
    # asserts. Network use is Profile-gated (F6.3, F6.4).
    provider = _enrichment.LocalProvider()
    findings = provider.enrich(findings, network=_profiles.ALLOWS_NETWORK.get(profile, False))
    # Suppressions are a policy layer applied after detection and enrichment, and
    # before ranking. They never touch the Fingerprint or the Status diff — a
    # suppressed Finding is still present, and un-suppressing it must not read as new.
    policy = _suppressions.load(workspace)
    findings = _suppressions.apply(findings, policy)
    findings += _suppressions.policy_findings(policy, findings)

    findings = _ranking.apply(findings)

    results_dir = workspace / results.RESULTS_DIR
    previous, previously_fixed = _state.load(results_dir)
    identity_reset = _state.take_reset()

    findings = [
        replace(f, status=_state.status_for(f.fingerprint, previous, previously_fixed))
        for f in findings
    ]

    current = {f.fingerprint: f.title for f in findings}
    # Name what was fixed, using the title remembered from the previous run.
    fixed_now = [previous[fp] or fp for fp in previous if fp not in current]
    run = ScanRun(
        findings=findings,
        fixed=sorted(fixed_now),
        scanners=scanners,
        network_used=_profiles.ALLOWS_NETWORK.get(profile, False),
        kev_age_days=provider.kev_age_days,
        identity_reset=identity_reset,
        db_age_days=_cache.db_age_days(),
        db_overdue_days=_cache.db_overdue_days(),
        kev_source=provider.kev_source,
        vendored_dropped=vendored_dropped,
        config_dropped=config_dropped,
        excluded_paths=list(excluded_paths),
        profile=profile,
        coverage=coverage_declared,
    )

    results.write(workspace, run, scanner_artifacts=artifacts, raw_outputs=raw_outputs)
    still_fixed = {fp for fp in previously_fixed if fp not in current}
    still_fixed |= {fp for fp in previous if fp not in current}
    _state.save(results_dir, current, still_fixed)
    return run
