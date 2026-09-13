"""Public interface: scan a Workspace, get a ScanRun.

Orchestration only. Everything tool-specific lives in `adapters/` — this module
sequences adapters, merges their Findings, diffs against the previous run, and
writes the Results Folder.
"""

from __future__ import annotations

import contextlib
import dataclasses
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass, field
from pathlib import Path

from . import cache as _cache
from . import pipeline as _pipeline
from . import profiles as _profiles
from . import results
from . import results as _results
from . import state as _state
from .adapters import DEFAULT_ADAPTERS
from .coverage import NOTE_RULES as _NOTE_RULES
from .findings import Finding
from .provenance import ScannerRun


class ScannerFailed(RuntimeError):
    """A Scanner could not complete. Never downgraded to a clean result (F2.5)."""


class ScanCancelled(RuntimeError):
    """The developer stopped the scan (F1.11). Not a failure and not a result: the
    containers were killed, and nothing is written. Deliberately not a
    `ScannerFailed` — "every Scanner failed" is what killing them looks like."""


#: The default number of Scanners the fleet runs at once, for every surface: the
#: MCP server takes no flags, so a laptop whose Docker Desktop cannot start eight
#: containers at once says so here, and `--jobs` overrides it on the CLI (23.3.3).
JOBS_ENV = "VALVUR_JOBS"


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
    #: The package-name index the dependency-reality Check answered existence from
    #: (ADR-0018). None when there is no index — then the Check failed loudly and the
    #: run says so; there is no staleness to report about something absent.
    name_index_age_days: float | None = None
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
    #: The scan budget in force (23.3.7), and the Scanners it cut — stopped while
    #: running, or never started. Each is also a failed ScannerRun naming the cut,
    #: so every surface that reports an incomplete run reports this.
    budget_s: float | None = None
    budget_cut: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[ScannerRun]:
        return [s for s in self.scanners if s.failed]

    @property
    def active(self) -> list[Finding]:
        """Findings about the scanned project, and nothing else (task 19.C.1).

        Two kinds of Finding are deliberately not here, for opposite reasons.

        A **suppressed** Finding is a risk this project recorded a decision about. It
        is still reported, never hidden — but a scan whose only Findings are accepted
        risks is not a scan that found problems, and reading like one trains people to
        ignore the verdict.

        A **coverage note** is valvur's own limitation, not the user's defect. Counting
        "we have no existence check for Rust" as a finding against their code would
        make the verdict permanently negative for something they cannot fix, and would
        fail their CI for our missing feature.
        """
        return [f for f in self.findings if not f.suppressed and f.rule not in _NOTE_RULES]

    @property
    def suppressed(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    @property
    def coverage_notes(self) -> list[Finding]:
        """What valvur did not inspect, as opposed to what it did not find."""
        return [f for f in self.findings if f.rule in _NOTE_RULES and not f.suppressed]

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

        **Still three, decided 2026-09-10 (task 19.C.2).** A fourth —
        `clean-with-suppressions` — was rejected: three statuses are a documented
        contract (§7, F7.16) and every consumer switches on them, so a new one is a
        breaking change that buys a count already printed beside the verdict. A
        suppression is a decision this project recorded in a committed file; a scan
        whose only Findings are accepted risks *is* clean by that project's own policy,
        and `active` versus `suppressed` is now explicit on every surface.

        What changed is what feeds the verdict (task 19.E.2). It used to be
        `self.findings` — every Finding, suppressed ones included, and after 19.D.1
        coverage notes too. So a repository with an accepted risk and no live problem
        read as `findings`, and any repository containing a `Cargo.toml` could never
        read `clean` at all. Neither is a statement about the user's code.

        `inconclusive` covers a coverage gap for the same reason it covers a stale
        database: **we did not look, so "clean" is not ours to claim.** It does *not*
        cover a Profile omission — the user chose `offline` and valvur did that job
        completely, which is a different thing from valvur silently being unable to do
        a job nobody declined. The Profile gap is named in `SUMMARY.md` and `run.json`
        instead, on every run.
        """
        if self.active:
            return "findings"
        return "inconclusive" if self.doubts else "clean"

    @property
    def doubts(self) -> list[str]:
        """Every reason a nil result is not evidence, in the order they are checked.

        Empty means `clean`. Each entry is one sentence a reader can act on, and
        `status_reason` joins them — so the MCP `scan_status` message, `run.json`
        and `SUMMARY.md` all say the same thing without any of them reconstructing
        it from `database.stale` and `findings.not_covered` (task 22.D.4).
        """
        from . import cache as _cache

        reasons: list[str] = []
        age = self.db_age_days
        if age is not None and age > _cache.DB_STALE_AFTER_DAYS:
            reasons.append(
                f"the vulnerability database is {age:.0f} days old "
                f"(threshold {_cache.DB_STALE_AFTER_DAYS})"
            )
        # The same rule for the name index (ADR-0018): "no hallucinated packages"
        # from a month-old list of names is not a claim about today's registry.
        index_age = self.name_index_age_days
        if index_age is not None and index_age > _cache.NAME_INDEX_STALE_AFTER_DAYS:
            reasons.append(
                f"the package-name index is {index_age:.0f} days old "
                f"(threshold {_cache.NAME_INDEX_STALE_AFTER_DAYS})"
            )
        if self.coverage_notes:
            # Each note's title is "<what> were not checked for <question>"; the
            # doubt keeps both halves, so "known vulnerabilities" and "existence"
            # read as the different gaps they are.
            which = "; ".join(n.title.replace(" were not checked for ", ": ")
                              for n in self.coverage_notes)
            reasons.append(f"not inspected — {which}")
        return reasons

    @property
    def status_reason(self) -> str:
        """One line that says why the Status is what it is."""
        if self.status == "findings":
            return f"{len(self.active)} active finding(s)"
        if self.status == "inconclusive":
            return "nothing was found, and that is not evidence: " + "; ".join(self.doubts)
        return "nothing was found, by a scan able to support the claim"


def _ensure_image(runner, on_progress) -> None:
    from .runner import ImagePullFailed

    present = getattr(runner, "image_present", None)
    if present is None or present():
        return
    size = runner.pull_size_mb()
    stated = f" ({size}MB)" if size else ""
    if on_progress is not None:
        on_progress(f"pulling {runner.image}{stated} — the first run only; the runtime "
                    "keeps it")
    started = time.monotonic()
    result = runner.pull_image()
    if result.exit_code != 0:
        detail = (result.stderr.strip() or result.stdout.strip() or "(no output)")[-400:]
        raise ImagePullFailed(
            f"The image {runner.image} is not available locally and could not be pulled.\n"
            f"The runtime said:\n  {detail}\n"
            f"Fetch it yourself with: {runner.runtime} pull {runner.image}"
        )
    if on_progress is not None:
        on_progress(f"image pulled ({time.monotonic() - started:.0f}s)")


#: What a first run says on `on_progress` while it fetches (23.2.4, 24.1): one line
#: as each fetch starts, one as it ends. `scan_status` shows the current one as
#: `Now:`; the CLI prints both kinds to stderr. Every other progress message is a
#: Scanner finishing.
FETCH_STARTED = ("pulling ", "fetching ")
FETCH_ENDED = ("image pulled", "database fetched", "database not fetched",
               "index fetched", "index not fetched")


def _ensure_data(runner, on_progress) -> dict[str, str]:
    """The vulnerability database and the package-name index, when ABSENT (24.1).

    Task 14.2 decided valvur never refreshes on its own, and its three reasons were
    about staleness: a download inside a scan the user asked to be fast, the
    Profiles diverging, and refreshing on the user's behalf being the same move as
    fixing on their behalf. Absence is a different case — without these there is no
    scan at all, and the primary path, an agent over MCP, has no `valvur update` to
    run. Measured 2026-09-13 against the published 0.2.0: the first `scan` finished
    incomplete, each failure naming a command the agent could not run. So an absent
    database or index is fetched here and announced like the image (23.2.4); a stale
    one is never touched — the warning stands and the user decides.

    Runs BEFORE `scan` takes the shared cache lock: both fetches take it
    exclusively, and a shared lock already held on another descriptor of the same
    file in this process would deadlock them. Returns what could not be fetched, by
    the Scanner it costs, so that Scanner's failure says the fetch was tried and why
    it failed rather than only naming `valvur update`.
    """
    update = getattr(runner, "update_db", None)
    if update is None:
        return {}          # the suite's fakes; the rule `_ensure_image` applies too
    say = on_progress if on_progress is not None else (lambda _: None)
    unfetched: dict[str, str] = {}

    if not _cache.db_present():
        say(f"fetching the vulnerability database{_mb(runner.db_size_mb())} — the first "
            "run only")
        started = time.monotonic()
        result = update()
        if result.exit_code != 0:
            detail = (result.stderr.strip() or result.stdout.strip() or "(no output)")[-300:]
            unfetched["trivy"] = f"the vulnerability database could not be fetched: {detail}"
            say(f"database not fetched: {detail}")
        else:
            say(f"database fetched ({time.monotonic() - started:.0f}s)")

    if not _cache.name_index_present():
        from . import locking, name_index

        say(f"fetching the package-name index{_mb(name_index.published_size_mb())} — the "
            "first run only")
        started = time.monotonic()
        try:
            with locking.held(locking.cache_lock(_cache.root()), exclusive=True, wait=True):
                # `oci.SignatureInvalid` is deliberately not caught: a refused
                # signature on a supply-chain artifact stops the scan (23.2.1).
                name_index.refresh(_cache.name_index(), fallback=False)
        except name_index.IndexUnavailable as exc:
            unfetched["dependency-reality"] = (
                f"the package-name index could not be fetched: {exc}")
            say(f"index not fetched: {exc}")
        else:
            say(f"index fetched ({time.monotonic() - started:.0f}s)")
    return unfetched


def _mb(size: int | None) -> str:
    return f" ({size}MB)" if size else ""


def _say_why_unfetched(scanners: list[ScannerRun], unfetched: dict[str, str]) -> list[ScannerRun]:
    """A Scanner that failed for want of data this run tried to fetch says so, ahead
    of the runner's own refusal — which names `valvur update`, still the right fix
    for a person, but not the whole story once a fetch has been tried (24.1)."""
    return [
        dataclasses.replace(s, reason=f"{unfetched[s.tool]}. {s.reason}")
        if s.failed and s.tool in unfetched else s
        for s in scanners
    ]


def _run_one(adapter, runner, workspace) -> tuple:
    """Run one Scanner, timed. One broken Scanner must never cost the others (F2.5)."""
    started = time.monotonic()
    scanner, findings, produced, raw = _attempt(adapter, runner, workspace)
    timed = dataclasses.replace(scanner, duration_s=time.monotonic() - started)
    return timed, findings, produced, raw


def _attempt(adapter, runner, workspace) -> tuple:
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
    on_progress=None, jobs: int | None = None, budget_s: float | None = None,
) -> ScanRun:
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
        # What a first run needs and does not have, in dependency order: the image
        # (10.2 claim 4 — `run` would pull it silently, and a first scan that shows
        # nothing for a minute looks hung, measured through Kiro in 22.G.1); then
        # the database, which Trivy fetches from inside that image; then the index
        # (24.1). Each is said on `on_progress`, and each happens here, before the
        # shared cache lock, because the two data fetches take it exclusively.
        _ensure_image(runner, on_progress)
        unfetched = _ensure_data(runner, on_progress)
        _locks.enter_context(_locking.held(
            _locking.cache_lock(_cache_mod.root()), exclusive=False, wait=True,
        ))
        return _scan_locked(
            workspace, runner=runner, adapters=adapters, profile=profile,
            on_progress=on_progress, unfetched=unfetched, jobs=jobs, budget_s=budget_s,
        )


def _jobs_from_environment() -> int | None:
    import os

    raw = os.environ.get(JOBS_ENV, "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


def _refuse_if_cancelled(runner, finished: int, total: int) -> None:
    if getattr(runner, "cancelled", False):
        raise ScanCancelled(f"cancelled: {finished} of {total} Scanner(s) had finished; "
                            "the rest were stopped and nothing was written")


def _scan_locked(workspace, *, runner, adapters, profile, on_progress,
                 unfetched: dict[str, str] | None = None, jobs: int | None = None,
                 budget_s: float | None = None) -> ScanRun:
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
    _refuse_if_cancelled(runner, 0, len(adapters))

    # `--jobs` bounds the fleet (23.3.3); the default is everything at once.
    width = jobs if jobs is not None else (_jobs_from_environment() or len(adapters))
    fleet_started = time.monotonic()
    cut: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, min(width, max(1, len(adapters))))) as pool:
        futures = {
            pool.submit(_run_one, adapter, runner, workspace): index
            for index, adapter in enumerate(adapters)
        }

        def collect(future) -> None:
            outcome = future.result()
            outcomes[futures[future]] = outcome
            if on_progress is not None:
                status = 'ok' if outcome[0].ok else 'failed'
                on_progress(f"{outcome[0].tool}: {status} ({outcome[0].duration_s:.1f}s)")

        try:
            for future in as_completed(futures, timeout=budget_s):
                collect(future)
        except TimeoutError:
            # The budget (23.3.7): past it, nothing new starts, what is running is
            # stopped, and the run is reported incomplete with each cut named. A cut
            # is not a cancel — the Scanners that finished are a result (F1.11 is
            # for the developer stopping the scan; this is the scan bounding itself).
            spent = time.monotonic() - fleet_started
            queued = [f for f in futures if f.cancel()]
            running = [f for f in futures if not f.done() and f not in queued]
            for future in queued:
                adapter = adapters[futures[future]]
                cut.append(adapter.name)
                outcomes[futures[future]] = (ScannerRun(
                    adapter.name, ok=False,
                    reason=f"not started: the {budget_s:g}s budget was spent before its turn",
                ), [], None, "")
            stop = getattr(runner, "stop_containers", None)
            if on_progress is not None:
                on_progress(f"budget spent after {spent:.0f}s: stopping "
                            f"{', '.join(adapters[futures[f]].name for f in running) or 'nothing'}"
                            f"; not starting {', '.join(cut) or 'nothing'}")
            if stop is not None and running:
                stop()
            # A stopped container comes back promptly with no report; a runner that
            # cannot stop one is waited for, and its result is real.
            wait(running)
            for future in running:
                adapter = adapters[futures[future]]
                collect(future)
                outcome = outcomes[futures[future]]
                if outcome is not None and stop is not None and not outcome[0].ok:
                    cut.append(adapter.name)
                    outcomes[futures[future]] = (dataclasses.replace(
                        outcome[0], reason=f"cut by the {budget_s:g}s budget after "
                        f"{spent:.0f}s ({outcome[0].reason})",
                    ), *outcome[1:])

    completed = [o for o in outcomes if o is not None]
    # A cancel that landed during the fleet (F1.11): the Scanners it stopped came
    # back with no report, and the ones that finished are not a result either.
    _refuse_if_cancelled(runner, sum(1 for o in completed if o[0].ok), len(adapters))
    scanners = _say_why_unfetched([outcome[0] for outcome in completed], unfetched or {})
    findings = [f for outcome in completed for f in outcome[1]]
    artifacts = [o[2] for o in completed if o[2] is not None]
    raw_outputs = [(o[0].tool, o[3]) for o in completed if o[3]]

    # Total failure is a failed Scan Run (N3.2). Partial failure is a reported one.
    if scanners and all(s.failed for s in scanners):
        detail = "; ".join(f"{s.tool}: {s.reason}" for s in scanners)
        raise ScannerFailed(f"Every scanner failed. Refusing to report a scan.\n{detail}")

    # Everything after the fleet is the named pipeline (22.D.1): each stage says
    # why it sits where it does, and tests/test_pipeline.py pins the order.
    network = _profiles.ALLOWS_NETWORK.get(profile, False)
    ctx = _pipeline.Context(
        workspace=workspace, profile=profile, network=network,
        # Every adapter, but each told what THIS Profile permits: dependency-reality's
        # contract says whether package age was checked, and that depends on the
        # network the Profile granted (ADR-0018), not on whether the adapter was run.
        declaring=[a.for_profile(network=network) for a in DEFAULT_ADAPTERS],
        artifacts=artifacts,
    )
    findings = _pipeline.run(findings, ctx)
    # And once more before anything is written: a kill that arrives between the
    # last Scanner and the write must not leave a Results Folder from a run the
    # developer said to stop.
    _refuse_if_cancelled(runner, len(scanners), len(adapters))
    if ctx.provider is None:
        # Cannot happen while `enrich` is in the pipeline; said out loud rather than
        # left to an AttributeError three lines down.
        raise RuntimeError("the enrich stage did not run")

    results_dir = workspace / results.RESULTS_DIR
    current = {f.fingerprint: f.title for f in findings}
    # Name what was fixed, using the title remembered from the previous run.
    fixed_now = [ctx.previous[fp] or fp for fp in ctx.previous if fp not in current]
    run = ScanRun(
        findings=findings,
        fixed=sorted(fixed_now),
        scanners=scanners,
        network_used=network,
        kev_age_days=ctx.provider.kev_age_days,
        identity_reset=ctx.identity_reset,
        db_age_days=_cache.db_age_days(),
        db_overdue_days=_cache.db_overdue_days(),
        name_index_age_days=_cache.name_index_age_days(),
        kev_source=ctx.provider.kev_source,
        vendored_dropped=ctx.vendored_dropped,
        config_dropped=ctx.config_dropped,
        excluded_paths=list(ctx.configured),
        profile=profile,
        coverage=ctx.coverage,
        budget_s=budget_s,
        budget_cut=cut,
    )

    results.write(workspace, run, scanner_artifacts=artifacts, raw_outputs=raw_outputs)
    still_fixed = {fp for fp in ctx.previously_fixed if fp not in current}
    still_fixed |= {fp for fp in ctx.previous if fp not in current}
    _state.save(results_dir, current, still_fixed)
    return run
