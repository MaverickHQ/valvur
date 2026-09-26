"""Public interface: scan a Workspace, get a ScanRun.

Orchestration only. Everything tool-specific lives in `adapters/` — this module
sequences adapters, merges their Findings, diffs against the previous run, and
writes the Results Folder.
"""

from __future__ import annotations

import contextlib
import dataclasses
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass, field
from pathlib import Path

from . import cache as _cache
from . import egress as _egress
from . import pipeline as _pipeline
from . import profiles as _profiles
from . import results
from . import results as _results
from . import staleness as _staleness
from . import state as _state
from .adapters import DEFAULT_ADAPTERS
from .coverage import DOUBT_RULES as _DOUBT_RULES
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


@dataclass(frozen=True)
class ScannerOutcome:
    """One Scanner's result as the fleet records it (26.3.2): the ScannerRun, its
    Findings, the artifact it produced (an SBOM: file name and content) and the
    raw text of its report for `raw/`. Was a 4-tuple the fleet indexed by
    position in eleven places."""

    scanner: ScannerRun
    findings: list = field(default_factory=list)
    artifact: tuple[str, str] | None = None
    raw: str = ""

    def timed(self, seconds: float) -> ScannerOutcome:
        return dataclasses.replace(
            self, scanner=dataclasses.replace(self.scanner, duration_s=seconds))

    def cut(self, reason: str) -> ScannerOutcome:
        """The same outcome, its ScannerRun's reason rewritten — what the budget
        does to a Scanner it stopped (23.3.7)."""
        return dataclasses.replace(self, scanner=dataclasses.replace(self.scanner, reason=reason))


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
    #: What a first run fetched before the fleet — the image, the database, the
    #: index — each as what/source/size_mb/seconds (and the index's signature
    #: verdict). Empty on a steady-state run, and written empty on purpose: a
    #: reader can tell "nothing fetched" from "a valvur that did not record". Until
    #: 28.0.4 `run.json` said `network.used: false, what_left_the_machine: nothing`
    #: about a run that had opened sockets to three hosts — true in the sentence's
    #: sense and silent about the fetches (F10.8, ADR-0010).
    fetched: list[dict] = field(default_factory=list)
    vendored_dropped: int = 0
    config_dropped: int = 0
    #: OSV-Scanner answers against the lower bounds of unpinned ranges, dropped
    #: (25.3), and the requirements files they came from.
    unpinned_dropped: int = 0
    unpinned_files: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()
    #: The `.gitignore` opt-in (29.0.1 part 2): asked for, the directories it
    #: hid, why git could not be asked, and what a Scanner reported there anyway.
    honour_gitignore: bool = False
    gitignored_paths: tuple[str, ...] = ()
    gitignore_note: str | None = None
    gitignore_dropped: int = 0
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
    #: The tree the shim was built beside and the tree the image was built from
    #: (23.4.4). Equal on a release; different is the rc1 hole — same version,
    #: different code — reported as a warning, never a refusal. None: unrecorded.
    shim_built_from: str | None = None
    image_built_from: str | None = None
    #: One id per Scan Run, in every JSON artifact and SARIF's own
    #: `automationDetails.guid` (26.0.3): a reader who trusts `run.json` can tell
    #: whether each sibling was written by the same run. Minted here so every
    #: projection reads one value.
    generation: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def build_match(self) -> bool | None:
        if self.shim_built_from is None or self.image_built_from is None:
            return None
        return self.shim_built_from == self.image_built_from

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
        """What valvur did not inspect or could not read, as opposed to what it did
        not find. Two kinds: the gaps, which make a nil result `inconclusive`, and
        the licence statements, which do not (`coverage.DOUBT_RULES`, 23.5.5)."""
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
        reasons: list[str] = []
        # The predicates are `staleness.py`'s, the same ones `run.json`'s `stale`
        # flags use — this method carried its own copy of each comparison until
        # 28.1.1, and two copies of a predicate agree only until one is edited.
        if _staleness.db_is_stale(self):
            reasons.append(
                f"the vulnerability database is {self.db_age_days:.0f} days old "
                f"(threshold {_cache.DB_STALE_AFTER_DAYS})"
            )
        # The same rule for the name index (ADR-0018): "no hallucinated packages"
        # from a month-old list of names is not a claim about today's registry.
        if _staleness.index_is_stale(self):
            reasons.append(
                f"the package-name index is {self.name_index_age_days:.0f} days old "
                f"(threshold {_cache.NAME_INDEX_STALE_AFTER_DAYS})"
            )
        gaps = [n for n in self.coverage_notes if n.rule in _DOUBT_RULES]
        if gaps:
            # Each gap's title is "<what> were not checked for <question>"; the
            # doubt keeps both halves, so "known vulnerabilities" and "existence"
            # read as the different gaps they are. A licence statement is a note
            # too, and is not here: it casts no doubt (23.5.5).
            which = "; ".join(n.title.replace(" were not checked for ", ": ")
                              for n in gaps)
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


def _ensure_image(runner, on_progress) -> dict | None:
    """Pull the image when absent (23.2.4). Returns the fetch record, or None."""
    from .runner import ImagePullFailed

    present = getattr(runner, "image_present", None)
    if present is None or present():
        return None
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
    seconds = time.monotonic() - started
    if on_progress is not None:
        on_progress(f"image pulled ({seconds:.0f}s)")
    return _fetch_record("image", runner.image, size, seconds)


def _fetch_record(what: str, source: str, size_mb: int | None, seconds: float,
                  **extra) -> dict:
    """One fetch, for the record (28.0.4): what arrived, from where, how large as
    the source stated it, how long. `seconds` rounded to a tenth like every other
    duration `run.json` carries."""
    return {"what": what, "source": source, "size_mb": size_mb,
            "seconds": round(seconds, 1), **extra}


#: What a first run says on `on_progress` while it fetches (23.2.4, 24.1): one line
#: as each fetch starts, one as it ends. `scan_status` shows the current one as
#: `Now:`; the CLI prints both kinds to stderr. Every other progress message is a
#: Scanner finishing.
FETCH_STARTED = ("pulling ", "fetching ")
FETCH_ENDED = ("image pulled", "database fetched", "database not fetched",
               "index fetched", "index not fetched")


def _ensure_data(runner, on_progress) -> tuple[list[dict], dict[str, str]]:
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
        return [], {}      # the suite's fakes; the rule `_ensure_image` applies too
    say = on_progress if on_progress is not None else (lambda _: None)
    fetched: list[dict] = []
    unfetched: dict[str, str] = {}

    if not _cache.db_present():
        db_size = runner.db_size_mb()
        say(f"fetching the vulnerability database{_mb(db_size)} — the first run only")
        started = time.monotonic()
        result = update()
        if result.exit_code != 0:
            detail = (result.stderr.strip() or result.stdout.strip() or "(no output)")[-300:]
            unfetched["trivy"] = f"the vulnerability database could not be fetched: {detail}"
            say(f"database not fetched: {detail}")
        else:
            seconds = time.monotonic() - started
            say(f"database fetched ({seconds:.0f}s)")
            fetched.append(_fetch_record(
                "vulnerability database",
                _egress.db_repository() or _egress.DEFAULT_DB_REPOSITORY, db_size, seconds))

    _stop_if_cancelled(runner, "during the first run's fetches")
    if not _cache.name_index_present():
        from . import locking, name_index

        index_size = name_index.published.published_size_mb()
        say(f"fetching the package-name index{_mb(index_size)} — the first run only")
        started = time.monotonic()
        try:
            with locking.held(locking.cache_lock(_cache.root()), exclusive=True, wait=True):
                # `oci.SignatureInvalid` is deliberately not caught: a refused
                # signature on a supply-chain artifact stops the scan (23.2.1).
                metadata = name_index.build.refresh(_cache.name_index(), fallback=False)
        except name_index.IndexUnavailable as exc:
            unfetched["dependency-reality"] = (
                f"the package-name index could not be fetched: {exc}")
            say(f"index not fetched: {exc}")
        else:
            seconds = time.monotonic() - started
            say(f"index fetched ({seconds:.0f}s)")
            fetched.append(_fetch_record(
                "package-name index", name_index.published.repository(), index_size, seconds,
                signature=_index_signature(metadata)))
    return fetched, unfetched


def _index_signature(metadata: object) -> str:
    """The verdict the pull recorded, from any ecosystem's entry — they are one
    artifact, verified once (23.2.1)."""
    ecosystems = metadata.get("ecosystems") if isinstance(metadata, dict) else None
    for entry in (ecosystems or {}).values():
        published = entry.get("published") if isinstance(entry, dict) else None
        if isinstance(published, dict) and published.get("signature"):
            return str(published["signature"])
    return "not recorded"


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


def _plan(adapters, runner) -> list[tuple]:
    """The fleet as tasks: `(work(runner, workspace) -> [outcome, …], [indices])`.

    Every Scanner is its own task. valvur's own Checks are one task when there are
    at least two of them (23.4.2): one container, one interpreter start, and still
    one outcome — one ScannerRun, one coverage contract, one line of provenance —
    per Check.
    """
    checks = [i for i, a in enumerate(adapters) if getattr(a, "kind", "") == "check"]
    # Two or more Checks batch. Until 26.2.1 this also asked whether the RUNNER
    # could — a capability the old split put on the container side; now any
    # runner runs any Invocation, and an image that cannot says so (BatchUnsupported).
    batched = len(checks) >= 2
    tasks: list[tuple] = []
    for index, adapter in enumerate(adapters):
        if batched and index in checks:
            if index == checks[0]:
                members = [adapters[i] for i in checks]
                tasks.append((lambda r, w, m=members: _run_checks(m, r, w), list(checks)))
            continue
        tasks.append((lambda r, w, a=adapter: [_run_one(a, r, w)], [index]))
    return tasks


def _run_checks(adapters, runner, workspace) -> list[ScannerOutcome]:
    """Several Checks, one container: each gets the outcome `_run_one` would have
    given it, timed as the batch — what it cost the fleet — and the container gets
    the widest grant any of them was given, which is dependency-reality's on
    `full` and nothing otherwise."""
    started = time.monotonic()
    wanted = []
    outcomes: dict[str, ScannerOutcome] = {}
    for adapter in adapters:
        should_run, why = adapter.applies_to(workspace)
        if should_run:
            wanted.append(adapter)
        else:
            outcomes[adapter.name] = ScannerOutcome(
                ScannerRun(adapter.name, ok=True, skipped=True, reason=why))
    outputs: dict = {}
    if wanted:
        from .adapters.check import BatchUnsupported, run_batch

        try:
            outputs = run_batch(
                runner, [a.name for a in wanted], workspace,
                network=any(getattr(a, "network", False) for a in wanted),
            )
        except BatchUnsupported:
            # An image from before the batch — pinned by VALVUR_IMAGE, or the
            # published one under a newer shim: the Checks run one by one, as they
            # did, and the F1.9 version check is not asked to know about this.
            return [_run_one(a, runner, workspace) for a in adapters]
        except Exception as exc:
            outputs = {a.name: None for a in wanted}
            failure = str(exc)
    for adapter in wanted:
        output = outputs.get(adapter.name)
        if output is None:
            outcomes[adapter.name] = ScannerOutcome(
                ScannerRun(adapter.name, ok=False, reason=failure))
        else:
            outcomes[adapter.name] = _outcome(adapter, output)
    elapsed = time.monotonic() - started
    return [outcomes[a.name].timed(elapsed) for a in adapters]


def _run_one(adapter, runner, workspace) -> ScannerOutcome:
    """Run one Scanner, timed. One broken Scanner must never cost the others (F2.5)."""
    started = time.monotonic()
    return _attempt(adapter, runner, workspace).timed(time.monotonic() - started)


def _attempt(adapter, runner, workspace) -> ScannerOutcome:
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
        return ScannerOutcome(ScannerRun(adapter.name, ok=True, skipped=True, reason=why))

    try:
        output = adapter.run(runner, workspace)
    except Exception as exc:
        return ScannerOutcome(ScannerRun(adapter.name, ok=False, reason=str(exc)))
    return _outcome(adapter, output)


def _outcome(adapter, output) -> ScannerOutcome:
    """A Scanner's output as the fleet records it: a failure with no report, or a
    ScannerRun with its Findings and any artifact."""
    if output.exit_code != 0 and not output.stdout.strip():
        return ScannerOutcome(
            ScannerRun(
                adapter.name,
                ok=False,
                version=output.version,
                reason=f"exited {output.exit_code} with no report: "
                f"{output.stderr.strip()[:200]}",
                argv=output.argv,
            ),
            raw=output.stdout,
        )

    # F2.5's third clause: a report the adapter cannot read — a container killed
    # mid-write, a format change, a stray line on stdout — is this Scanner's
    # failure, with the raw text kept for `raw/` so the reader can see what was
    # actually written. Until 26.0.1 this raised out of the fleet and took every
    # other Scanner's result with it; measured with Trivy's JSON cut at character 50.
    try:
        findings = adapter.parse(output)
    except Exception as exc:
        return ScannerOutcome(
            ScannerRun(
                adapter.name, ok=False, version=output.version,
                reason=f"report unreadable: {type(exc).__name__}: {str(exc)[:200]}",
                argv=output.argv,
            ),
            raw=output.stdout,
        )

    # An adapter may produce an artifact (an SBOM) instead of, or as well as, Findings.
    # Not on the protocol: see the note in adapters/base.py — a Protocol class
    # attribute's default is not inherited, only a method body is.
    artifact = getattr(adapter, "artifact", None)
    produced = (artifact, output.stdout) if artifact and output.stdout.strip() else None
    return ScannerOutcome(
        ScannerRun(adapter.name, ok=True, version=output.version, argv=output.argv),
        findings=findings, artifact=produced, raw=output.stdout,
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
        _stop_if_cancelled(runner, "before it began")
        fetched: list[dict] = []
        image = _ensure_image(runner, on_progress)
        if image is not None:
            fetched.append(image)
        _stop_if_cancelled(runner, "during the first run's fetches")
        data, unfetched = _ensure_data(runner, on_progress)
        fetched += data
        _locks.enter_context(_locking.held(
            _locking.cache_lock(_cache_mod.root()), exclusive=False, wait=True,
        ))
        return _scan_locked(
            workspace, runner=runner, adapters=adapters, profile=profile,
            on_progress=on_progress, unfetched=unfetched, fetched=fetched, jobs=jobs,
            budget_s=budget_s,
        )


def _jobs_from_environment() -> int | None:
    import os

    raw = os.environ.get(JOBS_ENV, "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


def _refuse_if_cancelled(runner, finished: int, total: int) -> None:
    if getattr(runner, "cancelled", False):
        raise ScanCancelled(f"cancelled: {finished} of {total} Scanner(s) had finished; "
                            "the rest were stopped and nothing was written")


def _stop_if_cancelled(runner, where: str) -> None:
    """The cancel checks before the fleet (26.0.2): a first run fetches the image,
    the database and the index — up to ~45s measured — and a cancel that lands
    during one was honoured only once all of them had finished. Now before each."""
    if getattr(runner, "cancelled", False):
        raise ScanCancelled(f"cancelled {where}: no Scanner had started and nothing "
                            "was written")


def _scan_locked(workspace, *, runner, adapters, profile, on_progress,
                 unfetched: dict[str, str] | None = None, fetched: list[dict] | None = None,
                 jobs: int | None = None, budget_s: float | None = None) -> ScanRun:
    """One Scan Run, under the Workspace lock: preflight, the fleet, then the
    assembly of the record — three functions since 28.4.2, one each."""
    shim_built_from, image_built_from = _preflight(runner, workspace)
    if adapters is None:
        adapters = _profiles.select(DEFAULT_ADAPTERS, profile)

    outcomes, cut = _fleet(adapters, runner, workspace, on_progress=on_progress, jobs=jobs,
                           budget_s=budget_s)
    return _assemble(
        outcomes, cut, adapters=adapters, runner=runner, workspace=workspace, profile=profile,
        unfetched=unfetched, fetched=fetched, budget_s=budget_s,
        shim_built_from=shim_built_from, image_built_from=image_built_from,
    )


def _preflight(runner, workspace) -> tuple[str | None, str | None]:
    """What has to be true before a container starts (F1.9, the mount, 23.4.4).
    Returns the tree the shim and the image were built from."""
    # Refuse a mismatched shim/image pair before doing any work (F1.9).
    verify = getattr(runner, "verify_compatible", None)
    if verify is not None:
        verify()

    # And confirm the container can actually see the source. An unreadable workspace
    # is indistinguishable from a clean one from inside a Scanner.
    readable = getattr(runner, "verify_workspace_readable", None)
    if readable is not None:
        readable(workspace)

    # The tree, not the version (23.4.4): recorded now, judged in the report.
    provenance = getattr(runner, "build_provenance", None)
    return provenance() if provenance is not None else (None, None)



def _fleet(adapters, runner, workspace, *, on_progress, jobs, budget_s):
    """Every Scanner, concurrently, under the budget (23.3.7): the outcomes in
    declaration order, and the names the budget cut."""
    # Scanners are independent and I/O-bound — each is a container invocation — so
    # they run concurrently. Serially, six Scanners will not meet the 5-minute
    # standard budget (F2.6, N1.2). Results are collected back into declaration
    # order so a Scan Run is reproducible regardless of which finished first.
    outcomes: list[ScannerOutcome | None] = [None] * len(adapters)
    _refuse_if_cancelled(runner, 0, len(adapters))

    # `--jobs` bounds the fleet (23.3.3); the default is everything at once.
    width = jobs if jobs is not None else (_jobs_from_environment() or len(adapters))
    fleet_started = time.monotonic()
    cut: list[str] = []
    # One task per Scanner — except valvur's own Checks, which share one container
    # (23.4.2) and so one task producing an outcome each. `futures` maps a task to
    # the adapter indices it answers for.
    tasks = _plan(adapters, runner)
    with ThreadPoolExecutor(max_workers=max(1, min(width, max(1, len(tasks))))) as pool:
        futures = {
            pool.submit(work, runner, workspace): indices
            for work, indices in tasks
        }

        def names(future) -> str:
            return ", ".join(adapters[i].name for i in futures[future])

        def collect(future) -> None:
            for index, outcome in zip(futures[future], future.result(), strict=True):
                outcomes[index] = outcome
                if on_progress is not None:
                    run = outcome.scanner
                    status = 'ok' if run.ok else 'failed'
                    on_progress(f"{run.tool}: {status} ({run.duration_s:.1f}s)")

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
                for index in futures[future]:
                    cut.append(adapters[index].name)
                    outcomes[index] = ScannerOutcome(ScannerRun(
                        adapters[index].name, ok=False,
                        reason=f"not started: the {budget_s:g}s budget was spent before "
                        "its turn",
                    ))
            stop = getattr(runner, "stop_containers", None)
            if on_progress is not None:
                on_progress(f"budget spent after {spent:.0f}s: stopping "
                            f"{', '.join(names(f) for f in running) or 'nothing'}"
                            f"; not starting {', '.join(cut) or 'nothing'}")
            if stop is not None and running:
                stop()
            # A stopped container comes back promptly with no report; a runner that
            # cannot stop one is waited for, and its result is real.
            wait(running)
            for future in running:
                collect(future)
                for index in futures[future]:
                    outcome = outcomes[index]
                    if outcome is not None and stop is not None and not outcome.scanner.ok:
                        cut.append(adapters[index].name)
                        outcomes[index] = outcome.cut(
                            f"cut by the {budget_s:g}s budget after {spent:.0f}s "
                            f"({outcome.scanner.reason})")

    return outcomes, cut


def _assemble(outcomes, cut, *, adapters, runner, workspace, profile, unfetched, fetched,
              budget_s, shim_built_from, image_built_from) -> ScanRun:
    """The record: the fleet's outcomes through the named pipeline into one
    ScanRun, written as one generation (26.0.3)."""
    completed = [o for o in outcomes if o is not None]
    # A cancel that landed during the fleet (F1.11): the Scanners it stopped came
    # back with no report, and the ones that finished are not a result either.
    _refuse_if_cancelled(runner, sum(1 for o in completed if o.scanner.ok), len(adapters))
    scanners = _say_why_unfetched([o.scanner for o in completed], unfetched or {})
    findings = [f for o in completed for f in o.findings]
    artifacts = [o.artifact for o in completed if o.artifact is not None]
    raw_outputs = [(o.scanner.tool, o.raw) for o in completed if o.raw]

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
    # One value out, with every field a stage recorded (27.3.4): the ScanRun below
    # is assembled from it rather than by reaching into the Context the stages
    # shared, which `StageFn`'s type could not describe.
    outcome = _pipeline.run(findings, ctx)
    findings = outcome.findings
    # And once more before anything is written: a kill that arrives between the
    # last Scanner and the write must not leave a Results Folder from a run the
    # developer said to stop.
    _refuse_if_cancelled(runner, len(scanners), len(adapters))
    if outcome.provider is None:
        # Cannot happen while `enrich` is in the pipeline; said out loud rather than
        # left to an AttributeError three lines down.
        raise RuntimeError("the enrich stage did not run")

    current = {f.fingerprint: f.title for f in findings}
    # Name what was fixed, using the title remembered from the previous run.
    fixed_now = [outcome.previous[fp] or fp for fp in outcome.previous if fp not in current]
    run = ScanRun(
        findings=findings,
        fixed=sorted(fixed_now),
        scanners=scanners,
        network_used=network,
        kev_age_days=outcome.provider.kev_age_days,
        identity_reset=outcome.identity_reset,
        fetched=list(fetched or []),
        db_age_days=_cache.db_age_days(),
        db_overdue_days=_cache.db_overdue_days(),
        name_index_age_days=_cache.name_index_age_days(),
        kev_source=outcome.provider.kev_source,
        vendored_dropped=outcome.vendored_dropped,
        config_dropped=outcome.config_dropped,
        unpinned_dropped=outcome.unpinned_dropped,
        unpinned_files=outcome.unpinned_files,
        excluded_paths=outcome.configured,
        honour_gitignore=outcome.honour_gitignore,
        gitignored_paths=outcome.gitignored,
        gitignore_note=outcome.gitignore_note,
        gitignore_dropped=outcome.gitignore_dropped,
        profile=profile,
        coverage=outcome.coverage,
        budget_s=budget_s,
        budget_cut=cut,
        shim_built_from=shim_built_from,
        image_built_from=image_built_from,
    )

    still_fixed = {fp for fp in outcome.previously_fixed if fp not in current}
    still_fixed |= {fp for fp in outcome.previous if fp not in current}
    results.write(
        workspace, run, scanner_artifacts=artifacts, raw_outputs=raw_outputs,
        state=_state.render(current, still_fixed, generation=run.generation),
    )
    return run
