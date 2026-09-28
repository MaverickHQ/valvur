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
from .text import cut as _cut


class ScannerFailed(RuntimeError):
    #: Whether `doctor` could name the cause (29.0.3). True for every failure
    #: but the budget's: on a machine whose preconditions all hold, the one
    #: sentence `scan_status` used to add sent the agent to a tool that said
    #: *ready* (the first gate, B1).
    doctor_may_help = True

    """A Scanner could not complete. Never downgraded to a clean result (F2.5)."""


class BudgetExhausted(ScannerFailed):
    """The budget cut every Scanner before one finished (29.0.3): its message is
    `levers.budget_exhausted_message`, and `doctor` has nothing to add. Carries
    the same refusal as fields (`levers.budget_fields`, 29.2.4) for the
    structured reply; None when built from a message alone."""

    doctor_may_help = False

    def __init__(self, message: str, fields: dict | None = None):
        super().__init__(message)
        self.fields = fields


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
    #: What git history was read for secrets (R3.7): commits, bytes and the bound
    #: that stopped the read, or None when none was read.
    history: dict | None = None
    fixed: list[str] = field(default_factory=list)
    #: Previous Findings whose Scanner did not run this time — cut, timed out or
    #: failed — as (title, the Scanners that did not run), so neither fixed nor
    #: persisting (29.0.5). Carried in the state for the next run to decide.
    not_rechecked: list[tuple[str, str]] = field(default_factory=list)
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
    config_dropped: int = 0
    #: OSV-Scanner answers against the lower bounds of unpinned ranges, dropped
    #: (25.3), and the requirements files they came from.
    unpinned_dropped: int = 0
    unpinned_files: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()
    #: The pre-flight count (29.1.2): files the Scanners were told to read, and
    #: the three largest top-level directories by that count.
    workspace_files: int = 0
    largest_dirs: tuple[tuple[str, int], ...] = ()
    #: What the File Set left out, and why (ADR-0021): a dependency cache, a
    #: directory git ignores, a submodule, a link leaving the repository, an
    #: exclusion. What no Scanner read, named on every surface (R1.4, R3.9).
    not_read: tuple[tuple[str, str], ...] = ()
    #: The File Set's manifest: scope, files, bytes and the list's sha256.
    scope: dict | None = None
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
               "index fetched", "index not fetched", "OSV database fetched",
               "OSV database not fetched")


def _ensure_data(runner, on_progress, *, workspace=None,
                 adapters=()) -> tuple[list[dict], dict[str, str]]:
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
    if workspace is not None and any(getattr(a, "offline", False) for a in adapters
                                     if getattr(a, "name", "") == "osv-scanner"):
        _stop_if_cancelled(runner, "during the first run's fetches")
        _ensure_osv(workspace, say, fetched, unfetched)
    return fetched, unfetched


def _ensure_osv(workspace, say, fetched: list[dict], unfetched: dict[str, str]) -> None:
    """OSV's offline database for each ecosystem the File Set holds a lockfile for,
    when absent (R4.6, 24.1): announced, recorded, and a failure costs OSV-Scanner
    alone, with the reason."""
    from . import fileset, locking, osv_offline
    from .refusal import Refusal

    try:
        files = fileset.build(workspace).files
    except Refusal:
        return                       # the scan refuses the walk itself, with the reason
    missing = osv_offline.absent(osv_offline.needed(files))
    failed = []
    for name in missing:
        say(f"fetching the OSV database for {name} — the first run for it only")
        try:
            with locking.held(locking.cache_lock(_cache.root()), exclusive=True, wait=True):
                record = osv_offline.fetch(name)
        except OSError as exc:
            failed.append(f"{name}: {exc}")
            say(f"OSV database not fetched for {name}: {exc}")
            continue
        say(f"OSV database fetched for {name} ({record['seconds']:.0f}s)")
        fetched.append(record)
    if failed:
        unfetched["osv-scanner"] = ("the OSV offline database could not be fetched: "
                                    + "; ".join(failed))


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


def _outcome(adapter, output) -> ScannerOutcome:
    """A Scanner's output as the fleet records it: a failure with no report, or a
    ScannerRun with its Findings and any artifact."""
    if output.stopped_after is not None:
        # The timeout fired and the runner stopped the container (29.0.2). The
        # cause and the seconds, then what it had said — the argv stays in
        # `run.json`, not in the sentence a reader gets (the gate's B6).
        tail = output.stderr.strip()
        reason = f"timed out after {output.stopped_after:g}s and was stopped"
        if tail:
            reason += f" — last stderr: {_cut(tail, 200)}"
        return ScannerOutcome(
            ScannerRun(adapter.name, ok=False, version=output.version, reason=reason,
                       argv=output.argv),
            raw=output.stdout,
        )
    if output.exit_code != 0 and not output.stdout.strip():
        tail = _cut(output.stderr.strip(), 200)
        if output.exit_code == 137:
            # SIGKILL, and valvur did not send it — the budget's and the timeout's
            # kills are rewritten above and in the engine. What is left is the
            # runtime: the Scan Container's ceiling (D4, R3.9) or the VM's (29.0.3).
            from . import runner as _runner

            reason = ("exit 137: killed by the runtime — the Scan Container's memory "
                      f"ceiling ({_runner.SCAN_CEILING_BYTES // 2**30} GiB, or three "
                      "quarters of the runtime's memory) or the VM's")
            if tail:
                reason += f" — last stderr: {tail}"
        else:
            reason = f"exited {output.exit_code} with no report: {tail}"
        return ScannerOutcome(
            ScannerRun(adapter.name, ok=False, version=output.version, reason=reason,
                       argv=output.argv),
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
        generation = _begin(runner, on_progress)
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
        if adapters is None:
            adapters = _profiles.select(DEFAULT_ADAPTERS, profile)
        data, unfetched = _ensure_data(runner, on_progress, workspace=workspace,
                                       adapters=adapters)
        fetched += data
        _locks.enter_context(_locking.held(
            _locking.cache_lock(_cache_mod.root()), exclusive=False, wait=True,
        ))
        return _scan_locked(
            workspace, runner=runner, adapters=adapters, profile=profile,
            on_progress=on_progress, unfetched=unfetched, fetched=fetched, jobs=jobs,
            budget_s=budget_s, generation=generation,
        )


def _begin(runner, on_progress) -> str:
    """The Scan Run's generation, handed to the runner so every container it starts
    carries it (R3.6); and first, the containers an ended process left, removed.
    The second gate's next scan met the fleet a killed server had left running."""
    import uuid

    from . import owner

    generation = str(uuid.uuid4())
    with contextlib.suppress(AttributeError):
        runner.generation = generation
    runtime = getattr(runner, "runtime", None)
    if isinstance(runtime, str):
        reaped = owner.reap(runtime)
        if reaped and on_progress is not None:
            on_progress(f"removed {len(reaped)} container(s) left by a scan whose process "
                        f"had ended: {', '.join(reaped)}")
    return generation


def _jobs_from_environment() -> int | None:
    import os

    raw = os.environ.get(JOBS_ENV, "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


def _refuse_if_cancelled(runner, finished: int, total: int) -> None:
    if getattr(runner, "cancelled", False):
        # CANCELLED is the job's word once this raises, so it must be true when
        # said (R1.1): `docker kill` returns before `--rm` removes the container,
        # and the second gate saw CANCELLED with a container still up.
        wait_stopped = getattr(runner, "wait_stopped", None)
        if wait_stopped is not None:
            wait_stopped()
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
                 jobs: int | None = None, budget_s: float | None = None,
                 generation: str | None = None) -> ScanRun:
    """One Scan Run, under the Workspace lock: preflight, the fleet, then the
    assembly of the record — three functions since 28.4.2, one each."""
    shim_built_from, image_built_from = _preflight(runner, workspace)
    if adapters is None:
        adapters = _profiles.select(DEFAULT_ADAPTERS, profile)

    # The count (29.1.2), before a container starts: what the Scanners will read,
    # the largest directories, and — past the threshold — the one line that
    # would drop the largest, said before the budget is spent rather than after.
    from . import fileset as _fileset
    from . import levers as _levers

    # The File Set (ADR-0021), once: what the Snapshot holds, what every host-side
    # count reads, and what the record says was and was not read.
    chosen = _fileset.build(workspace)
    files, largest = len(chosen.files), _fileset.largest(chosen.files)
    if on_progress is not None:
        on_progress(_levers.workspace_line(files, largest))
        warning = chosen.warning or _levers.large_tree_line(files, largest)
        if warning is not None:
            on_progress(warning)

    beside: dict = {}
    if not _engine_two(runner):
        # The Scan Container is the only engine since R3.9 (ADR-0022).
        raise TypeError(f"{type(runner).__name__} does not run the Scan Container's engine")
    outcomes, cut = _engine_fleet(adapters, runner, workspace, on_progress=on_progress,
                                  budget_s=budget_s, record=beside,
                                  jobs=jobs or _jobs_from_environment(), chosen=chosen)
    return _assemble(
        outcomes, cut, adapters=adapters, runner=runner, workspace=workspace, profile=profile,
        unfetched=unfetched, fetched=fetched, budget_s=budget_s,
        shim_built_from=shim_built_from, image_built_from=image_built_from,
        workspace_files=files, largest_dirs=largest, not_read=tuple(chosen.skipped),
        scope=chosen.manifest(workspace),
        generation=generation, history=beside.get("history"),
    )


def _engine_two(runner) -> bool:
    """A runtime that runs the Scan Container's engine (ADR-0022) says so."""
    return getattr(runner, "engine", False) is True and hasattr(runner, "run")


def _engine_fleet(adapters, runtime, workspace, *, on_progress, budget_s=None,
                  record: dict | None = None, jobs: int | None = None, chosen=None):
    """Every Scanner in one Scan Container, fed a Snapshot of the File Set
    (ADR-0022): the outcomes in declaration order, and what the budget cut.
    `record` receives what was read beside the File Set: `history` (R3.7)."""
    import json
    import tempfile

    from . import engine_host, fileset
    from .invocation import ScannerOutput, nothing_to_scan

    outcomes: list[ScannerOutcome | None] = [None] * len(adapters)
    cut: list[str] = []
    plan, planned = [], []
    for index, adapter in enumerate(adapters):
        should_run, why = adapter.applies_to(workspace)
        if not should_run:
            outcomes[index] = ScannerOutcome(
                ScannerRun(adapter.name, ok=True, skipped=True, reason=why))
            continue
        try:
            plan.append(adapter.command(workspace))
        except Exception as exc:
            # A Scanner that cannot be asked — Trivy with no database, the name
            # Check with no index — fails alone, with its reason (F2.5).
            outcomes[index] = ScannerOutcome(ScannerRun(
                adapter.name, ok=False, version=getattr(adapter, "version", ""),
                reason=str(exc).strip()))
            continue
        planned.append(index)
    with tempfile.TemporaryDirectory(prefix="valvur-") as scratch_dir:
        scratch = Path(scratch_dir) / "results"
        scratch.mkdir()
        chosen = chosen if chosen is not None else fileset.build(workspace)
        tar = engine_host.snapshot(workspace, chosen.files)
        written, read = _history_pass(adapters, plan, planned, workspace, chosen, scratch,
                                      on_progress)
        if record is not None and read is not None:
            record["history"] = read
        _stop_if_cancelled(runtime, "before the Scan Container started")
        ended: list[str] = []
        say = on_progress if on_progress is not None else (lambda _: None)
        named = {i.tool: adapters[index].name for i, index in zip(plan, planned, strict=True)
                 if i.tool != _HISTORY_TOOL}
        fleet = len(set(planned))
        # The words the fleet used, which `scan_status` reads (29.0.4).
        say(f"fleet: {fleet} Scanners, {min(jobs or fleet, fleet)} at a time")

        def on_event(event: dict) -> None:
            name = named.get(event.get("tool", ""))
            if event.get("event") == "start" and name:
                say(f"{name}: started")
            elif event.get("event") == "end":
                ok = event.get("exit_code") == 0 and not event.get("timed_out")
                if ok:
                    ended.append(event.get("tool", ""))       # finished, for a cancel's count
                if name:
                    say(f"{name}: {'ok' if ok else 'failed'} "
                        f"({float(event.get('seconds', 0)):.1f}s)")

        # One Scan Container per network boundary (ADR-0022, R3.8): what needs a
        # network runs in its own, and everything else, Trivy included, in one
        # with no interface at all. `offline` has only the second.
        scratches = {False: scratch}
        if any(i.network for i in plan):
            scratches[True] = Path(scratch_dir) / "results-networked"
            scratches[True].mkdir()
        started = time.monotonic()
        _run_by_network(runtime, plan, tar, scratches, on_event, budget_s, jobs)
        spent = time.monotonic() - started
        # A cancel (F1.11, R3.5): CANCELLED once the runtime confirms the engine
        # is gone, and nothing written.
        _refuse_if_cancelled(runtime, len(ended), len(plan))
        entries: dict[tuple[bool, str], dict] = {}
        for network, where in scratches.items():
            manifest_path = where / "manifest.json"
            manifest = (json.loads(manifest_path.read_text()) if manifest_path.exists()
                        else {})
            received = manifest.get("received")
            if received is not None and received != len(chosen.files):
                # A Scanner reading part of the File Set would report a partial scan
                # as a whole one (ADR-0022): refused, with the numbers.
                raise ScannerFailed(
                    f"The Scan Container received {received} of {len(chosen.files)} "
                    "files; refusing to report a scan of a partial Snapshot.")
            entries.update({(network, e["tool"]): e for e in manifest.get("tools", [])})
        for invocation, index in zip(plan, planned, strict=True):
            entry = entries.get((invocation.network, invocation.tool))
            if entry is None:
                outcomes[index] = ScannerOutcome(ScannerRun(
                    adapters[index].name, ok=False, reason="the engine did not run it"))
                continue
            if entry.get("not_started"):
                # The budget was spent before `--jobs` reached it.
                cut.append(adapters[index].name)
                outcomes[index] = ScannerOutcome(ScannerRun(
                    adapters[index].name, ok=False,
                    reason=f"not started: the {budget_s:g}s budget was spent before its turn"))
                continue
            where = scratches[invocation.network]
            report = (where / invocation.report if invocation.report
                      else where / f"{invocation.tool}.stdout")
            stdout = report.read_text(encoding="utf-8") if report.exists() else ""
            code, stderr = entry["exit_code"], entry.get("stderr_tail", "")
            if invocation.report and not report.exists() and not entry.get("timed_out"):
                if nothing_to_scan(stderr, invocation.empty_when):
                    # Nothing to analyse: an empty result, honestly earned.
                    code, stderr = 0, ""
                else:
                    # Asked for a report and wrote none: it could not write, which
                    # is not the same as finding nothing (the fleet's rule, kept).
                    stderr = (f"{invocation.tool} produced no report at "
                              f"{invocation.report}. stderr: {stderr.strip()[:300]}")
                    code = code or 99
            output = ScannerOutput(
                invocation.tool, invocation.version, stdout, stderr, code,
                argv=invocation.argv,
                stopped_after=float(invocation.timeout) if entry.get("timed_out") else None)
            if written is not None and invocation.tool == _HISTORY_TOOL:
                outcomes[index] = _with_history(outcomes[index], adapters[index], output,
                                                entry, written, workspace, budget_s, spent)
                if entry.get("cut") and adapters[index].name not in cut:
                    cut.append(adapters[index].name)
                continue
            outcome = _outcome(adapters[index], output).timed(entry["seconds"])
            if entry.get("cut"):
                # The budget stopped it (R3.5): the cut is the cause, in the words
                # every surface already uses for one (29.0.3).
                cut.append(adapters[index].name)
                outcome = outcome.cut(f"cut by the {budget_s:g}s budget after {spent:.0f}s")
            outcomes[index] = outcome
        if cut and on_progress is not None:
            stopping = [n for n in cut if not any(
                o is not None and o.scanner.tool == n and o.scanner.reason.startswith(
                    "not started") for o in outcomes)]
            waiting = [n for n in cut if n not in stopping]
            on_progress(f"budget spent after {spent:.0f}s: stopping "
                        f"{', '.join(stopping) or 'nothing'}"
                        f"; not starting {', '.join(waiting) or 'nothing'}")
    return outcomes, cut


def _run_by_network(runtime, plan, tar, scratches, on_event, budget_s, jobs=None) -> None:
    """Each network boundary's part of the plan in its own Scan Container, at once
    when there are two: one budget, one cancel, both stopped by either."""
    import threading

    parts = [(network, [i for i in plan if i.network is network]) for network in scratches]
    parts = [(network, part) for network, part in parts if part]
    if len(parts) == 1:
        network, part = parts[0]
        runtime.run(part, tar, scratches[network], on_event=on_event, budget_s=budget_s,
                    jobs=jobs)
        return
    failed: list[BaseException] = []

    def run(network: bool, part: list) -> None:
        try:
            runtime.run(part, tar, scratches[network], on_event=on_event, budget_s=budget_s,
                        jobs=jobs)
        except BaseException as exc:          # raised again below, on the scan's thread
            failed.append(exc)

    threads = [threading.Thread(target=run, args=part, name=f"valvur-engine-{part[0]}")
               for part in parts]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if failed:
        raise failed[0]


_HISTORY_TOOL = "gitleaks-history"


def _history_pass(adapters, plan, planned, workspace, chosen, scratch, on_progress):
    """Git history, for Gitleaks (R3.7, D3): written into the scratch directory
    when Gitleaks runs on a repository and the project has not said
    `history = false`, and its pass added to the plan. Returns what was written
    and what the record says: what was read, or why nothing was."""
    from . import exclusions as _exclusions
    from . import history as _history
    from .adapters.gitleaks import HISTORY_FILE, PROJECT_GITLEAKS_CONFIG

    say = on_progress if on_progress is not None else (lambda _: None)
    index = next((i for i in planned if adapters[i].name == "gitleaks"), None)
    if index is None or chosen.scope != "git":
        return None, None
    if not _exclusions.load_scan_settings(workspace).history:
        say("history: not read ([scan] history = false)")
        return None, {"off": "[scan] history = false"}
    written = _history.write(workspace, scratch / HISTORY_FILE)
    if written is None:
        return None, None
    plan.append(adapters[index].history_command(
        project_config=PROJECT_GITLEAKS_CONFIG in chosen.files))
    planned.append(index)
    bound = f", stopped at {written.bounded}" if written.bounded else ""
    say(f"history: {written.commits} commits read for secrets "
        f"({written.bytes / 2**20:.1f} MB{bound})")
    return written, {"commits": written.commits, "bytes": written.bytes,
                     "bounded": written.bounded}


def _with_history(outcome, adapter, output, entry, written, workspace, budget_s, spent):
    """Gitleaks's outcome with its history pass folded in: the hits after the
    tree's, so a secret still in the tree keeps its line; a pass that did not
    finish makes Gitleaks's run incomplete, with the reason."""
    from . import exclusions as _exclusions

    if outcome is None:
        return outcome
    if entry.get("cut") or entry.get("timed_out") or entry["exit_code"] != 0:
        why = (f"cut by the {budget_s:g}s budget after {spent:.0f}s" if entry.get("cut")
               else f"timed out after {output.stopped_after:g}s" if entry.get("timed_out")
               else f"exit {entry['exit_code']}: {output.stderr.strip()[-200:]}")
        return dataclasses.replace(outcome, scanner=dataclasses.replace(
            outcome.scanner, ok=False, reason=f"its git history pass did not finish: {why}"))
    try:
        found = adapter.parse_history(output, written, workspace,
                                      _exclusions.excluded_prefixes(workspace))
    except (ValueError, KeyError) as exc:
        return dataclasses.replace(outcome, scanner=dataclasses.replace(
            outcome.scanner, ok=False,
            reason=f"its git history report was unreadable: {exc}"))
    return dataclasses.replace(outcome, findings=[*outcome.findings, *found])


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



def _budget_shaped(reason: str) -> bool:
    return reason.startswith(("cut by the ", "not started: the "))


def _assemble(outcomes, cut, *, adapters, runner, workspace, profile, unfetched, fetched,
              budget_s, shim_built_from, image_built_from,
              workspace_files: int = 0, largest_dirs=(), not_read=(), scope=None,
              generation: str | None = None, history: dict | None = None) -> ScanRun:
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
        if budget_s is not None and all(_budget_shaped(s.reason) for s in scanners):
            # Not "every scanner failed" — the budget ran out, which is what
            # killing them looks like from inside (29.0.3). The message names
            # what ran, what did not start, and the three levers.
            from . import levers

            raise BudgetExhausted(
                levers.budget_exhausted_message(
                    scanners, budget_s, files=workspace_files, largest=largest_dirs),
                levers.budget_fields(
                    scanners, budget_s, files=workspace_files, largest=largest_dirs))
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
    # A previous Finding absent now is fixed only if the Scanner that reported it
    # ran this time (29.0.5). Cut, timed out or failed, it could not have looked,
    # and the Finding is *not re-checked*: carried, counted, neither fixed nor
    # persisting. Measured before this: a 30 s budget cut seven Scanners and the
    # run said `fixed: 8`, then the next complete run would have said regressed.
    # A skipped Scanner had nothing to analyse, which is an answer: its old
    # Finding's file is gone, and gone is fixed.
    did_not_run = {r.tool for r in scanners if not r.ok and not r.skipped} | set(cut)
    previous_sources = _state.load_sources(workspace / _results.RESULTS_DIR)

    def not_run_for(fp: str) -> str | None:
        """The Scanners that would have re-checked `fp` and did not run, joined;
        "" when the state does not say which and something did not run; None
        when it was looked for."""
        sources = set(previous_sources.get(fp, ()))
        if not sources:
            return "" if did_not_run else None
        missing = sources & did_not_run
        return ", ".join(sorted(missing)) if missing else None

    gone = [fp for fp in outcome.previous if fp not in current]
    # Name what was fixed, using the title remembered from the previous run.
    fixed_now = [outcome.previous[fp] or fp for fp in gone if not_run_for(fp) is None]
    carried = {fp: outcome.previous[fp] for fp in gone if not_run_for(fp) is not None}
    run = ScanRun(
        **({"generation": generation} if generation else {}),
        history=history,
        findings=findings,
        fixed=sorted(fixed_now),
        not_rechecked=sorted((title or fp, not_run_for(fp) or "") for fp, title in carried.items()),
        scanners=scanners,
        network_used=network,
        kev_age_days=outcome.provider.kev_age_days,
        identity_reset=outcome.identity_reset,
        fetched=list(fetched or []),
        db_age_days=_cache.db_age_days(),
        db_overdue_days=_cache.db_overdue_days(),
        name_index_age_days=_cache.name_index_age_days(),
        kev_source=outcome.provider.kev_source,
        config_dropped=outcome.config_dropped,
        unpinned_dropped=outcome.unpinned_dropped,
        unpinned_files=outcome.unpinned_files,
        excluded_paths=outcome.configured,
        profile=profile,
        coverage=outcome.coverage,
        budget_s=budget_s,
        budget_cut=cut,
        shim_built_from=shim_built_from,
        workspace_files=workspace_files,
        largest_dirs=tuple(largest_dirs),
        not_read=tuple(not_read),
        scope=scope,
        image_built_from=image_built_from,
    )

    still_fixed = {fp for fp in outcome.previously_fixed if fp not in current}
    still_fixed |= {fp for fp in gone if fp not in carried}
    # A carried Finding stays present, with the sources it had, so the next run
    # that looks for it says persisting or fixed rather than new or regressed.
    present_next = {**current, **carried}
    sources_next = {f.fingerprint: f.sources for f in findings}
    sources_next.update({fp: previous_sources.get(fp, ()) for fp in carried})
    results.write(
        workspace, run, scanner_artifacts=artifacts, raw_outputs=raw_outputs,
        state=_state.render(present_next, still_fixed, sources=sources_next,
                            generation=run.generation),
    )
    return run
