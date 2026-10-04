"""A Scan Run's record, and the ways a scan ends without one.

`ScanRun` is what one scan found and did: the Findings, the Scanners and what each
did, the data's ages, what was fetched and what was not read. Its verdict is
`status`, with `status_reason` saying why in one line (F7.16). It moved out of
`api`, the orchestrator, so the modules that render it (`summary`, `provenance`,
`results`) and the one that writes it import a record, not the scan (R23.9).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from . import datasets as _datasets
from . import settings as _settings
from . import staleness as _staleness
from . import verdict
from .findings import Finding
from .scanner_run import ScannerRun


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
    #: Where the Scanners ran (R8.1): the Scan Container, or a job's own container
    #: and whether it had a network.
    boundary: str = "the Scan Container"
    kev_age_days: float | None = None
    kev_source: str = ""
    #: The KEV catalog's release day, `YYYY-MM-DD`; empty when it does not say (D23).
    kev_catalog: str = ""
    #: The EPSS scores' day and age (D25): from their `score_date`, or empty and None
    #: when the host cache holds none, and findings ranked without EPSS.
    epss_scored: str = ""
    epss_age_days: float | None = None
    #: Every dataset's age and its basis (R11.6, `staleness.data_ages`): what
    #: `run.json`'s `data`, `SUMMARY.md`'s `Data:` line and the MCP reply say.
    data_ages: dict = field(default_factory=dict)
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
    #: What the class table removed (D56): {class: {rule: count}}, said in run.json.
    removed_by_class: dict[str, dict[str, int]] = field(default_factory=dict)
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
    #: Repository hygiene (D13, R5.5): facts, never Findings, never the Status.
    hygiene: dict | None = None
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
        return [f for f in self.findings if verdict.active(f)]

    @property
    def suppressed(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    @property
    def coverage_notes(self) -> list[Finding]:
        """What valvur did not inspect or could not read, as opposed to what it did
        not find. Two kinds: the gaps, which make a nil result `inconclusive`, and
        the licence statements, which do not (`coverage.DOUBT_RULES`, 23.5.5)."""
        return [f for f in self.findings if verdict.note(f) and not f.suppressed]

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
        # A Scanner that failed, timed out or was cut did not look (F7.19, D30):
        # nothing found beside it is not evidence. Until R10 such a run read
        # `clean` beside `complete: false`, and the verdict an agent switches on
        # said the code was clean where part of it was never read.
        for failure in self.failures:
            reasons.append(f"{failure.tool} did not complete ({failure.reason or 'failed'})")
        # The predicates are `staleness.py`'s, the same ones `run.json`'s `stale`
        # flags use — this method carried its own copy of each comparison until
        # 28.1.1, and two copies of a predicate agree only until one is edited.
        if _staleness.db_is_stale(self):
            reasons.append(
                f"the vulnerability database is {self.db_age_days:.0f} days old "
                f"(threshold {_datasets.DATABASE.inconclusive_after_days:g})"
            )
        # The same rule for the name index (ADR-0018): "no hallucinated packages"
        # from a month-old list of names is not a claim about today's registry.
        if _staleness.index_is_stale(self):
            reasons.append(
                f"the package-name index is {self.name_index_age_days:.0f} days old "
                f"(threshold {_datasets.NAME_INDEX.inconclusive_after_days:g})"
            )
        if reasons and _settings.fetch() == _settings.NEVER:
            # Why it was not refreshed (ADR-0025): the machine said never.
            reasons.append("fetching is off (fetch = never), so it was not refreshed")
        gaps = [n for n in self.coverage_notes if n.rule in verdict.DOUBT_RULES]
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
