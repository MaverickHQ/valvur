"""The fleet: every Scanner in one Scan Container, fed a Snapshot (ADR-0022), and
what the engine left read back into each Scanner's outcome. Moved out of `api`, the
orchestrator, with the reuse of results whose inputs are unchanged (ADR-0030), the
history pass (R3.7) and the cancel checks (F1.11), so each step is one function a
reader can hold (R23.9).
"""

from __future__ import annotations

import dataclasses
import json
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import engine_host
from . import events as _events
from . import history as _history
from . import reuse as _reuse
from . import runner as _runner
from . import scancontext as _scancontext
from .adapters.gitleaks import HISTORY_DIR, HISTORY_TOOL, PROJECT_GITLEAKS_CONFIG
from .invocation import Invocation, ScannerOutput, nothing_to_scan
from .scanner_run import BUDGET_CUT, BUDGET_NOT_STARTED, ScannerRun
from .scanrun import ScanCancelled, ScannerFailed
from .text import cut as _cut

if TYPE_CHECKING:
    from .engine_host import Runtime
    from .scancontext import ScanContext


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
        """The same outcome, marked cut and its reason rewritten — what the budget
        does to a Scanner it stopped (23.3.7)."""
        return dataclasses.replace(self, scanner=dataclasses.replace(
            self.scanner, reason=reason, budget=BUDGET_CUT))


def outcome(adapter, output) -> ScannerOutcome:
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
    artifact = adapter.artifact
    produced = (artifact, output.stdout) if artifact and output.stdout.strip() else None
    return ScannerOutcome(
        ScannerRun(adapter.name, ok=True, version=output.version, argv=output.argv),
        findings=findings, artifact=produced, raw=output.stdout,
    )


def refuse_if_cancelled(runner: Runtime, finished: int, total: int) -> None:
    if runner.cancelled:
        # CANCELLED is the job's word once this raises, so it must be true when
        # said (R1.1): `docker kill` returns before `--rm` removes the container,
        # and the second gate saw CANCELLED with a container still up.
        runner.wait_stopped()
        raise ScanCancelled(f"cancelled: {finished} of {total} Scanner(s) had finished; "
                            "the rest were stopped and nothing was written")


def stop_if_cancelled(runner: Runtime, where: str) -> None:
    """The cancel checks before the fleet (26.0.2): a first run fetches the image,
    the database and the index — up to ~45s measured — and a cancel that lands
    during one was honoured only once all of them had finished. Now before each."""
    if runner.cancelled:
        raise ScanCancelled(f"cancelled {where}: no Scanner had started and nothing "
                            "was written")


def engine_fleet(adapters, runtime: Runtime, workspace, *, on_progress, budget_s=None,
                 record: dict | None = None, jobs: int | None = None,
                 context: ScanContext | None = None,
                 reuse: tuple[str, str] | None = None, fresh: bool = False):
    """Every Scanner in one Scan Container, fed a Snapshot of the File Set
    (ADR-0022): the outcomes in declaration order, and what the budget cut.
    `record` receives what was read beside the File Set: `history` (R3.7).
    `reuse`, (Profile, this run's generation), lets a dependency Scanner whose
    inputs and data are unchanged answer from its last clean result (R14.3, D32);
    with `fresh`, none answers so, and each clean result is stored as ever."""
    context = context if context is not None else _scancontext.build(workspace)
    outcomes, plan, planned = _plan(adapters, workspace, context)
    keys = _reused(adapters, plan, planned, outcomes, workspace, context.file_set, reuse,
                   on_progress, fresh=fresh)
    say = on_progress if on_progress is not None else (lambda _: None)
    with tempfile.TemporaryDirectory(prefix="valvur-") as scratch_dir:
        scratch = Path(scratch_dir) / "results"
        scratch.mkdir()
        tar = engine_host.snapshot(workspace, context.files)
        written, read = _history_pass(adapters, plan, planned, workspace, context, scratch,
                                      on_progress)
        if record is not None and read is not None:
            record["history"] = read
        stop_if_cancelled(runtime, "before the Scan Container started")
        named = {i.tool: adapters[index].name for i, index in zip(plan, planned, strict=True)
                 if i.tool != HISTORY_TOOL}
        fleet = len(set(planned))
        # The words the fleet used, which `scan_status` reads (29.0.4).
        say(_events.fleet(fleet, min(jobs or fleet, fleet)))
        ended: list[str] = []
        # One Scan Container per network boundary (ADR-0022, R3.8): what needs a
        # network runs in its own, and everything else, Trivy included, in one
        # with no interface at all. `offline` has only the second.
        scratches = {False: scratch}
        if any(i.network for i in plan):
            scratches[True] = Path(scratch_dir) / "results-networked"
            scratches[True].mkdir()
        started = time.monotonic()
        _run_by_network(runtime, plan, tar, scratches, _on_event(named, ended, say),
                        budget_s, jobs)
        spent = time.monotonic() - started
        # A cancel (F1.11, R3.5): CANCELLED once the runtime confirms the engine
        # is gone, and nothing written.
        refuse_if_cancelled(runtime, len(ended), len(plan))
        entries = _manifests(scratches, len(context.files))
        ran = _Ran(adapters, outcomes, entries, scratches, budget_s, spent, written,
                   workspace, context, keys, reuse)
        cut = ran.collect(plan, planned)
        if cut and on_progress is not None:
            stopping = [n for n in cut if not any(
                o is not None and o.scanner.tool == n
                and o.scanner.budget == BUDGET_NOT_STARTED for o in outcomes)]
            waiting = [n for n in cut if n not in stopping]
            on_progress(_events.budget(spent, stopping, waiting))
    return outcomes, cut


def _plan(adapters, workspace, context: ScanContext):
    """Each adapter asked whether it has anything to read and how it is invoked:
    the outcomes already decided (skipped, or refused before launch), the plan, and
    each planned Invocation's adapter, by index."""
    outcomes: list[ScannerOutcome | None] = [None] * len(adapters)
    plan: list[Invocation] = []
    planned: list[int] = []
    for index, adapter in enumerate(adapters):
        should_run, why = adapter.applies_to(workspace, context)
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
                adapter.name, ok=False, version=adapter.version,
                reason=str(exc).strip()))
            continue
        planned.append(index)
    return outcomes, plan, planned


def _on_event(named: dict[str, str], ended: list[str], say):
    """The engine's events (R3.4), as the scan's typed events, by Scanner name;
    `ended` collects what finished, for a cancel's count."""

    def on_event(event: dict) -> None:
        name = named.get(event.get("tool", ""))
        if event.get("event") == "start" and name:
            say(_events.scanner_started(name))
        elif event.get("event") == "end":
            ok = event.get("exit_code") == 0 and not event.get("timed_out")
            if ok:
                ended.append(event.get("tool", ""))
            if name:
                say(_events.scanner_ended(name, ok=ok, seconds=float(event.get("seconds", 0))))

    return on_event


def _manifests(scratches: dict[bool, Path], files: int) -> dict[tuple[bool, str], dict]:
    """Each Scan Container's manifest entries, by (network, tool). A Scanner reading
    part of the File Set would report a partial scan as a whole one (ADR-0022): a
    Snapshot that arrived short is refused, with the numbers."""
    entries: dict[tuple[bool, str], dict] = {}
    for network, where in scratches.items():
        manifest_path = where / "manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
        received = manifest.get("received")
        if received is not None and received != files:
            raise ScannerFailed(
                f"The Scan Container received {received} of {files} "
                "files; refusing to report a scan of a partial Snapshot.")
        entries.update({(network, e["tool"]): e for e in manifest.get("tools", [])})
    return entries


@dataclass
class _Ran:
    """What the engine left, read back into each Scanner's outcome."""

    adapters: Any
    outcomes: list[ScannerOutcome | None]
    entries: dict[tuple[bool, str], dict]
    scratches: dict[bool, Path]
    budget_s: float | None
    spent: float
    written: Any
    workspace: Path
    context: ScanContext
    keys: dict[int, tuple[str, str]]
    reuse: tuple[str, str] | None

    def collect(self, plan: list[Invocation], planned: list[int]) -> list[str]:
        """Every planned Scanner's outcome, in place; what the budget cut."""
        cut: list[str] = []
        for invocation, index in zip(plan, planned, strict=True):
            name = self.adapters[index].name
            entry = self.entries.get((invocation.network, invocation.tool))
            if entry is None:
                self.outcomes[index] = ScannerOutcome(ScannerRun(
                    name, ok=False, reason="the engine did not run it"))
            elif entry.get("not_started"):
                # The budget was spent before `--jobs` reached it.
                cut.append(name)
                self.outcomes[index] = ScannerOutcome(ScannerRun(
                    name, ok=False, budget=BUDGET_NOT_STARTED,
                    reason=f"not started: the {self.budget_s:g}s budget was spent "
                           "before its turn"))
            else:
                self._read(invocation, index, entry, cut)
        return cut

    def _read(self, invocation: Invocation, index: int, entry: dict, cut: list[str]) -> None:
        adapter = self.adapters[index]
        output, stdout = self._output(invocation, entry)
        if self.written is not None and invocation.tool == HISTORY_TOOL:
            self.outcomes[index] = _with_history(
                self.outcomes[index], adapter, output, entry, self.written, self.workspace,
                self.budget_s, self.spent, self.context.settings.exclude)
            if entry.get("cut") and adapter.name not in cut:
                cut.append(adapter.name)
            return
        result = outcome(adapter, output).timed(entry["seconds"])
        if entry.get("cut"):
            # The budget stopped it (R3.5): the cut is the cause, in the words
            # every surface already uses for one (29.0.3).
            cut.append(adapter.name)
            result = result.cut(f"cut by the {self.budget_s:g}s budget after {self.spent:.0f}s")
        self.outcomes[index] = result
        keyed = self.keys.get(index)
        if keyed is not None and self.reuse is not None and result.scanner.ok \
                and not entry.get("cut") and not entry.get("timed_out"):
            _reuse.save(adapter.name, keyed[0], raw=stdout, version=invocation.version,
                        generation=self.reuse[1], data=keyed[1])

    def _output(self, invocation: Invocation, entry: dict) -> tuple[ScannerOutput, str]:
        """The tool's report as its adapter reads it, and the raw text."""
        where = self.scratches[invocation.network]
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
        return ScannerOutput(
            invocation.tool, invocation.version, stdout, stderr, code, argv=invocation.argv,
            stopped_after=float(invocation.timeout) if entry.get("timed_out") else None), stdout


def _reused(adapters, plan, planned, outcomes, workspace, chosen, reuse, on_progress, *,
            fresh: bool = False) -> dict[int, tuple[str, str]]:
    """Take each dependency Scanner whose key has a stored result out of the plan,
    its outcome that result (R14.3, D32); return the keys of those that will run,
    so their clean results can be stored. With `fresh`, every one runs and is
    keyed: a fresh answer replaces the stored one. Nothing, with `reuse` None."""
    if reuse is None:
        return {}
    profile, _ = reuse
    keys: dict[int, tuple[str, str]] = {}
    inputs = None
    for invocation, index in list(zip(plan, planned, strict=True)):
        name = adapters[index].name
        if not _reuse.reusable(name, profile):
            continue
        if inputs is None:
            inputs = _reuse.inputs(workspace, chosen.files)
        stamp = _reuse.data(name, chosen.files)
        key = _reuse.key(tool=name, version=invocation.version, profile=profile,
                         inputs=inputs, data=stamp)
        stored = None if fresh else _reuse.load(name, key)
        if stored is None:
            keys[index] = (key, stamp)
            continue
        output = ScannerOutput(invocation.tool, stored.get("version", invocation.version),
                               stored["raw"], "", 0, argv=invocation.argv)
        answered = outcome(adapters[index], output)
        outcomes[index] = dataclasses.replace(answered, scanner=dataclasses.replace(
            answered.scanner, reused_from=str(stored.get("generation", ""))))
        position = planned.index(index)
        del plan[position], planned[position]
        if on_progress is not None:
            on_progress(_events.reused(name, str(stored.get("generation", ""))))
    return keys


def _run_by_network(runtime, plan, tar, scratches, on_event, budget_s, jobs=None) -> None:
    """Each network boundary's part of the plan in its own Scan Container, at once
    when there are two: one budget, one cancel, both stopped by either."""
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


def _history_pass(adapters, plan, planned, workspace, context, scratch, on_progress):
    """Git history, for Gitleaks (R3.7, D3): written into the scratch directory
    when Gitleaks runs on a repository and the project has not said
    `history = false`, and its pass added to the plan. Returns what was written
    and what the record says: what was read, or why nothing was."""
    say = on_progress if on_progress is not None else (lambda _: None)
    index = next((i for i in planned if adapters[i].name == "gitleaks"), None)
    if index is None:
        return None, None
    chosen = context.file_set
    if chosen.note:
        # A repository walked for want of `git` (R8.1): its history cannot be read,
        # and a record that said nothing would read as a repository with none.
        say(_events.history_not_read("git is not on PATH here"))
        return None, {"unavailable": "git is not on PATH here (the image carries none, "
                                     "ADR-0005)"}
    if chosen.scope != "git":
        return None, None
    if not context.settings.history:
        say(_events.history_not_read("[scan] history = false"))
        return None, {"off": "[scan] history = false"}
    written = _history.write(workspace, scratch / HISTORY_DIR)
    if written is None:
        return None, None
    plan.append(adapters[index].history_command(
        project_config=PROJECT_GITLEAKS_CONFIG in chosen.files, workspace=workspace))
    planned.append(index)
    say(_events.history_read(written.commits, written.bytes, written.bounded))
    return written, {"commits": written.commits, "bytes": written.bytes,
                     "bounded": written.bounded}


def _with_history(outcome, adapter, output, entry, written, workspace, budget_s, spent,
                  excluded: tuple[str, ...] = ()):
    """Gitleaks's outcome with its history pass folded in: the hits after the
    tree's, so a secret still in the tree keeps its line; a pass that did not
    finish makes Gitleaks's run incomplete, with the reason."""
    if outcome is None:
        return outcome
    if entry.get("cut") or entry.get("timed_out") or entry["exit_code"] != 0:
        why = (f"cut by the {budget_s:g}s budget after {spent:.0f}s" if entry.get("cut")
               else f"timed out after {output.stopped_after:g}s" if entry.get("timed_out")
               else f"exit {entry['exit_code']}: {output.stderr.strip()[-200:]}")
        return dataclasses.replace(outcome, scanner=dataclasses.replace(
            outcome.scanner, ok=False, reason=f"its git history pass did not finish: {why}",
            budget=BUDGET_CUT if entry.get("cut") else outcome.scanner.budget))
    try:
        found = adapter.parse_history(output, written, workspace, excluded)
    except (ValueError, KeyError) as exc:
        return dataclasses.replace(outcome, scanner=dataclasses.replace(
            outcome.scanner, ok=False,
            reason=f"its git history report was unreadable: {exc}"))
    return dataclasses.replace(outcome, findings=[*outcome.findings, *found])
