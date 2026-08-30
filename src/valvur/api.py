"""Public interface: scan a Workspace, get a ScanRun.

Orchestration only. Everything tool-specific lives in `adapters/` — this module
sequences adapters, merges their Findings, diffs against the previous run, and
writes the Results Folder.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import profiles as _profiles
from . import results
from . import state as _state
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

    @property
    def failures(self) -> list[ScannerRun]:
        return [s for s in self.scanners if s.failed]

    @property
    def status(self) -> str:
        """`clean` must be explicit, so an agent can tell it from a run that never happened."""
        return "clean" if not self.findings else "findings"


def _run_one(adapter, runner, workspace) -> tuple[ScannerRun, list[Finding]]:
    """Run one Scanner. One broken Scanner must never cost the others (F2.5)."""
    try:
        output = adapter.run(runner, workspace)
    except Exception as exc:
        return ScannerRun(adapter.name, ok=False, reason=str(exc)), []

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
        )

    return ScannerRun(adapter.name, ok=True, version=output.version), adapter.parse(output)


def scan(
    workspace: Path, *, runner, adapters=None, profile: str = _profiles.STANDARD
) -> ScanRun:
    if adapters is None:
        adapters = _profiles.select(DEFAULT_ADAPTERS, profile)

    # Scanners are independent and I/O-bound — each is a container invocation — so
    # they run concurrently. Serially, six Scanners will not meet the 5-minute
    # standard budget (F2.6, N1.2). Results are collected back into declaration
    # order so a Scan Run is reproducible regardless of which finished first.
    outcomes: list[tuple[ScannerRun, list[Finding]] | None] = [None] * len(adapters)

    with ThreadPoolExecutor(max_workers=max(1, len(adapters))) as pool:
        futures = {
            pool.submit(_run_one, adapter, runner, workspace): index
            for index, adapter in enumerate(adapters)
        }
        for future in as_completed(futures):
            outcomes[futures[future]] = future.result()

    completed = [o for o in outcomes if o is not None]
    scanners = [outcome[0] for outcome in completed]
    findings = [f for outcome in completed for f in outcome[1]]

    # Total failure is a failed Scan Run (N3.2). Partial failure is a reported one.
    if scanners and all(s.failed for s in scanners):
        detail = "; ".join(f"{s.tool}: {s.reason}" for s in scanners)
        raise ScannerFailed(f"Every scanner failed. Refusing to report a scan.\n{detail}")

    findings = merge(findings)

    results_dir = workspace / results.RESULTS_DIR
    previous, previously_fixed = _state.load(results_dir)

    findings = [
        replace(f, status=_state.status_for(f.fingerprint, previous, previously_fixed))
        for f in findings
    ]

    current = {f.fingerprint for f in findings}
    run = ScanRun(findings=findings, fixed=sorted(previous - current), scanners=scanners)

    results.write(workspace, run)
    _state.save(results_dir, current, (previously_fixed | set(run.fixed)) - current)
    return run
