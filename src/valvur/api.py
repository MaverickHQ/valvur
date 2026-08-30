"""Public interface: scan a Workspace, get a ScanRun.

Orchestration only. Everything tool-specific lives in `adapters/` — this module
sequences adapters, merges their Findings, diffs against the previous run, and
writes the Results Folder.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import enrichment as _enrichment
from . import licence_policy as _licence
from . import profiles as _profiles
from . import ranking as _ranking
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
    network_used: bool = False
    kev_age_days: float | None = None
    kev_source: str = ""

    @property
    def failures(self) -> list[ScannerRun]:
        return [s for s in self.scanners if s.failed]

    @property
    def status(self) -> str:
        """`clean` must be explicit, so an agent can tell it from a run that never happened."""
        return "clean" if not self.findings else "findings"


def _run_one(adapter, runner, workspace) -> tuple[ScannerRun, list[Finding], tuple | None]:
    """Run one Scanner. One broken Scanner must never cost the others (F2.5)."""
    try:
        output = adapter.run(runner, workspace)
    except Exception as exc:
        return ScannerRun(adapter.name, ok=False, reason=str(exc)), [], None

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
        )

    # An adapter may produce an artifact (an SBOM) instead of, or as well as, Findings.
    artifact = getattr(adapter, "artifact", None)
    produced = (artifact, output.stdout) if artifact and output.stdout.strip() else None
    return (
        ScannerRun(adapter.name, ok=True, version=output.version),
        adapter.parse(output),
        produced,
    )


def scan(
    workspace: Path, *, runner, adapters=None, profile: str = _profiles.STANDARD
) -> ScanRun:
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
            outcomes[futures[future]] = future.result()

    completed = [o for o in outcomes if o is not None]
    scanners = [outcome[0] for outcome in completed]
    findings = [f for outcome in completed for f in outcome[1]]
    artifacts = [o[2] for o in completed if o[2] is not None]

    # Total failure is a failed Scan Run (N3.2). Partial failure is a reported one.
    if scanners and all(s.failed for s in scanners):
        detail = "; ".join(f"{s.tool}: {s.reason}" for s in scanners)
        raise ScannerFailed(f"Every scanner failed. Refusing to report a scan.\n{detail}")

    # Dependency licence policy reads the SBOM the fleet just produced (F4.4-F4.6).
    sbom = next((body for name, body in artifacts if name == "sbom.cdx.json"), "")
    if sbom:
        findings += _licence.evaluate(_licence.project_licence(workspace), sbom)

    findings = merge(findings)

    # Exploit intelligence: what the world reports, as opposed to what a Scanner
    # asserts. Network use is Profile-gated (F6.3, F6.4).
    provider = _enrichment.LocalProvider()
    findings = provider.enrich(findings, network=_profiles.ALLOWS_NETWORK.get(profile, False))
    findings = _ranking.apply(findings)

    results_dir = workspace / results.RESULTS_DIR
    previous, previously_fixed = _state.load(results_dir)

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
        kev_source=provider.kev_source,
    )

    results.write(workspace, run, artifacts=artifacts)
    still_fixed = {fp for fp in previously_fixed if fp not in current}
    still_fixed |= {fp for fp in previous if fp not in current}
    _state.save(results_dir, current, still_fixed)
    return run
