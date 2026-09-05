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
from . import exclusions as _exclusions
from . import gitcontext as _gitcontext
from . import licence_policy as _licence
from . import profiles as _profiles
from . import ranking as _ranking
from . import results
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
    vendored_dropped: int = 0
    config_dropped: int = 0
    excluded_paths: list[str] = field(default_factory=list)
    profile: str = ""

    @property
    def failures(self) -> list[ScannerRun]:
        return [s for s in self.scanners if s.failed]

    @property
    def status(self) -> str:
        """`clean` must be explicit, so an agent can tell it from a run that never happened."""
        return "clean" if not self.findings else "findings"


def _run_one(adapter, runner, workspace) -> tuple:
    """Run one Scanner. One broken Scanner must never cost the others (F2.5)."""
    applies = getattr(adapter, "applies_to", None)
    if applies is not None:
        should_run, why = applies(workspace)
        if not should_run:
            # Not a failure: the Scan Run stays complete. Recorded so the reader can
            # tell "had nothing to look at" from "looked and found nothing".
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

    # Dependency licence policy reads the SBOM the fleet just produced (F4.4-F4.6).
    sbom = next((body for name, body in artifacts if name == "sbom.cdx.json"), "")
    if sbom:
        findings += _licence.evaluate(_licence.project_licence(workspace), sbom)

    # Vendored and generated code is not the developer's to fix.
    findings, vendored_dropped = _exclusions.filter_findings(findings)

    # Paths this project chose not to scan, from its committed config. Never a
    # built-in default: silently skipping a project's tests would hide real code.
    excluded_paths = _exclusions.load_configured(workspace)
    findings, config_dropped = _exclusions.filter_configured(findings, excluded_paths)

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
        vendored_dropped=vendored_dropped,
        config_dropped=config_dropped,
        excluded_paths=list(excluded_paths),
        profile=profile,
    )

    results.write(workspace, run, scanner_artifacts=artifacts, raw_outputs=raw_outputs)
    still_fixed = {fp for fp in previously_fixed if fp not in current}
    still_fixed |= {fp for fp in previous if fp not in current}
    _state.save(results_dir, current, still_fixed)
    return run
