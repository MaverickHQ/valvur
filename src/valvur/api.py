"""Public interface: scan a Workspace, get a ScanRun.

Orchestration only. Everything tool-specific lives in `adapters/` — this module
sequences adapters, merges their Findings, diffs against the previous run, and
writes the Results Folder.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from . import results
from . import state as _state
from .adapters import DEFAULT_ADAPTERS
from .findings import Finding, merge


class ScannerFailed(RuntimeError):
    """A Scanner could not complete. Never downgraded to a clean result (F2.5)."""


@dataclass
class ScanRun:
    findings: list[Finding] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        """`clean` must be explicit, so an agent can tell it from a run that never happened."""
        return "clean" if not self.findings else "findings"


def scan(workspace: Path, *, runner, adapters=DEFAULT_ADAPTERS) -> ScanRun:
    findings: list[Finding] = []
    for adapter in adapters:
        output = adapter.run(runner, workspace)
        if output.exit_code != 0 and not output.stdout.strip():
            raise ScannerFailed(
                f"{output.tool} exited {output.exit_code} and produced no report. "
                f"Refusing to report a clean scan.\n{output.stderr.strip()[:500]}"
            )
        findings.extend(adapter.parse(output))

    findings = merge(findings)

    results_dir = workspace / results.RESULTS_DIR
    previous, previously_fixed = _state.load(results_dir)

    findings = [
        replace(f, status=_state.status_for(f.fingerprint, previous, previously_fixed))
        for f in findings
    ]

    current = {f.fingerprint for f in findings}
    run = ScanRun(findings=findings, fixed=sorted(previous - current))

    results.write(workspace, run)
    _state.save(results_dir, current, (previously_fixed | set(run.fixed)) - current)
    return run
