"""Public interface: scan a Workspace, get a ScanRun."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import redact as _redact
from . import results
from .findings import Finding

CONTAINER_WORKSPACE = "/workspace"


class ScannerFailed(RuntimeError):
    """A Scanner could not complete. Never downgraded to a clean result (F2.5)."""


def _relative(path: str) -> str:
    """Scanners see /workspace; users and fingerprints need repo-relative paths (F5.4)."""
    if path.startswith(CONTAINER_WORKSPACE + "/"):
        return path[len(CONTAINER_WORKSPACE) + 1 :]
    return path.lstrip("./")


@dataclass
class ScanRun:
    findings: list[Finding] = field(default_factory=list)

    @property
    def status(self) -> str:
        """`clean` must be explicit, so an agent can tell it from a run that never happened."""
        return "clean" if not self.findings else "findings"


def scan(workspace: Path, *, runner) -> ScanRun:
    output = runner.run_gitleaks(workspace)
    if output.exit_code != 0 and not output.stdout.strip():
        raise ScannerFailed(
            f"{output.tool} exited {output.exit_code} and produced no report. "
            f"Refusing to report a clean scan.\n{output.stderr.strip()[:500]}"
        )
    raw = json.loads(output.stdout or "[]")
    findings = [
        Finding(
            rule=item["RuleID"],
            path=_relative(item["File"]),
            line=item["StartLine"],
            title=item["Description"],
            # Redact at the boundary — the raw secret never enters the model.
            evidence=_redact.redact(item.get("Match", ""), item.get("Secret", "")),
        )
        for item in raw
    ]
    run = ScanRun(findings=findings)
    results.write(workspace, run)
    return run
