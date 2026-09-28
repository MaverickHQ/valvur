"""zizmor — GitHub Actions workflows and action definitions (F3.11; D8, ADR-0023).

Adopted by measurement (R4.1): on the corpus it reported every unpinned action valvur's
own rule found (85 of 85) and every write permission Checkov's workflow checks found
(18 of 18), at `--persona pedantic --min-severity medium`, offline, in 1.1 s for
sixteen repositories. The regular persona missed a one-job workflow's `write-all`.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .. import fingerprint as _fp
from ..findings import Finding, Severity
from ..invocation import Invocation, ScannerOutput
from .base import ScannerAdapter, container_relative

VERSION = "1.30.1"

_SEVERITY = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}


def _workflow(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    in_workflows = rel.startswith(".github/workflows/") and name.endswith((".yml", ".yaml"))
    return in_workflows or name in ("action.yml", "action.yaml")


class ZizmorAdapter(ScannerAdapter):
    kind = "scanner"
    name = "zizmor"
    version = VERSION

    def applies_to(self, workspace: Path) -> tuple[bool, str]:
        """Only where there is a workflow or an action definition, read from the
        File Set (ADR-0021). Biased to running: a File Set that cannot be listed
        runs zizmor, which finds nothing where there is nothing."""
        from ..fileset import files
        from ..refusal import Refusal

        try:
            listed = files(workspace)
        except Refusal:
            return True, "the File Set could not be listed"
        found = next((rel for rel in listed if _workflow(rel)), None)
        if found is not None:
            return True, found
        return False, "no GitHub Actions workflow or action definition found"

    def command(self, workspace: Path) -> Invocation:
        # `--offline`: no audit that asks GitHub. `--no-exit-codes`: findings are a
        # successful run (F2.4). The project's own `zizmor.yml`, if any, is read.
        return Invocation(
            tool=self.name, version=VERSION,
            argv=("zizmor", "--offline", "--persona", "pedantic", "--min-severity", "medium",
                  "--format", "json", "--no-progress", "--no-exit-codes", "/workspace"),
            report=None, timeout=300,
        )

    def parse(self, output: ScannerOutput) -> list[Finding]:
        findings: list[Finding] = []
        seen: Counter[tuple[str, str, str]] = Counter()
        for item in json.loads(output.stdout or "[]"):
            primary = next((loc for loc in item.get("locations", [])
                            if loc.get("symbolic", {}).get("kind") == "Primary"), None)
            if primary is None:
                continue
            local = primary["symbolic"].get("key", {}).get("Local") or {}
            path = container_relative(str(local.get("verbatim_path")
                                          or local.get("given_path", ""))).removeprefix("./")
            concrete = primary.get("concrete", {})
            feature = str(concrete.get("feature", "")).strip()
            rule = str(item.get("ident", "zizmor"))
            annotation = str(primary["symbolic"].get("annotation", "")).strip()
            key = (rule, path, feature)
            ordinal = seen[key]
            seen[key] += 1
            severity = str(item.get("determinations", {}).get("severity", "")).lower()
            findings.append(Finding(
                rule=rule,
                path=path,
                line=int(concrete.get("location", {}).get("start_point", {}).get("row", -1)) + 1,
                title=f"{item.get('desc', rule)}: {annotation}" if annotation else item.get(
                    "desc", rule),
                evidence=feature,
                fingerprint=_fp.for_sast(rule, path, feature, ordinal),
                sources=(output.tool,),
                severity=Severity.parse(_SEVERITY.get(severity, "medium")),
            ))
        return findings
