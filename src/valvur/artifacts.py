"""Projections of the findings model into the Results Folder.

Every artifact here is generated in one pass from one list, which is what makes the
F7.13 invariant enforceable rather than aspirational: they cannot drift because there
is nothing for them to drift from.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .findings import Finding
from .fingerprint import FP_VERSION

SCHEMA = 1
FINGERPRINT_KEY = f"valvurFingerprint/v{FP_VERSION}"

# SARIF has three levels; our six severities map onto them. Losing granularity here
# is fine — findings.json keeps the original, and SARIF is for IDE gutters.
_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note", "unknown": "warning",
}


def findings_json(findings: list[Finding], *, status: str, complete: bool) -> str:
    return json.dumps(
        {
            "schema": SCHEMA,
            "fp_version": FP_VERSION,
            "status": status,
            "complete": complete,
            "findings": [_serialise(f) for f in findings],
        },
        indent=2,
    ) + "\n"


def _serialise(finding: Finding) -> dict:
    record = asdict(finding)
    # Tuples serialise as lists; keep the shape predictable for whoever queries this.
    record["sources"] = list(finding.sources)
    if finding.dependency:
        record["dependency"]["path"] = list(finding.dependency.path)
    return record


def sarif(findings: list[Finding], *, version: str) -> str:
    """SARIF 2.1.0 for IDEs and tooling.

    Fingerprints travel in `partialFingerprints`, so an IDE's suppression survives an
    edit for exactly the reason ours does (ADR-0003).
    """
    rules: dict[str, dict] = {}
    results = []

    for finding in findings:
        rules.setdefault(finding.rule, {
            "id": finding.rule,
            "shortDescription": {"text": finding.title[:120]},
            "properties": {"security-severity": _security_severity(finding.severity)},
        })
        results.append({
            "ruleId": finding.rule,
            "level": _SARIF_LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    **({"region": {"startLine": finding.line}} if finding.line > 0 else {}),
                }
            }],
            "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
            "properties": {"status": finding.status, "rank": finding.rank},
        })
        if finding.suppressed:
            # SARIF's own concept. An invented property would make IDEs show
            # suppressed findings as live — worse than emitting no SARIF, because the
            # tool would look wrong rather than misconfigured.
            results[-1]["suppressions"] = [{
                "kind": "external",
                "status": "accepted",
                "justification": finding.suppressed,
            }]

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "valvur",
                "version": version,
                "informationUri": "https://github.com/MaverickHQ/valvur",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }, indent=2) + "\n"


def _security_severity(severity: str) -> str:
    """GitHub and several IDEs read this numeric field rather than `level`."""
    return {"critical": "9.5", "high": "7.5", "medium": "5.0",
            "low": "3.0", "info": "1.0"}.get(severity, "5.0")
