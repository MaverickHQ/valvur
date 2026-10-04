"""Projections of the findings model into the Results Folder.

Every artifact here is generated in one pass from one list, which is what makes the
F7.13 invariant enforceable rather than aspirational: they cannot drift because there
is nothing for them to drift from.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from . import grouping as _grouping
from .findings import Finding
from .fingerprint import FP_VERSION
from .text import cut

SCHEMA = 1
FINGERPRINT_KEY = f"valvurFingerprint/v{FP_VERSION}"

# SARIF has three levels; our six severities map onto them. Losing granularity here
# is fine — findings.json keeps the original, and SARIF is for IDE gutters.
_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note", "unknown": "warning",
}


def findings_json(findings: list[Finding], *, status: str, status_reason: str = "",
                  complete: bool, generation: str = "", fetched: list[dict] | None = None) -> str:
    return json.dumps(
        {
            "schema": SCHEMA,
            "fp_version": FP_VERSION,
            # The Scan Run this document belongs to; the same value is in run.json,
            # state.json and results.sarif (26.0.3). Additive to schema 1.
            "generation": generation,
            "status": status,
            "status_reason": status_reason,
            "fetched": list(fetched or []),
            "complete": complete,
            # Floods of one rule under one directory (R5.1), derived from the
            # Findings' own `group` ids. Additive to schema 1.
            "groups": [{**asdict(g), "label": g.label} for g in _grouping.describe(findings)],
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
    # Additive to schema 1 (R13.4, F5.10): present when the rule declares one.
    record["cwe"] = list(finding.cwe)
    if not finding.cwe:
        del record["cwe"]
    # Additive (D47a): present on the sink inventory alone.
    if not finding.inventory:
        del record["inventory"]
    # Additive (R38.3): present when a project's ignore names the finding.
    record["aliases"] = list(finding.aliases)
    if not finding.aliases:
        del record["aliases"]
    if finding.ignored_by is None:
        del record["ignored_by"]
    return record


def sarif(findings: list[Finding], *, version: str, generation: str = "") -> str:
    """SARIF 2.1.0 for IDEs and tooling.

    Fingerprints travel in `partialFingerprints`, so an IDE's suppression survives an
    edit for exactly the reason ours does (ADR-0003). The Scan Run's generation is
    SARIF's own `automationDetails.guid` — the field the format has for it.
    """
    rules: dict[str, dict] = {}
    results = []

    for finding in findings:
        rules.setdefault(finding.rule, {
            "id": finding.rule,
            "shortDescription": {"text": cut(finding.title, 120)},
            "properties": {"security-severity": _security_severity(finding.severity),
                           # The rule's weaknesses (R13.4), and the tag code-scanning
                           # tools read them from.
                           **({"cwe": list(finding.cwe),
                               "tags": [f"external/cwe/{c.lower()}" for c in finding.cwe]}
                              if finding.cwe else {})},
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
            "properties": {"status": finding.status, "rank": finding.rank,
                           # The path's class (D56), which is not identity.
                           **({"context": finding.context} if finding.context else {}),
                           **({"inventory": True} if finding.inventory else {})},
        })
        if finding.suppressed:
            # SARIF's own concept. An invented property would make IDEs show
            # suppressed findings as live — worse than emitting no SARIF, because the
            # tool would look wrong rather than misconfigured.
            results[-1]["suppressions"] = [{
                "kind": finding.ignored_by.kind if finding.ignored_by else "external",
                "status": "accepted",
                "justification": finding.suppressed,
            }]
        elif finding.ignored_by:
            # The project's own ignore, which valvur did not accept (R38.3, D77c): a
            # suppression SARIF readers show as rejected, so the result stays live.
            by = finding.ignored_by
            results[-1]["suppressions"] = [{
                "kind": by.kind,
                "status": "rejected",
                "justification": (f"{by.ignore} at {by.where}, with no reason and expiry "
                                  "valvur accepts as a suppression"),
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
            **({"automationDetails": {"id": f"valvur/{generation}", "guid": generation}}
               if generation else {}),
            "results": results,
        }],
    }, indent=2) + "\n"


def _security_severity(severity: str) -> str:
    """GitHub and several IDEs read this numeric field rather than `level`."""
    return {"critical": "9.5", "high": "7.5", "medium": "5.0",
            "low": "3.0", "info": "1.0"}.get(severity, "5.0")
