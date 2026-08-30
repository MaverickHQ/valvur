"""The tools valvur exposes over MCP.

Every one is read-only with respect to the **Workspace**. There is no `scan_and_fix`,
no `apply`, no `write` and no `remediate` — and a test asserts their absence, because
ADR-0009 is a safety property rather than a preference.

Responses are **bounded by default** (F9.10) and carry **neutralised evidence**
(F9.9). An MCP response reaches an agent's context with no file in between: it is the
most direct injection path valvur has, and the only one the agent cannot decline to
read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..results import RESULTS_DIR
from .server import Tool

# Names that must never appear here. Asserted by test, not by convention.
FORBIDDEN = ("scan_and_fix", "apply", "write", "remediate", "fix", "patch", "edit")

DEFAULT_LIMIT = 20
MAX_LIMIT = 100

_WORKSPACE = {
    "type": "string",
    "description": "Absolute path to the project to scan. Defaults to the current directory.",
}


def _results(workspace: str | None) -> Path:
    return Path(workspace or ".").resolve() / RESULTS_DIR


def _load(workspace: str | None) -> dict:
    path = _results(workspace) / "findings.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"No scan results at {path}. Run the `scan` tool first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _one_line(finding: dict) -> str:
    exploit = finding.get("exploit") or {}
    badge = ""
    if exploit.get("ransomware"):
        badge = " [KEV·RANSOMWARE]"
    elif exploit.get("kev"):
        badge = " [KEV]"
    elif exploit.get("epss") and exploit["epss"] >= 0.10:
        badge = f" [EPSS {exploit['epss']:.0%}]"
    suppressed = " [suppressed]" if finding.get("suppressed") else ""
    where = f"{finding['path']}:{finding['line']}" if finding.get("line") else finding["path"]
    return (
        f"{finding.get('rank', 0)}. [{finding.get('status', '?')}] {where} — "
        f"{finding['title']} ({finding['rule']}){badge}{suppressed}\n"
        f"   fingerprint: {finding['fingerprint']}"
    )


# ----------------------------------------------------------------- the tools

def _scan(args: dict) -> str:
    from ..api import scan
    from ..runner import ContainerRunner

    workspace = Path(args.get("workspace") or ".").resolve()
    profile = args.get("profile") or "standard"

    run = scan(workspace, runner=ContainerRunner(), profile=profile)

    lines = [f"Scan complete: {run.status}, {len(run.findings)} finding(s)."]
    if run.failures:
        lines.append("")
        lines.append("INCOMPLETE — these scanners did not run:")
        lines += [f"  - {f.tool}: {f.reason}" for f in run.failures]
        lines.append("Findings below are partial; do not treat this as a clean result.")
    if run.fixed:
        lines.append(f"Fixed since the last scan: {len(run.fixed)}")
    lines.append("")
    lines.append(f"Results: {workspace / RESULTS_DIR}")
    lines.append("Use `list_findings` next, then `explain_finding` for detail.")
    return "\n".join(lines)


def _list_findings(args: dict) -> str:
    data = _load(args.get("workspace"))
    findings = data["findings"]

    status = args.get("status")
    if status:
        findings = [f for f in findings if f.get("status") == status]
    if not args.get("include_suppressed"):
        findings = [f for f in findings if not f.get("suppressed")]

    findings.sort(key=lambda f: f.get("rank") or 10**9)

    limit = min(int(args.get("limit") or DEFAULT_LIMIT), MAX_LIMIT)
    shown, omitted = findings[:limit], max(0, len(findings) - limit)

    if not findings:
        return (
            "No findings match. The scan itself may still have been incomplete — "
            "check `scan_status`."
        )

    lines = [f"{len(findings)} finding(s); showing {len(shown)}, worst first.", ""]
    lines += [_one_line(f) for f in shown]
    if omitted:
        # Silent truncation reads as "that is everything" (F9.10).
        lines += [
            "",
            f"{omitted} more not shown. Raise `limit` (max {MAX_LIMIT}) or filter "
            "by `status`.",
        ]
    return "\n".join(lines)


def _explain_finding(args: dict) -> str:
    fingerprint = args.get("fingerprint")
    if not fingerprint:
        raise ValueError("fingerprint is required; list_findings reports it for each finding")

    data = _load(args.get("workspace"))
    finding = next(
        (f for f in data["findings"] if f["fingerprint"] == fingerprint), None
    )
    if finding is None:
        raise ValueError(f"No finding with fingerprint {fingerprint}")

    lines = [
        f"{finding['title']}",
        f"  rule:        {finding['rule']}",
        f"  location:    {finding['path']}"
        + (f":{finding['line']}" if finding.get("line") else ""),
        f"  severity:    {finding.get('severity', 'unknown')}",
        f"  status:      {finding.get('status', '?')}",
        f"  reported by: {', '.join(finding.get('sources') or []) or 'unknown'}",
    ]

    exploit = finding.get("exploit") or {}
    if exploit.get("cve"):
        lines += [
            "",
            "Exploitation:",
            f"  CVE:        {exploit['cve']}",
            f"  in CISA KEV: {exploit.get('kev')}"
            + ("  — used in ransomware campaigns"
               if exploit.get("ransomware") else ""),
            f"  EPSS:       {exploit.get('epss')}",
        ]

    dependency = finding.get("dependency") or {}
    if dependency.get("package"):
        lines += ["", "Dependency:",
                  f"  package: {dependency['package']} {dependency.get('version', '')}",
                  f"  scope:   {dependency.get('scope', 'unknown')}"]
        if dependency.get("path") and len(dependency["path"]) > 1:
            lines.append(f"  reached via: {' -> '.join(dependency['path'])}")
        if dependency.get("fixed_version"):
            lines.append(f"  fixed in: {dependency['fixed_version']}")

    if finding.get("suppressed"):
        lines += ["", f"SUPPRESSED: {finding['suppressed']}",
                  "This is an accepted risk recorded in .security-scan.toml."]

    if finding.get("evidence"):
        # Already neutralised at the model boundary (F3.13, F9.9). Quoted, never
        # presented as prose the agent might read as addressed to it.
        lines += ["", "Evidence:", finding["evidence"]]

    lines += [
        "",
        "valvur proposes; it does not change your code. Applying this is your "
        "decision, and a finding disappearing is not proof it was fixed.",
    ]
    return "\n".join(lines)


def _scan_status(args: dict) -> str:
    path = _results(args.get("workspace")) / "run.json"
    if not path.is_file():
        return f"No scan has run in this workspace ({path.parent})."
    data = json.loads(path.read_text(encoding="utf-8"))

    lines = [
        f"status:   {data.get('status')}",
        f"complete: {data.get('complete')}",
        f"findings: {data.get('findings')}",
        "",
        "Scanners:",
    ]
    for scanner in data.get("scanners", []):
        mark = "ok" if scanner["ok"] else f"FAILED — {scanner['reason'][:80]}"
        lines.append(f"  {scanner['tool']}: {mark}")
    network = data.get("network", {})
    lines += ["", f"left this machine: {network.get('what_left_the_machine', 'unknown')}"]
    if not data.get("complete"):
        lines += ["", "This scan was INCOMPLETE. Do not report it as clean."]
    return "\n".join(lines)


def registry() -> list[Tool]:
    workspace_arg: dict[str, Any] = {"workspace": _WORKSPACE}
    return [
        Tool("scan", "Run a security scan of a project. Writes results into "
                     ".security-scan/ and never modifies your source.",
             {"type": "object", "properties": {
                 **workspace_arg,
                 "profile": {"type": "string", "enum": ["quick", "standard", "deep"],
                             "description": "quick is fully offline. Defaults to standard."},
             }}, _scan),
        Tool("list_findings", "List findings from the last scan, worst first. "
                              "Bounded by default.",
             {"type": "object", "properties": {
                 **workspace_arg,
                 "status": {"type": "string",
                            "enum": ["new", "persisting", "regressed"]},
                 "limit": {"type": "integer",
                           "description": f"Default {DEFAULT_LIMIT}, max {MAX_LIMIT}."},
                 "include_suppressed": {"type": "boolean"},
             }}, _list_findings),
        Tool("explain_finding", "Full detail for one finding: evidence, exploitation, "
                                "dependency path and which scanner reported it.",
             {"type": "object", "required": ["fingerprint"], "properties": {
                 **workspace_arg,
                 "fingerprint": {"type": "string",
                                 "description": "From list_findings."},
             }}, _explain_finding),
        Tool("scan_status", "What the last scan actually did: which scanners ran, "
                            "which failed, and whether the result is complete.",
             {"type": "object", "properties": workspace_arg}, _scan_status),
    ]
