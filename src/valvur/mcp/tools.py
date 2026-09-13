"""The tools valvur exposes over MCP.

Thin wrappers over `valvur.operations`, which the CLI calls too — so the two surfaces
cannot drift (F9.3).

Every tool is read-only with respect to the **Workspace**. There is no `scan_and_fix`,
no `apply`, no `write` and no `remediate`, and a test asserts their absence, because
ADR-0009 is a safety property rather than a preference.
"""

from __future__ import annotations

from typing import Any

from ..operations import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    doctor,
    explain_finding,
    list_findings,
    scan_status,
    start_scan,
)
from .server import Tool

# Names that must never appear here. Asserted by test, not by convention.
FORBIDDEN = ("scan_and_fix", "apply", "write", "remediate", "fix", "patch", "edit")

_WORKSPACE = {
    "type": "string",
    "description": "Absolute path to the project to scan. Defaults to the current directory.",
}


def registry() -> list[Tool]:
    workspace_arg: dict[str, Any] = {"workspace": _WORKSPACE}
    return [
        Tool("scan", "Run a security scan of a project. Writes results into "
                     ".security-scan/ and never modifies your source.",
             {"type": "object", "properties": {
                 **workspace_arg,
                 "profile": {"type": "string", "enum": ["offline", "full"],
                             "description": "offline (the default) runs every Scanner "
                             "that works with no network access. full adds a second "
                             "advisory source and the dependency-reality Check, both "
                             "of which send package names to public registries."},
             }}, start_scan),
        Tool("list_findings", "List findings from the last scan, worst first. "
                              "Bounded by default.",
             {"type": "object", "properties": {
                 **workspace_arg,
                 "status": {"type": "string",
                            "enum": ["new", "persisting", "regressed"]},
                 "limit": {"type": "integer",
                           "description": f"Default {DEFAULT_LIMIT}, max {MAX_LIMIT}."},
                 "include_suppressed": {"type": "boolean"},
             }}, list_findings),
        Tool("explain_finding", "Full detail for one finding: evidence, exploitation, "
                                "dependency path and which scanner reported it.",
             {"type": "object", "required": ["fingerprint"], "properties": {
                 **workspace_arg,
                 "fingerprint": {"type": "string", "description": "From list_findings."},
             }}, explain_finding),
        Tool("scan_status", "What the last scan actually did: which scanners ran, "
                            "which failed, and whether the result is complete.",
             {"type": "object", "properties": workspace_arg}, scan_status),
        Tool("doctor", "Check that this machine can scan, before scanning: the "
                       "container runtime, the image, the vulnerability database, the "
                       "package-name index, SELinux, TLS trust, and which MCP client "
                       "configuration names valvur. One line per check with the fix on "
                       "any that would fail a scan. Changes nothing.",
             {"type": "object", "properties": {
                 **workspace_arg,
                 "network": {"type": "boolean",
                             "description": "Also probe, with one bounded TCP connect "
                             "per host, whether the registries a first run and the "
                             "full profile need are reachable from here. Off by "
                             "default: without it doctor opens no socket."},
             }}, doctor),
    ]
