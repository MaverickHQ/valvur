"""Dependency licence policy (F4.4-F4.6).

Host-side, deliberately. ADR-0013 puts Checks in the container because the Dependency
Reality Check makes network calls; this one makes none — it reads the CycloneDX SBOM
the fleet has just produced, which does not exist until after the Scanners have run.
The network rationale simply does not apply.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import fingerprint as _fp
from .findings import Finding

COPYLEFT = re.compile(r"\b(AGPL|GPL|SSPL|OSL|EUPL)\b", re.IGNORECASE)
PERMISSIVE = re.compile(r"\b(MIT|Apache|BSD|ISC|Unlicense|Zlib)\b", re.IGNORECASE)


def evaluate(project_licence: str | None, sbom_json: str) -> list[Finding]:
    try:
        sbom = json.loads(sbom_json or "{}")
    except json.JSONDecodeError:
        return []

    project_is_permissive = bool(project_licence and PERMISSIVE.search(project_licence))
    findings: list[Finding] = []
    undeclared: list[str] = []

    for component in sbom.get("components") or []:
        name = component.get("name", "")
        version = component.get("version", "")
        if not name:
            continue
        licences = _licences(component)

        if not licences:
            # Collected, not reported one by one. See below.
            undeclared.append(f"{name} {version}".strip())
            continue

        for licence in licences:
            if project_is_permissive and COPYLEFT.search(licence):
                findings.append(_finding(
                    "valvur.licence.copyleft-in-permissive", name, version, licence,
                    f"{name} {version} is {licence} in a {project_licence} project",
                    f"{licence} obligations may extend to your own source.",
                ))
    if undeclared:
        # ONE finding, not one per package. A real TypeScript project produced 618 of
        # these — 96% of its findings — burying two dozen genuine CVEs. Missing
        # licence metadata is a bulk property of the dependency tree, and
        # "618 dependencies declare no licence" is actionable where 618 separate
        # findings are just a wall.
        shown = ", ".join(sorted(undeclared)[:8])
        more = f" …and {len(undeclared) - 8} more" if len(undeclared) > 8 else ""
        findings.append(Finding(
            rule="valvur.licence.dependency-unknown",
            path="sbom.cdx.json",
            line=0,
            title=f"{len(undeclared)} dependencies declare no licence",
            evidence=f"{shown}{more}",
            fingerprint=_fp.for_licence("<dependencies>", "undeclared"),
            severity="low",
            sources=("valvur",),
        ))

    return findings


def _licences(component: dict) -> list[str]:
    out = []
    for entry in component.get("licenses") or []:
        value = entry.get("license", {}).get("id") or entry.get("license", {}).get("name")
        if not value:
            value = entry.get("expression")
        if value:
            out.append(str(value))
    return out


def _finding(rule, name, version, licence, title, evidence) -> Finding:
    return Finding(
        rule=rule,
        path="sbom.cdx.json",
        line=0,
        title=title,
        evidence=evidence,
        fingerprint=_fp.for_licence(f"{name}@{version}", licence),
        sources=("valvur",),
    )


def project_licence(workspace: Path) -> str | None:
    """The licence the project claims, as opposed to the one its LICENSE file is."""
    for name, pattern in (
        ("pyproject.toml", re.compile(r'^\s*license\s*=\s*[{\s]*(?:text\s*=\s*)?"([^"]+)"', re.M)),
        ("package.json", re.compile(r'"license"\s*:\s*"([^"]+)"')),
    ):
        path = workspace / name
        if path.is_file():
            match = pattern.search(path.read_text(encoding="utf-8", errors="replace"))
            if match:
                return match.group(1)
    return None
