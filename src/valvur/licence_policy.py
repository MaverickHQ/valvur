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

    for component in sbom.get("components") or []:
        name = component.get("name", "")
        version = component.get("version", "")
        if not name:
            continue
        licences = _licences(component)

        if not licences:
            findings.append(_finding(
                "valvur.licence.dependency-unknown", name, version, "unknown",
                f"{name} {version} declares no licence",
                "A dependency of unknown licence cannot be cleared for release.",
            ))
            continue

        for licence in licences:
            if project_is_permissive and COPYLEFT.search(licence):
                findings.append(_finding(
                    "valvur.licence.copyleft-in-permissive", name, version, licence,
                    f"{name} {version} is {licence} in a {project_licence} project",
                    f"{licence} obligations may extend to your own source.",
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
