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


def _is_dependency(component: dict) -> bool:
    """Whether an SBOM component is a dependency whose licence we can sensibly ask
    about.

    Syft catalogues more than packages. Workflow YAML and lockfiles arrive as type
    "file", with container paths for names. GitHub Actions arrive as type "library"
    with a pkg:github purl — they are workflow steps pinned by git ref, not licensed
    packages, and the pinning rule already covers the risk they actually carry.
    Counting either inflates "N dependencies declare no licence" with things that
    have no licence to declare.
    """
    if component.get("type") == "file":
        return False
    return not str(component.get("purl") or "").startswith("pkg:github/")


def evaluate(project_licence: str | None, sbom_json: str) -> list[Finding]:
    try:
        sbom = json.loads(sbom_json or "{}")
    except json.JSONDecodeError:
        return []

    project_is_permissive = bool(project_licence and PERMISSIVE.search(project_licence))
    findings: list[Finding] = []
    undeclared: list[str] = []

    components = [c for c in (sbom.get("components") or []) if _is_dependency(c)]
    for component in components:
        name = component.get("name", "")
        version = component.get("version", "")
        # Syft catalogues workflow YAML and lockfiles as type "file". They are not
        # dependencies, they carry no licence to declare, and their names are
        # container paths — counting them inflated the total and leaked /workspace
        # into evidence that ends up in a committed suppressions file.
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
    # Licence metadata for npm lives in each package's own package.json, which is
    # absent when only a lockfile is present. Reporting "618 dependencies declare no
    # licence" then states as fact something we simply could not read. Saying so is
    # a coverage statement, and it comes with an action that actually works.
    if undeclared and components and len(undeclared) >= 0.9 * len(components):
        findings.append(Finding(
            rule="valvur.licence.dependencies-unreadable",
            path="sbom.cdx.json",
            line=0,
            title=(
                f"Licences could not be determined for {len(undeclared)} of "
                f"{len(components)} dependencies"
            ),
            evidence=(
                "Licence metadata ships inside each installed package, not in the "
                "lockfile. Install dependencies and rescan to resolve them."
            ),
            fingerprint=_fp.for_licence("<dependencies>", "unreadable"),
            severity="low",
            sources=("valvur",),
        ))
    elif undeclared:
        # ONE finding, not one per package. A real TypeScript project produced 618 of
        # these — 96% of its findings — burying two dozen genuine CVEs. Missing
        # licence metadata is a bulk property of the dependency tree, and
        # one aggregated count is actionable where 618 separate
        # findings are just a wall.
        shown = ", ".join(sorted(undeclared)[:8])
        more = f" …and {len(undeclared) - 8} more" if len(undeclared) > 8 else ""
        findings.append(Finding(
            rule="valvur.licence.dependency-unknown",
            path="sbom.cdx.json",
            line=0,
            title=f"{len(undeclared)} dependencies have no licence recorded",
            evidence=(
                f"{shown}{more}. Not the same as declaring none: the SBOM is the "
                "source, and licence detection is partial — a package declaring its "
                "licence only through PyPI classifiers, for instance, records none "
                "here. Check upstream before treating this as a compliance gap."
            ),
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
