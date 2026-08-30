"""Trivy — dependency vulnerabilities.

Runs against a host-cached vulnerability DB with --skip-db-update, so the scan itself
makes no network connection (ADR-0012, N2.1).
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import fingerprint as _fp
from ..findings import Dependency, Exploit, Finding
from ..runner import ScannerOutput
from .base import container_relative


class TrivyAdapter:
    kind = "scanner"
    name = "trivy"

    def run(self, runner, workspace: Path) -> ScannerOutput:
        return runner.run_trivy(workspace)

    def parse(self, output: ScannerOutput) -> list[Finding]:
        report = json.loads(output.stdout or "{}")
        findings: list[Finding] = []

        for result in report.get("Results") or []:
            # The dependency graph lives in Packages[].DependsOn, not on the
            # vulnerability records — and only for lockfiles. A flat manifest like
            # requirements.txt has no transitive information to report, so there is
            # genuinely no path to give (verified, task 5.4.12).
            parents = _parent_map(result.get("Packages") or [])
            # Trivy reports a target, not always a path — a lockfile, an image layer,
            # or an OS package database. container_relative handles the path case.
            target = container_relative(str(result.get("Target", "")))
            ecosystem = str(result.get("Type", "unknown"))

            for vuln in result.get("Vulnerabilities") or []:
                package = vuln["PkgName"]
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion") or ""
                findings.append(
                    Finding(
                        rule=vuln["VulnerabilityID"],
                        path=target,
                        line=0,  # a dependency has no line; identity never uses one
                        title=f"{package} {installed} — {vuln.get('Title', 'vulnerability')}",
                        evidence=_advice(package, installed, fixed, parents),
                        fingerprint=_fp.for_dependency_vuln(
                            ecosystem, package, installed, vuln["VulnerabilityID"]
                        ),
                        sources=(output.tool,),
                        severity=str(vuln.get("Severity", "unknown")).lower(),
                        exploit=Exploit(cve=vuln["VulnerabilityID"]),
                        dependency=Dependency(
                            ecosystem=ecosystem,
                            package=package,
                            version=installed,
                            fixed_version=fixed,
                            purl=str((vuln.get("PkgIdentifier") or {}).get("PURL", "")),
                            scope=_scope(target),
                            direct=_pkg_id(package, installed) not in parents or None,
                            path=_path_to_root(
                                _pkg_id(package, installed), parents
                            ),
                        ),
                    )
                )
        return findings


# requirements-dev.txt and friends never ship. A CVE there is real but not urgent,
# and treating it as urgent is how a scanner teaches people to ignore it (F6.6).
_DEV_HINTS = ("dev", "test", "tests", "ci", "lint", "doc", "docs")


def _scope(target: str) -> str:
    if not target:
        return "unknown"
    lowered = target.lower()
    segments = [seg for seg in lowered.replace("\\", "/").split("/") if seg]
    # A directory named tests/ or ci/ anywhere in the path, or a filename suffixed
    # -dev / _test, means this dependency does not ship.
    if any(seg in _DEV_HINTS for seg in segments[:-1]):
        return "development"
    stem = segments[-1].rsplit(".", 1)[0]
    parts = stem.replace("-", " ").replace("_", " ").replace(".", " ").split()
    if any(part in _DEV_HINTS for part in parts):
        return "development"
    return "production"


def _pkg_id(name: str, version: str) -> str:
    return f"{name}@{version}" if version else name


def _parent_map(packages: list[dict]) -> dict[str, str]:
    """child -> parent, from Trivy's DependsOn edges."""
    parents: dict[str, str] = {}
    for pkg in packages:
        for child in pkg.get("DependsOn") or []:
            parents.setdefault(child, pkg.get("ID", ""))
    return parents


def _path_to_root(pkg_id: str, parents: dict[str, str]) -> tuple[str, ...]:
    """Walk up to the direct dependency, so the developer knows what to change."""
    chain = [pkg_id]
    seen = {pkg_id}
    current = pkg_id
    while current in parents:
        current = parents[current]
        if current in seen or not current:
            break                      # cycles exist in real lockfiles
        seen.add(current)
        chain.append(current)
    return tuple(reversed(chain))


def _advice(package: str, installed: str, fixed: str, parents: dict[str, str]) -> str:
    """Name the package the developer can actually change.

    'Upgrade json5' is useless when json5 is three levels down and pinned by
    something else. The direct dependency is the actionable one (F6.9).
    """
    chain = _path_to_root(_pkg_id(package, installed), parents)
    root = chain[0] if len(chain) > 1 else ""
    if not fixed:
        return f"no fixed version available for {package}"
    if root:
        return (
            f"upgrade {package} to {fixed} — reached via {' → '.join(chain)}; "
            f"change {root.split('@')[0]}"
        )
    return f"upgrade {package} to {fixed}"
