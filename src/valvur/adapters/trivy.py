"""Trivy — dependency vulnerabilities.

Runs against a host-cached vulnerability DB with --skip-db-update, so the scan itself
makes no network connection (ADR-0012, N2.1).
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import ecosystems as _ecosystems
from .. import fingerprint as _fp
from ..coverage import Coverage
from ..findings import Dependency, Exploit, Finding
from ..invocation import Invocation, ScannerOutput
from ..versions import version_key
from .base import ScannerAdapter, container_relative

VERSION = "0.74.0"

DB_REFUSAL = (
    "Trivy vulnerability database not present. Fetch it once with:\n"
    "  valvur update\n"
    "Scans then run fully offline against the cached database."
)


def db_flags() -> list[str]:
    """Trivy's own switches for a mirrored database (F10.5, 22.B.3): where to
    fetch it from, and `--insecure` for a mirror that speaks plain HTTP or a
    certificate the container does not trust. Read from the two settings the
    runner names; the flags are Trivy's and so are here."""
    import os

    from .. import runner as _runner

    mirror = _runner.db_repository()
    if not mirror:
        return []                    # the default path is TLS to ghcr.io; never insecure
    flags = ["--db-repository", mirror]
    if os.environ.get(_runner.DB_INSECURE_ENV) == "1":
        flags.append("--insecure")
    return flags


def database_fetch() -> Invocation:
    """`valvur update`'s fetch of the vulnerability database: Trivy, told to
    download its database and nothing else, with a network. The runner runs it
    under the cache lock (task 16.3); the command is Trivy's (26.2.1)."""
    return Invocation(
        tool="trivy-db", version="",
        argv=("trivy", "image", "--download-db-only", "--cache-dir", "/cache/trivy",
              *db_flags()),
        report=None, network=True, timeout=900,
    )


class TrivyAdapter(ScannerAdapter):
    kind = "scanner"
    name = "trivy"
    version = VERSION

    def command(self, workspace: Path) -> Invocation:
        from .. import cache

        if not cache.db_present():
            # Refused here, before a container starts, so the message leads with
            # the fix rather than arriving as Trivy's stderr.
            raise RuntimeError(DB_REFUSAL)
        return Invocation(
            tool=self.name, version=VERSION,
            argv=(
                "trivy", "fs", "/workspace",
                "--cache-dir", "/cache/trivy",
                *db_flags(),
                "--skip-db-update", "--skip-java-db-update",
                "--format", "json", "--output", "/results/trivy.json",
                "--quiet", "--scanners", "vuln",
                # Trivy excludes dev dependencies by default; OSV-Scanner includes
                # them. Measured on a real Electron app: without this the quick
                # profile found 0 CVEs and standard found 24 — the same 24, in the
                # same lockfile, differing only by this flag. Build and test tooling
                # runs on the developer's machine and in CI, which is precisely the
                # supply-chain surface this product exists to cover.
                "--include-dev-deps",
            ),
            report="trivy.json", timeout=600,
        )

    def coverage(self, workspace: Path, exclude: tuple[str, ...] = ()) -> Coverage:
        """What Trivy reads for known vulnerabilities, and the ecosystems present here
        for which none of it exists (22.E.1). The corpus's first finding: Express
        commits no lockfile, Trivy produced no result, and the run read `clean`."""
        from .. import coverage as _coverage

        reads = tuple(
            f"{_ecosystems.MANIFESTS[key].label}: {', '.join(files)}"
            for key, files in sorted(_ecosystems.VULNERABILITY_MANIFESTS.items())
            if key in _ecosystems.MANIFESTS
        )
        return Coverage(
            inspects=reads,
            ignores=("a manifest with no lockfile beside it: package.json, "
                     "pyproject.toml, Gemfile, Cargo.toml alone are not scanned",),
            gaps=tuple(_coverage.vulnerability_gaps(workspace, exclude)),
        )

    def parse(self, output: ScannerOutput) -> list[Finding]:
        report = json.loads(output.stdout or "{}")
        findings: list[Finding] = []

        for result in report.get("Results") or []:
            # The dependency graph lives in Packages[].DependsOn, not on the
            # vulnerability records — and only for lockfiles. A flat manifest like
            # requirements.txt has no transitive information to report, so there is
            # genuinely no path to give (verified, task 5.4.12).
            parents = _parent_map(result.get("Packages") or [])
            # Trivy marks each package dev-or-not; the vulnerability records do not
            # carry it. Now that dev dependencies are scanned, saying which findings
            # reach shipped code is the difference between 24 findings and 24
            # findings a developer can triage.
            dev = {
                (pkg.get("Name"), pkg.get("Version")): bool(pkg.get("Dev"))
                for pkg in result.get("Packages") or []
            }
            # Trivy reports a target, not always a path — a lockfile, an image layer,
            # or an OS package database. container_relative handles the path case.
            target = container_relative(str(result.get("Target", "")))
            # Trivy reports the lockfile FORMAT ("pnpm"), not the ecosystem ("npm").
            ecosystem = _ecosystems.normalise(str(result.get("Type", "")))

            for vuln in result.get("Vulnerabilities") or []:
                package = vuln["PkgName"]
                installed = vuln.get("InstalledVersion", "")
                fixed = _minimal_fix(vuln.get("FixedVersion") or "", installed)
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
                            scope=_scope_for(target, dev.get((package, installed))),
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


def _scope_for(target: str, is_dev: bool | None) -> str:
    """Trivy's own dev flag beats inferring scope from the target path."""
    if is_dev is None:
        return _scope(target)
    return "development" if is_dev else "production"


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


def _minimal_fix(fixed: str, installed: str) -> str:
    """One target, the minimal one (23.5.5). Trivy reports a fix per release line,
    comma-joined — `"2.2.2, 1.0.2"` for json5 1.0.1 — and copying the string put two
    versions in one action, the major jump first. The smallest fix above the
    installed version is the upgrade that works, the answer OSV's adapter already
    gives from the same ordering. When nothing in the list is above the installed
    version, Trivy's own words are kept: they are its claim, and `raw/` must agree."""
    parts = [part.strip() for part in fixed.split(",") if part.strip()]
    if len(parts) < 2:
        return fixed
    above = [part for part in parts if version_key(part) > version_key(installed)]
    return min(above, key=version_key) if above else fixed


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
