"""Dependency Reality — does this package actually exist? (F3.1-F3.5)

The signature failure of AI-written code. Language models invent plausible package
names; attackers register them. **No advisory database can catch this**, because the
package is *new*, not known-bad — which is precisely why it needs its own Check.

Runs in-container (ADR-0013). On the `quick` Profile there is no network interface,
so this Check cannot reach a registry and fails loudly rather than reporting the
dependencies clean (F3.5). That honesty is enforced by the architecture.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

TIMEOUT = 10
NEW_PACKAGE_DAYS = 90
_UA = {"User-Agent": "valvur/0.1 (+https://github.com/MaverickHQ/valvur)"}

REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[=<>!~\[;].*)?$")

#: Manifests this Check reads. Everything else in the table below is declared as
#: *not* read, because the alternative is silence (task 19.D.3).
COVERED = ("requirements*.txt",)

#: Manifests that declare dependencies this Check does not inspect, mapped to the
#: ecosystem a reader would expect it to cover.
#:
#: Without this, a repository with no `requirements.txt` produced no findings and no
#: explanation — indistinguishable from one that was checked and found clean. Measured
#: 2026-09-10: an npm project with a deliberately non-existent package returned zero
#: findings. The most distinctive Check in the product was silently absent for most
#: repositories, which is the failure class this project exists to remove.
UNCOVERED: dict[str, str] = {
    "pyproject.toml": "Python (PEP 621 / Poetry)",
    "poetry.lock": "Python (Poetry)",
    "Pipfile": "Python (Pipenv)",
    "package.json": "npm",
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "npm (pnpm)",
    "yarn.lock": "npm (Yarn)",
    "Cargo.toml": "Rust (Cargo)",
    "go.mod": "Go",
    "Gemfile": "Ruby (Bundler)",
    "composer.json": "PHP (Composer)",
    "build.gradle": "JVM (Gradle)",
    "pom.xml": "JVM (Maven)",
}


class RegistryUnreachable(RuntimeError):
    """Raised so the run records this Check as failed rather than clean (F3.5)."""


class DependencyRealityCheck:
    name = "dependency-reality"

    def run(self, workspace: Path) -> list[dict]:
        # Reported first, and before the early return below: a repository with no
        # `requirements.txt` used to exit here with nothing at all, which is exactly
        # the case where the gap most needs stating (task 19.D.3).
        findings: list[dict] = list(_coverage_gap(workspace))

        declared = _declared_packages(workspace)
        if not declared:
            return findings

        popular = _popular()
        reached_any = False

        for name, source in sorted(declared):
            try:
                meta = _pypi(name)
                reached_any = True
            except RegistryUnreachable:
                continue

            if meta is None:
                # A nonexistent name that is one edit from a popular package is
                # almost always a typo, and saying so is far more useful than
                # reporting absence alone.
                suggestion = _near_miss(name, popular)
                findings.append(_finding(
                    "valvur.dependency.nonexistent", name, source,
                    f"'{name}' does not exist on PyPI"
                    + (f" — did you mean '{suggestion}'?" if suggestion else ""),
                    "A dependency that does not exist was almost certainly hallucinated. "
                    "If someone registers that name, your next install runs their code.",
                ))
                continue

            age = _age_days(meta)
            if age is not None and age < NEW_PACKAGE_DAYS:
                findings.append(_finding(
                    "valvur.dependency.newly-registered", name, source,
                    f"'{name}' was first published {int(age)} day(s) ago",
                    "Recently registered packages matching a plausible name are the "
                    "slopsquat pattern. Confirm this is the package you meant.",
                ))

            near = _near_miss(name, popular)
            if near:
                findings.append(_finding(
                    "valvur.dependency.near-miss", name, source,
                    f"'{name}' is one character from the far more popular '{near}'",
                    f"Typosquat pattern. Did you mean '{near}'?",
                ))

        if declared and not reached_any:
            raise RegistryUnreachable(
                f"No registry was reachable, so {len(declared)} dependency name(s) "
                "could not be verified. They are NOT reported as clean. "
                "Re-run on the standard profile, which permits registry lookups."
            )
        return findings


def _coverage_gap(workspace: Path):
    """State the manifests this Check did not read, so their silence is not mistaken
    for a clean result.

    One finding per ecosystem rather than per file: a monorepo with forty
    `package.json` files has one gap, not forty. The same lesson the licence Check
    learned when 618 undeclared dependencies buried two dozen real CVEs.
    """
    from .. import exclusions

    seen: dict[str, list[str]] = {}
    for manifest, ecosystem in UNCOVERED.items():
        for path in sorted(workspace.rglob(manifest)):
            relative = str(path.relative_to(workspace))
            if exclusions.is_vendored(relative):
                continue          # a dependency's own manifest is not this project's
            seen.setdefault(ecosystem, []).append(relative)

    for ecosystem, paths in sorted(seen.items()):
        shown = ", ".join(paths[:3])
        more = f" and {len(paths) - 3} more" if len(paths) > 3 else ""
        yield {
            "rule": "valvur.dependency.ecosystem-not-covered",
            "path": paths[0],
            "line": 0,
            "severity": "low",
            "title": f"{ecosystem} dependencies were not checked for existence",
            "evidence": (
                f"Found {shown}{more}. The Dependency Reality Check currently reads "
                f"{' and '.join(COVERED)} against PyPI only, so no {ecosystem} "
                "dependency here was verified to exist. This is missing coverage, "
                "not a clean result — see task 19.D.1."
            ),
            "identity": ("dependency_reality_gap", ecosystem),
        }


def _declared_packages(workspace: Path) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for req in workspace.rglob("requirements*.txt"):
        rel = str(req.relative_to(workspace))
        for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith("-") or "git+" in line:
                continue
            match = REQUIREMENT.match(line)
            if match:
                found.add((match.group(1).lower(), rel))
    return found


def _pypi(name: str) -> dict | None:
    request = urllib.request.Request(f"https://pypi.org/pypi/{name}/json", headers=_UA)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None          # definitively absent — the headline finding
        raise RegistryUnreachable(str(exc)) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise RegistryUnreachable(str(exc)) from exc


def _age_days(meta: dict) -> float | None:
    stamps = [
        f["upload_time_iso_8601"]
        for files in (meta.get("releases") or {}).values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    if not stamps:
        return None
    first = min(stamps).replace("Z", "+00:00")
    return (datetime.now(UTC) - datetime.fromisoformat(first)).days


def _popular() -> set[str]:
    path = Path(__file__).resolve().parent.parent / "data" / "popular-pypi.json"
    if not path.is_file():
        return set()
    return {n.lower() for n in json.loads(path.read_text())["packages"]}


def _near_miss(name: str, popular: set[str]) -> str | None:
    if name in popular:
        return None
    for candidate in popular:
        if abs(len(candidate) - len(name)) <= 1 and _within_one_edit(name, candidate):
            return candidate
    return None


def _within_one_edit(a: str, b: str) -> bool:
    """Damerau-Levenshtein distance of 1: substitution, insertion, deletion, or a
    TRANSPOSITION of adjacent characters.

    Transposition matters. 'reqeusts' for 'requests' is distance 1 under Damerau but
    2 under plain substitution, and swapped adjacent letters are one of the commonest
    typosquat forms precisely because they read correctly at a glance.
    """
    if a == b:
        return False
    if len(a) == len(b):
        differing = [i for i, (x, y) in enumerate(zip(a, b, strict=True)) if x != y]
        if len(differing) == 1:
            return True
        if len(differing) == 2:
            i, j = differing
            return j == i + 1 and a[i] == b[j] and a[j] == b[i]
        return False
    short, long = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(long)):
        if long[:i] + long[i + 1:] == short:
            return True
    return False


def _finding(rule: str, name: str, source: str, title: str, evidence: str) -> dict:
    return {
        "rule": rule,
        "path": source,
        "line": 0,
        "title": title,
        "evidence": evidence,
        "identity": ("dependency_reality", "pip", name),
    }
