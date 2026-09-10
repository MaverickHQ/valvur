"""Dependency Reality — does this package actually exist? (F3.1-F3.5)

The signature failure of AI-written code. Language models invent plausible package
names; attackers register them. **No advisory database can catch this**, because the
package is *new*, not known-bad — which is precisely why it needs its own Check.

Runs in-container (ADR-0013). On the `offline` Profile there is no network interface,
so this Check cannot reach a registry and fails loudly rather than reporting the
dependencies clean (F3.5). That honesty is enforced by the architecture.

Covers **Python** (`requirements*.txt`, and `pyproject.toml` in both PEP 621 and
Poetry shapes) against PyPI, and **npm** (`package.json`) against the npm registry.
Everything else is reported as missing coverage by `valvur.coverage` rather than
passed over — which is the half that stays true however many ecosystems are added,
because something is always uncovered.

Direct manifests only, never lockfiles. A lockfile is a resolved transitive tree, and
transitive dependencies are not the ones a language model invents: the hallucination
is written into the file a human or an agent edited.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

TIMEOUT = 10
NEW_PACKAGE_DAYS = 90
_UA = {"User-Agent": "valvur/0.1 (+https://github.com/MaverickHQ/valvur)"}

REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[=<>!~\[;].*)?$")

#: `pyproject.toml` keys that hold dependency *names*, in the two shapes that are
#: common in the wild. PEP 621 lists requirement strings; Poetry uses a table whose
#: keys are the names. Both are parsed because both are everywhere, and a project
#: using the one we skipped would scan clean for the wrong reason.
_POETRY_SKIP = {"python"}

#: `package.json` keys that declare registry dependencies. `peerDependencies` is
#: included: a hallucinated peer is still a name someone can register.
_NPM_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")

#: Specs that do not name a registry package — a local path, a git URL, a workspace
#: sibling. Checking these against the registry would report every monorepo package as
#: nonexistent, which is the false positive most likely to make a real finding ignored.
_NOT_REGISTRY = ("file:", "link:", "workspace:", "git+", "git:", "http://", "https://", "portal:")


class RegistryUnreachable(RuntimeError):
    """Raised so the run records this Check as failed rather than clean (F3.5)."""


class DependencyRealityCheck:
    name = "dependency-reality"

    def run(self, workspace: Path) -> list[dict]:
        # Coverage gaps are NOT reported here any more. They were, until a local
        # corpus showed the consequence: this Check needs the network, so it does not
        # run on the default Profile at all, and the one message that says "this scan
        # could not help you" was absent from the Profile almost everyone uses. The
        # gap is a static fact about files on disk — it belongs somewhere that runs
        # unconditionally. See `valvur/coverage.py` (task 19.D.1, C1).
        findings: list[dict] = []

        declared = _declared_packages(workspace)
        if not declared:
            return findings

        popular = _popular()
        reached_any = False

        for ecosystem, name, source in sorted(declared):
            try:
                meta = _lookup(ecosystem, name)
                reached_any = True
            except RegistryUnreachable:
                continue

            registry = _REGISTRY_NAME[ecosystem]
            if meta is None:
                # A nonexistent name that is one edit from a popular package is
                # almost always a typo, and saying so is far more useful than
                # reporting absence alone.
                suggestion = _near_miss(name, popular) if ecosystem == "pip" else None
                findings.append(_finding(
                    "valvur.dependency.nonexistent", ecosystem, name, source, "high",
                    f"'{name}' does not exist on {registry}"
                    + (f" — did you mean '{suggestion}'?" if suggestion else ""),
                    "A dependency that does not exist was almost certainly hallucinated. "
                    "If someone registers that name, your next install runs their code.",
                ))
                continue

            age = _age_days(ecosystem, meta)
            if age is not None and age < NEW_PACKAGE_DAYS:
                findings.append(_finding(
                    "valvur.dependency.newly-registered", ecosystem, name, source, "medium",
                    f"'{name}' was first published {int(age)} day(s) ago",
                    "Recently registered packages matching a plausible name are the "
                    "slopsquat pattern. Confirm this is the package you meant.",
                ))

            # PyPI only. The near-miss comparison needs a corpus of popular names and
            # only PyPI's ships in the image, so npm names are checked for existence
            # and not for similarity. Declared in the Check's Coverage rather than
            # left for a reader to infer from silence.
            near = _near_miss(name, popular) if ecosystem == "pip" else None
            if near:
                findings.append(_finding(
                    "valvur.dependency.near-miss", ecosystem, name, source, "medium",
                    f"'{name}' is one character from the far more popular '{near}'",
                    f"Typosquat pattern. Did you mean '{near}'?",
                ))

        if declared and not reached_any:
            raise RegistryUnreachable(
                f"No registry was reachable, so {len(declared)} dependency name(s) "
                "could not be verified. They are NOT reported as clean. "
                "Re-run with `--profile full`, which permits registry lookups."
            )
        return findings


def _declared_packages(workspace: Path) -> set[tuple[str, str, str]]:
    """Every directly-declared dependency, as (ecosystem, name, manifest path).

    Ecosystem travels with the name because the same string is a different package in
    two registries — and because the registry to ask is decided here, once, rather
    than guessed later.
    """
    found: set[tuple[str, str, str]] = set()
    for path in _manifests(workspace, "requirements*.txt"):
        found |= _from_requirements(path, workspace)
    for path in _manifests(workspace, "pyproject.toml"):
        found |= _from_pyproject(path, workspace)
    for path in _manifests(workspace, "package.json"):
        found |= _from_package_json(path, workspace)
    return found


def _manifests(workspace: Path, pattern: str):
    from .. import exclusions

    for path in sorted(workspace.rglob(pattern)):
        if path.is_file() and not exclusions.is_vendored(str(path.relative_to(workspace))):
            yield path


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _from_requirements(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    rel = str(path.relative_to(workspace))
    found: set[tuple[str, str, str]] = set()
    for line in _text(path).splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-") or "git+" in line:
            continue
        match = REQUIREMENT.match(line)
        if match:
            found.add(("pip", match.group(1).lower(), rel))
    return found


def _from_pyproject(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    """PEP 621 and Poetry, because both are common and a project using the shape we
    skipped would scan clean for the wrong reason.

    A malformed manifest yields nothing rather than raising: this Check exists to
    report hallucinated packages, and failing the whole Scanner over a TOML syntax
    error would take the real findings down with it.
    """
    import tomllib

    rel = str(path.relative_to(workspace))
    try:
        data = tomllib.loads(_text(path))
    except (tomllib.TOMLDecodeError, ValueError):
        return set()

    found: set[tuple[str, str, str]] = set()

    project = data.get("project") or {}
    specs = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        specs += list(group or [])
    for spec in specs:
        if not isinstance(spec, str) or "git+" in spec or "@" in spec.split(";")[0]:
            continue          # a direct URL reference names no registry package
        match = REQUIREMENT.match(spec.strip())
        if match:
            found.add(("pip", match.group(1).lower(), rel))

    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies") or {}]
    tables += [
        (group or {}).get("dependencies") or {}
        for group in (poetry.get("group") or {}).values()
    ]
    for table in tables:
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            # `python = "^3.11"` is the interpreter constraint, not a package; and a
            # table-valued spec with `path`/`git`/`url` is not from the registry.
            if name.lower() in _POETRY_SKIP:
                continue
            if isinstance(spec, dict) and not spec.keys() & {"version", "extras"}:
                continue
            found.add(("pip", name.lower(), rel))

    return found


def _from_package_json(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    rel = str(path.relative_to(workspace))
    try:
        data = json.loads(_text(path))
    except (json.JSONDecodeError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()

    found: set[tuple[str, str, str]] = set()
    for field in _NPM_FIELDS:
        table = data.get(field)
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if not isinstance(name, str) or not name:
                continue
            if isinstance(spec, str) and spec.startswith(_NOT_REGISTRY):
                continue
            # npm names are lowercase by rule, and case-insensitive at the registry.
            found.add(("npm", name.lower(), rel))
    return found


#: Where each ecosystem's names are verified, named as a reader would name it.
_REGISTRY_NAME = {"pip": "PyPI", "npm": "the npm registry"}


def _lookup(ecosystem: str, name: str) -> dict | None:
    """Registry metadata, or None when the package definitively does not exist.

    One dispatch rather than a call site per ecosystem: the 404-versus-unreachable
    distinction is the load-bearing part of F3.5 — *absent* is a finding, *could not
    ask* must never be reported as clean — and writing it twice is how the two answers
    end up drifting apart.
    """
    if ecosystem == "npm":
        # `safe="@/"`: a scoped name is `@scope/name`, and the slash stays a slash.
        # Measured against registry.npmjs.org 2026-09-10, all of `@types/node`,
        # `@types%2Fnode` and `@types%2fnode` return 200 — so this is not a live bug
        # there. It is the canonical form npm itself uses, and private mirrors
        # (Artifactory, Verdaccio, Nexus) are stricter than npmjs.org about the
        # encoded variant. This product's users are disproportionately behind one.
        return _fetch(f"https://registry.npmjs.org/{quote(name, safe='@/')}")
    return _fetch(f"https://pypi.org/pypi/{quote(name, safe='')}/json")


def _fetch(url: str) -> dict | None:
    # Both callers build this from a literal https:// prefix and a percent-quoted
    # package name, so no caller-controlled scheme can reach here. Asserted rather
    # than assumed, because a scheme reaching urlopen is how a dependency name turns
    # into a file read.
    if not url.startswith("https://"):
        raise RegistryUnreachable(f"refusing a non-https registry URL: {url!r}")
    request = urllib.request.Request(url, headers=_UA)  # noqa: S310 — asserted above
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            body = json.load(response)
            return body if isinstance(body, dict) else {}
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 405):
            return None          # definitively absent — the headline finding
        raise RegistryUnreachable(str(exc)) from exc
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
        raise RegistryUnreachable(str(exc)) from exc


def _age_days(ecosystem: str, meta: dict) -> float | None:
    stamps: list[str] = []
    if ecosystem == "npm":
        created = (meta.get("time") or {}).get("created")
        if isinstance(created, str):
            stamps = [created]
    else:
        stamps = [
            f["upload_time_iso_8601"]
            for files in (meta.get("releases") or {}).values()
            for f in files
            if f.get("upload_time_iso_8601")
        ]
    if not stamps:
        return None
    first = min(stamps).replace("Z", "+00:00")
    try:
        return (datetime.now(UTC) - datetime.fromisoformat(first)).days
    except ValueError:
        return None


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


def _finding(
    rule: str, ecosystem: str, name: str, source: str, severity: str,
    title: str, evidence: str,
) -> dict:
    """Severity is stated rather than defaulted.

    Every finding from this Check used to arrive as `unknown`, including the one the
    product exists for: a dependency that does not exist is the signature failure of
    AI-written code, and it ranked below a missing licence file. `high` rather than
    `critical` — nobody has registered the name yet, and if someone has, the CVE
    Scanners are the ones that will say so.
    """
    return {
        "rule": rule,
        "path": source,
        "line": 0,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        # The canonical ecosystem is part of identity, and "pip" is spelled exactly as
        # before: changing it would alter every existing Python fingerprint and
        # invalidate every committed suppression keyed on one (ADR-0003).
        "identity": ("dependency_reality", ecosystem, name),
    }
