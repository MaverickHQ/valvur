"""Dependency Reality — does this package actually exist? (F3.1-F3.5)

The signature failure of AI-written code. Language models invent plausible package
names; attackers register them. **No advisory database can catch this**, because the
package is *new*, not known-bad — which is precisely why it needs its own Check.

Runs in-container (ADR-0013), on **both** Profiles. Existence is answered from the
package-name index in the host cache (ADR-0018), mounted read-only at `/cache/names`,
so the hallucination check needs no socket; the near-miss comparison uses the popular
list shipped in the image. Only first-publish age still asks a registry, and only on
`full` — the container tells the Check whether it was given a network
(`VALVUR_NETWORK=1`), and the Check never guesses. No index on a Profile without a
network is a loud failure with the command that fixes it, never a clean result (F3.5).

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
import os
import re
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

TIMEOUT = 10
NEW_PACKAGE_DAYS = 90

#: Where the runner mounts the host cache's name index (ADR-0018), and the variable
#: the runner sets when — and only when — the container was launched with a network.
INDEX_MOUNT = "/cache/names"
INDEX_ENV = "VALVUR_NAME_INDEX"
NETWORK_ENV = "VALVUR_NETWORK"
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


class IndexMissing(RuntimeError):
    """No index for an ecosystem this Workspace declares, and no network to ask
    instead. Raised so the run records this Check as failed, with the fix."""


class DependencyRealityCheck:
    name = "dependency-reality"

    def run(self, workspace: Path) -> list[dict]:
        # Coverage gaps are NOT reported here. They were, until a local corpus showed
        # the consequence: at the time this Check needed the network and did not run
        # on the default Profile at all, so the one message that says "this scan
        # could not help you" was absent from the Profile almost everyone uses. The
        # gap is a static fact about files on disk — it belongs somewhere that runs
        # unconditionally. See `valvur/coverage.py` (task 19.D.1, C1).
        findings: list[dict] = []

        declared = _declared_packages(workspace)
        if not declared:
            return findings

        from .. import name_index as _index

        popular = _popular()
        network = _network_allowed()
        indexes = {eco: _index.open_index(_index_dir(), eco) for eco in {d[0] for d in declared}}
        try:
            unindexed = sorted(eco for eco, idx in indexes.items() if idx is None)
            if unindexed and not network:
                # Fail with the command that fixes it, the way Trivy fails without its
                # database. Raising rather than returning [] is the whole of F3.5:
                # "could not check" must never read as "checked and found nothing".
                raise IndexMissing(
                    "Run `valvur update`: no package-name index for "
                    f"{', '.join(_REGISTRY_NAME[e] for e in unindexed)}, so "
                    f"{len(declared)} dependency name(s) were NOT verified (and are "
                    "NOT clean)."
                )
            findings, reached_any, asked_any = self._verify(declared, indexes, popular, network)
        finally:
            for idx in indexes.values():
                if idx is not None:
                    idx.close()

        if asked_any and not reached_any:
            # Two different situations, each with its own fix. Naming the wrong one
            # sends a user without an index to a Profile that will fail for the
            # other reason.
            if unindexed:
                raise RegistryUnreachable(
                    f"No registry was reachable, so {len(declared)} dependency name(s) "
                    "could not be verified. They are NOT reported as clean. Run "
                    "`valvur update` to fetch the package-name index, which answers "
                    "existence with no registry at all; re-run when the network is "
                    "available for package age."
                )
            raise RegistryUnreachable(
                "No registry was reachable, so first-publish age could not be checked. "
                "Existence was verified from the local index, but this Profile promises "
                "more than that, and the result is NOT reported as clean. Re-run when the "
                "network is available, or with `--profile offline`, which does not ask."
            )
        return findings

    def _verify(self, declared, indexes, popular, network) -> tuple[list[dict], bool, bool]:
        """The per-package decisions. Returns (findings, reached a registry, asked one).

        Two passes. The first decides existence from the index and collects what the
        registry still has to be asked; the second asks it, concurrently; then the
        findings are built in declaration order so the output is reproducible
        whatever order the answers arrived in.
        """
        findings: list[dict] = []
        ordered = sorted(declared)

        # Existence, locally where there is an index. `None` means the registry has
        # to answer it — no index for this ecosystem, and a network to ask with.
        known: dict[tuple[str, str], bool | None] = {}
        for ecosystem, name, _ in ordered:
            index = indexes[ecosystem]
            known[(ecosystem, name)] = (
                index.contains(_index_form(ecosystem, name)) if index is not None else None
            )

        # What still needs a registry: existence where there was no index, and age
        # for every name that exists — asked only with a network, and never about a
        # name the index has already settled as absent.
        to_ask = [key for key, exists in known.items() if exists is not False] if network else []
        answers = _lookup_many(to_ask)
        asked_any = bool(to_ask)
        reached_any = any(not isinstance(a, RegistryUnreachable) for a in answers.values())

        for ecosystem, name, source in ordered:
            key = (ecosystem, name)
            exists = known[key]
            meta: dict | None = None
            if exists is None:
                # No index but a network: the registry answers existence as well as
                # age, which is what this Check did before ADR-0018.
                answer = answers.get(key)
                if isinstance(answer, RegistryUnreachable):
                    continue
                meta = answer
                exists = meta is not None

            registry = _REGISTRY_NAME[ecosystem]
            if not exists:
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

            # PyPI only. The near-miss comparison needs a corpus of popular names and
            # only PyPI's ships in the image, so npm names are checked for existence
            # and not for similarity. Declared in the Check's Coverage rather than
            # left for a reader to infer from silence. Local: it never needed a
            # registry, and until ADR-0018 it was withheld offline for no reason.
            near = _near_miss(name, popular) if ecosystem == "pip" else None
            if near:
                findings.append(_finding(
                    "valvur.dependency.near-miss", ecosystem, name, source, "medium",
                    f"'{name}' is one character from the far more popular '{near}'",
                    f"Typosquat pattern. Did you mean '{near}'?",
                ))

            # First-publish age is the one question that still needs a registry, so
            # it is asked only with a network — and only about names the index has
            # already said exist. A nonexistent name is settled locally and never
            # leaves the machine.
            if not network:
                continue
            if meta is None:
                answer = answers.get(key)
                if isinstance(answer, RegistryUnreachable):
                    continue
                meta = answer
                if meta is None:
                    # The index said it exists and the registry says it does not:
                    # unpublished since the index was built. Report it — an
                    # unpublished name is exactly the one an attacker re-registers.
                    findings.append(_finding(
                        "valvur.dependency.nonexistent", ecosystem, name, source, "high",
                        f"'{name}' no longer exists on {registry}",
                        "This package was in the local index but the registry no longer "
                        "has it. A name that has just been freed is the slopsquat target.",
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

        return findings, reached_any, asked_any


def _network_allowed() -> bool:
    """Whether the runner launched this container with a network. The runner sets
    the variable in exactly the case it omits `--network=none`, so the Check reads
    the same decision the kernel enforces rather than probing for a socket."""
    return os.environ.get(NETWORK_ENV) == "1"


def _index_dir() -> Path:
    return Path(os.environ.get(INDEX_ENV) or INDEX_MOUNT)


def _index_form(ecosystem: str, name: str) -> str:
    """The spelling the index stores: PEP 503 for PyPI, lowercase for npm."""
    return canonical(name) if ecosystem == "pip" else name.lower()


def _defined_locally(workspace: Path) -> set[tuple[str, str]]:
    """Package names this Workspace *defines*, as (ecosystem, name).

    A monorepo member is declared like any other dependency and resolved from the tree
    beside it — `uv`, Poetry and Hatch all do this for a plain `"demo-core"` when a
    member's `pyproject.toml` names it. Nothing in the dependency string says so, and
    the npm markers we already skip (`workspace:*`, `file:`, `link:`) have no Python
    equivalent.

    Measured on a real local monorepo: **three high-severity findings**, each telling a
    developer that a package they wrote was "almost certainly hallucinated". That is
    the worst finding this product can emit — someone who is told their own code is a
    supply-chain attack stops reading the report, and the real finding in it goes too.

    Keyed on what a manifest *defines*, not on what appears in one: a dependency that
    happens to share a name with something in the tree is still a dependency.
    """
    import tomllib

    defined: set[tuple[str, str]] = set()
    for path in _manifests(workspace, "pyproject.toml"):
        try:
            data = tomllib.loads(_text(path))
        except (tomllib.TOMLDecodeError, ValueError):
            continue
        for name in (
            (data.get("project") or {}).get("name"),
            ((data.get("tool") or {}).get("poetry") or {}).get("name"),
        ):
            if isinstance(name, str) and name:
                defined.add(("pip", name.lower()))
    for path in _manifests(workspace, "package.json"):
        try:
            data = json.loads(_text(path))
        except (json.JSONDecodeError, ValueError):
            continue
        name = data.get("name") if isinstance(data, dict) else None
        if isinstance(name, str) and name:
            defined.add(("npm", name.lower()))
    return defined


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

    # Never asked about, not merely unreported. A workspace member's name leaving the
    # machine buys nothing, and §3 is about what we transmit as much as what we say.
    local = _defined_locally(workspace)
    return {(eco, name, src) for eco, name, src in found if (eco, name) not in local}


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

#: How many registry requests are in flight at once on `full`. Measured 2026-09-12
#: against PyPI from this Check: serial, 159ms a name — 123s on a real monorepo, and
#: each name carries a 10s timeout on top when the registry is slow. The lookups are
#: independent and I/O-bound, so they overlap; the bound is what keeps this the one
#: code path that reaches the network rather than the one that gets rate-limited and
#: then reports "unreachable" as if nothing had been declared.
LOOKUP_CONCURRENCY = 8


Answer = dict | RegistryUnreachable | None


def _lookup_many(keys: list[tuple[str, str]]) -> dict[tuple[str, str], Answer]:
    """Every lookup in `keys`, `LOOKUP_CONCURRENCY` at a time, each answer or its
    failure recorded under its key. Nothing is retried and nothing is dropped: a
    name whose lookup failed is reported as unverified by the caller, not as clean."""
    if not keys:
        return {}
    from concurrent.futures import ThreadPoolExecutor

    def one(key):
        try:
            return key, _lookup(*key)
        except RegistryUnreachable as exc:
            return key, exc

    with ThreadPoolExecutor(max_workers=min(LOOKUP_CONCURRENCY, len(keys))) as pool:
        return dict(pool.map(one, keys))


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


def _popular() -> dict[str, str]:
    """Popular PyPI names, keyed by PEP 503 canonical form.

    Folded once here rather than inside `_near_miss`, which is called per declared
    dependency: rebuilding a 4000-entry map for every package in a monorepo is work
    nobody asked for.
    """
    path = Path(__file__).resolve().parent.parent / "data" / "popular-pypi.json"
    if not path.is_file():
        return {}
    return {canonical(n): n.lower() for n in json.loads(path.read_text())["packages"]}


#: PEP 503 name normalisation. Runs of `.`, `-` and `_` are one separator, and PyPI
#: serves every spelling from a single project.
_SEPARATORS = re.compile(r"[-_.]+")


def canonical(name: str) -> str:
    return _SEPARATORS.sub("-", name).lower()


def _near_miss(name: str, popular: dict[str, str]) -> str | None:
    """The nearest popular package, comparing PEP 503 canonical forms.

    Measured on a real project before this: *"'discord.py' is one character from the
    far more popular 'discord-py'"* — the same package. Verified 2026-09-10 that PyPI
    returns 200 for `discord.py`, `discord-py` and `discord_py`, all with the canonical
    name `discord.py`. The comparison was one edit apart on raw strings and zero apart
    in fact, so any package whose name contains a dot or an underscore could accuse
    itself of typosquatting itself.

    Canonical form is used for the COMPARISON only. Identity keeps the declared
    spelling — normalising it would move every existing fingerprint and invalidate
    every committed suppression on a dependency finding (ADR-0003).
    """
    target = canonical(name)
    if target in popular:
        return None
    for candidate, original in popular.items():
        if abs(len(candidate) - len(target)) <= 1 and _within_one_edit(target, candidate):
            return original
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
