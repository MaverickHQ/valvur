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
Poetry shapes) against PyPI, **npm** (`package.json`), **Ruby** (`Gemfile` and
`*.gemspec`) against RubyGems, **PHP** (`composer.json`) against Packagist and
**Rust** (`Cargo.toml`) against crates.io — all offline, from the index (Ruby, PHP
and Rust since 23.2.2 and 23.2.3). **JVM** (`pom.xml`, Gradle build scripts and the version
catalog) against Maven Central and **Go** (`go.mod`) against the module proxy are
checked on `full` only: neither registry publishes a name list an index could be
built from (ADR-0018 has the numbers), so on `offline` they are a stated Profile
omission in the Coverage contract, not a failure and not a gap. Everything else is
reported as missing coverage by `valvur.coverage` rather than passed over — which is
the half that stays true however many ecosystems are added, because something is
always uncovered.

Direct manifests only, never lockfiles. A lockfile is a resolved transitive tree, and
transitive dependencies are not the ones a language model invents: the hallucination
is written into the file a human or an agent edited.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from .. import ecosystems as _ecosystems
from .. import egress as _egress
from ..coverage import Coverage
from ..ecosystems import parsers as _parsers
from ..ecosystems.registry import pep503 as _pep503
from .base import Check

TIMEOUT = 10
#: F3.3's age half. design.md pairs it with "downloads < 1000/month". For PyPI
#: adoption is NOT measured — it publishes no download counts without a third-party
#: service, and section 10 rules those out; the requirement says so since 22.C.2.
#: For npm it is (23.5.4): `api.npmjs.org` is public and unauthenticated, and is
#: asked only about names the registry has already dated under the threshold, so
#: nothing leaves the machine that had not already.
NEW_PACKAGE_DAYS = 90
NPM_UNADOPTED_DOWNLOADS = 1000

#: Where the runner mounts the host cache's name index (ADR-0018), and the variable
#: the runner sets when — and only when — the container was launched with a network.
INDEX_MOUNT = "/cache/names"
INDEX_ENV = "VALVUR_NAME_INDEX"
NETWORK_ENV = _egress.NETWORK_ENV
_UA = {"User-Agent": "valvur/0.1 (+https://github.com/MaverickHQ/valvur)"}

class RegistryUnreachable(RuntimeError):
    """Raised so the run records this Check as failed rather than clean (F3.5)."""


class IndexMissing(RuntimeError):
    """No index for an ecosystem this Workspace declares, and no network to ask
    instead. Raised so the run records this Check as failed, with the fix."""


class DependencyRealityCheck(Check):
    name = "dependency-reality"

    def coverage(self, workspace: Path, exclude: tuple[str, ...] = (),
                 *, network: bool = False) -> Coverage:
        """The one Check whose limits are worth stating, because nothing else in the
        product substitutes for it. Host-side, static, per Profile."""
        from .. import coverage as _coverage
        _INDEXED = _ecosystems.INDEX_FILES

        reads, ignores = [], []
        for key, manifests in _ecosystems.MANIFESTS.items():
            if not manifests.reads:
                ignores.append(f"{manifests.label}: no existence check")
            elif key in _INDEXED or network:
                reads.append(f"{manifests.label}: {', '.join(manifests.reads)}")
            else:
                # Read, but only where a registry can be asked (22.A.4): neither
                # Maven Central nor the Go proxy publishes a name list an offline
                # index could be built from. A Profile omission, stated as one.
                ignores.append(f"{manifests.label}: existence checked on `full` only "
                               "(no offline index exists for this registry)")
        # Stated rather than left implicit: names are checked for existence in every
        # indexed ecosystem, but the near-miss typosquat comparison needs a corpus of
        # popular package names and only PyPI's ships in the image.
        ignores.append("typosquat near-miss comparison: PyPI only (no popular-name corpus "
                       "for the other registries)")
        if not network:
            # The one question the local index cannot answer (ADR-0018).
            ignores.append("first-publish age: not checked without a network "
                           "(run `--profile full`)")
        else:
            ignores.append("JVM and Go: existence only, no first-publish age "
                           "(neither registry states first publication)")
            # F3.3's adoption half, where a registry publishes it (23.5.4).
            reads.append("npm adoption: last-month downloads from api.npmjs.org, "
                         "for names first published under 90 days ago")
            ignores.append("adoption for PyPI, RubyGems, Packagist and crates.io: "
                           "age only (no download counts without a third party)")
        return Coverage(
            inspects=tuple(sorted(reads)),
            ignores=tuple(sorted(ignores)),
            gaps=tuple(_coverage.dependency_gaps(workspace, exclude)),
        )

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
        if not network:
            # Ecosystems with no offline index BY DESIGN (JVM, Go) are a Profile
            # omission the Coverage contract states; dropping them here is what keeps
            # that statement true. Not a failure: nothing was promised for them here.
            declared = {d for d in declared if d[0] in _index.FILES}
            if not declared:
                return findings
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
                index.contains(_ecosystems.index_form(ecosystem, name))
                if index is not None else None
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
                suggestion = (_near_miss(name, popular)
                              if _ecosystems.get(ecosystem).near_miss else None)
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
            near = _near_miss(name, popular) if _ecosystems.get(ecosystem).near_miss else None
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
                findings.append(_newly_registered(ecosystem, name, source, int(age)))

        return findings, reached_any, asked_any


def _newly_registered(ecosystem: str, name: str, source: str, age: int) -> dict:
    """F3.3: *first published recently AND low adoption*. Both halves for npm, whose
    downloads API is public; the age half alone everywhere else, and the evidence
    says which. A new package with real adoption is a new package, not the signal —
    reported at low with the number, because the age is not nothing."""
    title = f"'{name}' was first published {age} day(s) ago"
    if ecosystem != "npm":
        return _finding(
            "valvur.dependency.newly-registered", ecosystem, name, source, "medium", title,
            "Recently registered packages matching a plausible name are the slopsquat "
            "pattern. Confirm this is the package you meant. Adoption is not "
            "measured for PyPI, RubyGems, Packagist or crates.io: none publishes "
            "download counts without a third party, which valvur does not use.",
        )
    try:
        downloads = _downloads(name)
    except RegistryUnreachable:
        return _finding(
            "valvur.dependency.newly-registered", ecosystem, name, source, "medium", title,
            "Recently registered packages matching a plausible name are the slopsquat "
            "pattern. Confirm this is the package you meant. Its adoption could not "
            "be checked: api.npmjs.org did not answer.",
        )
    title += f" and had {downloads:,} downloads last month"
    if downloads < NPM_UNADOPTED_DOWNLOADS:
        return _finding(
            "valvur.dependency.newly-registered", ecosystem, name, source, "high", title,
            "New and unadopted is the slopsquat pattern: a plausible name registered "
            "recently that almost nobody installs. Confirm this is the package you "
            "meant before your next install runs its code.",
        )
    return _finding(
        "valvur.dependency.newly-registered", ecosystem, name, source, "low", title,
        "Recently registered, but adopted: the download count says others depend on "
        "it too. Listed because the age is not nothing; not the slopsquat pattern.",
    )


def _downloads_url(name: str) -> str:
    # The slash in a scoped name stays a slash, as it does for the registry itself
    # (19.D.1): measured, `@types/node` answers here unencoded.
    return f"https://api.npmjs.org/downloads/point/last-month/{quote(name, safe='@/')}"


def _downloads(name: str) -> int:
    """Last-month download count from npm's public statistics API. A 404 is a
    package too new to have any — the least-adopted it can be — so it is zero;
    an unreachable API is raised, and the caller keeps the age-only finding."""
    body = _fetch(_downloads_url(name))
    if body is None:
        return 0
    count = body.get("downloads") if isinstance(body, dict) else None
    return int(count) if isinstance(count, int | float) else 0


def _network_allowed() -> bool:
    """Whether the runner launched this container with a network. The runner sets
    the variable in exactly the case it omits `--network=none`, so the Check reads
    the same decision the kernel enforces rather than probing for a socket."""
    return os.environ.get(NETWORK_ENV) == "1"


def _index_dir() -> Path:
    return Path(os.environ.get(INDEX_ENV) or INDEX_MOUNT)


def _declared_packages(workspace: Path) -> set[tuple[str, str, str]]:
    """Every directly-declared dependency, as (ecosystem, name, manifest path).

    The parsers and the manifest patterns they read live in the ecosystem
    package since 27.3.2; this Check asks for the answer rather than holding
    eleven parsers and a hand-written list of which to call.
    """
    return _ecosystems.declared(workspace)


#: Where each ecosystem's names are verified, named as a reader would name it —
#: from the ecosystem registry (27.3.2), which owns the host beside the name.
_REGISTRY_NAME = {e.key: e.registry for e in _ecosystems.ECOSYSTEMS}

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
    url, as_json = _registry_url(ecosystem, name)
    body = _fetch(url, as_json=as_json)
    if isinstance(body, list):
        # RubyGems answers with a bare list of versions; everything else with an
        # object. Wrapped so the caller has one shape to read an age from.
        return {"versions": body}
    return body


def _registry_url(ecosystem: str, name: str) -> tuple[str, bool]:
    """Where a name's existence (and, where the registry states it, first
    publication) is asked, and whether the answer is JSON worth reading."""
    if ecosystem == "npm":
        # `safe="@/"`: a scoped name is `@scope/name`, and the slash stays a slash.
        # Measured against registry.npmjs.org 2026-09-10, all of `@types/node`,
        # `@types%2Fnode` and `@types%2fnode` return 200 — so this is not a live bug
        # there. It is the canonical form npm itself uses, and private mirrors
        # (Artifactory, Verdaccio, Nexus) are stricter than npmjs.org about the
        # encoded variant. This product's users are disproportionately behind one.
        return f"https://registry.npmjs.org/{quote(name, safe='@/')}", True
    if ecosystem == "maven":
        # Existence only: `maven-metadata.xml` exists for every artifact ever
        # published and says nothing about first publication, so there is no age.
        group, _, artifact = name.partition(":")
        path = "/".join(quote(part, safe="") for part in group.split("."))
        return (f"https://repo1.maven.org/maven2/{path}/{quote(artifact, safe='')}"
                "/maven-metadata.xml"), False
    if ecosystem == "gomod":
        # The proxy fetches from the origin on demand, so a 404 here means `go get`
        # would fail too. 410 is the proxy's "gone" and means the same for our purposes.
        escaped = quote(_parsers.escape_go(name), safe="/!")
        return f"https://proxy.golang.org/{escaped}/@v/list", False
    if ecosystem == "gem":
        # Every version with its `created_at`; the gem endpoint itself only dates
        # the latest. Case-sensitive, like the index (measured: `Rails.json` → 404).
        return f"https://rubygems.org/api/v1/versions/{quote(name, safe='')}.json", True
    if ecosystem == "composer":
        # Composer's own metadata endpoint. Case-insensitive at the server; the
        # index holds lowercase, so the name arrives lowercase.
        return f"https://repo.packagist.org/p2/{quote(name, safe='/')}.json", True
    if ecosystem == "cargo":
        return (f"https://crates.io/api/v1/crates/"
                f"{quote(_ecosystems.index_form('cargo', name), safe='')}"), True
    return f"https://pypi.org/pypi/{quote(name, safe='')}/json", True


def _fetch(url: str, *, as_json: bool = True) -> dict | list | None:
    # Both callers build this from a literal https:// prefix and a percent-quoted
    # package name, so no caller-controlled scheme can reach here. Asserted rather
    # than assumed, because a scheme reaching urlopen is how a dependency name turns
    # into a file read.
    if not url.startswith("https://"):
        raise RegistryUnreachable(f"refusing a non-https registry URL: {url!r}")
    request = urllib.request.Request(url, headers=_UA)  # noqa: S310 — asserted above
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            if not as_json:
                response.read()
                return {}        # exists; the body carries nothing we use
            body = json.load(response)
            return body if isinstance(body, dict | list) else {}
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 405, 410):
            return None          # definitively absent — the headline finding
        raise RegistryUnreachable(str(exc)) from exc
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
        raise RegistryUnreachable(str(exc)) from exc


def _age_days(ecosystem: str, meta: dict) -> float | None:
    """Days since first publication, from what each registry states about it."""
    stamps: list[str] = []
    if ecosystem == "npm":
        created = (meta.get("time") or {}).get("created")
        if isinstance(created, str):
            stamps = [created]
    elif ecosystem == "gem":
        stamps = [v["created_at"] for v in meta.get("versions") or []
                  if isinstance(v, dict) and isinstance(v.get("created_at"), str)]
    elif ecosystem == "composer":
        stamps = _packagist_times(meta)
    elif ecosystem == "cargo":
        created = (meta.get("crate") or {}).get("created_at")
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


def _packagist_times(meta: dict) -> list[str]:
    """Composer 2's `p2` metadata is *minified*: the first version carries every
    field and each later one only what changed, so a missing `time` means "same
    as the version before", not "unknown". Expanded here, or a package whose
    versions share a timestamp would have no first-publish date at all."""
    stamps: list[str] = []
    for versions in (meta.get("packages") or {}).values():
        carried: str | None = None
        for version in versions if isinstance(versions, list) else []:
            if not isinstance(version, dict):
                continue
            if isinstance(version.get("time"), str):
                carried = version["time"]
            if carried:
                stamps.append(carried)
    return stamps


def _popular() -> dict[str, str]:
    """Popular PyPI names, keyed by PEP 503 canonical form.

    Folded once here rather than inside `_near_miss`, which is called per declared
    dependency: rebuilding a 4000-entry map for every package in a monorepo is work
    nobody asked for.
    """
    path = Path(__file__).resolve().parent.parent / "data" / "popular-pypi.json"
    if not path.is_file():
        return {}
    return {_pep503(n): n.lower() for n in json.loads(path.read_text())["packages"]}


def _near_miss(name: str, popular: dict[str, str]) -> str | None:
    """The nearest popular package, comparing PEP 503 canonical forms (F3.4).

    "Substantially more popular" is membership of the bundled top-3000 list, not the
    100x download ratio design.md names — the ratio needs per-package download
    counts, which is the same third-party dependency F3.3 declines. PyPI only.

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
    target = _pep503(name)
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
