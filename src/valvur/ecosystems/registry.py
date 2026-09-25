"""One ecosystem, one entry: everything valvur knows about it (task 27.3.2).

Until this, an ecosystem's truth was spread over three modules that had to be
edited together — `ecosystems.MANIFESTS` said which files to read,
`name_index.FILES` which index answers existence, and a chain of
`if ecosystem == "…"` inside `checks/dependency_reality.py` held the registry's
name and the spelling the index stores. `name_index` imported the Check for one
function and the Check imported `name_index` for another, each lazily, in both
directions.

Adding an ecosystem is now one entry here plus its parsers: what it reads, what
it defines (so a Workspace's own packages are never asked about), which index
answers existence, and how a name is spelled there. What a reader needs to know
about an existing one is on one screen, and a test holds every entry to what the
rest of the code assumes of it: an index file or a stated reason there is none,
and a host `egress.SPOKEN_AS` names — because a registry this Check can ask about
a package is a destination `run.json` has to disclose (CLAUDE.md §3).

Two things stay in the Check on purpose, and are the registry's *transport*
rather than its identity: the URL that answers for a package and the shape each
registry states a first publication in (`_registry_url`, `_age_days`). An
ecosystem added here that is asked on `full` needs a branch in each; the entry
does not pretend otherwise (28.1.1).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import parsers as _parsers

_SEPARATORS = re.compile(r"[-_.]+")


def pep503(name: str) -> str:
    """PyPI's own idea of identity (PEP 503): runs of `-`, `_` and `.` fold to one
    `-`, and the whole thing lowercases."""
    return _SEPARATORS.sub("-", name).lower()


def crate(name: str) -> str:
    """crates.io: lowercase, with `-` and `_` the same character."""
    return name.lower().replace("-", "_")


def as_written(name: str) -> str:
    """RubyGems is case-sensitive: `rails` exists, `Rails` does not — measured
    2026-09-12."""
    return name


def lowercase(name: str) -> str:
    return name.lower()


@dataclass(frozen=True)
class Ecosystem:
    """What valvur knows about one packaging ecosystem."""

    #: The key every other surface uses — a Finding's identity, the index file,
    #: `run.json`. Never renamed: suppressions are keyed on it (ADR-0003).
    key: str
    #: How a reader is told which ecosystem this is.
    label: str
    #: The manifests this ecosystem declares dependencies in, each with the parser
    #: that reads it: `(pattern, parse)`, where `parse(path, workspace)` answers
    #: `{(ecosystem, name, source)}`. One place, so a new ecosystem is an entry
    #: here and a function in `parsers.py` — it was three tables before 27.3.2.
    parsers: tuple[tuple[str, Callable], ...] = ()
    #: The manifests that *define* a package this Workspace owns, each with the
    #: reader that answers `define(path) -> {name}`: a monorepo member, a Maven
    #: reactor module, a Cargo workspace crate. Removed from what is declared
    #: before anything is asked of an index or a registry — a developer told their
    #: own package is hallucinated stops reading (28.1.1; it was a second table in
    #: `parsers.py`, outside the entry). Each pattern is one of `reads`.
    defines: tuple[tuple[str, Callable[[Path], set[str]]], ...] = ()
    #: Manifests valvur recognises and does not read — either because another
    #: manifest covers them (a lockfile's transitive tree is not where a language
    #: model invents a name) or because nothing parses the shape. Their presence
    #: with nothing readable beside them is a coverage note, so the gap is stated
    #: rather than inferred from a clean result.
    sees: tuple[str, ...] = ()
    #: The file in the Name Index that answers existence offline (ADR-0018), or
    #: None where no offline index can exist — `no_index_because` says why.
    index_file: str | None = None
    #: Why this ecosystem has no offline index. On `offline` its packages are a
    #: stated Profile omission rather than a silence (22.A.4).
    no_index_because: str = ""
    #: The registry, as a reader would name it.
    registry: str = ""
    #: The host that registry lives on. `egress.SPOKEN_AS` must name it.
    host: str = ""
    #: The spelling the index stores and the registry answers to.
    index_form: Callable[[str], str] = lowercase
    #: Whether the near-miss (typosquat) comparison runs here. Only pip has the
    #: popularity data behind it (F3.4).
    near_miss: bool = False

    @property
    def reads(self) -> tuple[str, ...]:
        """The manifest patterns, in the order they are read — what the coverage
        contract lists and what `MANIFESTS` carries."""
        return tuple(pattern for pattern, _ in self.parsers)


#: Every ecosystem valvur reads, in the order a reader meets them.
ECOSYSTEMS: tuple[Ecosystem, ...] = (
    Ecosystem(
        key="pip", label="Python",
        parsers=(("requirements*.txt", _parsers.from_requirements),
                 ("pyproject.toml", _parsers.from_pyproject)),
        defines=(("pyproject.toml", _parsers.defines_pyproject),),
        sees=("Pipfile", "setup.py", "setup.cfg", "poetry.lock", "uv.lock"),
        index_file="pypi.txt", registry="PyPI", host="pypi.org",
        index_form=pep503, near_miss=True,
    ),
    Ecosystem(
        key="npm", label="npm",
        parsers=(("package.json", _parsers.from_package_json),),
        defines=(("package.json", _parsers.defines_package_json),),
        sees=("package-lock.json", "pnpm-lock.yaml", "yarn.lock"),
        index_file="npm.txt", registry="the npm registry", host="registry.npmjs.org",
    ),
    # Read since 23.2.3: crates.io's list is streamed out of its database dump.
    Ecosystem(
        key="cargo", label="Rust (Cargo)",
        parsers=(("Cargo.toml", _parsers.from_cargo),), sees=("Cargo.lock",),
        defines=(("Cargo.toml", _parsers.defines_cargo),),
        index_file="crates.txt", registry="crates.io", host="crates.io",
        index_form=crate,
    ),
    # Read since 22.A.4, on `full` only: neither registry publishes a name list that
    # could be fetched into the offline index (ADR-0018 records the numbers), so
    # existence is asked of the registry per name.
    Ecosystem(
        key="gomod", label="Go",
        parsers=(("go.mod", _parsers.from_go_mod),), sees=("go.sum",),
        defines=(("go.mod", _parsers.defines_go_mod),),
        no_index_because="the Go module proxy publishes no list of modules",
        registry="the Go module proxy", host="proxy.golang.org",
    ),
    # Maven and Gradle resolve from the same registry, so they are one ecosystem with
    # two build tools — the distinction that produced the pnpm/yarn bug (19.D.3). The
    # Gradle version catalog is read too: a project that declares everything there and
    # references `libs.foo` from its build script would otherwise scan clean.
    Ecosystem(
        key="maven", label="JVM (Maven/Gradle)",
        parsers=(("pom.xml", _parsers.from_pom),
                 ("build.gradle", _parsers.from_gradle),
                 ("build.gradle.kts", _parsers.from_gradle),
                 ("gradle/libs.versions.toml", _parsers.from_version_catalog)),
        defines=(("pom.xml", _parsers.defines_pom),),
        sees=("settings.gradle", "settings.gradle.kts", "gradle.lockfile"),
        no_index_because="Maven Central publishes no list of coordinates",
        registry="Maven Central", host="repo1.maven.org",
    ),
    # Read since 23.2.2: RubyGems and Packagist each publish their whole list in one
    # request, and both are in the index.
    Ecosystem(
        key="gem", label="Ruby (Bundler)",
        parsers=(("Gemfile", _parsers.from_gemfile),
                 ("*.gemspec", _parsers.from_gemspec)), sees=("Gemfile.lock",),
        defines=(("*.gemspec", _parsers.defines_gemspec),),
        index_file="rubygems.txt", registry="RubyGems", host="rubygems.org",
        index_form=as_written,
    ),
    Ecosystem(
        key="composer", label="PHP (Composer)",
        parsers=(("composer.json", _parsers.from_composer),), sees=("composer.lock",),
        defines=(("composer.json", _parsers.defines_composer),),
        index_file="packagist.txt", registry="Packagist", host="repo.packagist.org",
    ),
)

BY_KEY: dict[str, Ecosystem] = {e.key: e for e in ECOSYSTEMS}

#: The order the indexed ecosystems are listed in — `valvur doctor`'s index line and
#: `valvur update`'s progress both print it, so it is user-visible text and not an
#: implementation detail. Preserved exactly from `name_index.FILES`, which ordered
#: them differently from `MANIFESTS` above; deriving one dict from the other without
#: this changed what doctor printed, which three tests caught (27.3.2).
INDEX_ORDER: tuple[str, ...] = ("pip", "npm", "gem", "composer", "cargo")

#: The index files, by ecosystem — what `name_index` builds and pulls. Derived from
#: the entries above, so the two cannot disagree; it was a second table until 27.3.2.
INDEX_FILES: dict[str, str] = {
    key: name for key in INDEX_ORDER if (name := BY_KEY[key].index_file) is not None
}


def get(key: str) -> Ecosystem:
    return BY_KEY[key]


def index_form(key: str, name: str) -> str:
    """The spelling the index stores for this name — each registry's own identity."""
    return BY_KEY[key].index_form(name)
