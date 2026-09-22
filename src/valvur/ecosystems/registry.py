"""One ecosystem, one entry: everything valvur knows about it (task 27.3.2).

Until this, an ecosystem's truth was spread over three modules that had to be
edited together — `ecosystems.MANIFESTS` said which files to read,
`name_index.FILES` which index answers existence, and a chain of
`if ecosystem == "…"` inside `checks/dependency_reality.py` held the registry's
name, the URL that answers for a package, how that registry states a first
publication, and the spelling the index stores. `name_index` imported the Check
for one function and the Check imported `name_index` for another, each lazily,
in both directions.

Adding an ecosystem is now one entry here plus a parser. What a reader needs to
know about an existing one is on one screen, and a test holds every entry to what
the rest of the code assumes of it: an index file or a stated reason there is
none, and a host `egress.SPOKEN_AS` names — because a registry this Check can ask
about a package is a destination `run.json` has to disclose (CLAUDE.md §3).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

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
    #: The manifests the dependency-reality Check READS for declared names.
    reads: tuple[str, ...] = ()
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


#: Every ecosystem valvur reads, in the order a reader meets them.
ECOSYSTEMS: tuple[Ecosystem, ...] = (
    Ecosystem(
        key="pip", label="Python",
        reads=("requirements*.txt", "pyproject.toml"),
        sees=("Pipfile", "setup.py", "setup.cfg", "poetry.lock", "uv.lock"),
        index_file="pypi.txt", registry="PyPI", host="pypi.org",
        index_form=pep503, near_miss=True,
    ),
    Ecosystem(
        key="npm", label="npm",
        reads=("package.json",),
        sees=("package-lock.json", "pnpm-lock.yaml", "yarn.lock"),
        index_file="npm.txt", registry="the npm registry", host="registry.npmjs.org",
    ),
    # Read since 23.2.3: crates.io's list is streamed out of its database dump.
    Ecosystem(
        key="cargo", label="Rust (Cargo)",
        reads=("Cargo.toml",), sees=("Cargo.lock",),
        index_file="crates.txt", registry="crates.io", host="crates.io",
        index_form=crate,
    ),
    # Read since 22.A.4, on `full` only: neither registry publishes a name list that
    # could be fetched into the offline index (ADR-0018 records the numbers), so
    # existence is asked of the registry per name.
    Ecosystem(
        key="gomod", label="Go",
        reads=("go.mod",), sees=("go.sum",),
        no_index_because="the Go module proxy publishes no list of modules",
        registry="the Go module proxy", host="proxy.golang.org",
    ),
    # Maven and Gradle resolve from the same registry, so they are one ecosystem with
    # two build tools — the distinction that produced the pnpm/yarn bug (19.D.3). The
    # Gradle version catalog is read too: a project that declares everything there and
    # references `libs.foo` from its build script would otherwise scan clean.
    Ecosystem(
        key="maven", label="JVM (Maven/Gradle)",
        reads=("pom.xml", "build.gradle", "build.gradle.kts", "gradle/libs.versions.toml"),
        sees=("settings.gradle", "settings.gradle.kts", "gradle.lockfile"),
        no_index_because="Maven Central publishes no list of coordinates",
        registry="Maven Central", host="repo1.maven.org",
    ),
    # Read since 23.2.2: RubyGems and Packagist each publish their whole list in one
    # request, and both are in the index.
    Ecosystem(
        key="gem", label="Ruby (Bundler)",
        reads=("Gemfile", "*.gemspec"), sees=("Gemfile.lock",),
        index_file="rubygems.txt", registry="RubyGems", host="rubygems.org",
        index_form=as_written,
    ),
    Ecosystem(
        key="composer", label="PHP (Composer)",
        reads=("composer.json",), sees=("composer.lock",),
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
    key: BY_KEY[key].index_file for key in INDEX_ORDER if BY_KEY[key].index_file
}


def get(key: str) -> Ecosystem:
    return BY_KEY[key]


def index_form(key: str, name: str) -> str:
    """The spelling the index stores for this name — each registry's own identity."""
    return BY_KEY[key].index_form(name)
