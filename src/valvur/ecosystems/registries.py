"""Where a project says its packages come from (R10.3, R10.4; D27, F3.15, ADR-0028).

A name missing from the public index is a hallucination only if the project would
look for it on the public registry. A company's internal packages are served by its
own registry, and the project says so in its own files: `.npmrc` and `.yarnrc.yml`
for npm; `pip.conf`, a requirements file's index options, and the uv, Poetry and
Pipfile source tables for Python; Composer's repositories; and, for `check_package`
(R12.4), a Gemfile's private `source` blocks and a Cargo.toml's `registry` keys.
Read from the File Set, never from a home directory: what is not in the project is
not what the project declares.

Three answers, from the safest:

- **private**: the name, or its npm scope, is bound to a private registry. It is not
  looked up publicly at all, and a note says which registry serves it.
- **replaced**: the public registry is replaced entirely. A missing name is served
  privately, and the advice is to reserve it publicly: a registry setting that is
  mistyped or dropped installs whoever registered it.
- **supplemental**: a private source is merged with the public one, and the resolver
  takes the best version from either. A missing name is a dependency-confusion
  exposure, since the next `pip install` takes a public package registered under it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

#: The public registries, by host. A configured URL on any other host is private.
PUBLIC_HOSTS = {
    "npm": frozenset({"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"}),
    "pip": frozenset({"pypi.org", "pypi.python.org", "files.pythonhosted.org"}),
    "composer": frozenset({"packagist.org", "repo.packagist.org"}),
}


@dataclass(frozen=True)
class Registries:
    #: npm scopes bound to a private registry: `@acme` to its URL.
    private_scopes: dict[str, str] = field(default_factory=dict)
    #: The public registry's replacement, when the project replaces it entirely.
    replaced: str | None = None
    #: Private sources merged with the public one.
    supplemental: tuple[str, ...] = ()
    #: Names a configuration binds to a private source explicitly, to its URL.
    private_names: dict[str, str] = field(default_factory=dict)


def is_public(ecosystem: str, url: str) -> bool:
    return (urlparse(url.strip().strip("\"'")).hostname or "") in PUBLIC_HOSTS[ecosystem]


def _between(workspace: Path, manifest: Path) -> list[Path]:
    """The manifest's directory and each above it, up to the workspace root, nearest
    first: a nearer configuration wins, as npm's and pip's own lookups do."""
    directory, root = manifest.parent.resolve(), workspace.resolve()
    found = [directory]
    while directory != root and root in directory.parents:
        directory = directory.parent
        found.append(directory)
    return found


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ------------------------------------------------------------------------ npm

_NPMRC_SCOPE = re.compile(r"^\s*(@[\w.-]+):registry\s*=\s*(\S+)", re.M)
_NPMRC_REGISTRY = re.compile(r"^\s*registry\s*=\s*(\S+)", re.M)
_YARN_SERVER = re.compile(r"""^npmRegistryServer:\s*["']?([^"'\s]+)""", re.M)


def _yarn_scopes(text: str) -> dict[str, str]:
    """`npmScopes:` then `  <scope>:` then `    npmRegistryServer: <url>`, read by
    indentation: the shim has no YAML parser, and these keys are flat."""
    scopes: dict[str, str] = {}
    inside, scope = False, ""
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            inside = line.startswith("npmScopes:")
            continue
        if not inside:
            continue
        key, _, value = line.strip().partition(":")
        if indent <= 2 and not value.strip():
            scope = "@" + key.strip().strip("\"'").lstrip("@")
        elif key.strip() == "npmRegistryServer" and scope:
            scopes[scope] = value.strip().strip("\"'")
    return scopes


def npm(workspace: Path, manifest: Path) -> Registries:
    scopes: dict[str, str] = {}
    replaced: str | None = None
    for directory in reversed(_between(workspace, manifest)):      # farthest first
        npmrc = _text(directory / ".npmrc")
        yarnrc = _text(directory / ".yarnrc.yml")
        scopes.update({scope: url for scope, url in _NPMRC_SCOPE.findall(npmrc)})
        scopes.update(_yarn_scopes(yarnrc))
        for url in _NPMRC_REGISTRY.findall(npmrc) + _YARN_SERVER.findall(yarnrc):
            replaced = None if is_public("npm", url) else url
    return Registries(
        private_scopes={s: u for s, u in scopes.items() if not is_public("npm", u)},
        replaced=replaced)


# --------------------------------------------------------------------- Python

_REQUIREMENT_INDEX = re.compile(
    r"^\s*(-i|--index-url|--extra-index-url)(?:\s+|=)(\S+)", re.M)


def _normal(name: str) -> str:
    """PEP 503's form, so `acme_billing` and `Acme-Billing` are one name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _pip_conf(path: Path) -> tuple[str | None, list[str]]:
    """`index-url` and `extra-index-url` under `[global]` or `[install]`."""
    import configparser

    parser = configparser.ConfigParser()
    try:
        parser.read_string(_text(path))
    except configparser.Error:
        return None, []
    index, extras = None, []
    for section in ("global", "install"):
        if parser.has_section(section):
            index = parser.get(section, "index-url", fallback=index)
            extras += parser.get(section, "extra-index-url", fallback="").split()
    return index, extras


def _toml(path: Path) -> dict:
    import tomllib

    try:
        data = tomllib.loads(_text(path))
    except (tomllib.TOMLDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _pyproject(data: dict, private: dict[str, str]) -> tuple[str | None, list[str]]:
    """uv's and Poetry's source tables: what replaces PyPI, what merges with it, and
    which names they bind (into `private`)."""
    tool = data.get("tool") or {}
    replaced, merged = None, []
    uv = tool.get("uv") or {}
    indexes = {i.get("name"): i for i in uv.get("index") or [] if isinstance(i, dict)}
    unsafe = uv.get("index-strategy") == "unsafe-best-match"
    for index in indexes.values():
        url = str(index.get("url") or "")
        if not url or is_public("pip", url) or index.get("explicit"):
            continue
        # uv searches its indexes before PyPI and stops at the first that has the
        # package: searched first, a missing name is served privately, unless the
        # strategy takes the best version from every index, which is a merge.
        if unsafe:
            merged.append(url)
        else:
            replaced = replaced or url
    for name, source in (uv.get("sources") or {}).items():
        named = indexes.get(source.get("index")) if isinstance(source, dict) else None
        if named and not is_public("pip", str(named.get("url") or "")):
            private[_normal(name)] = str(named["url"])
    poetry = tool.get("poetry") or {}
    sources = {s.get("name"): s for s in poetry.get("source") or [] if isinstance(s, dict)}
    for source in sources.values():
        url, priority = str(source.get("url") or ""), source.get("priority", "primary")
        if not url or is_public("pip", url):
            continue
        if priority in ("supplemental", "secondary"):
            merged.append(url)
        elif priority in ("primary", "default"):
            replaced = replaced or url
    tables = [poetry.get("dependencies") or {}] + [
        (group or {}).get("dependencies") or {} for group in (poetry.get("group") or {}).values()]
    for table in tables:
        for name, spec in (table.items() if isinstance(table, dict) else ()):
            source = sources.get(spec.get("source")) if isinstance(spec, dict) else None
            if source and not is_public("pip", str(source.get("url") or "")):
                private[_normal(name)] = str(source["url"])
    return replaced, merged


def _pipfile(data: dict, private: dict[str, str]) -> str | None:
    """Pipenv installs from the first `[[source]]` unless a package names another."""
    sources = [s for s in data.get("source") or [] if isinstance(s, dict)]
    by_name = {s.get("name"): s for s in sources}
    for table in ("packages", "dev-packages"):
        for name, spec in (data.get(table) or {}).items():
            source = by_name.get(spec.get("index")) if isinstance(spec, dict) else None
            if source and not is_public("pip", str(source.get("url") or "")):
                private[_normal(name)] = str(source["url"])
    first = str(sources[0].get("url") or "") if sources else ""
    return first if first and not is_public("pip", first) else None


def python(workspace: Path, manifest: Path) -> Registries:
    replaced: str | None = None
    extras: list[str] = []
    private: dict[str, str] = {}
    for directory in reversed(_between(workspace, manifest)):      # farthest first
        if (directory / "pip.conf").is_file():
            index, more = _pip_conf(directory / "pip.conf")
            if index is not None:
                replaced = None if is_public("pip", index) else index
            extras += more
    name = manifest.name
    if name.startswith("requirements") and name.endswith(".txt"):
        for option, url in _REQUIREMENT_INDEX.findall(_text(manifest)):
            if option == "--extra-index-url":
                extras.append(url)
            else:
                replaced = None if is_public("pip", url) else url
    elif name == "pyproject.toml":
        index, merged = _pyproject(_toml(manifest), private)
        replaced, extras = index or replaced, extras + merged
    elif name == "Pipfile":
        replaced = _pipfile(_toml(manifest), private) or replaced
    return Registries(replaced=replaced,
                      supplemental=tuple(u for u in extras if not is_public("pip", u)),
                      private_names=private)


# ------------------------------------------------------------------- Composer

def composer(manifest: Path) -> Registries:
    """`composer`-type repositories (R10.10). Composer treats one as canonical, taking
    a package from it before Packagist, unless `"canonical": false`, which merges;
    `"packagist.org": false` turns Packagist off. Path, VCS and package repositories
    are the parser's: their packages are not looked up at all."""
    import json

    try:
        data = json.loads(_text(manifest))
    except ValueError:
        return Registries()
    repositories = data.get("repositories") if isinstance(data, dict) else None
    entries = list(repositories.values()) if isinstance(repositories, dict) else \
        list(repositories or []) if isinstance(repositories, list) else []
    # Off in either form: a `"packagist.org": false` key, or an entry that is one.
    keyed = isinstance(repositories, dict) and repositories.get("packagist.org") is False
    listed = any(isinstance(e, dict) and e.get("packagist.org") is False for e in entries)
    packagist_off = keyed or listed
    first, merged = None, []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") != "composer":
            continue
        url = str(entry.get("url") or "")
        if not url or is_public("composer", url):
            continue
        if entry.get("canonical", True) is False and not packagist_off:
            merged.append(url)
        else:
            first = first or url
    return Registries(replaced=first, supplemental=tuple(merged))


_GEM_SOURCE_BLOCK = re.compile(r"""^\s*source\s*\(?\s*["']([^"']+)["'][^#]*\bdo\b""")


def gem(manifest: Path) -> Registries:
    """The gems a Gemfile takes from a `source '...' do` block that is not RubyGems
    (R12.4). The parser already leaves them undeclared; `check_package` needs to
    know where they come from, or it would call a private gem nonexistent."""
    from . import parsers as _parsers

    bound: dict[str, str] = {}
    stack: list[str | None] = []       # per open block: its private source, if any
    for raw in _text(manifest).splitlines():
        line = raw.split("#", 1)[0].rstrip()
        stripped = line.strip()
        if stripped == "end" or stripped.startswith("end "):
            if stack:
                stack.pop()
            continue
        match = _parsers._GEM_LINE.match(line)
        source = next((s for s in reversed(stack) if s), None)
        if match and source:
            bound[match.group(1)] = source
        if _parsers._BLOCK_OPENS.search(line):
            opened = _GEM_SOURCE_BLOCK.match(line)
            stack.append(opened.group(1) if opened and not is_public_gem(opened.group(1))
                         else None)
    return Registries(private_names=bound)


def is_public_gem(url: str) -> bool:
    return (urlparse(url).hostname or "") in ("rubygems.org", "www.rubygems.org")


def cargo(workspace: Path, manifest: Path) -> Registries:
    """The crates a Cargo.toml takes from an alternative `registry`, each bound to that
    registry's index from `.cargo/config.toml` between the manifest and the root
    (R12.4); the parser already leaves them undeclared."""
    data = _toml(manifest)
    indexes: dict[str, str] = {}
    for directory in _between(workspace, manifest):
        for name in ("config.toml", "config"):
            configured = _toml(directory / ".cargo" / name).get("registries") or {}
            for registry, entry in configured.items() if isinstance(configured, dict) else ():
                if isinstance(entry, dict) and isinstance(entry.get("index"), str):
                    indexes.setdefault(registry, entry["index"])
    bound: dict[str, str] = {}
    tables = [data.get(key) or {} for key in
              ("dependencies", "dev-dependencies", "build-dependencies")]
    tables.append((data.get("workspace") or {}).get("dependencies") or {})
    for table in tables:
        for alias, spec in (table.items() if isinstance(table, dict) else ()):
            if isinstance(spec, dict) and isinstance(spec.get("registry"), str):
                name = spec["package"] if isinstance(spec.get("package"), str) else alias
                bound[name] = indexes.get(spec["registry"], f"the {spec['registry']} registry")
    return Registries(private_names=bound)


def for_manifest(workspace: Path, ecosystem: str, manifest: Path) -> Registries:
    if ecosystem == "npm":
        return npm(workspace, manifest)
    if ecosystem == "pip":
        return python(workspace, manifest)
    if ecosystem == "composer" and manifest.name == "composer.json":
        return composer(manifest)
    if ecosystem == "gem" and manifest.name == "Gemfile":
        return gem(manifest)
    if ecosystem == "cargo" and manifest.name == "Cargo.toml":
        return cargo(workspace, manifest)
    return Registries()


def bound(configured: Registries, name: str) -> str | None:
    """The private URL a name is bound to by its own configuration, if any."""
    return configured.private_names.get(name) or configured.private_names.get(_normal(name))
