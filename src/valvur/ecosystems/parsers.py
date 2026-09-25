"""Reading declared dependencies out of manifests, one parser per shape (27.3.2).

Extracted from `checks/dependency_reality.py`, which held the Check, these parsers,
the registry transport and the typosquat comparison in 1,200 lines — so adding an
ecosystem meant editing the parser here, the manifest table in `ecosystems.py` and
the index table in `name_index.py`, and forgetting any one of them produced a scan
that read a manifest and said nothing about it.

Every parser has the same shape: `(path, workspace) -> {(ecosystem, name, source)}`,
where `source` is the manifest's path relative to the Workspace. The registry pairs
each with the filename pattern it reads, and `ecosystems.declared` — the package's
own function, not this module's — is the loop over both, so a new ecosystem is one
registry entry plus one function here. This module imports nothing of the
registry: it was the tree's only module-level import cycle until 28.0.5.

A name that the Workspace itself defines — a monorepo package, a Gradle sibling, a
Cargo workspace member — is removed at the end: asking a registry about it buys
nothing and would report every monorepo's own packages as nonexistent, which is the
false positive most likely to make a real finding ignored.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

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


# What a manifest DEFINES — the package this tree owns — as against what it
# declares. One reader per manifest that can, paired with its pattern on the
# registry entry's `defines`; `ecosystems.defined_locally` is the loop.

def defines_pyproject(path: Path) -> set[str]:
    """PEP 621's `project.name`, or Poetry's, lowercased as a declaration is."""
    import tomllib

    try:
        data = tomllib.loads(text(path))
    except (tomllib.TOMLDecodeError, ValueError):
        return set()
    names = ((data.get("project") or {}).get("name"),
             ((data.get("tool") or {}).get("poetry") or {}).get("name"))
    return {name.lower() for name in names if isinstance(name, str) and name}


def defines_package_json(path: Path) -> set[str]:
    try:
        data = json.loads(text(path))
    except (json.JSONDecodeError, ValueError):
        return set()
    name = data.get("name") if isinstance(data, dict) else None
    return {name.lower()} if isinstance(name, str) and name else set()


def defines_pom(path: Path) -> set[str]:
    """A Maven reactor declares its own modules as dependencies of each other."""
    own = _pom_coordinates(path)
    return {own} if own else set()


def defines_go_mod(path: Path) -> set[str]:
    """The module, and anything `replace`d with a local path."""
    return _go_local_modules(path)


def defines_gemspec(path: Path) -> set[str]:
    match = _GEMSPEC_NAME.search(text(path))
    return {match.group(1)} if match else set()


def defines_composer(path: Path) -> set[str]:
    """The package, and everything its `repositories` fetch from somewhere other
    than Packagist."""
    return _composer_local(path)


def defines_cargo(path: Path) -> set[str]:
    """The crate; a workspace's members are each a `Cargo.toml` of their own."""
    name = _cargo_package_name(path)
    return {name} if name else set()


def manifests(workspace: Path, pattern: str):
    from .. import exclusions

    for path in sorted(workspace.rglob(pattern)):
        if path.is_file() and not exclusions.is_vendored(str(path.relative_to(workspace))):
            yield path


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def from_requirements(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    rel = str(path.relative_to(workspace))
    found: set[tuple[str, str, str]] = set()
    for line in text(path).splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-") or "git+" in line:
            continue
        match = REQUIREMENT.match(line)
        if match:
            found.add(("pip", match.group(1).lower(), rel))
    return found


def from_pyproject(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    """PEP 621 and Poetry, because both are common and a project using the shape we
    skipped would scan clean for the wrong reason.

    A malformed manifest yields nothing rather than raising: this Check exists to
    report hallucinated packages, and failing the whole Scanner over a TOML syntax
    error would take the real findings down with it.
    """
    import tomllib

    rel = str(path.relative_to(workspace))
    try:
        data = tomllib.loads(text(path))
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


def from_package_json(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    rel = str(path.relative_to(workspace))
    try:
        data = json.loads(text(path))
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


# ------------------------------------------------------------ JVM (22.A.4)

#: A Maven coordinate as Gradle writes it: `group:artifact`, optionally `:version`
#: and more. Both halves are the characters Maven allows; a leading colon — Gradle's
#: `project(":lib")` — is a sibling module, not a coordinate, and does not match.
_COORDINATE = re.compile(
    r"""["']([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)(?::[^"'\s]+)?["']"""
)
_PROPERTY = re.compile(r"\$\{[^}]*\}")


def _xml_children(element, name: str):
    """Namespace-agnostic child lookup: `pom.xml` files come with and without the
    Maven namespace, and both are common."""
    for child in element:
        if isinstance(child.tag, str) and child.tag.rsplit("}", 1)[-1] == name:
            yield child


def _xmltext(element, name: str) -> str:
    child = next(_xml_children(element, name), None)
    return (child.text or "").strip() if child is not None else ""


def _parse_pom(path: Path):
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(text(path))  # noqa: S314 — no entity expansion of interest
    except ET.ParseError:
        return None
    return root if root.tag.rsplit("}", 1)[-1] == "project" else None


def _pom_coordinates(path: Path) -> str | None:
    """The `group:artifact` a pom defines. The group may be inherited from `<parent>`,
    which is the usual shape of a reactor module."""
    root = _parse_pom(path)
    if root is None:
        return None
    group = _xmltext(root, "groupId") or _parent_group(root)
    artifact = _xmltext(root, "artifactId")
    return f"{group}:{artifact}".lower() if group and artifact else None


def _parent_group(root) -> str:
    parent = next(_xml_children(root, "parent"), None)
    return _xmltext(parent, "groupId") if parent is not None else ""


def from_pom(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    """`<dependencies>` and `<dependencyManagement>`; plugins are not read. A
    coordinate carrying an unresolved `${property}` names nothing we can ask about —
    except `${project.groupId}`, which is this pom's own group and is resolved."""
    rel = str(path.relative_to(workspace))
    root = _parse_pom(path)
    if root is None:
        return set()
    own_group = _xmltext(root, "groupId") or _parent_group(root)

    found: set[tuple[str, str, str]] = set()
    blocks = list(_xml_children(root, "dependencies"))
    for management in _xml_children(root, "dependencyManagement"):
        blocks += list(_xml_children(management, "dependencies"))
    for block in blocks:
        for dependency in _xml_children(block, "dependency"):
            group = _xmltext(dependency, "groupId").replace("${project.groupId}", own_group)
            artifact = _xmltext(dependency, "artifactId")
            if not group or not artifact or _PROPERTY.search(group + artifact):
                continue
            found.add(("maven", f"{group}:{artifact}".lower(), rel))
    return found


def from_gradle(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    """Every quoted `group:artifact[:version]` in a build script. Groovy and Kotlin
    DSLs write coordinates the same way; what differs is around them."""
    rel = str(path.relative_to(workspace))
    found: set[tuple[str, str, str]] = set()
    for line in text(path).splitlines():
        code = line.split("//")[0]
        for group, artifact in _COORDINATE.findall(code):
            if _PROPERTY.search(group + artifact):
                continue
            found.add(("maven", f"{group}:{artifact}".lower(), rel))
    return found


def from_version_catalog(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    """Gradle's `[libraries]` table, in its three shapes: a `module = "g:a"` key, a
    `group`/`name` pair, or a bare `"g:a:v"` string."""
    import tomllib

    rel = str(path.relative_to(workspace))
    try:
        data = tomllib.loads(text(path))
    except (tomllib.TOMLDecodeError, ValueError):
        return set()
    found: set[tuple[str, str, str]] = set()
    libraries = data.get("libraries") or {}
    if not isinstance(libraries, dict):
        return set()
    for spec in libraries.values():
        coordinate = ""
        if isinstance(spec, str):
            coordinate = ":".join(spec.split(":")[:2])
        elif isinstance(spec, dict):
            if isinstance(spec.get("module"), str):
                coordinate = ":".join(spec["module"].split(":")[:2])
            elif isinstance(spec.get("group"), str) and isinstance(spec.get("name"), str):
                coordinate = f"{spec['group']}:{spec['name']}"
        group, _, artifact = coordinate.partition(":")
        if group and artifact and not _PROPERTY.search(coordinate):
            found.add(("maven", coordinate.lower(), rel))
    return found


# -------------------------------------------------------------- Go (22.A.4)

_GO_REQUIRE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._~\-/]*)\s+v[0-9][^\s]*(.*)$")


def _go_lines(path: Path):
    """`(directive, line)` pairs, with block directives expanded: `require (` ... `)`
    yields each inner line under `require`."""
    block = ""
    for raw in text(path).splitlines():
        line = raw.split("//", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if block:
            if stripped == ")":
                block = ""
                continue
            yield block, stripped
            continue
        directive, _, rest = stripped.partition(" ")
        if rest.strip() == "(":
            block = directive
            continue
        yield directive, rest.strip()


def from_go_mod(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    """Direct `require`s. `// indirect` lines are transitive — a lockfile's contents
    in a manifest's clothing — and are not where a hallucinated import lands."""
    rel = str(path.relative_to(workspace))
    found: set[tuple[str, str, str]] = set()
    raw_lines = {
        line.split("//", 1)[0].strip(): "// indirect" in line
        for line in text(path).splitlines()
    }
    for directive, line in _go_lines(path):
        if directive != "require":
            continue
        match = _GO_REQUIRE.match(line)
        if not match or raw_lines.get(line.strip(), False):
            continue
        found.add(("gomod", match.group(1), rel))
    return found


def _go_local_modules(path: Path) -> set[str]:
    """The module this file defines, and anything `replace`d with a local path."""
    local: set[str] = set()
    for directive, line in _go_lines(path):
        if directive == "module" and line:
            local.add(line.split()[0])
        elif directive == "replace" and "=>" in line:
            source, _, target = line.partition("=>")
            target = target.strip()
            if target.startswith((".", "/")):
                local.add(source.split()[0])
    return local


def escape_go(module: str) -> str:
    """The module proxy's case encoding: an uppercase letter is `!` + lowercase."""
    return "".join(f"!{c.lower()}" if c.isupper() else c for c in module)


# ------------------------------------------------------------- Ruby (23.2.2)

#: `gem "name"` / `gem 'name', "~> 1.0", require: false`. The name is the first
#: string argument; everything after it is options.
_GEM_LINE = re.compile(r"""^\s*gem\s*\(?\s*["']([A-Za-z0-9_.\-]+)["'](.*)$""")
#: Options that say the gem comes from somewhere other than a registry — a git
#: repository, a path in the tree, a GitHub shorthand — in both hash syntaxes.
_GEM_NOT_REGISTRY = re.compile(r"""(?:\b(?:git|github|path|source|gist|bitbucket)\s*:)|"""
                               r"""(?::(?:git|github|path|source|gist|bitbucket)\s*=>)""")
#: A block whose gems are not on RubyGems: a `source` other than rubygems.org, or a
#: `path`/`git` block. `group :test do` and `platforms :jruby do` are neither.
_GEM_PRIVATE_BLOCK = re.compile(
    r"""^\s*(?:(?:path|git)\s*\(?\s*["'][^"']*["']|source\s*\(?\s*["'](?!https://rubygems\.org/?["'])[^"']*["'])"""
    r"""[^#]*\bdo\b"""
)
_BLOCK_OPENS = re.compile(r"\bdo\b(?:\s*\|[^|]*\|)?\s*$")
_GEMSPEC_DEPENDENCY = re.compile(
    r"""\.add_(?:runtime_|development_)?dependency\s*\(?\s*["']([A-Za-z0-9_.\-]+)["']"""
)
_GEMSPEC_NAME = re.compile(r"""\.name\s*=\s*["']([A-Za-z0-9_.\-]+)["']""")


def from_gemfile(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    """Every `gem` line outside a block that points somewhere other than RubyGems.

    Ruby is not parsed; the lines are. A Gemfile is a DSL of one call per line, and
    the shapes that matter — `gem` with a name, the options that make it
    non-registry, and the `source`/`path`/`git ... do` blocks that make everything
    inside non-registry — are regular. `group ... do` blocks are transparent.
    """
    rel = str(path.relative_to(workspace))
    found: set[tuple[str, str, str]] = set()
    stack: list[bool] = []          # per open block: is it a private source?
    for raw in text(path).splitlines():
        line = raw.split("#", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "end" or stripped.startswith("end "):
            if stack:
                stack.pop()
            continue
        match = _GEM_LINE.match(line)
        if match and not any(stack) and not _GEM_NOT_REGISTRY.search(match.group(2)):
            found.add(("gem", match.group(1), rel))
        if _BLOCK_OPENS.search(line):
            stack.append(bool(_GEM_PRIVATE_BLOCK.match(line)))
    return found


def from_gemspec(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    """`add_dependency`, `add_runtime_dependency` and `add_development_dependency`
    on whatever the spec object is called."""
    rel = str(path.relative_to(workspace))
    return {("gem", name, rel) for name in _GEMSPEC_DEPENDENCY.findall(text(path))}


# -------------------------------------------------------------- PHP (23.2.2)

_COMPOSER_FIELDS = ("require", "require-dev")


def from_composer(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    """`require` and `require-dev`. A platform package — `php`, `ext-json`,
    `lib-curl`, `composer-plugin-api` — has no vendor and is not on Packagist;
    every registry package is `vendor/name`, lowercase by Composer's own rule."""
    rel = str(path.relative_to(workspace))
    try:
        data = json.loads(text(path))
    except (json.JSONDecodeError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()
    found: set[tuple[str, str, str]] = set()
    for field in _COMPOSER_FIELDS:
        table = data.get(field)
        if not isinstance(table, dict):
            continue
        for name in table:
            if isinstance(name, str) and "/" in name:
                found.add(("composer", name.lower(), rel))
    return found


def _composer_local(path: Path) -> set[str]:
    """The package this manifest defines, and every package its `repositories`
    fetch from somewhere other than Packagist: a `path` or `vcs`/`git` repository
    named by its URL's last two segments, or a `package` repository by its own
    `name`. A private library required this way is not a hallucination."""
    try:
        data = json.loads(text(path))
    except (json.JSONDecodeError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()
    local: set[str] = set()
    if isinstance(data.get("name"), str) and "/" in data["name"]:
        local.add(data["name"].lower())
    repositories = data.get("repositories")
    entries = repositories.values() if isinstance(repositories, dict) else repositories
    for entry in entries if isinstance(entries, list | type({}.values())) else []:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("type")
        if kind == "package" and isinstance(entry.get("package"), dict):
            name = entry["package"].get("name")
            if isinstance(name, str) and "/" in name:
                local.add(name.lower())
        elif kind in ("vcs", "git", "github", "gitlab", "bitbucket", "path"):
            url = entry.get("url")
            if isinstance(url, str):
                segments = [seg for seg in url.rstrip("/").split("/") if seg]
                if len(segments) >= 2:
                    name = f"{segments[-2]}/{segments[-1]}".removesuffix(".git").lower()
                    local.add(name)
    return local


# ------------------------------------------------------------- Rust (23.2.3)

_CARGO_DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def from_cargo(path: Path, workspace: Path) -> set[tuple[str, str, str]]:
    """`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, the same
    three under any `[target.<cfg>]`, and `[workspace.dependencies]`.

    A table-valued entry with `path` or `git` comes from somewhere other than
    crates.io; one with `workspace = true` is declared in the workspace table and
    is read there; one with `package = "real-name"` renames a crate, and the real
    name is the one that has to exist. An alternative `registry` is not crates.io
    and is skipped.
    """
    import tomllib

    rel = str(path.relative_to(workspace))
    try:
        data = tomllib.loads(text(path))
    except (tomllib.TOMLDecodeError, ValueError):
        return set()

    tables: list[dict] = []
    for key in _CARGO_DEPENDENCY_TABLES:
        tables.append(data.get(key) or {})
    for target in (data.get("target") or {}).values():
        if isinstance(target, dict):
            for key in _CARGO_DEPENDENCY_TABLES:
                tables.append(target.get(key) or {})
    tables.append((data.get("workspace") or {}).get("dependencies") or {})

    found: set[tuple[str, str, str]] = set()
    for table in tables:
        if not isinstance(table, dict):
            continue
        for alias, spec in table.items():
            name = alias
            if isinstance(spec, dict):
                if spec.keys() & {"path", "git", "registry"} or spec.get("workspace") is True:
                    continue
                if isinstance(spec.get("package"), str):
                    name = spec["package"]
            elif not isinstance(spec, str):
                continue
            if isinstance(name, str) and name:
                found.add(("cargo", name, rel))
    return found


def _cargo_package_name(path: Path) -> str | None:
    import tomllib

    try:
        data = tomllib.loads(text(path))
    except (tomllib.TOMLDecodeError, ValueError):
        return None
    name = (data.get("package") or {}).get("name")
    return name if isinstance(name, str) and name else None

