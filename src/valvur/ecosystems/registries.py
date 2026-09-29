"""Where a project says its packages come from (R10.3, R10.4; D27, F3.15, ADR-0028).

A name missing from the public index is a hallucination only if the project would
look for it on the public registry. A company's internal packages are served by its
own registry, and the project says so in its own files: `.npmrc` and `.yarnrc.yml`
for npm; `pip.conf`, a requirements file's index options, and the uv, Poetry and
Pipfile source tables for Python. Read from the File Set, never from a home
directory: what is not in the project is not what the project declares.

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


def for_manifest(workspace: Path, ecosystem: str, manifest: Path) -> Registries:
    if ecosystem == "npm":
        return npm(workspace, manifest)
    return Registries()
