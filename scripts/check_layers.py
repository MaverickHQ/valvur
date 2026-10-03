#!/usr/bin/env python3
"""The host side in layers (D50): each layer imports only from the layers below it.

    core      the Finding, identity, the verdict, ranking; no I/O
    infra     the runtimes, the datasets, the registries, git, the image's side
    app       the scan service, the read models, the jobs
    surfaces  the CLI, the MCP server, the hook

`scripts/layers.toml` assigns every module under `src/valvur` to one layer. This reads
each module's imports from the AST with the standard library, as
`check_traceability.py` reads its files, so an import inside a function body counts
as much as one at the top: a deferred import still runs, and still couples. Modules
are not moved; a module's layer is its entry in the table.

    python3 scripts/check_layers.py            # verify
"""

from __future__ import annotations

import ast
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "src" / "valvur"
CONFIG = REPO / "scripts" / "layers.toml"


@dataclass(frozen=True)
class Import:
    """One import of a module of the package, by a module of the package."""

    module: str
    target: str
    path: str
    line: int
    deferred: bool


@dataclass(frozen=True)
class Upward:
    """An import that points at a higher layer."""

    edge: Import
    from_layer: str
    to_layer: str

    @property
    def where(self) -> str:
        return f"{self.edge.path}:{self.edge.line}"

    @property
    def deferred(self) -> bool:
        return self.edge.deferred

    @property
    def message(self) -> str:
        kind = "a deferred import" if self.edge.deferred else "an import"
        return (f"{self.where}: {self.edge.module} ({self.from_layer}) imports "
                f"{self.edge.target} ({self.to_layer}), {kind} pointing upward")


@dataclass
class Found:
    upward: list[Upward] = field(default_factory=list)


def module_name(package: Path, path: Path) -> str:
    parts = list(path.relative_to(package.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def modules(package: Path) -> dict[str, Path]:
    return {module_name(package, path): path for path in sorted(package.rglob("*.py"))}


def _targets(node: ast.Import | ast.ImportFrom, module: str, is_package: bool,
             known: set[str], top: str) -> list[str]:
    """The package's modules an import statement loads, each resolved to the longest
    name the package defines: `from . import x` is the module `x` when there is one,
    else a name in the package itself."""
    names: list[str] = []
    if isinstance(node, ast.Import):
        names = [alias.name for alias in node.names]
    else:
        if node.level:
            base = module.split(".") if is_package else module.split(".")[:-1]
            base = base[:len(base) - (node.level - 1)]
            source = ".".join([*base, *([node.module] if node.module else [])])
        else:
            source = node.module or ""
        names = [f"{source}.{alias.name}" for alias in node.names]
    resolved = []
    for name in names:
        if name != top and not name.startswith(top + "."):
            continue
        while name not in known and "." in name:
            name = name.rpartition(".")[0]
        if name in known and name != module and name not in resolved:
            resolved.append(name)
    return resolved


def imports(package: Path, extra: frozenset[str] = frozenset()) -> list[Import]:
    """Every import of one of the package's modules, with whether it is deferred:
    inside a function or class body rather than at the module's top level."""
    found = modules(package)
    known = set(found) | set(extra)
    top = package.name
    edges: list[Import] = []
    for module, path in found.items():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(package.parent).as_posix()
        for node, deferred in _walk(tree.body, deferred=False):
            for target in _targets(node, module, path.name == "__init__.py", known, top):
                edges.append(Import(module, target, rel, node.lineno, deferred))
    return edges


def _walk(body: list[ast.stmt], *, deferred: bool):
    """Each import statement in `body`, and whether a function or class encloses it;
    a module-level `if` or `try` does not defer."""
    for node in body:
        if isinstance(node, ast.Import | ast.ImportFrom):
            yield node, deferred
            continue
        inner = deferred or isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef
                                       | ast.ClassDef)
        for child in ast.iter_child_nodes(node):
            # Statements nest directly (`if`, `with`, a body) or through a handler
            # or a match case, which are not statements themselves.
            nested = [child] if isinstance(child, ast.stmt) else [
                grandchild for grandchild in ast.iter_child_nodes(child)
                if isinstance(grandchild, ast.stmt)]
            yield from _walk(nested, deferred=inner)


@dataclass(frozen=True)
class Config:
    order: tuple[str, ...]
    assignment: dict[str, str]


def load(path: Path) -> Config:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    order = tuple(data["order"])
    assignment: dict[str, str] = {}
    for layer, names in (data.get("layers") or {}).items():
        for name in names:
            assignment[name] = layer
    return Config(order, assignment)


def check(package: Path = PACKAGE, config_path: Path = CONFIG) -> Found:
    config = load(config_path)
    rank = {layer: index for index, layer in enumerate(config.order)}
    found = Found()
    for edge in imports(package):
        here, there = config.assignment.get(edge.module), config.assignment.get(edge.target)
        if here is None or there is None:
            continue
        if rank[there] > rank[here]:
            found.upward.append(Upward(edge, here, there))
    return found


def main() -> int:
    found = check()
    for upward in found.upward:
        print(upward.message)
    if found.upward:
        print(f"\n{len(found.upward)} import(s) point upward (D50).")
        return 1
    print("layers: every import points down or across")
    return 0


if __name__ == "__main__":
    sys.exit(main())
