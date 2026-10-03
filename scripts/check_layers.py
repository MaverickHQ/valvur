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

    python3 scripts/check_layers.py              # verify
    python3 scripts/check_layers.py --core-files # the core layer's files, for mypy --strict
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
    #: Inside `if TYPE_CHECKING:`: an annotation's import, which never runs.
    type_checking: bool = False


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
    def key(self) -> str:
        """How the baseline names it: by module, not by line, which moves."""
        return f"{self.edge.module} -> {self.edge.target}"

    @property
    def message(self) -> str:
        kind = "a deferred import" if self.edge.deferred else "an import"
        return (f"{self.where}: {self.edge.module} ({self.from_layer}) imports "
                f"{self.edge.target} ({self.to_layer}), {kind} pointing upward")


@dataclass
class Found:
    upward: list[Upward] = field(default_factory=list)
    #: Modules the table assigns to no layer.
    unassigned: list[str] = field(default_factory=list)
    #: Names the table assigns that are no module of the package.
    stray: list[str] = field(default_factory=list)
    #: Upward imports the baseline holds: recorded on the check's first run, and
    #: allowed until they are fixed.
    baselined: list[Upward] = field(default_factory=list)
    #: Baseline entries that no longer happen, which must be removed: the baseline
    #: only shrinks, and says what is true.
    gone: list[str] = field(default_factory=list)
    #: Groups of modules that import one another, each sorted (R23.9).
    cycles: list[list[str]] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return bool(self.upward or self.unassigned or self.stray or self.gone or self.cycles)


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
        for node, deferred, typing_only in _walk(tree.body, deferred=False):
            for target in _targets(node, module, path.name == "__init__.py", known, top):
                edges.append(Import(module, target, rel, node.lineno, deferred, typing_only))
    return edges


def _walk(body: list[ast.stmt], *, deferred: bool, typing_only: bool = False):
    """Each import statement in `body`, whether a function or class encloses it (a
    module-level `if` or `try` does not defer), and whether it sits under `if
    TYPE_CHECKING:`, which never runs."""
    for node in body:
        if isinstance(node, ast.Import | ast.ImportFrom):
            yield node, deferred, typing_only
            continue
        inner = deferred or isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef
                                       | ast.ClassDef)
        typing = typing_only or (isinstance(node, ast.If)
                                 and ast.unparse(node.test).endswith("TYPE_CHECKING"))
        for child in ast.iter_child_nodes(node):
            # Statements nest directly (`if`, `with`, a body) or through a handler
            # or a match case, which are not statements themselves.
            nested = [child] if isinstance(child, ast.stmt) else [
                grandchild for grandchild in ast.iter_child_nodes(child)
                if isinstance(grandchild, ast.stmt)]
            yield from _walk(nested, deferred=inner, typing_only=typing)


@dataclass(frozen=True)
class Config:
    order: tuple[str, ...]
    assignment: dict[str, str]
    #: Modules written at build time, absent from the source tree, which an import
    #: may still name (`valvur._build`).
    generated: frozenset[str] = frozenset()
    #: The upward imports allowed for now, as `module -> target`.
    baseline: frozenset[str] = frozenset()


def load(path: Path) -> Config:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    order = tuple(data["order"])
    assignment: dict[str, str] = {}
    for layer, names in (data.get("layers") or {}).items():
        if layer not in order:
            raise ValueError(f"{path}: the layer {layer!r} is not in `order`")
        for name in names:
            if name in assignment:
                raise ValueError(f"{path}: {name} is in two layers")
            assignment[name] = layer
    return Config(order, assignment, frozenset(data.get("generated") or ()),
                  frozenset(data.get("baseline") or ()))


def cycles(edges: list[Import], names: set[str]) -> list[list[str]]:
    """The groups of modules that can reach one another (Tarjan's strongly connected
    components), counting deferred imports, and each module's import of its
    packages' `__init__`, which Python runs first. An import for type checking alone
    never runs, and closes no cycle."""
    graph: dict[str, set[str]] = {name: set() for name in names}
    for edge in edges:
        if not edge.type_checking and edge.target in graph:
            graph[edge.module].add(edge.target)
    for name in names:
        parts = name.split(".")
        graph[name] |= {".".join(parts[:i]) for i in range(1, len(parts))} & names
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    found: list[list[str]] = []

    def strong(node: str) -> None:
        index[node] = low[node] = len(index)
        stack.append(node)
        on_stack.add(node)
        for target in sorted(graph[node]):
            if target not in index:
                strong(target)
                low[node] = min(low[node], low[target])
            elif target in on_stack:
                low[node] = min(low[node], index[target])
        if low[node] == index[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == node:
                    break
            if len(component) > 1:
                found.append(sorted(component))

    sys.setrecursionlimit(max(sys.getrecursionlimit(), 10 * len(graph) + 100))
    for node in sorted(graph):
        if node not in index:
            strong(node)
    return sorted(found)


def check(package: Path = PACKAGE, config_path: Path = CONFIG) -> Found:
    config = load(config_path)
    rank = {layer: index for index, layer in enumerate(config.order)}
    present = set(modules(package))
    found = Found(
        unassigned=sorted(present - set(config.assignment)),
        stray=sorted(set(config.assignment) - present - config.generated),
    )
    edges = imports(package, config.generated)
    found.cycles = cycles(edges, present)
    for edge in edges:
        here, there = config.assignment.get(edge.module), config.assignment.get(edge.target)
        if here is None or there is None:
            continue
        if rank[there] > rank[here]:
            upward = Upward(edge, here, there)
            (found.baselined if upward.key in config.baseline else found.upward).append(upward)
    found.gone = sorted(config.baseline - {u.key for u in found.baselined})
    return found


def core_files(package: Path = PACKAGE, config_path: Path = CONFIG) -> list[str]:
    """The source files of the `core` layer, which `mypy --strict` holds (D53)."""
    config = load(config_path)
    present = modules(package)
    return sorted(str(present[m].relative_to(REPO)) for m, layer in config.assignment.items()
                  if layer == "core" and m in present)


#: What a deferred import's comment starts with: `# deferred: <why>`, on its line or
#: in the comments directly above it (R23.9).
DEFERRED_MARK = "deferred:"


@dataclass(frozen=True)
class Deferred:
    """One deferred import of the package's own modules, and why it is deferred."""

    module: str
    targets: tuple[str, ...]
    path: str
    line: int
    reason: str | None

    @property
    def listed(self) -> str:
        return f"{self.module} -> {', '.join(self.targets)}: {self.reason or '(no reason)'}"


def _reason(lines: list[str], line: int) -> str | None:
    """The `# deferred:` comment on line `line` (1-based) or directly above it."""
    candidates = [lines[line - 1].partition("#")[2]]
    above = line - 2
    while above >= 0 and lines[above].lstrip().startswith("#"):
        candidates.append(lines[above].lstrip()[1:])
        above -= 1
    for text in candidates:
        text = text.strip()
        if text.lower().startswith(DEFERRED_MARK):
            return text[len(DEFERRED_MARK):].strip()
    return None


def deferred(package: Path = PACKAGE, config_path: Path = CONFIG) -> list[Deferred]:
    """Every deferred import of the package's own modules that runs (one under `if
    TYPE_CHECKING:` never does), by statement, with its reason or None."""
    config = load(config_path)
    statements: dict[tuple[str, int], list[Import]] = {}
    for edge in imports(package, frozenset(config.generated)):
        if edge.deferred and not edge.type_checking:
            statements.setdefault((edge.path, edge.line), []).append(edge)
    found = []
    for (path, line), edges in sorted(statements.items()):
        lines = (package.parent / path).read_text(encoding="utf-8").splitlines()
        found.append(Deferred(edges[0].module, tuple(sorted({e.target for e in edges})),
                              path, line, _reason(lines, line)))
    return found


def main() -> int:
    if sys.argv[1:] == ["--core-files"]:
        print("\n".join(core_files()))
        return 0
    if sys.argv[1:] == ["--deferred"]:
        # The listing `tests/fixtures/deferred-imports.txt` holds (R23.9).
        print("\n".join(sorted(d.listed for d in deferred())))
        return 0
    found = check()
    for upward in found.upward:
        print(upward.message)
    for module in found.unassigned:
        print(f"{module}: in no layer; assign it in {CONFIG.relative_to(REPO)}")
    for name in found.stray:
        print(f"{name}: assigned in {CONFIG.relative_to(REPO)}, and no such module")
    for key in found.gone:
        print(f"{key}: in the baseline and no longer imported; remove it, so it stays gone")
    for cycle in found.cycles:
        print(f"an import cycle: {', '.join(cycle)}")
    if found.failed:
        print(f"\nlayers: {len(found.upward)} upward, {len(found.unassigned)} unassigned, "
              f"{len(found.stray)} stray, {len(found.gone)} gone from the baseline, "
              f"{len(found.cycles)} cycle(s) (D50).")
        return 1
    held = f"; {len(found.baselined)} upward import(s) held by the baseline" \
        if found.baselined else ""
    print("layers: every module has a layer, every import points down or across, and "
          f"none closes a cycle{held}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
