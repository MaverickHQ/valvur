"""The dependency-reality Check's output, and the ecosystem registry (task 27.3.2).

`dependency_reality.py` was 1,206 lines holding Check orchestration, seven manifest
parsers, registry transport, per-registry age decoding and typosquat matching — and
the truth about an ecosystem was spread over three modules that had to be edited
together: `ecosystems.MANIFESTS` (what to read), `name_index.FILES` (which index),
and a per-ecosystem `if` in the Check for the registry, the URL and the age. The two
modules imported each other, lazily, in both directions.

The goldens here were captured from the Check **before** any of that moved. They are
the guard on a refactor whose whole claim is that nothing changed: what a scan of a
real manifest reports is what a user sees, so "equivalent" is not the standard.

    UPDATE_DEPENDENCY_GOLDEN=1 uv run pytest tests/test_ecosystem_registry.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

GOLDEN = Path(__file__).parent / "fixtures" / "dependency-reality"
UPDATE = "UPDATE_DEPENDENCY_GOLDEN"
FIXTURES = Path(__file__).parent / "fixtures"

#: Every manifest shape the parsers know, in one tree per case. Written here rather
#: than pointing at the repository's own fixtures so a change to those cannot move
#: this guard underneath the refactor it is guarding.
TREES: dict[str, dict[str, str]] = {
    "python": {
        "requirements.txt": "requests==2.31.0\nreqeusts==1.0\nflask>=2\n",
        "pyproject.toml": '[project]\nname = "app"\ndependencies = ["httpx", "aws-helper-sdk"]\n',
    },
    "npm": {
        "package.json": json.dumps({
            "name": "app", "version": "1.0.0",
            "dependencies": {"react": "^18", "reakt": "^1", "@types/node": "^20"},
            "devDependencies": {"jest": "^29"},
        }),
    },
    "jvm": {
        "pom.xml": ('<project><dependencies><dependency>'
                    '<groupId>com.google.guava</groupId><artifactId>guava</artifactId>'
                    "</dependency></dependencies></project>"),
        "build.gradle": 'dependencies {\n  implementation "org.slf4j:slf4j-api:2.0.9"\n}\n',
    },
    "go-ruby-php-rust": {
        "go.mod": "module example.com/m\n\ngo 1.22\n\nrequire github.com/pkg/errors v0.9.1\n",
        "Gemfile": 'source "https://rubygems.org"\ngem "rack"\n',
        "composer.json": json.dumps({"require": {"monolog/monolog": "^3.0"}}),
        "Cargo.toml": '[package]\nname = "app"\n\n[dependencies]\nserde = "1"\n',
    },
}


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def _declared(workspace: Path) -> list[list[str]]:
    """What the Check believes is declared: the answer every later decision rests
    on, and the part a parser refactor can silently change."""
    from valvur.checks.dependency_reality import _declared_packages

    return sorted([eco, name, src] for eco, name, src in _declared_packages(workspace))


@pytest.mark.parametrize("name", sorted(TREES))
def test_what_the_check_reads_from_each_manifest_is_unchanged(name, tmp_path):
    workspace = _write(tmp_path / name, TREES[name])
    path = GOLDEN / f"{name}.json"
    declared = _declared(workspace)

    if os.environ.get(UPDATE):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(declared, indent=2) + "\n", encoding="utf-8")
        pytest.skip(f"regenerated {path.name}")

    assert path.is_file(), f"no golden for {name!r}; generate with {UPDATE}=1"
    assert declared == json.loads(path.read_text()), (
        f"the parsers read {name} differently than before the move"
    )


def test_the_broken_fixture_reads_the_same_as_before(tmp_path):
    """The repository's own deliberately-broken tree, which is what the e2e suite
    and every demo scan use: the two planted hallucinations are in here."""
    import shutil

    workspace = tmp_path / "broken"
    shutil.copytree(FIXTURES / "broken-repo", workspace)
    path = GOLDEN / "broken-repo.json"
    declared = _declared(workspace)

    if os.environ.get(UPDATE):
        path.write_text(json.dumps(declared, indent=2) + "\n", encoding="utf-8")
        pytest.skip("regenerated broken-repo.json")

    assert declared == json.loads(path.read_text())
    assert ["pip", "reqeusts", "requirements-ai.txt"] in declared, \
        "the planted hallucination is no longer read at all"


# ----------------------------------------------------- the registry is complete


def test_every_ecosystem_can_answer_existence_or_says_why_it_cannot():
    """An ecosystem valvur READS is one it can be asked about — from the offline
    index, or from a registry with the reason there is no index stated. Silence is
    the failure mode this project keeps finding: a Check that says nothing is
    indistinguishable from one that found nothing (F3.5)."""
    from valvur import ecosystems

    for e in ecosystems.ECOSYSTEMS:
        assert e.reads, f"{e.key} is in the registry and reads nothing"
        assert e.index_file or e.no_index_because, (
            f"{e.key} has no offline index and does not say why, so a user on "
            "`offline` would be told nothing at all"
        )
        assert e.registry and e.host, f"{e.key} names no registry to ask"
        assert e.label and e.key


def test_every_registry_host_is_one_the_disclosure_names():
    """CLAUDE.md §3: a host this Check can reach is a destination `run.json`
    discloses. 23.5.4 found that sentence three registries out of date for a week,
    which is the reason the two are held together rather than reviewed."""
    from valvur import ecosystems, egress

    for e in ecosystems.ECOSYSTEMS:
        assert e.host in egress.SPOKEN_AS, (
            f"{e.key} asks {e.host}, which `egress.SPOKEN_AS` does not name — so a "
            "`full` scan would reach a host `run.json` never mentions"
        )


def test_the_index_files_are_the_indexed_ecosystems_in_the_order_users_see():
    """`valvur doctor` and `valvur update` print this order, so it is text a user
    reads. It differed from the manifest table's order before 27.3.2, and deriving
    one from the other silently reordered the line."""
    from valvur import ecosystems, name_index

    # The literal order, not `INDEX_ORDER` — the dict is built FROM that constant,
    # so comparing the two says only that a loop works. What a user reads is this
    # sequence, unchanged since `name_index.FILES` first held it.
    assert tuple(ecosystems.INDEX_FILES) == ("pip", "npm", "gem", "composer", "cargo")
    assert name_index.FILES == ecosystems.INDEX_FILES
    assert set(ecosystems.INDEX_FILES) == {
        e.key for e in ecosystems.ECOSYSTEMS if e.index_file
    }


def test_the_name_index_and_the_check_no_longer_import_each_other(tmp_path):
    """They imported each other, lazily, in both directions: `name_index` wanted
    the Check's PEP 503 canonicalisation and the Check wanted `name_index`'s crate
    form. Both live in the registry now, and neither module reaches for the other
    to get them."""
    import subprocess
    import sys

    probe = tmp_path / "probe.py"
    probe.write_text(
        "import sys\n"
        "import valvur.name_index as ni\n"
        "assert 'valvur.checks.dependency_reality' not in sys.modules, "
        "'name_index pulled in the Check'\n"
        "assert ni.FILES and ni.crate_canonical('A-B') == 'a_b'\n"
        "print('ok')\n"
    )
    done = subprocess.run([sys.executable, str(probe)], capture_output=True, text=True,
                          timeout=60, check=False)

    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "ok"


def test_the_registry_holds_what_the_three_modules_each_held_a_piece_of():
    """The point of the move, asserted: one entry answers what `MANIFESTS`,
    `name_index.FILES` and a chain of `if ecosystem == …` in the Check each knew
    separately."""
    from valvur import ecosystems
    from valvur.checks import dependency_reality

    pip = ecosystems.get("pip")
    assert pip.reads == ecosystems.MANIFESTS["pip"].reads      # was ecosystems.py
    assert pip.index_file == "pypi.txt"                        # was name_index.FILES
    assert pip.registry == "PyPI"                              # was _REGISTRY_NAME
    assert dependency_reality._index_form("pip", "Flask_Login") == "flask-login"
    assert dependency_reality._index_form("gem", "Rails") == "Rails", "RubyGems is case-sensitive"
    assert dependency_reality._index_form("cargo", "serde-json") == "serde_json"
    assert ecosystems.get("gomod").near_miss is False and pip.near_miss is True


# --------------------------------------------------- the import graph (28.0.5)


def _import_graphs() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Every module under `src/valvur` → the modules it imports. Two graphs: HARD
    edges are module-level imports outside `if TYPE_CHECKING:`, which run at
    import time and can only work in a cycle by Python's partial-module accident;
    SOFT edges are everything, including lazy imports inside functions and
    annotation-only ones, which are a design choice this project uses on purpose."""
    import ast
    import collections

    root = Path(__file__).resolve().parent.parent / "src" / "valvur"
    modules: dict[str, Path] = {}
    for path in root.rglob("*.py"):
        name = ".".join(path.relative_to(root.parent).with_suffix("").parts)
        modules[name.removesuffix(".__init__")] = path

    def resolve(name: str, path: Path, node: ast.ImportFrom) -> set[str]:
        parts = name.split(".") + (["_"] if path.name == "__init__.py" else [])
        base = parts[:-node.level] if node.level else []
        module = [node.module] if node.module else []
        target = ".".join(base + module) if node.level else node.module
        found = set()
        for alias in node.names:
            candidate = f"{target}.{alias.name}"
            found.add(candidate if candidate in modules else target)
        return {f for f in found if f in modules}

    def _internal(node: ast.ImportFrom) -> bool:
        return bool(node.level) or (node.module or "").startswith("valvur")

    hard: dict[str, set[str]] = collections.defaultdict(set)
    soft: dict[str, set[str]] = collections.defaultdict(set)
    for name, path in modules.items():
        tree = ast.parse(path.read_text())
        for node in tree.body:
            if isinstance(node, ast.If) and getattr(node.test, "id", "") == "TYPE_CHECKING":
                continue
            if isinstance(node, ast.ImportFrom) and _internal(node):
                hard[name] |= resolve(name, path, node)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and _internal(node):
                soft[name] |= resolve(name, path, node)
    return hard, soft


def _components(graph: dict[str, set[str]]) -> set[frozenset[str]]:
    """The strongly connected components of size two or more — every group of
    modules that can reach each other. Tarjan's algorithm, over sorted nodes and
    edges, so the answer is the same on every filesystem: the first form of this
    ratchet enumerated individual cycles by DFS in `rglob` order, which names one
    set of sub-cycles on APFS and another on ext4, and failed on CI with a 4-node
    sub-cycle the Mac had never produced. A component is the canonical object —
    the same modules, whichever way round you walk them."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    found: set[frozenset[str]] = set()
    counter = 0

    def strong(node: str) -> None:
        nonlocal counter
        index[node] = low[node] = counter
        counter += 1
        stack.append(node)
        on_stack.add(node)
        for target in sorted(graph.get(node, ())):
            if target not in index:
                strong(target)
                low[node] = min(low[node], low[target])
            elif target in on_stack:
                low[node] = min(low[node], index[target])
        if low[node] == index[node]:
            component = set()
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.add(member)
                if member == node:
                    break
            if len(component) > 1:
                found.add(frozenset(component))

    for node in sorted(set(graph) | {t for ts in graph.values() for t in ts}):
        if node not in index:
            strong(node)
    return found


def test_no_module_level_import_cycles():
    """28.0.5. 27.3.2 removed the lazy two-way import between `name_index` and the
    Check and, one package down, introduced the tree's only HARD cycle:
    `ecosystems.registry` imported the parser functions at module level and
    `ecosystems.parsers.declared()` imported the registry at module level. It ran
    only because `declared` touched the registry at call time. Zero, by ratchet."""
    hard, _ = _import_graphs()

    tangled = {tuple(sorted(c)) for c in _components(hard)}
    assert not tangled, f"module-level import cycles: {sorted(tangled)}"


def test_soft_cycles_are_the_ones_chosen_on_purpose():
    """Lazy and annotation-only cycles are a design choice here — `api` and
    `results` need each other's names, `mcp.server` and `mcp.tools` register each
    other — and each group is named so a module joining one is a decision, not an
    accident. Named as components, not cycles: one group of modules that can all
    reach each other, whichever sub-cycle a walk happens to find first."""
    _, soft = _import_graphs()
    accepted = {
        frozenset({"valvur", "valvur.api", "valvur.compat", "valvur.pipeline", "valvur.results",
                   "valvur.runner", "valvur.staleness", "valvur.summary"}),
        frozenset({"valvur.mcp.server", "valvur.mcp.tools"}),
    }

    found = _components(soft)
    new = {tuple(sorted(c)) for c in found - accepted}
    assert not new, f"a lazy or annotation-only import cycle nobody chose: {sorted(new)}"
    gone = {tuple(sorted(c)) for c in accepted - found}
    assert not gone, f"an accepted cycle no longer exists; remove it from the list: {sorted(gone)}"
