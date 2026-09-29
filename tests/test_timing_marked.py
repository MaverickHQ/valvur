"""R10.6: a test that asserts on wall-clock time is marked `timing` (D35).

Such tests passed on Linux and failed on this Mac under swap: the container
ceiling's 60 s bound (73 s), the budget's 5 s, the doctor parity run. A unit run is
the one every slice makes, so a flake there stops the build for a reason that is
not the code. They run in CI's e2e job and at every phase exit instead.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLOCKS = {"monotonic", "perf_counter", "time"}


def _marks(node: ast.FunctionDef, module_marks: set[str]) -> set[str]:
    found = set(module_marks)
    for decorator in node.decorator_list:
        text = ast.unparse(decorator)
        if text.startswith("pytest.mark."):
            found.add(text.removeprefix("pytest.mark.").split("(")[0])
    return found


def _module_marks(tree: ast.Module) -> set[str]:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets):
            return {m.removeprefix("pytest.mark.").split("(")[0]
                    for m in ast.unparse(node.value).strip("[]()").replace(" ", "").split(",")}
    return set()


def _upper_bound(compare: ast.Compare) -> bool:
    """`x < 5`, `0.4 < x < 3.0`: a `<` against a number, which load can break. Two
    timestamps in order, or a lower bound, cannot fail for being slow."""
    operands = [compare.left, *compare.comparators]
    return any(isinstance(op, ast.Lt | ast.LtE)
               and isinstance(operands[i + 1], ast.Constant)
               and isinstance(operands[i + 1].value, int | float)
               for i, op in enumerate(compare.ops))


def _reads_the_clock_and_bounds_it(node: ast.FunctionDef) -> bool:
    """A call to a clock, and an assert holding something under a number."""
    clock = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in CLOCKS and ast.unparse(n.func.value) == "time"
                for n in ast.walk(node))
    bound = any(isinstance(n, ast.Assert) and any(
        isinstance(c, ast.Compare) and _upper_bound(c) for c in ast.walk(n.test))
        for n in ast.walk(node))
    return clock and bound


def test_every_wall_clock_assertion_is_marked_timing_or_e2e():
    unmarked = []
    for path in sorted((REPO / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text())
        module = _module_marks(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
                    and _reads_the_clock_and_bounds_it(node)
                    and not _marks(node, module) & {"timing", "e2e"}):
                unmarked.append(f"{path.name}::{node.name}")

    assert not unmarked, "\n".join(unmarked)


def test_the_unit_runs_select_no_timing_test_and_the_e2e_job_runs_them():
    verify = (REPO / "scripts" / "verify.sh").read_text()
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    pyproject = (REPO / "pyproject.toml").read_text()

    assert '"timing: ' in pyproject
    assert '-m "not e2e and not timing"' in verify
    assert '-m "not e2e and not timing"' in ci and '-m "not e2e"\n' not in ci
    assert '-m "e2e or timing"' in ci.split("\n  e2e:", 1)[1].split("\n  published:", 1)[0]
