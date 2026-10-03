"""R23.9: the orchestrator, small (D50).

`api.py` was 1,245 lines, with a 154-line fleet and a 135-line assembly in it
(R23.1's measurement). It is the scan's order now, and each step is a module of its
own: what a first run fetches, the fleet, the record's assembly and the record.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
LONGEST = 80


def _app_modules() -> list[Path]:
    layers = tomllib.loads((REPO / "scripts" / "layers.toml").read_text())["layers"]
    found = []
    for module in layers["app"]:
        path = SRC / (module.replace(".", "/") + ".py")
        found.append(path if path.exists() else path.with_suffix("") / "__init__.py")
    return found


def test_api_is_under_400_lines():
    lines = len((SRC / "valvur" / "api.py").read_text().splitlines())
    assert lines < 400, f"api.py is {lines} lines"


def test_no_function_in_the_app_layer_is_over_80_lines():
    long = []
    for path in _app_modules():
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                length = node.end_lineno - node.lineno + 1
                if length > LONGEST:
                    long.append(f"{path.relative_to(SRC)}:{node.name} ({length})")
    assert not long, f"over {LONGEST} lines: {long}"
