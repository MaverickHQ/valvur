"""R21.1: the README's demo is the CLI's own output, small, and holds nothing private.

`scripts/demo.py` scans acceptance repository 8 through the CLI and renders what it
printed as `docs/demo.svg` (D48a). These tests read the committed file: under 1 MB,
the verdict and the malicious package in it, no path of the machine that made it and
nothing a secret scanner would flag. The end-to-end test runs the script again and
finds the same lines, so the file cannot drift from the CLI unseen.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SVG = REPO / "docs" / "demo.svg"
#: The README's first screen, in lines: what a reader sees before scrolling.
FIRST_SCREEN = 24


def _demo():
    spec = importlib.util.spec_from_file_location("demo", REPO / "scripts" / "demo.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _text(svg: str) -> list[str]:
    root = ET.fromstring(svg)  # noqa: S314 — the file this repository renders
    return [t.text or "" for t in root.iter("{http://www.w3.org/2000/svg}text")]


def test_the_script_uses_the_standard_library_alone():
    for path in (REPO / "scripts" / "demo.py", REPO / "scripts" / "acceptance" / "generate.py"):
        tree = ast.parse(path.read_text())
        names = {alias.name.split(".")[0] for node in ast.walk(tree)
                 if isinstance(node, ast.Import) for alias in node.names}
        names |= {node.module.split(".")[0] for node in ast.walk(tree)
                  if isinstance(node, ast.ImportFrom) and node.module and not node.level}
        assert names - {"generate", "__future__"} <= sys.stdlib_module_names, (path, names)


def test_a_capture_renders_every_line_in_order_and_neutralises_the_path(tmp_path):
    demo = _demo()
    workspace = tmp_path / "somewhere" / "acceptance-8"
    printed = f"findings: 1 active\nresults: {workspace}/.security-scan\n"

    svg = demo.render([("valvur scan .", demo.neutral(printed, workspace))])

    assert _text(svg) == ["~/acceptance-8 $ valvur scan .", "findings: 1 active",
                          "results: ~/acceptance-8/.security-scan"]
    assert str(tmp_path) not in svg
