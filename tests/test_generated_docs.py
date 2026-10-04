"""R24.2: the docs' facts are generated, not compared (D55a).

A fact the code holds, such as a tool's fields, a path in the Scan Container or a
setting's variable, is written into the docs by `scripts/generate_docs.py`, between
`<!-- generated: <name> -->` and `<!-- /generated -->`. One test regenerates every
block and names the one that differs, in place of a test per fact that compared the
code with the prose around it.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _generator():
    spec = importlib.util.spec_from_file_location("generate_docs",
                                                  REPO / "scripts" / "generate_docs.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_docs"] = module
    spec.loader.exec_module(module)
    return module


def test_every_generated_block_is_what_the_code_says():
    stale = _generator().stale()
    assert not stale, (
        "generated blocks differ from the code: "
        + ", ".join(f"{name} in {path}" for path, name in stale)
        + "; run `uv run python scripts/generate_docs.py`")


def test_a_stale_block_is_named_and_rewritten(tmp_path):
    generate = _generator()
    doc = tmp_path / "doc.md"
    doc.write_text("before\n<!-- generated: demo -->\nold\n<!-- /generated -->\nafter\n")
    blocks = {"demo": lambda: "new\n"}

    assert generate.stale([doc], blocks) == [(doc, "demo")]
    generate.write([doc], blocks)
    assert doc.read_text() == ("before\n<!-- generated: demo -->\n\nnew\n\n"
                               "<!-- /generated -->\nafter\n")
    assert generate.stale([doc], blocks) == []


def test_every_block_is_used_and_every_marker_names_a_block():
    generate = _generator()
    used = {name for path in generate.FILES for name in generate.names(path.read_text())}
    assert used == set(generate.BLOCKS), (
        f"unused: {sorted(set(generate.BLOCKS) - used)}; "
        f"unknown: {sorted(used - set(generate.BLOCKS))}")
