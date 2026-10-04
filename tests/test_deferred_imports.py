"""R23.9: every deferred import left says why (D50).

An import inside a function was how this package broke its cycles, 229 of them at
R23.1's count. With no cycle left, a deferred import is a choice with a cost, such as
startup, that the plugin's hook pays on every install and the MCP server before its
handshake. Each says which, in a `# deferred:` comment on its line or directly above
it, and the list is committed, so one more is a visible change to review.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LISTED = REPO / "tests" / "fixtures" / "deferred-imports.txt"
REGENERATE = ("uv run python scripts/check_layers.py --deferred "
              "> tests/fixtures/deferred-imports.txt")


def _check():
    spec = importlib.util.spec_from_file_location("check_layers",
                                                  REPO / "scripts" / "check_layers.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_layers"] = module
    spec.loader.exec_module(module)
    return module


def _package(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / "pkg" / name).parent.mkdir(parents=True, exist_ok=True)
        (root / "pkg" / name).write_text(text)
    config = root / "layers.toml"
    config.write_text('order = ["core"]\ngenerated = []\nbaseline = []\n'
                      '[layers]\ncore = ["pkg", "pkg.a", "pkg.b"]\n')
    return config


def test_a_deferred_import_reads_its_reason_from_its_line_or_the_comment_above(tmp_path):
    config = _package(tmp_path, {
        "__init__.py": "",
        "a.py": "x = 1\n",
        "b.py": ("def f():\n"
                 "    # Something else first.\n"
                 "    # deferred: startup; the hook loads b.\n"
                 "    from . import a\n"
                 "    return a\n"
                 "def g():\n"
                 "    from .a import x  # deferred: only g needs it\n"
                 "    return x\n"
                 "def h():\n"
                 "    from . import a\n"
                 "    return a\n"
                 "from typing import TYPE_CHECKING\n"
                 "if TYPE_CHECKING:\n"
                 "    from . import a\n"),
    })
    found = _check().deferred(tmp_path / "pkg", config)
    assert [(d.line, d.reason) for d in found] == [
        (4, "startup; the hook loads b."), (7, "only g needs it"), (10, None)]


def test_every_deferred_import_says_why():
    silent = [f"{d.path}:{d.line}" for d in _check().deferred() if not d.reason]
    assert not silent, f"deferred imports with no `# deferred:` reason: {silent}"


def test_the_deferred_imports_are_the_ones_listed():
    listed = sorted(_check_listing())
    committed = sorted(LISTED.read_text(encoding="utf-8").splitlines())
    added = [line for line in listed if line not in committed]
    gone = [line for line in committed if line not in listed]
    assert listed == committed, (
        f"the deferred imports changed: added {added}, gone {gone}. Hoist what can be, "
        f"and regenerate the list: {REGENERATE}")


def _check_listing() -> list[str]:
    return [d.listed for d in _check().deferred()]
