"""R24.5: the archive is a record (D55f, amending D43).

The traceability check read 16,500 lines of `docs/history` to find citations, so a
closed phase's notes counted as citing a requirement the code had stopped citing.
It reads the living documents, the code, the tests and the workflows, and this
test holds the list.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _check():
    spec = importlib.util.spec_from_file_location("check_traceability",
                                                  REPO / "scripts" / "check_traceability.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_traceability"] = module
    spec.loader.exec_module(module)
    return module


def test_it_reads_these_and_nothing_else():
    check = _check()
    assert check.CITING == (".kiro", "docs", "src", "scripts", "tests", ".github",
                            "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "CLAUDE.md",
                            "SECURITY.md")
    assert check.SEARCHED == ("src", "tests", "scripts", ".github", "docs")
    assert check.SKIPPED == ("docs/history",)


def test_nothing_it_reads_is_in_the_archive():
    check = _check()
    read = [p.relative_to(REPO).as_posix() for p in check._citing_files(REPO)]
    read += [p.relative_to(REPO).as_posix() for p in check._searched_files()]
    assert read and not [p for p in read if p.startswith("docs/history/")]
