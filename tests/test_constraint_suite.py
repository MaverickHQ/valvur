"""The constraint suite, split (28.4.3, A4): seven files, one subject each.

`tests/test_constraints.py` was 1,442 lines — non-exfiltration, coverage,
isolation, budgets, supply chain, design and interruption in one file, the god
module moved into the tests. Split by subject; the count of tests is unchanged,
and this says so.
"""

from __future__ import annotations

import re
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SUBJECTS = ("exfiltration", "canary", "isolation", "budgets", "supply_chain", "design",
            "interruption")
#: What the one file held on the day it was split: not one fewer.
BEFORE_THE_SPLIT = 48


def test_the_split_kept_every_test_and_the_one_file_is_gone():
    files = [TESTS / f"test_constraints_{s}.py" for s in SUBJECTS]
    assert all(f.is_file() for f in files), [f.name for f in files if not f.is_file()]
    found = sum(len(re.findall(r"^def test_", f.read_text(encoding="utf-8"), re.M))
                for f in files)

    assert found == BEFORE_THE_SPLIT, \
        f"{found} tests across the split; the file held {BEFORE_THE_SPLIT}"
    assert not (TESTS / "test_constraints.py").exists(), "the god module is back"
