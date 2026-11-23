"""R51.8: the two import guides cite the second measurement, and nothing else (Req. 9.5).

`docs/DEFECTDOJO.md` and `docs/DEPENDENCY-TRACK.md` say what arrives in each tool. Each
number in them is one `docs/acceptance/r51.md` records under *Measured again*, the
measurement made after the corrections: the table is the record's own, byte for byte, and
no count stands in a guide's prose that the record's table does not hold.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
RECORD = REPO / "docs" / "acceptance" / "r51.md"
GUIDES = {"defectdojo": REPO / "docs" / "DEFECTDOJO.md",
          "dependency-track": REPO / "docs" / "DEPENDENCY-TRACK.md"}


def _measured(text: str, name: str) -> str:
    found = re.search(rf"<!-- measured: {name} -->\n(.*?)<!-- /measured -->", text, re.S)
    assert found, f"no block `measured: {name}`"
    return found[1]


def _counts(text: str) -> set[str]:
    """The whole numbers a reader would take as measured: not a version, a date, a port in
    an address, an identifier such as CWE-89 or A05:2025, or anything in code."""
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    text = re.sub(r"`[^`\n]*`", " ", text)
    text = re.sub(r"\]\([^)]*\)", "]", text)
    text = re.sub(r"\b\d{4}-\d{2}-\d{2}\b|\b\d+(?:\.\d+)+\b|\b[A-Za-z]+-?\d+(?::\d+)?\b", " ",
                  text)
    return set(re.findall(r"(?<![\w.:/-])\d+(?![\w.:/-])", text))


@pytest.mark.parametrize("name", list(GUIDES))
def test_a_guides_table_is_the_records_own(name):
    record = _measured(RECORD.read_text(encoding="utf-8"), name)

    assert record.count("\n|") >= 5, "the record's table has its rows"
    assert _measured(GUIDES[name].read_text(encoding="utf-8"), name) == record


@pytest.mark.parametrize("name", list(GUIDES))
def test_no_count_stands_in_a_guide_that_the_record_does_not_hold(name):
    guide = GUIDES[name].read_text(encoding="utf-8")
    held = _counts(_measured(RECORD.read_text(encoding="utf-8"), name))

    assert held, "the record's table holds counts"
    assert sorted(_counts(guide) - held, key=int) == []


def test_a_count_the_record_does_not_hold_is_seen():
    held = _counts("| components | 16 | 15 |")

    assert _counts("It kept 15 of 16, on 2026-11-23, in 5.2.2, for CWE-89 at "
                   "`localhost:8080`.") == held
    assert _counts("It kept 14 of 16.") - held == {"14"}


def test_the_record_says_which_measurement_the_guides_cite():
    record = RECORD.read_text(encoding="utf-8")

    assert record.index("### The first measurement") < record.index("### Measured again")
    for name in GUIDES:
        assert record.index("### Measured again") < record.index(f"<!-- measured: {name} -->")
