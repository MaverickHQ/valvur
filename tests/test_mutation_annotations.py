"""R48.5: a mutant of an annotation alone is not counted (Requirement 15.1).

`scripts/mutation_check.py` reverts each hunk of a change and counts the ones no unit test
notices. A hunk that only changed a type annotation changes nothing a test can see, so it
survived every time and pulled the score down for the wrong reason. It is *no code change*,
as a hunk of comments is. An annotation a dataclass reads is the exception: `ClassVar`,
`InitVar` and `KW_ONLY` change what the class is.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("mutation_check",
                                               REPO / "scripts" / "mutation_check.py")
check = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("mutation_check", check)        # its dataclass looks itself up
_spec.loader.exec_module(check)

BEFORE = ("def scan(path: str, deep: bool = False) -> list:\n"
          "    limit: int = 5\n"
          "    seen: dict\n"
          "    return [path][:limit]\n")


def test_an_annotation_and_a_value_changed_together_is_a_code_change():
    assert check.code_changed(BEFORE, BEFORE.replace("limit: int = 5", "limit: float = 6"))
    assert check.code_changed(BEFORE, BEFORE.replace("deep: bool = False", "deep: int = True"))


@pytest.mark.parametrize("after", [
    pytest.param(BEFORE.replace("path: str", "path: str | None"), id="an-argument"),
    pytest.param(BEFORE.replace("deep: bool", "deep: int"), id="an-argument-with-a-default"),
    pytest.param(BEFORE.replace("-> list", "-> list[str]"), id="the-return"),
    pytest.param(BEFORE.replace("-> list:", ":"), id="the-return-removed"),
    pytest.param(BEFORE.replace("limit: int = 5", "limit: float = 5"), id="an-assignment"),
    pytest.param(BEFORE.replace("seen: dict", "seen: dict[str, int]"), id="a-declaration"),
])
def test_an_annotation_changed_alone_is_no_code_change(after):
    assert after != BEFORE
    assert not check.code_changed(BEFORE, after)


@pytest.mark.parametrize("annotation", ["ClassVar[int]", "InitVar[int]", "KW_ONLY",
                                        "typing.ClassVar[int]", "dataclasses.InitVar[int]"])
def test_an_annotation_a_dataclass_reads_is_still_a_code_change(annotation):
    before = "@dataclass\nclass Row:\n    weight: int = 1\n"

    assert check.code_changed(before, before.replace("weight: int", f"weight: {annotation}"))
