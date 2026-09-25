"""The Python versions the claim names (28.3.4, B1).

`requires-python = ">=3.11"` was claimed and 3.12 alone tested — the kind of
claim this project refuses elsewhere. The unit suite now runs on the floor and on
the newest release in CI (`floor` in `ci.yml`), and this test holds the matrix
to the claim: the floor `pyproject.toml` names has to be a version the matrix
runs, so narrowing or widening either without the other fails here.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _floor() -> str:
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    spec = pyproject["project"]["requires-python"]
    match = re.fullmatch(r">=\s*(\d+\.\d+)", spec.strip())
    assert match, f"requires-python is {spec!r}; this test reads a plain floor"
    return match.group(1)


def _matrix() -> list[str]:
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    floor = ci.split("\n  floor:", 1)
    assert len(floor) == 2, "ci.yml has no `floor` job"
    match = re.search(r"python:\s*\[([^\]]+)\]", floor[1])
    assert match, "the floor job has no python matrix"
    return [v.strip().strip('"') for v in match.group(1).split(",")]


def test_the_matrix_runs_the_floor_the_claim_names():
    assert _floor() in _matrix(), (
        f"requires-python's floor {_floor()} is not tested; the matrix runs {_matrix()}"
    )


def test_the_floor_is_the_version_the_source_uses_nothing_newer_than():
    """A sanity check on the claim itself, in the interpreter running this test:
    the stdlib names the source relies on that arrived in 3.11 exist here, and
    the claim is not below them."""
    import datetime

    assert hasattr(datetime, "UTC"), "datetime.UTC is 3.11+; the source uses it"
    assert tuple(int(p) for p in _floor().split(".")) >= (3, 11)
