"""R26.4: no closing pull request (D62c).

`1.4.0` took four owner actions, the last a pull request whose one change flipped
the README to *published* (#192), and `published.yml` asked PyPI and GHCR every day
which wording was true. The status line now names the version alone and PyPI's
badge says what is published, so the flip, its flag and its check are gone, and a
release ends at the owner's approval at the brake.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _script():
    spec = importlib.util.spec_from_file_location("prepare_release",
                                                  REPO / "scripts" / "prepare_release.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["prepare_release"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_the_flip_its_flag_and_its_daily_check_are_gone(capsys):
    with pytest.raises(SystemExit) as refused:
        _script().main(["--published", "9.9.9"])

    assert refused.value.code == 2
    assert "--published" in capsys.readouterr().err
    assert not hasattr(_script(), "published")
    assert not (REPO / ".github" / "workflows" / "published.yml").exists()
    assert not (REPO / "tests" / "test_published_check.py").exists()


def _cutting() -> str:
    text = (REPO / "docs" / "RELEASING.md").read_text(encoding="utf-8")
    return text.split("\n## Cutting a release\n", 1)[1].split("\n## ", 1)[0].split("\n### ", 1)[0]


def test_the_steps_end_at_the_owner_s_approval_and_the_owner_acts_three_times():
    """R26's exit counts the owner's actions from `RELEASING.md`: three, from four."""
    import re

    steps = re.findall(r"^# (\d+)\. (.*)$", _cutting(), re.M)
    owner = [text for _, text in steps if text.startswith("(owner)")]

    assert [int(n) for n, _ in steps] == list(range(1, len(steps) + 1))
    assert len(owner) == 3, owner
    assert "approve" in steps[-1][1].lower() and steps[-1][1].startswith("(owner)")
    assert "--published" not in _cutting() and "closing" not in _cutting()
