"""The repository-guards test skips, not fails, when its token cannot read the settings.

`security_and_analysis` needs an admin-scoped token. A Claude Code cloud session's token
gets the repository without it, and `test_the_repositorys_own_guards_are_on` failed on
that empty answer (measured 2026-10-03, the second cloud pre-flight). As its neighbour
does with a token that cannot ask, only a guard seen to be off is a failure.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

GUARDS = Path(__file__).resolve().parent / "test_repository_guards.py"


def _guards():
    spec = importlib.util.spec_from_file_location("repository_guards", GUARDS)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["repository_guards"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


@pytest.mark.parametrize("answer", ["", "null\n"])
def test_an_answer_without_the_settings_is_a_skip(answer):
    with pytest.raises(pytest.skip.Exception, match="admin"):
        _guards()._settings(answer)


def test_settings_that_were_read_are_judged():
    read = '{"secret_scanning": {"status": "enabled"}}\n'

    assert _guards()._settings(read) == {"secret_scanning": {"status": "enabled"}}
