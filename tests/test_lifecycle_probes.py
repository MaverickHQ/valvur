"""R2.3: stop a scan four ways against the real image; nothing may be left, and the
next scan must start. A probe whose fix is a later task (`probes.UNTIL`) is expected
to fail until that task is ticked in `tasks.md`."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _probes():
    path = REPO / "scripts" / "acceptance" / "probes.py"
    spec = importlib.util.spec_from_file_location("acceptance_probes", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance_probes"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _ticked(task: str) -> bool:
    text = (REPO / ".kiro/specs/valvur/tasks.md").read_text()
    return re.search(rf"^- \[[xX]\] \*\*{re.escape(task)}\*\*", text, re.M) is not None


@pytest.mark.e2e
@pytest.mark.parametrize("kind", ["cancel", "budget", "stdin", "kill"])
def test_nothing_is_left_and_the_next_scan_starts(mountable_tmp, kind):
    probes = _probes()
    workspace = probes.workspace(mountable_tmp)
    until = probes.UNTIL.get(kind)
    result = probes.probe(kind, workspace)
    if until and not _ticked(until):
        if not result.ok:
            pytest.xfail(f"{kind}: {result.containers_left} left; fixed by {until}")
    assert result.ok, result
