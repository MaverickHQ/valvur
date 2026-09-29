"""R9.1: the live task list keeps the shapes `scripts/build_status.py` reads.

A resuming session learns where the build stands only from `tasks.md`: a phase
heading per phase and a checkbox line per task. A task written under the wrong
phase, or a heading the pattern misses, would send a fresh session to the wrong
branch or report the build finished while tasks remain.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "build_status.py"


def _module():
    import sys

    spec = importlib.util.spec_from_file_location("build_status", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["build_status"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_a_task_under_another_phase_s_heading_is_reported():
    text = ("### Phase R9: the Score\n\n- [ ] **R9.1** **One.**\n"
            "### Phase R10: trust fixes\n\n- [ ] **R9.2** **Misplaced.**\n")

    assert _module().shape_errors(text) == ["R9.2 sits under Phase R10"]


def test_a_gap_in_a_phase_s_numbering_is_reported():
    text = "### Phase R9: the Score\n\n- [x] **R9.1** **One.**\n- [ ] **R9.3** **Three.**\n"

    assert _module().shape_errors(text) == ["R9.3 follows R9.1"]
