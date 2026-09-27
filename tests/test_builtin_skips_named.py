"""R1.4: built-in skips are named (F7.7; the review's N2).

The built-in list skips `build`, `out`, `dist`, `target`, `vendor`, `external` and
more at any depth, before any Scanner reads. Measured 2026-09-27: a flow planted in
`mypkg/build/steps.py` was read by no Scanner, and the run said *2 active* without
naming the directory. Until the File Set replaces the list (R3.2), every surface
names what it skipped and how many files that was.
"""

from __future__ import annotations

from valvur import exclusions


def _tree(tmp_path):
    ws = tmp_path / "ws"
    (ws / "mypkg" / "build").mkdir(parents=True)
    (ws / "mypkg" / "core").mkdir(parents=True)
    (ws / "mypkg" / "build" / "steps.py").write_text("print('built')\n")
    (ws / "mypkg" / "core" / "run.py").write_text("print('run')\n")
    return ws


def test_each_skipped_builtin_directory_is_named_with_its_file_count(tmp_path):
    ws = _tree(tmp_path)
    assert exclusions.skipped_builtin(ws) == (("mypkg/build", 1),)
