"""No fixture holds a Results Folder.

A scan run inside `tests/fixtures/<x>` leaves `.security-scan/` there. Git never sees it,
since the folder ignores itself, but every test that copies the fixture reads it as a
previous run. Three tests failed that way in the second cloud pre-flight (2026-10-03),
and nothing named the cause. This test names it.
"""

from __future__ import annotations

from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_no_fixture_holds_a_results_folder():
    found = sorted(str(path.relative_to(FIXTURES)) for path in FIXTURES.glob("*/.security-scan"))

    assert not found, f"a scan was run inside a fixture; delete these: {found}"
