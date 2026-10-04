"""R3.9 on a real image: a data directory costs a scan nothing (the gate's tree).

Moved from 29.0.1's scan-time-excludes tests when the exclude dialects went: the
property is the same, the mechanism is the File Set (ADR-0021).
"""

from __future__ import annotations

import hashlib
import time

import pytest
from conftest import FIXTURES
from fixture_copy import copy_fixture


@pytest.mark.e2e
def test_a_data_directory_is_skipped_not_walked(mountable_tmp):
    """The gate's tree in miniature: the broken fixture beside an excluded
    `archive/` of 20,000 files that each hold a token Gitleaks flags, and a
    `node_modules/` of 2,000 more. Neither reaches the Snapshot: nothing under
    either is reported, the raw Gitleaks report stays small, and the scan takes
    about the time the fixture alone does. Measured before 29.0.1, on the gate's
    tree: Gitleaks 211.7 s."""
    from valvur import engine_host, profiles
    from valvur.api import scan

    def token(i: int) -> str:
        # High-entropy, so Gitleaks's github-pat rule fires: a run of digits does
        # not, and a token nobody flags would make the raw-size assertion vacuous.
        return "ghp_" + hashlib.sha256(str(i).encode()).hexdigest()[:36]

    ws = mountable_tmp / "repo"
    copy_fixture(FIXTURES / "broken-repo", ws)
    (ws / ".security-scan.toml").write_text('[scan]\nexclude = ["archive"]\n')
    (ws / "planted.py").write_text(f'token = "{token(-1)}"\n')
    for top, count in (("archive", 20_000), ("node_modules", 2_000)):
        for part in range(40):
            (ws / top / f"part{part}").mkdir(parents=True, exist_ok=True)
        for i in range(count):
            (ws / top / f"part{i % 40}" / f"f{i}.py").write_text(
                f'token = "{token(i)}"\nimport os\nos.system("id")\n')
    started = time.monotonic()

    run = scan(ws, runner=engine_host.for_scan(), profile=profiles.OFFLINE)

    wall = time.monotonic() - started
    durations = {s.tool: s.duration_s for s in run.scanners}
    print(f"\nwall {wall:.1f}s; per Scanner: {durations}")
    assert not run.failures, [s.reason for s in run.failures]
    hidden = [f.path for f in run.findings if f.path.startswith(("archive/", "node_modules/"))]
    assert hidden == [], hidden[:5]
    assert any(f.path == "planted.py" for f in run.findings), \
        "the planted token form is not flagged"
    raw = (ws / ".security-scan" / "raw" / "gitleaks.json").stat().st_size
    assert raw < 200_000, f"Gitleaks read the archive: {raw} bytes of raw output"
    assert ("archive", "excluded by .security-scan.toml") in run.not_read
    assert ("node_modules", "a dependency cache") in run.not_read
    assert wall < 300, f"{wall:.0f}s on a ten-file tree beside 22,000 skipped files"
