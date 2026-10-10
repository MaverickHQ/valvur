"""One scan names one slowest Scanner, on every surface.

The fleet runs concurrently, so the scan reply and `SUMMARY.md` each name the Scanner
that took longest, as roughly what the scan cost. The engine rounds each Scanner's
time to a tenth of a second, so two quick Scanners often tie, and the two surfaces
broke the tie differently: the reply by name (`trivy`), the summary by run order
(`gitleaks`). One scan gave two answers, and the scan goldens froze both, until a
loaded machine made the times differ and the goldens failed.
"""

from __future__ import annotations

import json
import re

import pytest

from valvur import reply, summary
from valvur.scanner_run import ScannerRun
from valvur.scanrun import ScanRun

TIED = [("gitleaks", 0.1), ("trivy", 0.1)]
APART = [("gitleaks", 0.1), ("trivy", 0.3)]


def _reply_slowest(tmp_path, scanners) -> str:
    results = tmp_path / ".security-scan"
    results.mkdir()
    (results / "run.json").write_text(json.dumps({
        "complete": True, "status": "clean",
        "scanners": [{"tool": tool, "ok": True, "duration_s": seconds}
                     for tool, seconds in scanners]}))
    return reply.fields(tmp_path)["slowest"]["tool"]


def _summary_slowest(scanners) -> str:
    text = summary.render(ScanRun(scanners=[ScannerRun(tool, ok=True, duration_s=seconds)
                                            for tool, seconds in scanners]))
    found = re.search(r"slowest: (\S+) ", text)
    assert found, "the summary names no slowest Scanner"
    return found.group(1)


@pytest.mark.parametrize("scanners", [TIED, TIED[::-1], APART, APART[::-1]],
                         ids=["tied", "tied-reversed", "apart", "apart-reversed"])
def test_the_reply_and_the_summary_name_the_same_slowest_scanner(tmp_path, scanners):
    assert _reply_slowest(tmp_path, scanners) == _summary_slowest(scanners)


def test_a_tie_goes_to_the_scanner_that_ran_first(tmp_path):
    assert _reply_slowest(tmp_path, TIED) == "gitleaks"
    assert _summary_slowest(TIED) == "gitleaks"


def test_the_scan_goldens_treat_the_slowest_scanner_as_they_treat_its_time(tmp_path):
    """Which Scanner was slowest is decided by the clock, like the seconds the goldens
    already normalise: on a loaded machine either of two quick ones can be. The rule
    that names it is held above, deterministically."""
    from test_scan_goldens import _scrub, normalise

    for fast, slow in (("gitleaks", "trivy"), ("trivy", "gitleaks")):
        said = {"slowest": {"tool": slow, "seconds": 0.3}, "scanners": [{"tool": fast}]}
        assert normalise(f"  slowest: {slow} 0.3s — the fleet", tmp_path) == \
            "  slowest: <SCANNER> <T>s — the fleet"
        assert _scrub(said) == {"slowest": {"tool": "<SCANNER>", "seconds": "<N>"},
                                "scanners": [{"tool": fast}]}
