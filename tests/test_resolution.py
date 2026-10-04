"""R21.4: the loop closed (D59).

The owner's agent edited three findings and could not rescan, so nothing was
confirmed; and a rescan named what it fixed by title alone, which cannot be matched
line for line with the first report. So on a rescan `SUMMARY.md` and the `scan`
reply open with every active finding of the previous run, by rule ID and path as
the first report named it, each `fixed`, `open` or `not re-checked`, and then the
new ones. `fixed` still needs its Scanner to have run again (F5.6, 29.0.5).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur import api
from valvur import fingerprint as _fp
from valvur.engine_host import LocalRuntime
from valvur.findings import Finding
from valvur.invocation import Invocation

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
RESULTS = ".security-scan"


class _Planted:
    """A Scanner that reports the (rule, path) pairs it is given, or fails."""

    artifact = None
    kind = "scanner"
    version = "1"

    def __init__(self, pairs: list[tuple[str, str]], *, name: str = "planter",
                 seconds: float = 0.0):
        self.name, self.pairs, self.seconds = name, pairs, seconds

    def applies_to(self, workspace, context=None):
        return True, ""

    def for_profile(self, *, network):
        return self

    def command(self, workspace):
        return Invocation(tool=self.name, version="1", report=f"{self.name}.json", timeout=60,
                          argv=("fake-report", str(self.seconds), json.dumps(self.pairs),
                                f"/results/{self.name}.json"))

    def parse(self, output):
        return [Finding(rule=rule, path=path, line=1, title=f"{rule} in {path}",
                        fingerprint=_fp.derive(rule, path), severity="high",
                        sources=(output.tool,))
                for rule, path in json.loads(output.stdout or "[]")]


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def _scan(workspace, *adapters, **kwargs):
    return api.scan(workspace, runner=LocalRuntime(FAKE_TOOLS), adapters=list(adapters),
                    **kwargs)


def _summary(workspace) -> str:
    return (workspace / RESULTS / "SUMMARY.md").read_text()


def _since(summary: str) -> str:
    return summary.split("## Since the last scan", 1)[1].split("\n## ", 1)[0]


def test_a_rescan_opens_with_each_earlier_finding_s_state_then_the_new_ones(workspace):
    _scan(workspace, _Planted([("r.fixed", "src/a.py"), ("r.open", "src/b.py")]))

    run = _scan(workspace, _Planted([("r.open", "src/b.py"), ("r.new", "src/c.py")]))

    assert run.earlier == [("fixed", "r.fixed", "src/a.py"), ("open", "r.open", "src/b.py")] \
        or run.earlier == [("open", "r.open", "src/b.py"), ("fixed", "r.fixed", "src/a.py")]
    summary = _summary(workspace)
    since = _since(summary)
    assert "| fixed | `r.fixed` | `src/a.py` |" in since
    assert "| open | `r.open` | `src/b.py` |" in since
    assert since.index("| open |") < since.index("**New since the last scan:** 1")
    assert "- `r.new` at `src/c.py`" in since
    assert summary.index("## Since the last scan") < summary.index("**Active findings:**"), \
        "the table opens the report, after the verdict"


def test_the_first_scan_has_no_table(workspace):
    _scan(workspace, _Planted([("r.one", "a.py")]))

    assert "## Since the last scan" not in _summary(workspace)


def test_a_finding_whose_scanner_did_not_run_is_not_re_checked_and_the_next_run_says(
        workspace):
    """F5.6 as 29.0.5 has it: gone is fixed only where its Scanner looked. Cut by the
    budget, the Scanner did not; the finding keeps its row, and the next run that
    looks names it fixed."""
    other = _Planted([], name="other")
    _scan(workspace, _Planted([("r.kept", "src/a.py")]), other)

    cut = _scan(workspace, _Planted([], seconds=5.0), other, budget_s=1.5)
    assert cut.earlier == [("not re-checked", "r.kept", "src/a.py")]
    assert "| not re-checked | `r.kept` | `src/a.py` |" in _since(_summary(workspace))

    looked = _scan(workspace, _Planted([]), other)
    assert looked.earlier == [("fixed", "r.kept", "src/a.py")]


def test_the_table_shows_twenty_rows_by_rank_and_counts_the_rest(workspace):
    _scan(workspace, _Planted([(f"r.n{i:02}", "src/a.py") for i in range(25)]))

    _scan(workspace, _Planted([]))

    since = _since(_summary(workspace))
    assert since.count("| fixed |") == 20
    assert "| _…and 5 more_ | | |" in since
