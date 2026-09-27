"""Task 29.0.5 — a Finding whose Scanner did not run is not fixed.

Found by the agent-driven pass (29.2.3, run 2): a `scan` with a 30 s budget cut
seven of eight Scanners and reported the eight previous Findings as *fixed* —
`fixed: 8` in run.json, "fixed since last run" in SUMMARY.md, the DONE reply —
and rewrote state.json, so the next complete run would have called them
*regressed*. The agent caught it ("they show as fixed only because the scanner
that produces them never ran") and the message had told it otherwise.

A previous Finding is fixed only when the Scanner that reported it ran this time.
Otherwise it is *not re-checked*: carried in the state, counted on every surface,
neither fixed nor persisting.
"""

from __future__ import annotations

import json
import threading

import pytest

from valvur import api
from valvur import fingerprint as _fp
from valvur.findings import Finding
from valvur.runner import ScannerOutput

RESULTS = ".security-scan"


class _Finder:
    """A Scanner that reports one planted Finding, unless told to find nothing —
    and takes `seconds`, so a budget can cut it."""

    artifact = None

    def __init__(self, name: str = "finder", *, finds: bool = True, seconds: float = 0.0):
        self.name = name
        self.finds = finds
        self.seconds = seconds

    def applies_to(self, workspace):
        return True, ""

    def run(self, runner, workspace):
        if self.seconds and runner.stopped.wait(timeout=self.seconds):
            return ScannerOutput(self.name, "1", "", "killed", 137)
        return ScannerOutput(self.name, "1", "[1]" if self.finds else "[]", "", 0)

    def parse(self, output):
        if output.stdout != "[1]":
            return []
        return [Finding(rule="planted.rule", path="a.py", line=1, title="a planted finding",
                        fingerprint=_fp.derive("planted.rule", "a.py"), sources=(output.tool,))]


class _Other(_Finder):
    """A second Scanner that never finds anything."""

    def __init__(self, seconds: float = 0.0):
        super().__init__("other", finds=False, seconds=seconds)


class _Runner:
    image = "x/y:1"
    runtime = "/usr/local/bin/docker"

    def __init__(self):
        self.stopped = threading.Event()
        self.cancelled = False

    def stop_containers(self) -> int:
        self.stopped.set()
        return 1


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def _scan(workspace, adapters, **kwargs):
    return api.scan(workspace, runner=_Runner(), adapters=adapters, **kwargs)


def _run_json(workspace):
    return json.loads((workspace / RESULTS / "run.json").read_text())


def _state(workspace):
    return json.loads((workspace / RESULTS / "state.json").read_text())


# ------------------------------------------------------------------ the defect


def test_a_finding_whose_scanner_was_cut_is_not_reported_fixed(workspace):
    """Run 1 finds it; run 2's budget cuts the Scanner that would re-check it. The
    Finding is neither fixed nor persisting: it is *not re-checked*, on every
    surface, and the state still holds it for run 3."""
    from valvur.operations import scan_status

    first = _scan(workspace, [_Finder(), _Other()])
    assert [f.status for f in first.findings] == ["new"]

    cut = _scan(workspace, [_Finder(seconds=5.0), _Other()], budget_s=0.3)
    assert cut.budget_cut == ["finder"]
    assert cut.fixed == [], "a Scanner that did not run cannot have fixed anything"
    assert cut.not_rechecked == [("a planted finding", "finder")]

    run = _run_json(workspace)
    assert run["fixed"] == 0
    assert run["not_rechecked"] == 1
    summary = (workspace / RESULTS / "SUMMARY.md").read_text()
    assert "fixed since last run" not in summary
    assert "**not re-checked:** 1" in summary
    assert "## Not re-checked since the last scan" in summary
    assert "- a planted finding — `finder` did not run" in summary
    status = scan_status({"workspace": str(workspace)})
    assert "Fixed since the last scan" not in status
    assert "not re-checked: 1 previous finding(s) whose Scanner did not run" in status

    state = _state(workspace)
    fp = _fp.derive("planted.rule", "a.py")
    assert fp in state["present"], "carried, so the next run compares against it"
    assert state["fixed"] == []
    assert state["sources"][fp] == ["finder"]


def test_a_carried_finding_is_persisting_on_the_next_complete_run(workspace):
    """Run 3 re-checks and still finds it: persisting, not regressed — the run
    that did not look is not a run that found it gone."""
    _scan(workspace, [_Finder(), _Other()])
    _scan(workspace, [_Finder(seconds=5.0), _Other()], budget_s=0.3)
    third = _scan(workspace, [_Finder(), _Other()])
    assert [f.status for f in third.findings] == ["persisting"]
    assert third.not_rechecked == [] and third.fixed == []


def test_a_finding_absent_after_its_scanner_ran_is_fixed_as_before(workspace):
    """The other Scanner being cut changes nothing about a Finding whose own
    Scanner ran and found it gone (F5.6 unchanged where it applies)."""
    _scan(workspace, [_Finder(), _Other()])
    second = _scan(workspace, [_Finder(finds=False), _Other(seconds=5.0)], budget_s=0.3)
    assert second.budget_cut == ["other"]
    assert second.fixed == ["a planted finding"]
    assert second.not_rechecked == []
    assert _state(workspace)["fixed"] == [_fp.derive("planted.rule", "a.py")]


def test_a_carried_finding_that_is_gone_when_re_checked_is_fixed_then(workspace):
    """Carried through the cut run, then its Scanner runs and it is absent: fixed
    on that run, with its title remembered across the gap."""
    _scan(workspace, [_Finder(), _Other()])
    _scan(workspace, [_Finder(seconds=5.0), _Other()], budget_s=0.3)
    third = _scan(workspace, [_Finder(finds=False), _Other()])
    assert third.fixed == ["a planted finding"]
    assert third.not_rechecked == []


# ------------------------------------------------- state written before 29.0.5


def _old_state(workspace, fp: str, title: str) -> None:
    """A state.json from before sources were recorded."""
    from valvur.fingerprint import FP_VERSION

    results = workspace / RESULTS
    results.mkdir(exist_ok=True)
    (results / "state.json").write_text(json.dumps({
        "schema": 1, "fp_version": FP_VERSION, "generation": "old",
        "present": {fp: title}, "fixed": [],
    }))


def test_a_state_without_sources_is_carried_when_any_scanner_did_not_run(workspace):
    """Sources unknown, run incomplete: which Scanner would have re-checked it is
    unknowable, so it is not re-checked rather than fixed."""
    _old_state(workspace, _fp.derive("planted.rule", "a.py"), "a planted finding")
    cut = _scan(workspace, [_Finder(finds=False), _Other(seconds=5.0)], budget_s=0.3)
    assert cut.fixed == []
    assert cut.not_rechecked == [("a planted finding", "")]


def test_a_state_without_sources_is_fixed_when_every_scanner_ran(workspace):
    _old_state(workspace, _fp.derive("planted.rule", "a.py"), "a planted finding")
    complete = _scan(workspace, [_Finder(finds=False), _Other()])
    assert complete.fixed == ["a planted finding"]
    assert complete.not_rechecked == []


def test_the_structured_status_reply_carries_the_count(workspace):
    from valvur.operations import scan_status_reply

    _scan(workspace, [_Finder(), _Other()])
    _scan(workspace, [_Finder(seconds=5.0), _Other()], budget_s=0.3)
    _text, structured = scan_status_reply({"workspace": str(workspace)})
    assert structured["fixed"] == 0
    assert structured["not_rechecked"] == 1


def test_the_summary_groups_identical_titles(workspace):
    """Eight pinning Findings on one tree share a paragraph-long title; the
    section says it once with a count, not eight times (measured on the gate's
    tree)."""
    from valvur.api import ScanRun
    from valvur.summary import render

    run = ScanRun(not_rechecked=[("Action pinned to a mutable tag", "opengrep")] * 8
                  + [("a secret in config.py", "gitleaks")])
    summary = render(run)
    assert summary.count("Action pinned to a mutable tag") == 1
    assert "- Action pinned to a mutable tag (8 findings) — `opengrep` did not run" in summary
    assert "- a secret in config.py — `gitleaks` did not run" in summary
