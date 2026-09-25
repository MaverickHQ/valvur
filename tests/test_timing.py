"""Task 23.3.2 — `duration_s` on every ScannerRun, on every surface.

How users find the Checkov cost themselves, and how 23.4.2 (the Checks in one
container) and 24.3 (N1.1's number) are measured rather than argued. The fleet runs
concurrently, so a scan takes about as long as its slowest Scanner — which is the
one line SUMMARY.md says.
"""

from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path

import pytest

from valvur import api
from valvur.api import ScanRun
from valvur.provenance import ScannerRun
from valvur.provenance import render as _provenance
from valvur.runner import ScannerOutput
from valvur.summary import render as _summary

# ------------------------------------------------------------- the measurement


class _Adapter:
    """One Scanner that takes a known time and ends the way the test says."""

    name = "slowpoke"
    artifact = None

    def __init__(self, *, sleep: float = 0.05, ending: str = "ok"):
        self.sleep = sleep
        self.ending = ending

    def applies_to(self, workspace):
        if self.ending == "skipped":
            return False, "nothing to analyse"
        return True, ""

    def run(self, runner, workspace):
        time.sleep(self.sleep)
        if self.ending == "crash":
            raise RuntimeError("boom")
        if self.ending == "no-report":
            return ScannerOutput(self.name, "1.0", "", "went wrong", 2)
        return ScannerOutput(self.name, "1.0", "[]", "", 0)

    def parse(self, output):
        return []


@pytest.mark.parametrize("ending", ["ok", "crash", "no-report", "skipped"])
def test_every_outcome_carries_how_long_the_scanner_took(ending, tmp_path):
    scanner = api._run_one(_Adapter(ending=ending), None, tmp_path).scanner

    assert isinstance(scanner, ScannerRun)
    if ending == "skipped":
        assert scanner.skipped and scanner.duration_s < 0.05
    else:
        assert scanner.duration_s >= 0.05, f"{ending}: {scanner.duration_s}"
        assert scanner.duration_s < 5


def test_the_progress_line_says_how_long_each_scanner_took(tmp_path, monkeypatch):
    """`scan_status`'s "Completed so far" is where a user watching a slow first scan
    learns which Scanner is slow — before run.json exists."""
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    said: list[str] = []

    class Runner:
        pass

    api.scan(tmp_path / "ws", runner=Runner(), adapters=[_Adapter(sleep=0.1)],
             on_progress=said.append)

    [line] = [s for s in said if s.startswith("slowpoke")]
    assert line.startswith("slowpoke: ok (0.1s)") or line.startswith("slowpoke: ok (0.2s)"), line


# ------------------------------------------------------------------ run.json


def _run(*scanners: ScannerRun) -> ScanRun:
    return ScanRun(findings=[], scanners=list(scanners), profile="offline")


def test_run_json_records_each_scanners_duration_to_a_tenth():
    data = json.loads(_provenance(_run(
        ScannerRun("gitleaks", ok=True, duration_s=0.4321),
        ScannerRun("checkov", ok=True, duration_s=27.94),
        ScannerRun("trivy", ok=False, reason="exited 1", duration_s=3.06),
    )))

    assert [(s["tool"], s["duration_s"]) for s in data["scanners"]] == [
        ("gitleaks", 0.4), ("checkov", 27.9), ("trivy", 3.1)]


# ---------------------------------------------------------------- SUMMARY.md


def test_summary_names_the_slowest_scanner_and_why_that_is_the_number():
    text = _summary(_run(
        ScannerRun("gitleaks", ok=True, duration_s=0.4),
        ScannerRun("checkov", ok=True, duration_s=27.9),
        ScannerRun("trivy", ok=True, duration_s=3.1),
    ))

    assert "slowest: checkov 27.9s" in text
    assert "concurrently" in text


def test_summary_says_nothing_about_timing_for_a_run_that_has_none():
    """A ScanRun built by an older valvur, or a test: no invented number."""
    text = _summary(_run(ScannerRun("gitleaks", ok=True)))

    assert "slowest" not in text


def test_a_skipped_scanner_is_never_the_slowest():
    text = _summary(_run(
        ScannerRun("gitleaks", ok=True, duration_s=0.4),
        ScannerRun("checkov", ok=True, skipped=True, reason="no IaC", duration_s=99.0),
    ))

    assert "slowest: gitleaks 0.4s" in text


# --------------------------------------------------------------- scan_status


def test_scan_status_shows_each_scanners_time_and_tolerates_a_run_without_it(tmp_path):
    from valvur.operations import scan_status

    results = tmp_path / ".security-scan"
    results.mkdir()
    (results / "run.json").write_text(json.dumps({
        "status": "clean", "complete": True, "profile": "offline",
        "findings": {"active": 0, "suppressed": 0, "not_covered": 0},
        "scanners": [
            {"tool": "gitleaks", "ok": True, "reason": "", "duration_s": 0.4},
            {"tool": "checkov", "ok": True, "reason": "", "duration_s": 27.9},
            {"tool": "trivy", "ok": False, "reason": "exited 1"},        # an older run.json
        ],
        "network": {"what_left_the_machine": "nothing"},
    }))

    text = scan_status({"workspace": str(tmp_path)})

    assert "  gitleaks: ok (0.4s)" in text
    assert "  checkov: ok (27.9s)" in text
    assert "  trivy: FAILED — exited 1\n" in text
    assert "slowest: checkov 27.9s" in text


# ------------------------------------------------------------------ the corpus


def _corpus_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "corpus.py"
    spec = importlib.util.spec_from_file_location("corpus_script", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_corpus_report_gains_the_timings_and_the_slowest():
    corpus = _corpus_module()

    timings = corpus._timings({"scanners": [
        {"tool": "gitleaks", "ok": True, "duration_s": 0.4},
        {"tool": "checkov", "ok": True, "duration_s": 27.9},
        {"tool": "trivy", "ok": True, "duration_s": 3.1},
    ]})

    assert timings == {"duration_s": {"gitleaks": 0.4, "checkov": 27.9, "trivy": 3.1},
                       "slowest": "checkov 27.9s"}
    assert corpus._timings({"scanners": [{"tool": "x", "ok": True}]}) == {
        "duration_s": {}, "slowest": ""}


def test_the_corpus_compare_says_what_full_added_over_offline():
    """Task 23.4.5: osv-scanner's marginal value, from the two reports the corpus
    workflow writes — advisories apart from the rest, so the number is the one that
    matters."""
    corpus = _corpus_module()
    offline = {"repos": {
        "cobra": {"findings": {"total": 11}, "by_rule": {"valvur.pinning.mutable-action-ref": 10}},
        "flask": {"findings": {"total": 3}, "by_rule": {"CVE-2020-1": 1, "gitleaks-aws": 2}},
    }}
    full = {"repos": {
        "cobra": {"findings": {"total": 14}, "by_rule": {"valvur.pinning.mutable-action-ref": 10,
                                                        "CVE-2022-1705": 1, "GO-2022-0525": 2}},
        # gitleaks found one fewer on `full` (a redaction difference, say): a rule
        # that shrank is not something `full` added.
        "flask": {"findings": {"total": 3}, "by_rule": {"CVE-2020-1": 1, "gitleaks-aws": 1,
                                                        "valvur.dependency.young": 1}},
    }}

    rows = corpus.compare(offline, full)

    assert rows[0] == {"repo": "cobra", "offline": 11, "full": 14, "advisories_added": 3,
                       "other_added": 0, "examples": ["CVE-2022-1705", "GO-2022-0525"]}
    assert rows[1] == {"repo": "flask", "offline": 3, "full": 3, "advisories_added": 0,
                       "other_added": 1, "examples": []}

