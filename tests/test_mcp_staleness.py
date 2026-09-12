"""Task 16.1 — the MCP surface must carry the `inconclusive` verdict.

Phase 14 taught valvur to say "we found nothing, and our data was too old for that
to be evidence". It taught the CLI, `SUMMARY.md` and `run.json`. It did not teach the
surface that ADR-0015 makes primary, and that reaches an agent's context with no file
in between.

Measured 2026-09-05 against a 60-day-old database, before this fix:

    list_findings -> "No findings match. The scan itself may still have been
                      incomplete — check `scan_status`."

Which pointed at the wrong reason: the scan *was* complete. It was inconclusive, and
the word never appeared. An agent that reads "no findings" stops looking, and unlike
a human it will not glance at `SUMMARY.md` for a caveat nobody told it to expect.
"""

from __future__ import annotations

import json

import pytest

from valvur import operations


def _scanned(tmp_path, *, status, findings=(), db_age_days=None, stale=False):
    """A Results Folder as a scan would leave it."""
    results = tmp_path / ".security-scan"
    results.mkdir(parents=True)
    (results / "findings.json").write_text(json.dumps({
        "schema": 1, "status": status, "findings": list(findings),
    }))
    (results / "run.json").write_text(json.dumps({
        "status": status,
        "status_reason": (
            f"nothing was found, and that is not evidence: the vulnerability database "
            f"is {db_age_days:.0f} days old (threshold 7)" if stale else ""
        ),
        "complete": True,
        "findings": len(findings),
        "scanners": [{"tool": "trivy", "ok": True, "reason": ""}],
        "network": {"what_left_the_machine": "nothing"},
        "database": {"age_days": db_age_days, "stale": stale, "stale_after_days": 7},
    }))
    return tmp_path


def test_an_agent_finding_nothing_is_told_why_that_proves_nothing(tmp_path):
    """The case that mattered. Nothing found, by data too old to have found it."""
    workspace = _scanned(tmp_path, status="inconclusive", db_age_days=60.0, stale=True)

    answer = operations.list_findings({"workspace": str(workspace)})

    assert "60 days old" in answer
    assert "NOT evidence that there is nothing" in answer
    assert "valvur update --if-stale" in answer


def test_findings_from_a_stale_scan_are_marked_incomplete_not_worthless(tmp_path):
    """A different claim, because it is a different claim. What was found is real;
    what is missing is unknown. Saying "found nothing" here would be false."""
    finding = {"rule": "CVE-1", "path": "a.py", "line": 0, "rank": 1,
               "severity": "high", "title": "x", "status": "new",
               "fingerprint": "a" * 32, "sources": ["trivy"]}
    workspace = _scanned(tmp_path, status="findings", findings=[finding],
                         db_age_days=60.0, stale=True)

    answer = operations.list_findings({"workspace": str(workspace)})

    assert "the list is incomplete" in answer
    assert "NOT evidence that there is nothing" not in answer


def test_scan_status_explains_inconclusive_rather_than_only_reporting_it(tmp_path):
    """`inconclusive` beside `complete: True` and a healthy Scanner list reads as a
    contradiction unless the reason is given. It is not one: every Scanner ran, and
    the data was too old for a nil result to mean anything."""
    workspace = _scanned(tmp_path, status="inconclusive", db_age_days=60.0, stale=True)

    answer = operations.scan_status({"workspace": str(workspace)})

    # The reason is `run.json`'s own `status_reason`, printed verbatim (22.D.4) —
    # not reconstructed here from `database.stale`, which named only one cause.
    assert "^ nothing was found, and that is not evidence" in answer
    assert "database is 60 days old" in answer


def test_a_run_json_without_a_reason_says_so_rather_than_guessing(tmp_path):
    """A results folder written before 22.D.4 has no `status_reason`. Guessing one
    from `database.stale` is what this field replaced; say it is missing instead."""
    workspace = _scanned(tmp_path, status="inconclusive", db_age_days=60.0, stale=True)
    run = json.loads((workspace / ".security-scan" / "run.json").read_text())
    del run["status_reason"]
    (workspace / ".security-scan" / "run.json").write_text(json.dumps(run))

    answer = operations.scan_status({"workspace": str(workspace)})

    assert "reason is not recorded" in answer and "rescan" in answer


@pytest.mark.parametrize("tool", ["list_findings", "scan_status"])
def test_a_fresh_database_produces_no_warning_on_any_tool(tmp_path, tool):
    """The pair that keeps the warning worth reading. A caveat on every response is
    one an agent learns to skip — the same reason the coverage caveat is gated."""
    workspace = _scanned(tmp_path, status="clean", db_age_days=0.5, stale=False)

    answer = getattr(operations, tool)({"workspace": str(workspace)})

    assert "WARNING" not in answer
    assert "days old" not in answer


def test_a_missing_run_json_does_not_fabricate_a_warning(tmp_path):
    """Absent provenance is not stale provenance."""
    results = tmp_path / ".security-scan"
    results.mkdir(parents=True)
    (results / "findings.json").write_text(json.dumps({"status": "clean", "findings": []}))

    answer = operations.list_findings({"workspace": str(tmp_path)})

    assert "WARNING" not in answer
