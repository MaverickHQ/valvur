"""Sub-phase 3.1 — failure semantics for a fleet of Scanners.

Governing rule: findings never fail the run; infrastructure failures always surface.
A silent failure manufactures false confidence and is worse than no scan.
"""

import pytest
from conftest import CrashingAdapter

from valvur import scan
from valvur.adapters import GitleaksAdapter


def test_a_crashing_scanner_does_not_stop_the_other_scanners(
    workspace, runner_finding_one_secret
):
    """F2.5 — one broken Scanner must not cost you the other five."""
    run = scan(
        workspace,
        runner=runner_finding_one_secret,
        adapters=[GitleaksAdapter(), CrashingAdapter()],
    )

    # The subject is failure isolation: the surviving Scanner's finding must arrive.
    # Counting every Finding in the run made this depend on how many OTHER findings
    # the fixture happens to produce, which is not what the test is about — the
    # coverage gaps added in 19.D.1 broke it without touching failure isolation.
    assert [f.rule for f in run.findings if f.rule == "aws-access-token"]


def test_a_crashing_scanner_is_reported_at_the_top_of_the_summary(
    workspace, runner_finding_one_secret
):
    """F7.7 — failures appear before any finding, or the reader trusts a partial scan."""
    scan(
        workspace,
        runner=runner_finding_one_secret,
        adapters=[GitleaksAdapter(), CrashingAdapter()],
    )

    summary = (workspace / ".security-scan" / "SUMMARY.md").read_text()
    before_findings = summary.split("**Findings:**")[0]

    assert "exploding-scanner" in before_findings


def test_a_scanner_that_times_out_is_recorded_as_failed_not_clean(
    workspace, runner_finding_nothing
):
    """F2.7 — a timeout that reads as 'no findings' is the worst possible outcome."""
    import subprocess

    timing_out = CrashingAdapter(reason="timed out after 300s")
    timing_out.run = lambda runner, ws: (_ for _ in ()).throw(
        subprocess.TimeoutExpired(cmd="trivy", timeout=300)
    )

    run = scan(
        workspace, runner=runner_finding_nothing, adapters=[GitleaksAdapter(), timing_out]
    )

    assert [s.tool for s in run.failures] == ["exploding-scanner"]


def test_a_scanner_exiting_nonzero_because_it_found_issues_is_a_successful_run(
    workspace, runner_finding_one_secret
):
    """F2.4 — gitleaks exits 1 when it finds something. That is success, not failure."""
    run = scan(workspace, runner=runner_finding_one_secret)

    assert run.failures == []


def test_when_every_scanner_fails_the_scan_run_fails(workspace, runner_finding_nothing):
    """N3.2 — a run where nothing worked must never look like a clean result."""
    from valvur import ScannerFailed

    with pytest.raises(ScannerFailed):
        scan(workspace, runner=runner_finding_nothing, adapters=[CrashingAdapter()])


def test_run_json_records_which_scanners_ran_and_which_failed(
    workspace, runner_finding_one_secret
):
    """F7.12, N3.1 — without provenance you cannot tell 'no vulnerabilities' from
    'every scanner silently died'."""
    import json

    scan(
        workspace,
        runner=runner_finding_one_secret,
        adapters=[GitleaksAdapter(), CrashingAdapter()],
    )

    data = json.loads((workspace / ".security-scan" / "run.json").read_text())
    by_tool = {s["tool"]: s for s in data["scanners"]}

    assert by_tool["gitleaks"]["ok"] is True
    assert by_tool["exploding-scanner"]["ok"] is False
    assert "OOM" in by_tool["exploding-scanner"]["reason"]


def test_run_json_states_plainly_whether_the_scan_was_complete(
    workspace, runner_finding_nothing
):
    """The one field an agent should check before trusting anything else."""
    import json

    scan(workspace, runner=runner_finding_nothing,
         adapters=[GitleaksAdapter(), CrashingAdapter()])

    data = json.loads((workspace / ".security-scan" / "run.json").read_text())

    # `complete` is the subject, and it is deliberately independent of `status`: a
    # scan can find nothing and still be worthless because a Scanner crashed. That
    # separation is the whole point of the field.
    assert data["complete"] is False
