"""Sub-phase 3.1 — failure semantics for a fleet of Scanners.

Governing rule: findings never fail the run; infrastructure failures always surface.
A silent failure manufactures false confidence and is worse than no scan.
"""

import pytest
from conftest import GITLEAKS_ONE_SECRET, CrashingAdapter

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
    before_findings = summary.split("**Active findings:**")[0]

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


# ------------------------------------------------ the parse boundary (26.0.1)
#
# F2.5 names three failure shapes — a crash, a timeout, and *unparseable output* —
# and the tests above cover two. The third had none: a Scanner that exits 0 and
# writes a report the adapter cannot read (a container killed mid-write, a format
# change, a stray line on stdout) raised straight out of `api.scan`. Measured
# 2026-09-20 with Trivy's report cut at character 50: `JSONDecodeError` out of the
# whole run, Gitleaks' result thrown away with it, nothing written. The second
# external review called it the parse failure boundary; it is F2.5's own words.


def _reporting(tool: str, stdout: str, exit_code: int = 0):
    """A fake whose `run_<tool>` answers with exactly this report."""
    from conftest import FakeRunner

    from valvur.runner import ScannerOutput

    class Runner(FakeRunner):
        pass

    def run(self, workspace):
        return ScannerOutput(tool, "0.0.0", stdout, "", exit_code)

    setattr(Runner, f"run_{tool}", run)
    return Runner(GITLEAKS_ONE_SECRET, exit_code=1)


def test_a_report_the_adapter_cannot_read_is_one_failed_scanner_not_a_raised_scan(workspace):
    """F2.5's third clause. Trivy exits 0 with its JSON cut mid-write."""
    from valvur.adapters import TrivyAdapter

    truncated = '{"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{"Vuln'
    run = scan(
        workspace, runner=_reporting("trivy", truncated),
        adapters=[GitleaksAdapter(), TrivyAdapter()],
    )

    assert [s.tool for s in run.failures] == ["trivy"]
    reason = run.failures[0].reason
    assert reason.startswith("report unreadable: JSONDecodeError"), reason
    assert [f.rule for f in run.findings if f.rule == "aws-access-token"], \
        "the other Scanner's result went down with it"


def test_a_shape_change_that_raises_something_other_than_a_decode_error_is_the_same(workspace):
    """Checkov's parser indexes into its report; a shape change is a `KeyError` or
    an `AttributeError`, not a `JSONDecodeError`, and must be caught the same."""
    from valvur.adapters import CheckovAdapter

    (workspace / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    # Valid JSON, wrong shape: `results` is a string, so `.get` is an AttributeError.
    run = scan(
        workspace, runner=_reporting("checkov", '{"results": "gone"}'),
        adapters=[GitleaksAdapter(), CheckovAdapter()],
    )

    assert [s.tool for s in run.failures] == ["checkov"]
    assert "report unreadable: AttributeError" in run.failures[0].reason
    assert [f.rule for f in run.findings if f.rule == "aws-access-token"]


def test_an_unreadable_report_is_named_at_the_top_of_the_summary_and_kept_under_raw(workspace):
    """The reader learns of it first (F7.7) and can read what the Scanner actually
    wrote (F2.8) — the raw text is the evidence of what went wrong."""
    from valvur.adapters import TrivyAdapter

    truncated = '{"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{"Vuln'
    scan(workspace, runner=_reporting("trivy", truncated),
         adapters=[GitleaksAdapter(), TrivyAdapter()])

    folder = workspace / ".security-scan"
    summary = (folder / "SUMMARY.md").read_text()
    assert "report unreadable" in summary.split("**Active findings:**")[0]
    assert (folder / "raw" / "trivy.json").read_text() == truncated
    provenance = (folder / "run.json").read_text()
    assert "report unreadable" in provenance and '"complete": false' in provenance


def test_one_unreadable_check_report_in_the_batch_does_not_cost_the_other_checks(
    workspace, monkeypatch
):
    """23.4.2 runs the three Checks in one container and parses three reports out
    of one; one of them unreadable is one failed Check, not three."""
    from conftest import FakeRunner, run_checks_in_process

    from valvur.adapters import DEFAULT_ADAPTERS
    from valvur.runner import ScannerOutput

    CHECK_ADAPTERS = [a for a in DEFAULT_ADAPTERS if getattr(a, "kind", "") == "check"]

    class Runner(FakeRunner):
        def run_checks(self, names, workspace, *, network=False):
            outputs = run_checks_in_process(names, workspace, network=network)
            good = outputs["ai-artifact"]
            outputs["ai-artifact"] = ScannerOutput(
                good.tool, good.version, '[{"rule": "x", "path": ', good.stderr, 0)
            return outputs

    run = scan(workspace, runner=Runner(), adapters=list(CHECK_ADAPTERS))

    assert [s.tool for s in run.failures] == ["ai-artifact"]
    assert "report unreadable" in run.failures[0].reason
    assert {s.tool for s in run.scanners if s.ok} == {
        a.name for a in CHECK_ADAPTERS if a.name != "ai-artifact"}
