"""Sub-phase 4.0 — the Check protocol.

A Check is detection valvur performs itself, as opposed to a Scanner, which is a
third-party tool we orchestrate. Checks run in the container exactly as Scanners do.
"""

from valvur import scan
from valvur.adapters import CheckAdapter


def test_a_workspace_with_no_licence_file_is_a_finding(workspace, runner_finding_nothing):
    """F4.2 — invisible to every Scanner we orchestrate, and it blocks a release."""
    run = scan(workspace, runner=runner_finding_nothing,
               adapters=[CheckAdapter("licence-file")])

    assert [f.rule for f in run.findings] == ["valvur.licence.missing"]


def test_a_workspace_with_a_licence_file_is_clean(workspace, runner_finding_nothing):
    (workspace / "LICENSE").write_text("MIT License\n")

    run = scan(workspace, runner=runner_finding_nothing,
               adapters=[CheckAdapter("licence-file")])

    assert run.findings == []


def test_checks_are_distinguishable_from_scanners(workspace, runner_finding_nothing):
    """P4 — we credit Scanners by name and licence. Detection we perform ourselves
    must never be presented as a third-party tool's work, nor the reverse."""
    from valvur.adapters import GitleaksAdapter

    assert CheckAdapter("licence-file").kind == "check"
    assert GitleaksAdapter().kind == "scanner"


def test_a_check_failure_is_isolated_like_a_scanner_failure(
    workspace, runner_finding_one_secret
):
    """Checks inherit the fleet's failure isolation, so one broken Check does not
    cost the run."""
    run = scan(workspace, runner=runner_finding_one_secret,
               adapters=[CheckAdapter("no-such-check")])

    assert run.findings == [] or run.failures
